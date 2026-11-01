//! Accepted A10 inactive-restore journal-v2 protocol.
//!
//! This is a non-mutating protocol boundary. It can authenticate signed
//! inactive records and publish the protected journal, but it has no target
//! database executor and cannot authorize controller startup or activation.
//! Fixtures in this module are synthetic and test-signed; they are not
//! production qualification evidence.

use std::{collections::HashSet, path::Path};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const JOURNAL_FORMAT: &str = "o3k-restore-journal-v2";
pub const REQUEST_FORMAT: &str = "o3k-restore-signing-request-v2";
pub const RESPONSE_FORMAT: &str = "o3k-restore-signing-response-v2";
pub const BRANCH_INACTIVE: &str = "inactive";
pub const PROFILE: &str = "o3k-small-edge-v1";
pub const BACKEND: &str = "postgresql";
pub const DEPLOYMENT: &str = "virtualized";
pub const SIGNING_PURPOSE: &str = "restore_journal";
pub const MAX_JOURNAL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RECORDS: usize = 1024;
pub const MAX_CONFIRMATION_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InactivePhase {
    Preflighted,
    TargetReservedInactive,
    StagingInactive,
    DatabaseRestoredInactive,
    FilesRestoredInactive,
    InactiveVerified,
    Aborted,
    FailedRecoverable,
    Quarantined,
    Discarded,
}

impl InactivePhase {
    /// Complete closed A10 §7.1.2 transition allowlist. The verified terminal
    /// state is intentionally inert and cannot be resumed into another phase.
    pub fn permits_next(self, next: Self) -> bool {
        use InactivePhase as P;
        matches!(
            (self, next),
            (P::Preflighted, P::TargetReservedInactive | P::Aborted)
                | (
                    P::TargetReservedInactive,
                    P::StagingInactive | P::Aborted | P::Quarantined
                )
                | (
                    P::StagingInactive,
                    P::DatabaseRestoredInactive | P::FailedRecoverable | P::Quarantined
                )
                | (
                    P::DatabaseRestoredInactive,
                    P::FilesRestoredInactive | P::FailedRecoverable | P::Quarantined
                )
                | (
                    P::FilesRestoredInactive,
                    P::InactiveVerified | P::FailedRecoverable | P::Quarantined
                )
                | (P::FailedRecoverable, P::Discarded | P::Quarantined)
                | (P::Quarantined, P::Discarded)
        )
    }

    /// No A10 journal phase, including `INACTIVE_VERIFIED`, authorizes an
    /// operational store open. This policy is intentionally unconditional.
    pub const fn denies_runtime(self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationBinding {
    pub restored_target_database_identity: String,
    pub artifact_sha256: String,
    pub release_identity: String,
    pub migration_baseline_sha256: String,
    pub d10_catalog_definition_sha256: String,
    pub repository_inventory_sha256: String,
    pub target_installation_id: String,
    pub verification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    pub format: String,
    pub branch: String,
    pub request_id: Uuid,
    pub request_nonce: String,
    pub operation_id: Uuid,
    pub artifact_sha256: String,
    pub site_id: String,
    pub source_installation_id: String,
    pub target_installation_id: String,
    pub target_device: u64,
    pub target_inode: u64,
    pub target_database_identity: String,
    pub profile: String,
    pub backend: String,
    pub backend_version: String,
    pub deployment: String,
    pub release_identity: String,
    pub installation_policy_sha256: String,
    pub sequence: u64,
    pub previous_signed_record_sha256: String,
    pub intended_transition: InactivePhase,
    pub verification: Option<VerificationBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningResponse {
    pub format: String,
    pub request_sha256: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecord {
    pub format: String,
    pub request: SigningRequest,
    pub response: SigningResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub format: String,
    pub branch: String,
    pub records: Vec<SignedRecord>,
}

/// Purpose and installation scope come from the authenticated installed C1
/// trust bundle. The caller must not populate this from journal fields.
pub struct JournalAuthority<'a> {
    key_id: &'a str,
    purpose: &'a str,
    site_id: &'a str,
    installation_id: &'a str,
    profile: &'a str,
    backend: &'a str,
    backend_version: &'a str,
    deployment: &'a str,
    release_identity: &'a str,
    policy_sha256: &'a str,
    not_before: i64,
    not_after: i64,
    revoked: bool,
    verifying_key: &'a VerifyingKey,
}

/// Produced only after the installed v2 generation verifier has authenticated
/// the migration selector, high-water, signed policy, release inventory and
/// current C1 trust/revocation snapshot. Its fields remain private so callers
/// cannot turn policy presence into A10 selection.
#[cfg(target_os = "linux")]
pub struct SelectedV2JournalContext {
    pub(crate) policy: crate::recovery_migration_selector::InstallationPolicyV2,
    policy_sha256: String,
    trust: crate::recovery_trust::VerifiedTrust,
}

/// Backup and target identities observed by the authenticated Phase B
/// preflight. This value carries no authority by itself; all installation,
/// site, profile, backend, deployment, release, and policy bindings come from
/// `SelectedV2JournalContext`.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightObservation {
    pub operation_id: Uuid,
    pub artifact_sha256: String,
    pub source_installation_id: String,
    pub target_device: u64,
    pub target_inode: u64,
    pub target_database_identity: String,
}

#[cfg(target_os = "linux")]
impl SelectedV2JournalContext {
    pub(crate) fn from_verified_generation(
        policy: crate::recovery_migration_selector::InstallationPolicyV2,
        policy_sha256: String,
        trust: crate::recovery_trust::VerifiedTrust,
    ) -> Self {
        Self {
            policy,
            policy_sha256,
            trust,
        }
    }

    /// Construct the first, test-key-free `PREFLIGHTED` request from the
    /// authenticated selected policy and read-only backup/target observations.
    /// The disconnected journal signer signs only the returned canonical
    /// request after the caller has durably persisted these exact bytes.
    pub fn initial_preflight_request(
        &self,
        observation: &PreflightObservation,
    ) -> Result<SigningRequest, JournalError> {
        if self.policy.restore_branch_authorization != "inactive-materialization-only"
            || observation.operation_id.is_nil()
            || observation.source_installation_id.is_empty()
            || observation.target_device == 0
            || observation.target_inode == 0
            || observation.target_database_identity.is_empty()
            || !valid_sha256(&observation.artifact_sha256)
        {
            return Err(JournalError::InvalidBinding);
        }
        let mut nonce = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| JournalError::InvalidNonce)?;
        let request = SigningRequest {
            format: REQUEST_FORMAT.to_owned(),
            branch: BRANCH_INACTIVE.to_owned(),
            request_id: Uuid::new_v4(),
            request_nonce: hex::encode(nonce),
            operation_id: observation.operation_id,
            artifact_sha256: observation.artifact_sha256.clone(),
            site_id: self.policy.site_id.clone(),
            source_installation_id: observation.source_installation_id.clone(),
            target_installation_id: self.policy.installation_id.clone(),
            target_device: observation.target_device,
            target_inode: observation.target_inode,
            target_database_identity: observation.target_database_identity.clone(),
            profile: self.policy.profile.clone(),
            backend: self.policy.backend.clone(),
            backend_version: self.policy.backend_version.clone(),
            deployment: self.policy.deployment.clone(),
            release_identity: self.policy.release_identity.clone(),
            installation_policy_sha256: self.policy_sha256.clone(),
            sequence: 1,
            previous_signed_record_sha256: String::new(),
            intended_transition: InactivePhase::Preflighted,
            verification: None,
        };
        canonical_request(&request)?;
        Ok(request)
    }

    fn authority(&self, now_unix: i64) -> Result<JournalAuthority<'_>, JournalError> {
        let policy = &self.policy;
        let bundle = &self.trust.bundle;
        let certificate = &bundle.journal_certificate.payload;
        let key = self
            .trust
            .journal_key(&certificate.key_id)
            .ok_or(JournalError::WrongSigner)?;
        if bundle.installation_id != policy.installation_id
            || bundle.site_id != policy.site_id
            || bundle.profile != PROFILE
            || bundle.backend != BACKEND
            || certificate.key_id != bundle.journal_certificate.payload.key_id
            || certificate.purpose != SIGNING_PURPOSE
            || certificate.installation_id != policy.installation_id
            || certificate.site_id != policy.site_id
            || certificate.profile != PROFILE
            || certificate.backend != BACKEND
            || now_unix < certificate.not_before
            || now_unix > certificate.not_after
        {
            return Err(JournalError::ScopeMismatch);
        }
        Ok(JournalAuthority {
            key_id: &certificate.key_id,
            purpose: &certificate.purpose,
            site_id: &policy.site_id,
            installation_id: &policy.installation_id,
            profile: &policy.profile,
            backend: &policy.backend,
            backend_version: &policy.backend_version,
            deployment: &policy.deployment,
            release_identity: &policy.release_identity,
            policy_sha256: &self.policy_sha256,
            not_before: certificate.not_before,
            not_after: certificate.not_after,
            revoked: false,
            verifying_key: key,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    InvalidFormat,
    InvalidBinding,
    InvalidSequence,
    InvalidTransition,
    InvalidDigest,
    InvalidNonce,
    SignatureInvalid,
    WrongSigner,
    ScopeMismatch,
    Expired,
    ReplayOrFork,
    MixedBranch,
    LegacyJournal,
    UnsafeStorage,
    ReservationBusy,
    ConfirmationInvalid,
}

impl JournalError {
    /// Bounded stable output suitable for the D12 machine-readable envelope.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidFormat => "journal-invalid-format",
            Self::InvalidBinding => "journal-binding-invalid",
            Self::InvalidSequence => "journal-sequence-invalid",
            Self::InvalidTransition => "journal-transition-invalid",
            Self::InvalidDigest => "journal-digest-invalid",
            Self::InvalidNonce => "journal-nonce-invalid",
            Self::SignatureInvalid => "journal-signature-invalid",
            Self::WrongSigner => "journal-signer-invalid",
            Self::ScopeMismatch => "journal-scope-mismatch",
            Self::Expired => "journal-signer-expired",
            Self::ReplayOrFork => "journal-replay-or-fork",
            Self::MixedBranch => "journal-branch-conflict",
            Self::LegacyJournal => "legacy-journal-conversion-denied",
            Self::UnsafeStorage => "journal-storage-unsafe",
            Self::ReservationBusy => "restore-reservation-busy",
            Self::ConfirmationInvalid => "restore-confirmation-invalid",
        }
    }

    /// Accepted D12 exit classes: 2 rejected, 3 recoverable, 4 unknown or
    /// quarantined. This protocol-only API never returns success for mutation.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::ReservationBusy | Self::UnsafeStorage => 3,
            Self::ReplayOrFork | Self::MixedBranch | Self::Expired => 4,
            _ => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedJournal {
    pub operation_id: Uuid,
    pub artifact_sha256: String,
    pub site_id: String,
    pub source_installation_id: String,
    pub target_installation_id: String,
    pub target_device: u64,
    pub target_inode: u64,
    pub target_database_identity: String,
    pub profile: String,
    pub backend: String,
    pub deployment: String,
    pub release_identity: String,
    pub installation_policy_sha256: String,
    pub phase: InactivePhase,
    pub sequence: u64,
    pub signed_record_sha256: String,
    pub journal_sha256: String,
}

pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, JournalError> {
    serde_jcs::to_vec(value).map_err(|_| JournalError::InvalidFormat)
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn canonical_request(request: &SigningRequest) -> Result<Vec<u8>, JournalError> {
    validate_intrinsic(request)?;
    if !verification_matches(request) {
        return Err(JournalError::InvalidBinding);
    }
    canonical(request)
}

fn validate_request(
    request: &SigningRequest,
    prior: Option<&SigningRequest>,
    expected_previous_hash: &str,
) -> Result<(), JournalError> {
    validate_intrinsic(request)?;
    if !verification_matches(request) {
        return Err(JournalError::InvalidBinding);
    }
    match (prior, request.sequence) {
        (None, 1)
            if request.previous_signed_record_sha256.is_empty()
                && request.intended_transition == InactivePhase::Preflighted
                && request.verification.is_none() =>
        {
            Ok(())
        }
        (Some(previous), seq)
            if seq == previous.sequence.saturating_add(1)
                && valid_sha256(expected_previous_hash)
                && request.previous_signed_record_sha256 == expected_previous_hash
                && previous
                    .intended_transition
                    .permits_next(request.intended_transition)
                && bindings_match(previous, request) =>
        {
            Ok(())
        }
        (Some(_), _) => Err(JournalError::InvalidTransition),
        (None, _) => Err(JournalError::InvalidSequence),
    }
}

fn validate_intrinsic(request: &SigningRequest) -> Result<(), JournalError> {
    if request.format != REQUEST_FORMAT || request.branch != BRANCH_INACTIVE {
        return Err(JournalError::MixedBranch);
    }
    if request.request_id.is_nil()
        || request.operation_id.is_nil()
        || request.site_id.is_empty()
        || request.source_installation_id.is_empty()
        || request.target_installation_id.is_empty()
        || request.target_database_identity.is_empty()
        || request.target_device == 0
        || request.target_inode == 0
        || request.profile != PROFILE
        || request.backend != BACKEND
        || request.backend_version != "16"
        || request.deployment != DEPLOYMENT
        || request.release_identity.is_empty()
        || request.installation_policy_sha256.is_empty()
    {
        return Err(JournalError::InvalidBinding);
    }
    for value in [
        &request.artifact_sha256,
        &request.installation_policy_sha256,
    ] {
        if !valid_sha256(value) {
            return Err(JournalError::InvalidDigest);
        }
    }
    if request.request_nonce.len() != 64 || !is_hex(&request.request_nonce) {
        return Err(JournalError::InvalidNonce);
    }
    if request.sequence == 0 {
        return Err(JournalError::InvalidSequence);
    }
    if !request.previous_signed_record_sha256.is_empty()
        && !valid_sha256(&request.previous_signed_record_sha256)
    {
        return Err(JournalError::InvalidDigest);
    }
    Ok(())
}

fn verification_matches(request: &SigningRequest) -> bool {
    match (request.intended_transition, &request.verification) {
        (InactivePhase::InactiveVerified, Some(v)) => {
            v.verification == "passed"
                && v.restored_target_database_identity == request.target_database_identity
                && v.artifact_sha256 == request.artifact_sha256
                && v.release_identity == request.release_identity
                && v.target_installation_id == request.target_installation_id
                && [
                    &v.migration_baseline_sha256,
                    &v.d10_catalog_definition_sha256,
                    &v.repository_inventory_sha256,
                ]
                .iter()
                .all(|hash| valid_sha256(hash))
        }
        (InactivePhase::InactiveVerified, None) => false,
        (_, None) => true,
        (_, Some(_)) => false,
    }
}

fn bindings_match(a: &SigningRequest, b: &SigningRequest) -> bool {
    a.branch == b.branch
        && a.operation_id == b.operation_id
        && a.artifact_sha256 == b.artifact_sha256
        && a.site_id == b.site_id
        && a.source_installation_id == b.source_installation_id
        && a.target_installation_id == b.target_installation_id
        && a.target_device == b.target_device
        && a.target_inode == b.target_inode
        && a.target_database_identity == b.target_database_identity
        && a.profile == b.profile
        && a.backend == b.backend
        && a.backend_version == b.backend_version
        && a.deployment == b.deployment
        && a.release_identity == b.release_identity
        && a.installation_policy_sha256 == b.installation_policy_sha256
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_hex(value: &str) -> bool {
    value.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn verify_record(
    record: &SignedRecord,
    authority: &JournalAuthority<'_>,
    now_unix: i64,
) -> Result<(), JournalError> {
    if authority.purpose != SIGNING_PURPOSE || authority.revoked {
        return Err(JournalError::WrongSigner);
    }
    if now_unix < authority.not_before || now_unix > authority.not_after {
        return Err(JournalError::Expired);
    }
    let r = &record.request;
    if authority.key_id != record.response.key_id {
        return Err(JournalError::WrongSigner);
    }
    if authority.site_id != r.site_id
        || authority.installation_id != r.target_installation_id
        || authority.profile != r.profile
        || authority.backend != r.backend
        || authority.backend_version != r.backend_version
        || authority.deployment != r.deployment
        || authority.release_identity != r.release_identity
        || authority.policy_sha256 != r.installation_policy_sha256
    {
        return Err(JournalError::ScopeMismatch);
    }
    if record.format != JOURNAL_FORMAT || record.response.format != RESPONSE_FORMAT {
        return Err(JournalError::InvalidFormat);
    }
    let bytes = canonical_request(r)?;
    if record.response.request_sha256 != digest(&bytes) {
        return Err(JournalError::SignatureInvalid);
    }
    let signature_bytes =
        hex::decode(&record.response.signature).map_err(|_| JournalError::SignatureInvalid)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| JournalError::SignatureInvalid)?;
    authority
        .verifying_key
        .verify(&bytes, &signature)
        .map_err(|_| JournalError::SignatureInvalid)
}

pub fn authenticate_chain(
    bytes: &[u8],
    authority: &JournalAuthority<'_>,
    now_unix: i64,
) -> Result<AuthenticatedJournal, JournalError> {
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::InvalidFormat);
    }
    const V1_FORMAT: &[u8] = b"o3k-restore-journal-v1";
    if bytes.windows(V1_FORMAT.len()).any(|part| part == V1_FORMAT) {
        return Err(JournalError::LegacyJournal);
    }
    let journal: Journal =
        serde_json::from_slice(bytes).map_err(|_| JournalError::InvalidFormat)?;
    if journal.format != JOURNAL_FORMAT
        || journal.branch != BRANCH_INACTIVE
        || journal.records.is_empty()
        || journal.records.len() > MAX_RECORDS
    {
        return Err(JournalError::MixedBranch);
    }
    if canonical(&journal)? != bytes {
        return Err(JournalError::InvalidFormat);
    }
    let mut previous: Option<&SigningRequest> = None;
    let mut previous_hash = String::new();
    let mut request_ids = HashSet::new();
    let mut nonces = HashSet::new();
    for (index, record) in journal.records.iter().enumerate() {
        let request = &record.request;
        if record.format != JOURNAL_FORMAT
            || request.sequence != index as u64 + 1
            || request.previous_signed_record_sha256 != previous_hash
        {
            return Err(JournalError::InvalidSequence);
        }
        validate_request(request, previous, &previous_hash)?;
        if !request_ids.insert(request.request_id) || !nonces.insert(request.request_nonce.clone())
        {
            return Err(JournalError::ReplayOrFork);
        }
        verify_record(record, authority, now_unix)?;
        previous_hash = digest(&canonical(record)?);
        previous = Some(request);
    }
    let last = previous.ok_or(JournalError::InvalidFormat)?;
    Ok(AuthenticatedJournal {
        operation_id: last.operation_id,
        artifact_sha256: last.artifact_sha256.clone(),
        site_id: last.site_id.clone(),
        source_installation_id: last.source_installation_id.clone(),
        target_installation_id: last.target_installation_id.clone(),
        target_device: last.target_device,
        target_inode: last.target_inode,
        target_database_identity: last.target_database_identity.clone(),
        profile: last.profile.clone(),
        backend: last.backend.clone(),
        deployment: last.deployment.clone(),
        release_identity: last.release_identity.clone(),
        installation_policy_sha256: last.installation_policy_sha256.clone(),
        phase: last.intended_transition,
        sequence: last.sequence,
        signed_record_sha256: previous_hash,
        journal_sha256: digest(bytes),
    })
}

#[cfg(target_os = "linux")]
pub fn authenticate_selected_chain(
    bytes: &[u8],
    context: &SelectedV2JournalContext,
    now_unix: i64,
) -> Result<AuthenticatedJournal, JournalError> {
    let authority = context.authority(now_unix)?;
    authenticate_chain(bytes, &authority, now_unix)
}

/// Exact-byte retry helper. It never creates a second nonce/request for an
/// already persisted sequence and treats disagreement as a fork.
pub fn retry_request(existing: &[u8], expected: &SigningRequest) -> Result<Vec<u8>, JournalError> {
    let decoded: SigningRequest = decode_canonical(existing)?;
    if &decoded != expected {
        return Err(JournalError::ReplayOrFork);
    }
    Ok(existing.to_vec())
}

/// Durably stores one exact signed-intent request through the accepted D8
/// protected directory primitive. Repeating the same bytes is idempotent;
/// changing a request, nonce, identity or sequence is a fork. The caller must
/// complete this authenticated readback before any future target mutation.
#[cfg(target_os = "linux")]
pub fn persist_intent(
    protected: &crate::recovery_files::ProtectedDirectory,
    name: &str,
    request: &SigningRequest,
    uid: u32,
    gid: u32,
) -> Result<Vec<u8>, JournalError> {
    let expected_name = format!("restore-v2-pending-{}.json", request.operation_id);
    if name != expected_name {
        return Err(JournalError::UnsafeStorage);
    }
    let _lock = protected
        .try_lock_existing_file("restore-signing-request.lock", uid, gid, 0o600)
        .map_err(|_| JournalError::UnsafeStorage)?
        .ok_or(JournalError::UnsafeStorage)?;
    let bytes = canonical_request(request)?;
    match protected.read_bounded(name, uid, gid, 0o600, 64 * 1024) {
        Ok(existing) => {
            if existing != bytes {
                return Err(JournalError::ReplayOrFork);
            }
            let verified: SigningRequest = decode_canonical(&existing)?;
            if verified != *request {
                return Err(JournalError::ReplayOrFork);
            }
            Ok(existing)
        }
        Err(_) => {
            protected
                .atomic_write_installer(name, None, &bytes, uid, gid, 0o600)
                .map_err(|_| JournalError::UnsafeStorage)?;
            let readback = protected
                .read_bounded(name, uid, gid, 0o600, 64 * 1024)
                .map_err(|_| JournalError::UnsafeStorage)?;
            if readback != bytes || decode_canonical::<SigningRequest>(&readback)? != *request {
                return Err(JournalError::UnsafeStorage);
            }
            Ok(readback)
        }
    }
}

/// D8 lifetime guards required around every future Phase B resume step. The
/// concrete store and target guards remain owned by the accepted recovery
/// implementation; Phase B does not construct a competing lock authority.
pub trait PhaseBExclusion {
    fn revalidate_exclusion(&self) -> Result<(), JournalError>;
    fn verify_target_empty_before_first_mutation(&self) -> Result<(), JournalError>;
}

#[cfg(target_os = "linux")]
impl PhaseBExclusion for crate::restore_journal::TargetReservation {
    fn revalidate_exclusion(&self) -> Result<(), JournalError> {
        let (uid, gid) = (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        );
        self.revalidate(uid, gid)
            .map_err(|_| JournalError::UnsafeStorage)
    }

    fn verify_target_empty_before_first_mutation(&self) -> Result<(), JournalError> {
        self.verify_empty_before_mutation()
            .map_err(|_| JournalError::UnsafeStorage)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashClass {
    RetrySamePersistedSigningRequest,
    ReauthenticateDurableJournal,
    RevalidateAndObserveExactTarget,
    RestageOnlyBeforeTargetMutation,
    FailedRecoverableKnownPartialTarget,
    QuarantineUnknownOrForeignState,
    TerminalInactiveVerified,
}

/// Conservative A10 crash/restart classification. The caller supplies only
/// authenticated phase and observations; this returns no mutation command.
pub fn classify_crash(
    phase: InactivePhase,
    signing_ack_lost: bool,
    target_mutation_started: bool,
    target_state_known: bool,
    target_matches_operation: bool,
) -> CrashClass {
    if phase == InactivePhase::InactiveVerified {
        return CrashClass::TerminalInactiveVerified;
    }
    if signing_ack_lost {
        return CrashClass::RetrySamePersistedSigningRequest;
    }
    if !target_state_known || (target_mutation_started && !target_matches_operation) {
        return CrashClass::QuarantineUnknownOrForeignState;
    }
    if target_mutation_started {
        return if target_matches_operation {
            CrashClass::FailedRecoverableKnownPartialTarget
        } else {
            CrashClass::QuarantineUnknownOrForeignState
        };
    }
    match phase {
        InactivePhase::Preflighted => CrashClass::ReauthenticateDurableJournal,
        InactivePhase::TargetReservedInactive => CrashClass::RevalidateAndObserveExactTarget,
        InactivePhase::StagingInactive => CrashClass::RestageOnlyBeforeTargetMutation,
        InactivePhase::DatabaseRestoredInactive | InactivePhase::FilesRestoredInactive => {
            CrashClass::RevalidateAndObserveExactTarget
        }
        InactivePhase::FailedRecoverable
        | InactivePhase::Quarantined
        | InactivePhase::Aborted
        | InactivePhase::Discarded => CrashClass::QuarantineUnknownOrForeignState,
        InactivePhase::InactiveVerified => CrashClass::TerminalInactiveVerified,
    }
}

fn decode_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, JournalError> {
    let decoded = serde_json::from_slice(bytes).map_err(|_| JournalError::InvalidFormat)?;
    if canonical(&decoded)? != bytes {
        return Err(JournalError::InvalidFormat);
    }
    Ok(decoded)
}

/// D8 protected-directory journal publisher. It uses the existing anchored,
/// no-follow, ext4-only `ProtectedDirectory` and its CAS/fsync/rename/fsync/
/// readback operation; this function adds the v2 authentication and append
/// policy. It does not open or mutate a PostgreSQL target.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn publish_chain(
    protected: &crate::recovery_files::ProtectedDirectory,
    name: &str,
    prior: Option<&[u8]>,
    candidate: &[u8],
    authority: &JournalAuthority<'_>,
    now_unix: i64,
    uid: u32,
    gid: u32,
) -> Result<Vec<u8>, JournalError> {
    if name != "restore-journal-v2.json" {
        return Err(JournalError::UnsafeStorage);
    }
    let _lock = protected
        .try_lock_existing_file("restore-signing-request.lock", uid, gid, 0o600)
        .map_err(|_| JournalError::UnsafeStorage)?
        .ok_or(JournalError::UnsafeStorage)?;
    let next = authenticate_chain(candidate, authority, now_unix)?;
    let current = match prior {
        Some(bytes) => {
            let current = authenticate_chain(bytes, authority, now_unix)?;
            if candidate != bytes
                && (next.sequence != current.sequence + 1
                    || next.operation_id != current.operation_id
                    || next.signed_record_sha256 == current.signed_record_sha256)
            {
                return Err(JournalError::ReplayOrFork);
            }
            Some(bytes)
        }
        None if next.sequence == 1 => None,
        None => return Err(JournalError::InvalidSequence),
    };
    let readback = protected
        .read_bounded(name, uid, gid, 0o600, MAX_JOURNAL_BYTES)
        .ok();
    if readback.as_deref() != current {
        return Err(JournalError::ReplayOrFork);
    }
    protected
        .atomic_write_installer(name, current, candidate, uid, gid, 0o600)
        .map_err(|_| JournalError::UnsafeStorage)?;
    let readback = protected
        .read_bounded(name, uid, gid, 0o600, MAX_JOURNAL_BYTES)
        .map_err(|_| JournalError::UnsafeStorage)?;
    authenticate_chain(&readback, authority, now_unix)?;
    if readback != candidate {
        return Err(JournalError::UnsafeStorage);
    }
    Ok(readback)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn publish_selected_chain(
    protected: &crate::recovery_files::ProtectedDirectory,
    name: &str,
    prior: Option<&[u8]>,
    candidate: &[u8],
    context: &SelectedV2JournalContext,
    now_unix: i64,
    uid: u32,
    gid: u32,
) -> Result<Vec<u8>, JournalError> {
    let authority = context.authority(now_unix)?;
    publish_chain(
        protected, name, prior, candidate, &authority, now_unix, uid, gid,
    )
}

/// The only startup decision this module can make: any authenticated inactive
/// chain denies operational startup for its lifetime, including the terminal
/// `INACTIVE_VERIFIED` phase. This helper is not yet wired into an installed
/// C1 systemd qualification path.
pub fn startup_denial(journal: &AuthenticatedJournal) -> bool {
    journal.phase.denies_runtime()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeConfirmation {
    pub format: String,
    pub operation_id: Uuid,
    pub artifact_sha256: String,
}

pub fn validate_confirmation(
    bytes: &[u8],
    operation: Uuid,
    artifact_sha256: &str,
) -> Result<ResumeConfirmation, JournalError> {
    if bytes.len() > MAX_CONFIRMATION_BYTES {
        return Err(JournalError::ConfirmationInvalid);
    }
    let confirmation: ResumeConfirmation =
        decode_canonical(bytes).map_err(|_| JournalError::ConfirmationInvalid)?;
    if confirmation.format != "o3k-restore-resume-confirmation-v1"
        || confirmation.operation_id != operation
        || confirmation.artifact_sha256 != artifact_sha256
        || !valid_sha256(&confirmation.artifact_sha256)
    {
        return Err(JournalError::ConfirmationInvalid);
    }
    Ok(confirmation)
}

/// Validation-only path check. Mutation executors must remain unavailable
/// until installed C1 qualification is complete.
pub fn validate_phase_b_target(_target: &Path) -> Result<(), JournalError> {
    Err(JournalError::UnsafeStorage)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: i64 = 1_800_000_000;
    const KEY_ID: &str = "synthetic-test-journal-key";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42; 32])
    }

    fn authority<'a>(key: &'a SigningKey) -> JournalAuthority<'a> {
        let verifying_key = Box::leak(Box::new(key.verifying_key()));
        JournalAuthority {
            key_id: KEY_ID,
            purpose: SIGNING_PURPOSE,
            site_id: "test-site",
            installation_id: "target-installation",
            profile: PROFILE,
            backend: BACKEND,
            backend_version: "16",
            deployment: DEPLOYMENT,
            release_identity: "test-release-1",
            policy_sha256: Box::leak("b".repeat(64).into_boxed_str()),
            not_before: NOW - 10,
            not_after: NOW + 10,
            revoked: false,
            verifying_key,
        }
    }

    fn request(sequence: u64, prior_hash: String, phase: InactivePhase) -> SigningRequest {
        SigningRequest {
            format: REQUEST_FORMAT.into(),
            branch: BRANCH_INACTIVE.into(),
            request_id: Uuid::from_u128(sequence as u128 + 10),
            request_nonce: format!("{:064x}", sequence + 100),
            operation_id: Uuid::from_u128(900),
            artifact_sha256: "a".repeat(64),
            site_id: "test-site".into(),
            source_installation_id: "source-installation".into(),
            target_installation_id: "target-installation".into(),
            target_device: 8,
            target_inode: 9,
            target_database_identity: "o3k_restore_900".into(),
            profile: PROFILE.into(),
            backend: BACKEND.into(),
            backend_version: "16".into(),
            deployment: DEPLOYMENT.into(),
            release_identity: "test-release-1".into(),
            installation_policy_sha256: "b".repeat(64),
            sequence,
            previous_signed_record_sha256: prior_hash,
            intended_transition: phase,
            verification: if phase == InactivePhase::InactiveVerified {
                Some(VerificationBinding {
                    restored_target_database_identity: "o3k_restore_900".into(),
                    artifact_sha256: "a".repeat(64),
                    release_identity: "test-release-1".into(),
                    migration_baseline_sha256: "c".repeat(64),
                    d10_catalog_definition_sha256: "d".repeat(64),
                    repository_inventory_sha256: "e".repeat(64),
                    target_installation_id: "target-installation".into(),
                    verification: "passed".into(),
                })
            } else {
                None
            },
        }
    }

    fn signed(req: SigningRequest, key: &SigningKey) -> SignedRecord {
        let bytes = canonical(&req).expect("request canonicalizes");
        SignedRecord {
            format: JOURNAL_FORMAT.into(),
            request: req,
            response: SigningResponse {
                format: RESPONSE_FORMAT.into(),
                request_sha256: digest(&bytes),
                key_id: KEY_ID.into(),
                signature: hex::encode(key.sign(&bytes).to_bytes()),
            },
        }
    }

    fn chain(phases: &[InactivePhase], key: &SigningKey) -> Vec<u8> {
        let mut records = Vec::new();
        for (index, phase) in phases.iter().enumerate() {
            let previous_hash = records
                .last()
                .map(|record| digest(&canonical(record).unwrap()))
                .unwrap_or_default();
            records.push(signed(
                request(index as u64 + 1, previous_hash, *phase),
                key,
            ));
        }
        canonical(&Journal {
            format: JOURNAL_FORMAT.into(),
            branch: BRANCH_INACTIVE.into(),
            records,
        })
        .unwrap()
    }

    #[test]
    fn every_accepted_transition_is_allowlisted_and_all_others_are_denied() {
        let accepted = [
            (
                InactivePhase::Preflighted,
                InactivePhase::TargetReservedInactive,
            ),
            (InactivePhase::Preflighted, InactivePhase::Aborted),
            (
                InactivePhase::TargetReservedInactive,
                InactivePhase::StagingInactive,
            ),
            (
                InactivePhase::TargetReservedInactive,
                InactivePhase::Aborted,
            ),
            (
                InactivePhase::TargetReservedInactive,
                InactivePhase::Quarantined,
            ),
            (
                InactivePhase::StagingInactive,
                InactivePhase::DatabaseRestoredInactive,
            ),
            (
                InactivePhase::StagingInactive,
                InactivePhase::FailedRecoverable,
            ),
            (InactivePhase::StagingInactive, InactivePhase::Quarantined),
            (
                InactivePhase::DatabaseRestoredInactive,
                InactivePhase::FilesRestoredInactive,
            ),
            (
                InactivePhase::DatabaseRestoredInactive,
                InactivePhase::FailedRecoverable,
            ),
            (
                InactivePhase::DatabaseRestoredInactive,
                InactivePhase::Quarantined,
            ),
            (
                InactivePhase::FilesRestoredInactive,
                InactivePhase::InactiveVerified,
            ),
            (
                InactivePhase::FilesRestoredInactive,
                InactivePhase::FailedRecoverable,
            ),
            (
                InactivePhase::FilesRestoredInactive,
                InactivePhase::Quarantined,
            ),
            (InactivePhase::FailedRecoverable, InactivePhase::Discarded),
            (InactivePhase::FailedRecoverable, InactivePhase::Quarantined),
            (InactivePhase::Quarantined, InactivePhase::Discarded),
        ];
        let phases = [
            InactivePhase::Preflighted,
            InactivePhase::TargetReservedInactive,
            InactivePhase::StagingInactive,
            InactivePhase::DatabaseRestoredInactive,
            InactivePhase::FilesRestoredInactive,
            InactivePhase::InactiveVerified,
            InactivePhase::Aborted,
            InactivePhase::FailedRecoverable,
            InactivePhase::Quarantined,
            InactivePhase::Discarded,
        ];
        for from in phases {
            for to in phases {
                assert_eq!(
                    from.permits_next(to),
                    accepted.contains(&(from, to)),
                    "{from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn terminal_inactive_verified_is_inert_and_denies_runtime() {
        let key = key();
        let bytes = chain(
            &[
                InactivePhase::Preflighted,
                InactivePhase::TargetReservedInactive,
                InactivePhase::StagingInactive,
                InactivePhase::DatabaseRestoredInactive,
                InactivePhase::FilesRestoredInactive,
                InactivePhase::InactiveVerified,
            ],
            &key,
        );
        let journal = authenticate_chain(&bytes, &authority(&key), NOW).unwrap();
        assert_eq!(journal.phase, InactivePhase::InactiveVerified);
        assert!(startup_denial(&journal));
        for phase in [
            InactivePhase::Preflighted,
            InactivePhase::TargetReservedInactive,
            InactivePhase::StagingInactive,
            InactivePhase::DatabaseRestoredInactive,
            InactivePhase::FilesRestoredInactive,
            InactivePhase::InactiveVerified,
            InactivePhase::Aborted,
            InactivePhase::FailedRecoverable,
            InactivePhase::Quarantined,
            InactivePhase::Discarded,
        ] {
            assert!(phase.denies_runtime(), "{phase:?}");
        }
        assert!(!InactivePhase::InactiveVerified.permits_next(InactivePhase::Discarded));
    }

    #[test]
    fn signature_tamper_wrong_signer_scope_revocation_and_expiry_fail_closed() {
        let key = key();
        let bytes = chain(&[InactivePhase::Preflighted], &key);
        let mut journal: Journal = serde_json::from_slice(&bytes).unwrap();
        journal.records[0].response.signature = hex::encode([0_u8; 64]);
        assert_eq!(
            authenticate_chain(&canonical(&journal).unwrap(), &authority(&key), NOW),
            Err(JournalError::SignatureInvalid)
        );
        let record = signed(request(1, String::new(), InactivePhase::Preflighted), &key);
        let mut wrong = authority(&key);
        wrong.key_id = "other";
        assert_eq!(
            verify_record(&record, &wrong, NOW),
            Err(JournalError::WrongSigner)
        );
        let mut wrong_purpose = authority(&key);
        wrong_purpose.purpose = "recovery_evidence";
        assert_eq!(
            verify_record(&record, &wrong_purpose, NOW),
            Err(JournalError::WrongSigner)
        );
        let mut scope = authority(&key);
        scope.site_id = "other-site";
        assert_eq!(
            verify_record(&record, &scope, NOW),
            Err(JournalError::ScopeMismatch)
        );
        let mut expired = authority(&key);
        expired.not_after = NOW - 1;
        assert_eq!(
            verify_record(&record, &expired, NOW),
            Err(JournalError::Expired)
        );
        let mut revoked = authority(&key);
        revoked.revoked = true;
        assert_eq!(
            verify_record(&record, &revoked, NOW),
            Err(JournalError::WrongSigner)
        );
    }

    #[test]
    fn v2_policy_release_installation_and_backend_bindings_are_exact() {
        let key = key();
        let original = request(1, String::new(), InactivePhase::Preflighted);
        let mutators: [fn(&mut SigningRequest); 6] = [
            |r: &mut SigningRequest| r.installation_policy_sha256 = "c".repeat(64),
            |r: &mut SigningRequest| r.release_identity = "different-release".into(),
            |r: &mut SigningRequest| r.target_installation_id = "other-installation".into(),
            |r: &mut SigningRequest| r.site_id = "other-site".into(),
            |r: &mut SigningRequest| r.backend_version = "15".into(),
            |r: &mut SigningRequest| r.deployment = "bare-metal".into(),
        ];
        for mutate in mutators {
            let mut changed = original.clone();
            mutate(&mut changed);
            let signed_changed = signed(changed, &key);
            assert_eq!(
                verify_record(&signed_changed, &authority(&key), NOW),
                Err(JournalError::ScopeMismatch)
            );
        }
        let mut noncanonical_digest = original;
        noncanonical_digest.artifact_sha256 = "A".repeat(64);
        assert_eq!(
            canonical_request(&noncanonical_digest),
            Err(JournalError::InvalidDigest)
        );
    }

    #[test]
    fn noncanonical_and_duplicate_member_json_is_rejected() {
        let key = key();
        let bytes = chain(&[InactivePhase::Preflighted], &key);
        let pretty =
            serde_json::to_vec_pretty(&serde_json::from_slice::<Journal>(&bytes).unwrap()).unwrap();
        assert_eq!(
            authenticate_chain(&pretty, &authority(&key), NOW),
            Err(JournalError::InvalidFormat)
        );
        let duplicate = br#"{"branch":"inactive","branch":"inactive","format":"o3k-restore-journal-v2","records":[]}"#;
        assert!(matches!(
            authenticate_chain(duplicate, &authority(&key), NOW),
            Err(JournalError::InvalidFormat | JournalError::MixedBranch)
        ));
    }

    #[test]
    fn sequence_hash_binding_duplicate_replay_and_branch_conflicts_are_rejected() {
        let key = key();
        let mut value: Journal =
            serde_json::from_slice(&chain(&[InactivePhase::Preflighted], &key)).unwrap();
        let mut missing = request(3, "c".repeat(64), InactivePhase::TargetReservedInactive);
        value.records.push(signed(missing.clone(), &key));
        assert_eq!(
            authenticate_chain(&canonical(&value).unwrap(), &authority(&key), NOW),
            Err(JournalError::InvalidSequence)
        );
        value.records.truncate(1);
        missing = request(
            2,
            digest(&canonical(&value.records[0]).unwrap()),
            InactivePhase::TargetReservedInactive,
        );
        missing.request_id = value.records[0].request.request_id;
        value.records.push(signed(missing, &key));
        assert_eq!(
            authenticate_chain(&canonical(&value).unwrap(), &authority(&key), NOW),
            Err(JournalError::ReplayOrFork)
        );
        value.branch = "activation".into();
        assert_eq!(
            authenticate_chain(&canonical(&value).unwrap(), &authority(&key), NOW),
            Err(JournalError::MixedBranch)
        );
        assert_eq!(
            authenticate_chain(
                b"{\"format\":\"o3k-restore-journal-v1\"}",
                &authority(&key),
                NOW
            ),
            Err(JournalError::LegacyJournal)
        );
    }

    #[test]
    fn retry_is_exact_bytes_and_conflicting_request_is_a_fork() {
        let req = request(1, String::new(), InactivePhase::Preflighted);
        let bytes = canonical(&req).unwrap();
        assert_eq!(retry_request(&bytes, &req), Ok(bytes.clone()));
        let mut changed = req;
        changed.request_nonce = "f".repeat(64);
        assert_eq!(
            retry_request(&bytes, &changed),
            Err(JournalError::ReplayOrFork)
        );
    }

    #[test]
    fn crash_resume_classifies_lost_ack_known_partial_unknown_and_foreign_state() {
        assert_eq!(
            classify_crash(InactivePhase::StagingInactive, true, false, true, true),
            CrashClass::RetrySamePersistedSigningRequest
        );
        assert_eq!(
            classify_crash(
                InactivePhase::TargetReservedInactive,
                false,
                false,
                true,
                true
            ),
            CrashClass::RevalidateAndObserveExactTarget
        );
        assert_eq!(
            classify_crash(InactivePhase::StagingInactive, false, false, true, true),
            CrashClass::RestageOnlyBeforeTargetMutation
        );
        assert_eq!(
            classify_crash(InactivePhase::StagingInactive, false, true, true, true),
            CrashClass::FailedRecoverableKnownPartialTarget
        );
        assert_eq!(
            classify_crash(InactivePhase::StagingInactive, false, true, false, false),
            CrashClass::QuarantineUnknownOrForeignState
        );
        assert_eq!(
            classify_crash(InactivePhase::InactiveVerified, false, false, true, true),
            CrashClass::TerminalInactiveVerified
        );
    }

    #[test]
    fn confirmation_is_bounded_and_binds_operation_and_artifact() {
        let operation = Uuid::from_u128(900);
        let confirmation = ResumeConfirmation {
            format: "o3k-restore-resume-confirmation-v1".into(),
            operation_id: operation,
            artifact_sha256: "a".repeat(64),
        };
        let bytes = canonical(&confirmation).unwrap();
        assert!(validate_confirmation(&bytes, operation, &"a".repeat(64)).is_ok());
        assert_eq!(
            validate_confirmation(&bytes, Uuid::new_v4(), &"a".repeat(64)),
            Err(JournalError::ConfirmationInvalid)
        );
        assert_eq!(
            validate_confirmation(
                &vec![b' '; MAX_CONFIRMATION_BYTES + 1],
                operation,
                &"a".repeat(64)
            ),
            Err(JournalError::ConfirmationInvalid)
        );
        assert_eq!(JournalError::ConfirmationInvalid.exit_code(), 2);
        assert_eq!(JournalError::UnsafeStorage.exit_code(), 3);
        assert_eq!(JournalError::ReplayOrFork.exit_code(), 4);
    }

    #[test]
    fn verification_record_binds_the_complete_accepted_result() {
        let key = key();
        let phases = [
            InactivePhase::Preflighted,
            InactivePhase::TargetReservedInactive,
            InactivePhase::StagingInactive,
            InactivePhase::DatabaseRestoredInactive,
            InactivePhase::FilesRestoredInactive,
            InactivePhase::InactiveVerified,
        ];
        let bytes = chain(&phases, &key);
        assert!(authenticate_chain(&bytes, &authority(&key), NOW).is_ok());
    }

    #[test]
    fn path_and_mutation_executor_remain_closed_in_phase_b() {
        assert_eq!(
            validate_phase_b_target(Path::new("/tmp/never-open")),
            Err(JournalError::UnsafeStorage)
        );
    }
}
