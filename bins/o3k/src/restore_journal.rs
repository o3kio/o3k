//! Authenticated PP.6 restore journal protocol and protected file persistence.
//!
//! This is procedural recovery metadata, not a source of Cloud Kernel state.
//! Private signing keys stay in the disconnected custodian tool. The target
//! accepts only a detached Ed25519 response for the exact canonical request
//! already persisted on disk.

use std::{
    fs::{self, File},
    io::{Read, Write},
    os::fd::AsFd,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ring::rand::{SecureRandom, SystemRandom};
use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, RenameFlags, flock, fstatfs, open, openat,
    renameat_with, statat, unlinkat,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const JOURNAL_FORMAT: &str = "o3k-restore-journal-v1";
pub const REQUEST_FORMAT: &str = "o3k-restore-signing-request-v1";
pub const RESPONSE_FORMAT: &str = "o3k-restore-signing-response-v1";
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_HASH_BYTES: usize = 64;
const MAX_NONCE_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RestorePhase {
    Preflighted,
    SourceFenced,
    TargetReserved,
    Staging,
    DatabaseRestored,
    FilesRestored,
    TargetFenced,
    Started,
    Reconciled,
    Committed,
    Aborted,
    FailedRecoverable,
    Quarantined,
    Discarded,
}

impl RestorePhase {
    const fn stable_name(self) -> &'static str {
        match self {
            Self::Preflighted => "PREFLIGHTED",
            Self::SourceFenced => "SOURCE_FENCED",
            Self::TargetReserved => "TARGET_RESERVED",
            Self::Staging => "STAGING",
            Self::DatabaseRestored => "DATABASE_RESTORED",
            Self::FilesRestored => "FILES_RESTORED",
            Self::TargetFenced => "TARGET_FENCED",
            Self::Started => "STARTED",
            Self::Reconciled => "RECONCILED",
            Self::Committed => "COMMITTED",
            Self::Aborted => "ABORTED",
            Self::FailedRecoverable => "FAILED_RECOVERABLE",
            Self::Quarantined => "QUARANTINED",
            Self::Discarded => "DISCARDED",
        }
    }

    fn permits_next(self, next: Self) -> bool {
        use RestorePhase as P;
        matches!(
            (self, next),
            (P::Preflighted, P::SourceFenced)
                | (P::SourceFenced, P::TargetReserved)
                | (P::TargetReserved, P::Staging)
                | (P::Staging, P::DatabaseRestored)
                | (P::DatabaseRestored, P::FilesRestored)
                | (P::FilesRestored, P::TargetFenced)
                | (P::TargetFenced, P::Started)
                | (P::Started, P::Reconciled)
                | (P::Reconciled, P::Committed)
                | (P::Preflighted, P::Aborted)
                | (P::SourceFenced, P::Aborted)
                | (P::TargetReserved, P::Aborted)
                | (P::Staging, P::FailedRecoverable)
                | (P::DatabaseRestored, P::FailedRecoverable)
                | (P::FilesRestored, P::FailedRecoverable)
                | (P::Preflighted, P::Quarantined)
                | (P::SourceFenced, P::Quarantined)
                | (P::TargetReserved, P::Quarantined)
                | (P::Staging, P::Quarantined)
                | (P::DatabaseRestored, P::Quarantined)
                | (P::FilesRestored, P::Quarantined)
                | (P::TargetFenced, P::Quarantined)
                | (P::Started, P::Quarantined)
                | (P::FailedRecoverable, P::Discarded)
                | (P::Quarantined, P::Discarded)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    pub format: String,
    pub request_id: Uuid,
    pub request_nonce: String,
    pub operation_id: Uuid,
    pub site_id: String,
    pub artifact_sha256: String,
    pub journal_authority_id: String,
    pub target_installation_id: String,
    pub target_device: u64,
    pub target_inode: u64,
    pub target_database_identity: String,
    pub source_installation_id: String,
    pub deterministic_step_id: String,
    pub sequence: u64,
    pub previous_signed_hash: String,
    pub intended_transition: RestorePhase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningResponse {
    pub format: String,
    pub request_sha256: String,
    pub key_id: String,
    pub signature: String,
}

/// Fields fixed by the restore operation. The request ID and nonce are
/// generated once and persisted, so a lost signing response retries the same
/// bytes without changing any operation or target binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBinding {
    pub operation_id: Uuid,
    pub site_id: String,
    pub artifact_sha256: String,
    pub target_installation_id: String,
    pub target_device: u64,
    pub target_inode: u64,
    pub target_database_identity: String,
    pub source_installation_id: String,
    pub journal_authority_id: String,
    pub sequence: u64,
    pub previous_signed_hash: String,
    pub intended_transition: RestorePhase,
}

impl SigningRequest {
    fn matches_binding(&self, binding: &RequestBinding) -> bool {
        self.operation_id == binding.operation_id
            && self.site_id == binding.site_id
            && self.artifact_sha256 == binding.artifact_sha256
            && self.target_installation_id == binding.target_installation_id
            && self.target_device == binding.target_device
            && self.target_inode == binding.target_inode
            && self.target_database_identity == binding.target_database_identity
            && self.source_installation_id == binding.source_installation_id
            && self.journal_authority_id == binding.journal_authority_id
            && self.sequence == binding.sequence
            && self.previous_signed_hash == binding.previous_signed_hash
            && self.intended_transition == binding.intended_transition
            && self.deterministic_step_id
                == deterministic_step_id(
                    binding.operation_id,
                    &binding.artifact_sha256,
                    binding.sequence,
                    binding.intended_transition,
                )
    }
}

/// Creates the first signing request without loading a private key. The
/// initial request can authorize only the authenticated PREFLIGHTED record;
/// later phase builders belong with their prerequisite verifiers.
pub fn initial_preflight_request(binding: &RequestBinding) -> Result<SigningRequest, JournalError> {
    if binding.sequence != 1
        || !binding.previous_signed_hash.is_empty()
        || binding.intended_transition != RestorePhase::Preflighted
    {
        return Err(JournalError::InvalidTransition);
    }
    let mut nonce = [0_u8; MAX_NONCE_BYTES];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| JournalError::Io)?;
    let request = SigningRequest {
        format: REQUEST_FORMAT.to_owned(),
        request_id: Uuid::new_v4(),
        request_nonce: hex::encode(nonce),
        operation_id: binding.operation_id,
        site_id: binding.site_id.clone(),
        artifact_sha256: binding.artifact_sha256.clone(),
        journal_authority_id: binding.journal_authority_id.clone(),
        target_installation_id: binding.target_installation_id.clone(),
        target_device: binding.target_device,
        target_inode: binding.target_inode,
        target_database_identity: binding.target_database_identity.clone(),
        source_installation_id: binding.source_installation_id.clone(),
        deterministic_step_id: deterministic_step_id(
            binding.operation_id,
            &binding.artifact_sha256,
            binding.sequence,
            binding.intended_transition,
        ),
        sequence: binding.sequence,
        previous_signed_hash: binding.previous_signed_hash.clone(),
        intended_transition: binding.intended_transition,
    };
    validate_request(&request)?;
    Ok(request)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTransition {
    pub format: String,
    pub request: SigningRequest,
    pub response: SigningResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelope {
    format: String,
    transitions: Vec<SignedTransition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    InvalidIdentity,
    InvalidFormat,
    InvalidSequence,
    InvalidTransition,
    InvalidRequest,
    ResponseMismatch,
    SignatureInvalid,
    KeyMismatch,
    KeyRevoked,
    ReplayOrFork,
    Io,
    UnsafeDirectory,
    UnsafeRecord,
    ReservationBusy,
    TargetChanged,
    TargetNotEmpty,
}

/// A target-specific, process-lifetime reservation. It deliberately uses a
/// separate lock inode from `StoreAccessLock`; both guards must be held by any
/// future activation path.
pub struct TargetReservation {
    recovery_path: PathBuf,
    target_path: PathBuf,
    recovery_dir: File,
    target_dir: File,
    recovery_identity: (u64, u64),
    target_identity: (u64, u64),
    reservation_name: String,
    operation_id: Uuid,
    artifact_sha256: String,
    lock_file: File,
    require_ext4: bool,
    require_root_ancestors: bool,
}

struct ReservationPolicy<'a> {
    require_ext4: bool,
    require_root_ancestors: bool,
    authenticated: Option<&'a AuthenticatedJournal>,
}

impl TargetReservation {
    /// Opens an already provisioned recovery directory and an explicitly
    /// selected empty target, then continuously reserves both identities.
    /// Production callers must provide the configured `o3k:o3k` uid/gid.
    pub fn acquire(
        recovery_path: &Path,
        target_path: &Path,
        operation_id: Uuid,
        artifact_sha256: &str,
        uid: u32,
        gid: u32,
    ) -> Result<Self, JournalError> {
        Self::acquire_inner(
            recovery_path,
            target_path,
            operation_id,
            artifact_sha256,
            uid,
            gid,
            ReservationPolicy {
                require_ext4: true,
                require_root_ancestors: true,
                authenticated: None,
            },
        )
    }

    /// Re-establishes an operation reservation after process loss only from a
    /// journal that this module has already authenticated. The caller must
    /// still observe the target and call `verify_empty_before_mutation` before
    /// any write; this v1 implementation can recover only PREFLIGHTED state.
    pub fn acquire_after_authenticated_crash(
        recovery_path: &Path,
        target_path: &Path,
        operation_id: Uuid,
        artifact_sha256: &str,
        uid: u32,
        gid: u32,
        authenticated: &AuthenticatedJournal,
    ) -> Result<Self, JournalError> {
        Self::acquire_inner(
            recovery_path,
            target_path,
            operation_id,
            artifact_sha256,
            uid,
            gid,
            ReservationPolicy {
                require_ext4: true,
                require_root_ancestors: true,
                authenticated: Some(authenticated),
            },
        )
    }

    fn acquire_inner(
        recovery_path: &Path,
        target_path: &Path,
        operation_id: Uuid,
        artifact_sha256: &str,
        uid: u32,
        gid: u32,
        policy: ReservationPolicy<'_>,
    ) -> Result<Self, JournalError> {
        if !valid_sha256(artifact_sha256) || operation_id.is_nil() {
            return Err(JournalError::InvalidIdentity);
        }
        if policy.require_root_ancestors {
            validate_root_protected_ancestors(recovery_path)?;
            validate_root_protected_ancestors(target_path)?;
        }
        let recovery_dir = open_dir(recovery_path)?;
        let target_dir = open_dir(target_path)?;
        validate_dir(&recovery_dir, uid, gid, policy.require_ext4)?;
        validate_dir(&target_dir, uid, gid, policy.require_ext4)?;
        let recovery_identity = identity(&recovery_dir)?;
        let target_identity = identity(&target_dir)?;
        let lock_name = format!(
            "restore-reservation-{}.lock",
            hash_path_identity(target_identity)
        );
        let (lock_fd, created) = match openat(
            recovery_dir.as_fd(),
            lock_name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => (fd, true),
            Err(error) if error == rustix::io::Errno::EXIST => (
                openat(
                    recovery_dir.as_fd(),
                    lock_name.as_str(),
                    OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|_| JournalError::UnsafeRecord)?,
                false,
            ),
            Err(_) => return Err(JournalError::Io),
        };
        let mut lock_file = File::from(lock_fd);
        let meta = lock_file.metadata().map_err(|_| JournalError::Io)?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != uid
            || meta.gid() != gid
            || meta.mode() & 0o7777 != 0o600
        {
            return Err(JournalError::UnsafeRecord);
        }
        flock(lock_file.as_fd(), FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| JournalError::ReservationBusy)?;
        // This is the startup/store-access inode guard. The recovery lock
        // above remains the distinct target-specific operation reservation.
        flock(target_dir.as_fd(), FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| JournalError::ReservationBusy)?;
        let reservation =
            format!("operation_id={operation_id}\nartifact_sha256={artifact_sha256}\n");
        if let Some(authenticated) = policy.authenticated {
            if authenticated.operation_id != operation_id
                || authenticated.artifact_sha256 != artifact_sha256
                || authenticated.target_device != target_identity.0
                || authenticated.target_inode != target_identity.1
                || authenticated.phase != RestorePhase::Preflighted
                || authenticated.sequence != 1
            {
                return Err(JournalError::ReplayOrFork);
            }
            let journal = read_journal(
                &recovery_dir,
                &recovery_path.join("restore-journal.json"),
                uid,
                gid,
            )?;
            if hex::encode(Sha256::digest(&journal)) != authenticated.chain_sha256 {
                return Err(JournalError::ReplayOrFork);
            }
        } else if !created {
            return Err(JournalError::ReplayOrFork);
        }
        if !created && meta.len() != reservation.len() as u64 {
            return Err(JournalError::ReplayOrFork);
        }
        if created {
            lock_file
                .write_all(reservation.as_bytes())
                .map_err(|_| JournalError::Io)?;
            lock_file.sync_all().map_err(|_| JournalError::Io)?;
            recovery_dir.sync_all().map_err(|_| JournalError::Io)?;
        } else {
            let mut contents = Vec::new();
            (&lock_file)
                .take(1024)
                .read_to_end(&mut contents)
                .map_err(|_| JournalError::Io)?;
            if contents != reservation.as_bytes() {
                return Err(JournalError::ReplayOrFork);
            }
        }
        Ok(Self {
            recovery_path: recovery_path.to_path_buf(),
            target_path: target_path.to_path_buf(),
            recovery_dir,
            target_dir,
            recovery_identity,
            target_identity,
            reservation_name: lock_name,
            operation_id,
            artifact_sha256: artifact_sha256.to_owned(),
            lock_file,
            require_ext4: policy.require_ext4,
            require_root_ancestors: policy.require_root_ancestors,
        })
    }

    /// Revalidates held directory and reservation identities before every
    /// irreversible step. This remains valid after the target is populated.
    pub fn revalidate(&self, uid: u32, gid: u32) -> Result<(), JournalError> {
        if self.require_root_ancestors {
            validate_root_protected_ancestors(&self.recovery_path)?;
            validate_root_protected_ancestors(&self.target_path)?;
        }
        validate_dir(&self.recovery_dir, uid, gid, self.require_ext4)?;
        validate_dir(&self.target_dir, uid, gid, self.require_ext4)?;
        if identity(&self.recovery_dir)? != self.recovery_identity
            || identity(&self.target_dir)? != self.target_identity
            || identity(&open_dir(&self.recovery_path)?)? != self.recovery_identity
            || identity(&open_dir(&self.target_path)?)? != self.target_identity
        {
            return Err(JournalError::TargetChanged);
        }
        let meta = self.lock_file.metadata().map_err(|_| JournalError::Io)?;
        let expected = format!(
            "operation_id={}\nartifact_sha256={}\n",
            self.operation_id, self.artifact_sha256
        );
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != uid
            || meta.gid() != gid
            || meta.mode() & 0o7777 != 0o600
            || meta.len() != expected.len() as u64
        {
            return Err(JournalError::TargetChanged);
        }
        let mut content = vec![0_u8; 1024];
        let read = self
            .lock_file
            .read_at(&mut content, 0)
            .map_err(|_| JournalError::TargetChanged)?;
        content.truncate(read);
        if content != expected.as_bytes() {
            return Err(JournalError::TargetChanged);
        }
        let entry = statat(
            self.recovery_dir.as_fd(),
            self.reservation_name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| JournalError::TargetChanged)?;
        if entry.st_dev != meta.dev() || entry.st_ino != meta.ino() {
            return Err(JournalError::TargetChanged);
        }
        Ok(())
    }

    /// The last read-only target check before the first target mutation.
    pub fn verify_empty_before_mutation(&self) -> Result<(), JournalError> {
        if directory_empty(&self.target_dir)? {
            Ok(())
        } else {
            Err(JournalError::TargetNotEmpty)
        }
    }

    fn verify_for_chain(
        &self,
        operation_id: Uuid,
        artifact_sha256: &str,
        target_device: u64,
        target_inode: u64,
        uid: u32,
        gid: u32,
    ) -> Result<(), JournalError> {
        self.revalidate(uid, gid)?;
        if self.operation_id != operation_id
            || self.artifact_sha256 != artifact_sha256
            || self.target_identity != (target_device, target_inode)
        {
            return Err(JournalError::ReplayOrFork);
        }
        Ok(())
    }

    /// Stable selected-target filesystem identity for request binding.
    pub fn target_device_inode(&self) -> (u64, u64) {
        self.target_identity
    }
}

/// Authenticated view of one chain. Signer identity and public key are
/// supplied by trusted installation configuration, never by the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedJournal {
    operation_id: Uuid,
    artifact_sha256: String,
    target_installation_id: String,
    source_installation_id: String,
    target_device: u64,
    target_inode: u64,
    target_database_identity: String,
    phase: RestorePhase,
    sequence: u64,
    signed_hash: String,
    chain_sha256: String,
}

impl AuthenticatedJournal {
    /// The authenticated terminal-reached phase of the chain.  Callers must
    /// not treat this label as authority; signature, freshness and branch
    /// checks already ran, and an unaccepted phase never grants progress.
    pub fn phase(&self) -> RestorePhase {
        self.phase
    }
}

/// Canonical RFC 8785 bytes of a signing request.
pub fn canonical_request(request: &SigningRequest) -> Result<Vec<u8>, JournalError> {
    validate_request(request)?;
    serde_jcs::to_vec(request).map_err(|_| JournalError::InvalidRequest)
}

/// Validates a signature response against the exact persisted request. This
/// function does not load or retain any private signing material.
pub fn verify_response(
    request: &SigningRequest,
    response: &SigningResponse,
    expected_key_id: &str,
    verifying_key: &VerifyingKey,
) -> Result<SignedTransition, JournalError> {
    let bytes = canonical_request(request)?;
    let request_hash = hex::encode(Sha256::digest(&bytes));
    if request.journal_authority_id != expected_key_id
        || response.format != RESPONSE_FORMAT
        || response.key_id != expected_key_id
        || response.request_sha256 != request_hash
    {
        return Err(JournalError::ResponseMismatch);
    }
    let signature_bytes =
        hex::decode(&response.signature).map_err(|_| JournalError::SignatureInvalid)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| JournalError::SignatureInvalid)?;
    verifying_key
        .verify(&bytes, &signature)
        .map_err(|_| JournalError::SignatureInvalid)?;
    Ok(SignedTransition {
        format: JOURNAL_FORMAT.to_owned(),
        request: request.clone(),
        response: response.clone(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChainBinding {
    operation_id: Uuid,
    artifact_sha256: String,
    target_installation_id: String,
    source_installation_id: String,
    site_id: String,
    journal_authority_id: String,
    target_device: u64,
    target_inode: u64,
    target_database_identity: String,
}

/// Checks the complete chain, canonical encoding, request binding, signer and
/// hash linkage. Conflicting, skipped, replayed, or forked history is rejected.
pub fn authenticate_chain(
    bytes: &[u8],
    expected_key_id: &str,
    verifying_key: &VerifyingKey,
) -> Result<AuthenticatedJournal, JournalError> {
    if bytes.len() as u64 > MAX_RECORD_BYTES * 1024 {
        return Err(JournalError::InvalidFormat);
    }
    let envelope: JournalEnvelope =
        serde_json::from_slice(bytes).map_err(|_| JournalError::InvalidFormat)?;
    if envelope.format != JOURNAL_FORMAT
        || envelope.transitions.is_empty()
        || envelope.transitions.len() > 1024
    {
        return Err(JournalError::InvalidFormat);
    }
    if serde_jcs::to_vec(&envelope).map_err(|_| JournalError::InvalidFormat)? != bytes {
        return Err(JournalError::InvalidFormat);
    }
    let mut previous_hash = String::new();
    let mut previous_phase = None;
    let mut binding: Option<ChainBinding> = None;
    let mut request_ids = std::collections::HashSet::new();
    let mut request_nonces = std::collections::HashSet::new();
    for (index, transition) in envelope.transitions.iter().enumerate() {
        let request = &transition.request;
        if transition.format != JOURNAL_FORMAT
            || request.sequence != (index as u64 + 1)
            || request.previous_signed_hash != previous_hash
            || previous_phase
                .is_some_and(|phase: RestorePhase| !phase.permits_next(request.intended_transition))
        {
            return Err(JournalError::InvalidSequence);
        }
        let current_binding = ChainBinding {
            operation_id: request.operation_id,
            artifact_sha256: request.artifact_sha256.clone(),
            target_installation_id: request.target_installation_id.clone(),
            source_installation_id: request.source_installation_id.clone(),
            site_id: request.site_id.clone(),
            journal_authority_id: request.journal_authority_id.clone(),
            target_device: request.target_device,
            target_inode: request.target_inode,
            target_database_identity: request.target_database_identity.clone(),
        };
        if binding.as_ref().is_some_and(|old| old != &current_binding) {
            return Err(JournalError::ReplayOrFork);
        }
        binding = Some(current_binding);
        if !request_ids.insert(request.request_id)
            || !request_nonces.insert(request.request_nonce.clone())
        {
            return Err(JournalError::ReplayOrFork);
        }
        // This implementation intentionally authenticates only the initial
        // PREFLIGHTED record. D7 source fencing, D3 PKI replacement, target
        // fencing and activation verifiers are not implemented here; a
        // journal signature by itself cannot stand in for those authorities.
        if request.intended_transition != RestorePhase::Preflighted || index != 0 {
            return Err(JournalError::InvalidTransition);
        }
        verify_response(
            request,
            &transition.response,
            expected_key_id,
            verifying_key,
        )?;
        previous_hash = hex::encode(Sha256::digest(
            serde_jcs::to_vec(transition).map_err(|_| JournalError::InvalidFormat)?,
        ));
        previous_phase = Some(request.intended_transition);
    }
    let last = envelope
        .transitions
        .last()
        .ok_or(JournalError::InvalidFormat)?;
    let request = &last.request;
    Ok(AuthenticatedJournal {
        operation_id: request.operation_id,
        artifact_sha256: request.artifact_sha256.clone(),
        target_installation_id: request.target_installation_id.clone(),
        source_installation_id: request.source_installation_id.clone(),
        target_device: request.target_device,
        target_inode: request.target_inode,
        target_database_identity: request.target_database_identity.clone(),
        phase: request.intended_transition,
        sequence: request.sequence,
        signed_hash: previous_hash,
        chain_sha256: hex::encode(Sha256::digest(bytes)),
    })
}

/// Authenticates journal v1 using the installed purpose-bound certificate and
/// fresh signed revocation state. Caller-supplied public keys cannot enter this
/// boundary. v1 remains PREFLIGHTED-only.
pub fn authenticate_installed_chain(
    bytes: &[u8],
    policy: &crate::recovery_identity::InstallationPolicy,
    trust: &crate::recovery_trust::VerifiedTrust,
    operation_id: Uuid,
    artifact_sha256: &str,
) -> Result<AuthenticatedJournal, JournalError> {
    let envelope: JournalEnvelope =
        serde_json::from_slice(bytes).map_err(|_| JournalError::InvalidFormat)?;
    let first = envelope
        .transitions
        .first()
        .ok_or(JournalError::InvalidFormat)?;
    let key_id = &first.request.journal_authority_id;
    let key = trust.journal_key(key_id).ok_or(JournalError::KeyRevoked)?;
    let authenticated = authenticate_chain(bytes, key_id, key)?;
    if envelope.transitions.iter().any(|transition| {
        let request = &transition.request;
        request.site_id != policy.site_id
            || request.target_installation_id != policy.installation_id
            || request.target_device != policy.target_device
            || request.target_inode != policy.target_inode
            || request.operation_id != operation_id
            || request.artifact_sha256 != artifact_sha256
            || request.intended_transition != RestorePhase::Preflighted
    }) {
        return Err(JournalError::InvalidSequence);
    }
    Ok(authenticated)
}

/// Refuses a journal signer whose key ID appears in the release-provided
/// revocation set before performing the normal chain authentication.
pub fn authenticate_chain_with_revocations(
    bytes: &[u8],
    expected_key_id: &str,
    verifying_key: &VerifyingKey,
    revoked_key_ids: &[String],
) -> Result<AuthenticatedJournal, JournalError> {
    if revoked_key_ids
        .iter()
        .any(|key_id| key_id == expected_key_id)
    {
        return Err(JournalError::KeyRevoked);
    }
    authenticate_chain(bytes, expected_key_id, verifying_key)
}

/// Atomically persists a canonical request exactly once. A retry reads and
/// returns the original bytes; it never generates a new nonce for the same
/// sequence. `new_request` is called only if no request already exists.
pub fn persist_or_retry_request(
    directory: &Path,
    binding: &RequestBinding,
    uid: u32,
    gid: u32,
    new_request: impl FnOnce() -> Result<SigningRequest, JournalError>,
) -> Result<Vec<u8>, JournalError> {
    persist_or_retry_request_inner(directory, binding, uid, gid, true, new_request)
}

fn persist_or_retry_request_inner(
    directory: &Path,
    binding: &RequestBinding,
    uid: u32,
    gid: u32,
    require_ext4: bool,
    new_request: impl FnOnce() -> Result<SigningRequest, JournalError>,
) -> Result<Vec<u8>, JournalError> {
    // Only the initial PREFLIGHTED request has a verifier at this boundary.
    // Persisting a later-phase request would hand the offline signer bytes for
    // a transition the target must still refuse, so fail before any write.
    if binding.sequence != 1
        || !binding.previous_signed_hash.is_empty()
        || binding.intended_transition != RestorePhase::Preflighted
    {
        return Err(JournalError::InvalidTransition);
    }
    let dir = open_dir(directory)?;
    validate_dir(&dir, uid, gid, require_ext4)?;
    let _request_lock = acquire_named_lock(&dir, "restore-signing-request.lock", uid, gid)?;
    let path = directory.join("restore-signing-request.json");
    match read_regular(&path, uid, gid) {
        Ok(existing) => {
            let request: SigningRequest =
                serde_json::from_slice(&existing).map_err(|_| JournalError::InvalidRequest)?;
            let canonical = canonical_request(&request)?;
            if canonical != existing {
                return Err(JournalError::InvalidRequest);
            }
            if !request.matches_binding(binding) {
                return Err(JournalError::ReplayOrFork);
            }
            Ok(existing)
        }
        Err(JournalError::Io)
            if statat(
                dir.as_fd(),
                "restore-signing-request.json",
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .is_err_and(|error| error == rustix::io::Errno::NOENT) =>
        {
            let request = new_request()?;
            if !request.matches_binding(binding) {
                return Err(JournalError::ReplayOrFork);
            }
            let bytes = canonical_request(&request)?;
            atomic_create(&dir, &path, &bytes, uid, gid)?;
            Ok(bytes)
        }
        Err(error) => Err(error),
    }
}

fn acquire_named_lock(dir: &File, name: &str, uid: u32, gid: u32) -> Result<File, JournalError> {
    let fd = match openat(
        dir.as_fd(),
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => fd,
        Err(error) if error == rustix::io::Errno::EXIST => openat(
            dir.as_fd(),
            name,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| JournalError::UnsafeRecord)?,
        Err(_) => return Err(JournalError::Io),
    };
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|_| JournalError::Io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(JournalError::UnsafeRecord);
    }
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| JournalError::ReservationBusy)?;
    Ok(file)
}

/// Writes the authenticated chain using file fsync, same-directory rename,
/// and directory fsync. The required reservation guard makes it impossible
/// for this API to write a chain after its target reservation has been dropped.
pub fn persist_chain(
    reservation: &TargetReservation,
    transitions: &[SignedTransition],
    expected_key_id: &str,
    verifying_key: &VerifyingKey,
    uid: u32,
    gid: u32,
) -> Result<Vec<u8>, JournalError> {
    if transitions.is_empty() || transitions.len() > 1024 {
        return Err(JournalError::InvalidFormat);
    }
    let envelope = JournalEnvelope {
        format: JOURNAL_FORMAT.to_owned(),
        transitions: transitions.to_vec(),
    };
    let bytes = serde_jcs::to_vec(&envelope).map_err(|_| JournalError::InvalidFormat)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES * 1024 {
        return Err(JournalError::InvalidFormat);
    }
    let authenticated = authenticate_chain(&bytes, expected_key_id, verifying_key)?;
    reservation.verify_for_chain(
        authenticated.operation_id,
        &authenticated.artifact_sha256,
        authenticated.target_device,
        authenticated.target_inode,
        uid,
        gid,
    )?;
    let dir = open_dir(&reservation.recovery_path)?;
    validate_dir(&dir, uid, gid, reservation.require_ext4)?;
    let path = reservation.recovery_path.join("restore-journal.json");
    match read_journal(&dir, &path, uid, gid) {
        Ok(existing) if existing == bytes => return Ok(bytes),
        Ok(_) => return Err(JournalError::ReplayOrFork),
        Err(JournalError::Io) => {}
        Err(error) => return Err(error),
    }
    // At this stage only the initial PREFLIGHTED journal is enabled. Later
    // append operations require D7/D3 prerequisite verifiers and will be
    // added at those owning boundaries; never replace an existing history.
    if authenticated.phase != RestorePhase::Preflighted || authenticated.sequence != 1 {
        return Err(JournalError::InvalidTransition);
    }
    atomic_create(&dir, &path, &bytes, uid, gid)?;
    Ok(bytes)
}

fn validate_request(r: &SigningRequest) -> Result<(), JournalError> {
    if r.format != REQUEST_FORMAT
        || r.request_id.is_nil()
        || r.operation_id.is_nil()
        || !valid_sha256(&r.artifact_sha256)
        || (!r.previous_signed_hash.is_empty() && !valid_sha256(&r.previous_signed_hash))
        || r.request_nonce.len() != MAX_NONCE_BYTES * 2
        || hex::decode(&r.request_nonce).map_or(true, |n| n.len() != MAX_NONCE_BYTES)
        || !valid_identifier(&r.target_installation_id)
        || !valid_identifier(&r.target_database_identity)
        || !valid_identifier(&r.source_installation_id)
        || !valid_identifier(&r.site_id)
        || !valid_identifier(&r.journal_authority_id)
        || !valid_sha256(&r.deterministic_step_id)
        || r.target_device == 0
        || r.target_inode == 0
        || r.sequence == 0
    {
        return Err(JournalError::InvalidRequest);
    }
    Ok(())
}
fn deterministic_step_id(
    operation_id: Uuid,
    artifact_sha256: &str,
    sequence: u64,
    transition: RestorePhase,
) -> String {
    hex::encode(Sha256::digest(
        format!(
            "o3k-pp6-step-v1\0{operation_id}\0{artifact_sha256}\0{sequence}\0{}",
            transition.stable_name()
        )
        .as_bytes(),
    ))
}
fn valid_sha256(value: &str) -> bool {
    value.len() == MAX_HASH_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn open_dir(path: &Path) -> Result<File, JournalError> {
    if !path.is_absolute()
        || path.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(JournalError::UnsafeDirectory);
    }
    let mut current = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| JournalError::UnsafeDirectory)?,
    );
    for component in path.components().skip(1) {
        let std::path::Component::Normal(name) = component else {
            return Err(JournalError::UnsafeDirectory);
        };
        let fd = openat(
            current.as_fd(),
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| JournalError::UnsafeDirectory)?;
        current = File::from(fd);
    }
    Ok(current)
}
fn validate_dir(dir: &File, uid: u32, gid: u32, require_ext4: bool) -> Result<(), JournalError> {
    let metadata = dir.metadata().map_err(|_| JournalError::UnsafeDirectory)?;
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(JournalError::UnsafeDirectory);
    }
    if require_ext4 {
        let fs = fstatfs(dir.as_fd()).map_err(|_| JournalError::UnsafeDirectory)?;
        if fs.f_type != 0xef53 || !is_local_block_ext4(&metadata) {
            return Err(JournalError::UnsafeDirectory);
        }
    }
    Ok(())
}
fn is_local_block_ext4(metadata: &fs::Metadata) -> bool {
    let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let device = format!(
        "{}:{}",
        rustix::fs::major(metadata.dev()),
        rustix::fs::minor(metadata.dev())
    );
    mountinfo.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.get(2) == Some(&device.as_str())
            && line.split_once(" - ").is_some_and(|(_, after)| {
                let parts: Vec<_> = after.split_whitespace().collect();
                parts.first() == Some(&"ext4")
                    && parts
                        .get(1)
                        .is_some_and(|source| source.starts_with("/dev/"))
            })
    })
}
fn validate_root_protected_ancestors(path: &Path) -> Result<(), JournalError> {
    let mut ancestor = path.parent();
    while let Some(path) = ancestor {
        let directory = open_dir(path)?;
        let metadata = directory
            .metadata()
            .map_err(|_| JournalError::UnsafeDirectory)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(JournalError::UnsafeDirectory);
        }
        ancestor = path.parent();
    }
    Ok(())
}
fn identity(dir: &File) -> Result<(u64, u64), JournalError> {
    let m = dir.metadata().map_err(|_| JournalError::Io)?;
    Ok((m.dev(), m.ino()))
}
fn hash_path_identity(identity: (u64, u64)) -> String {
    hex::encode(Sha256::digest(
        format!("{}:{}", identity.0, identity.1).as_bytes(),
    ))[..24]
        .to_owned()
}
fn directory_empty(dir: &File) -> Result<bool, JournalError> {
    let path = format!("/proc/self/fd/{}", dir.as_raw_fd());
    Ok(fs::read_dir(path)
        .map_err(|_| JournalError::Io)?
        .next()
        .is_none())
}
fn read_regular(path: &Path, uid: u32, gid: u32) -> Result<Vec<u8>, JournalError> {
    let parent = path.parent().ok_or(JournalError::UnsafeRecord)?;
    let directory = open_dir(parent)?;
    let name = path.file_name().ok_or(JournalError::UnsafeRecord)?;
    let fd = openat(
        directory.as_fd(),
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| JournalError::Io)?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|_| JournalError::Io)?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_RECORD_BYTES
    {
        return Err(JournalError::UnsafeRecord);
    }
    let current = statat(directory.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| JournalError::UnsafeRecord)?;
    if current.st_dev != metadata.dev() || current.st_ino != metadata.ino() {
        return Err(JournalError::UnsafeRecord);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| JournalError::Io)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(JournalError::UnsafeRecord);
    }
    Ok(bytes)
}
fn atomic_create(
    dir: &File,
    path: &Path,
    bytes: &[u8],
    uid: u32,
    gid: u32,
) -> Result<(), JournalError> {
    atomic_write(dir, path, bytes, uid, gid, true)
}
fn atomic_write(
    dir: &File,
    path: &Path,
    bytes: &[u8],
    uid: u32,
    gid: u32,
    exclusive: bool,
) -> Result<(), JournalError> {
    let name = path
        .file_name()
        .ok_or(JournalError::UnsafeRecord)?
        .to_string_lossy();
    let temp = format!(".{name}.{}.tmp", Uuid::new_v4());
    let result = (|| {
        let temp_fd = openat(
            dir.as_fd(),
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| JournalError::Io)?;
        let mut file = File::from(temp_fd);
        let metadata = file.metadata().map_err(|_| JournalError::Io)?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.gid() != gid
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(JournalError::UnsafeRecord);
        }
        file.write_all(bytes).map_err(|_| JournalError::Io)?;
        file.sync_all().map_err(|_| JournalError::Io)?;
        let target = path.file_name().ok_or(JournalError::UnsafeRecord)?;
        if exclusive && statat(dir.as_fd(), target, AtFlags::SYMLINK_NOFOLLOW).is_ok() {
            return Err(JournalError::ReplayOrFork);
        }
        renameat_with(
            dir.as_fd(),
            temp.as_str(),
            dir.as_fd(),
            target,
            if exclusive {
                RenameFlags::NOREPLACE
            } else {
                RenameFlags::empty()
            },
        )
        .map_err(|_| JournalError::Io)?;
        dir.sync_all().map_err(|_| JournalError::Io)?;
        let written =
            statat(dir.as_fd(), target, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| JournalError::Io)?;
        if written.st_dev != metadata.dev() || written.st_ino != metadata.ino() {
            return Err(JournalError::UnsafeRecord);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(dir.as_fd(), temp.as_str(), AtFlags::empty());
    }
    result
}

fn read_journal(dir: &File, path: &Path, uid: u32, gid: u32) -> Result<Vec<u8>, JournalError> {
    let name = path.file_name().ok_or(JournalError::UnsafeRecord)?;
    let fd = openat(
        dir.as_fd(),
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| JournalError::Io)?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|_| JournalError::Io)?;
    let max = MAX_RECORD_BYTES * 1024;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > max
    {
        return Err(JournalError::UnsafeRecord);
    }
    let current = statat(dir.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| JournalError::UnsafeRecord)?;
    if current.st_dev != metadata.dev() || current.st_ino != metadata.ino() {
        return Err(JournalError::UnsafeRecord);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| JournalError::Io)?;
    if bytes.len() as u64 > max {
        return Err(JournalError::UnsafeRecord);
    }
    Ok(bytes)
}

use std::os::fd::AsRawFd;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    // Disposable test custody identity. This key must never be used by a
    // controller, restore target, release, or production custody workflow.
    const TEST_KEY_ID: &str = "test-only-restore-journal-key";

    fn request(sequence: u64, previous: &str, phase: RestorePhase) -> SigningRequest {
        SigningRequest {
            format: REQUEST_FORMAT.to_owned(),
            request_id: Uuid::from_u128(sequence as u128),
            request_nonce: hex::encode([sequence as u8; 32]),
            operation_id: Uuid::from_u128(999),
            site_id: "test-site".to_owned(),
            artifact_sha256: "ab".repeat(32),
            journal_authority_id: TEST_KEY_ID.to_owned(),
            target_installation_id: "target-installation".to_owned(),
            target_device: 1,
            target_inode: 2,
            target_database_identity: "o3k_fresh".to_owned(),
            source_installation_id: "source-installation".to_owned(),
            deterministic_step_id: "cd".repeat(32),
            sequence,
            previous_signed_hash: previous.to_owned(),
            intended_transition: phase,
        }
    }
    fn signed(r: &SigningRequest, key: &SigningKey) -> SignedTransition {
        let bytes = canonical_request(r).unwrap();
        let response = SigningResponse {
            format: RESPONSE_FORMAT.to_owned(),
            request_sha256: hex::encode(Sha256::digest(&bytes)),
            key_id: TEST_KEY_ID.to_owned(),
            signature: hex::encode(key.sign(&bytes).to_bytes()),
        };
        verify_response(r, &response, TEST_KEY_ID, &key.verifying_key()).unwrap()
    }

    #[test]
    fn exact_request_is_bound_and_wrong_key_replay_or_response_changes_fail_closed() {
        let key = SigningKey::from_bytes(&[41; 32]);
        let req = request(1, "", RestorePhase::Preflighted);
        let transition = signed(&req, &key);
        let chain = serde_jcs::to_vec(&JournalEnvelope {
            format: JOURNAL_FORMAT.into(),
            transitions: vec![transition.clone()],
        })
        .unwrap();
        let authenticated = authenticate_chain(&chain, TEST_KEY_ID, &key.verifying_key()).unwrap();
        assert_eq!(authenticated.phase, RestorePhase::Preflighted);
        assert_eq!(
            (authenticated.target_device, authenticated.target_inode),
            (1, 2)
        );
        assert_eq!(
            authenticate_chain(
                &chain,
                TEST_KEY_ID,
                &SigningKey::from_bytes(&[42; 32]).verifying_key()
            ),
            Err(JournalError::SignatureInvalid)
        );
        assert_eq!(
            authenticate_chain_with_revocations(
                &chain,
                TEST_KEY_ID,
                &key.verifying_key(),
                &[TEST_KEY_ID.to_owned()],
            ),
            Err(JournalError::KeyRevoked)
        );
        let mut changed = transition;
        changed.request.sequence = 2;
        let fork = serde_jcs::to_vec(&JournalEnvelope {
            format: JOURNAL_FORMAT.into(),
            transitions: vec![changed],
        })
        .unwrap();
        assert!(authenticate_chain(&fork, TEST_KEY_ID, &key.verifying_key()).is_err());
        let mut response = signed(&req, &key).response;
        response.request_sha256 = "00".repeat(32);
        assert_eq!(
            verify_response(&req, &response, TEST_KEY_ID, &key.verifying_key()),
            Err(JournalError::ResponseMismatch)
        );
        let mut other = req.clone();
        other.intended_transition = RestorePhase::SourceFenced;
        assert_ne!(
            canonical_request(&req).unwrap(),
            canonical_request(&other).unwrap()
        );
    }

    #[test]
    fn transitions_reject_skips_and_do_not_authorize_activation_from_database_restore() {
        assert!(!RestorePhase::Preflighted.permits_next(RestorePhase::TargetReserved));
        assert!(!RestorePhase::DatabaseRestored.permits_next(RestorePhase::Committed));
        assert!(!RestorePhase::DatabaseRestored.permits_next(RestorePhase::Started));
        assert!(RestorePhase::DatabaseRestored.permits_next(RestorePhase::FailedRecoverable));
        assert!(RestorePhase::DatabaseRestored.permits_next(RestorePhase::Quarantined));
        let key = SigningKey::from_bytes(&[45; 32]);
        let unproven = signed(&request(1, "", RestorePhase::SourceFenced), &key);
        let bytes = serde_jcs::to_vec(&JournalEnvelope {
            format: JOURNAL_FORMAT.into(),
            transitions: vec![unproven],
        })
        .unwrap();
        assert_eq!(
            authenticate_chain(&bytes, TEST_KEY_ID, &key.verifying_key()),
            Err(JournalError::InvalidTransition),
            "a test signature must not act as D7 source-fencing evidence"
        );
    }

    #[test]
    fn signing_request_wire_is_canonical_and_strict() {
        let req = request(1, "", RestorePhase::Preflighted);
        let bytes = canonical_request(&req).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_jcs::to_vec(&value).unwrap(), bytes);
        let mut invalid = req.clone();
        invalid.request_nonce = "00".to_owned();
        assert_eq!(
            canonical_request(&invalid),
            Err(JournalError::InvalidRequest)
        );
        let mut nil_operation = req.clone();
        nil_operation.operation_id = Uuid::nil();
        assert_eq!(
            canonical_request(&nil_operation),
            Err(JournalError::InvalidRequest)
        );
        let mut nil_request = req;
        nil_request.request_id = Uuid::nil();
        assert_eq!(
            canonical_request(&nil_request),
            Err(JournalError::InvalidRequest)
        );
    }

    fn binding() -> RequestBinding {
        RequestBinding {
            operation_id: Uuid::from_u128(999),
            site_id: "test-site".to_owned(),
            artifact_sha256: "ab".repeat(32),
            target_installation_id: "target-installation".to_owned(),
            target_device: 1,
            target_inode: 2,
            target_database_identity: "o3k_fresh".to_owned(),
            source_installation_id: "source-installation".to_owned(),
            journal_authority_id: TEST_KEY_ID.to_owned(),
            sequence: 1,
            previous_signed_hash: String::new(),
            intended_transition: RestorePhase::Preflighted,
        }
    }

    #[test]
    fn lost_signing_response_reuses_exact_persisted_request_and_rejects_binding_change() {
        let root =
            std::env::temp_dir().join(format!("o3k-restore-request-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let binding = binding();
        let first = persist_or_retry_request_inner(&root, &binding, uid, gid, false, || {
            initial_preflight_request(&binding)
        })
        .unwrap();
        let retry = persist_or_retry_request_inner(&root, &binding, uid, gid, false, || {
            Err(JournalError::Io)
        })
        .unwrap();
        assert_eq!(first, retry);
        let mut conflicting = binding.clone();
        conflicting.target_inode = 3;
        assert_eq!(
            persist_or_retry_request_inner(&root, &conflicting, uid, gid, false, || {
                initial_preflight_request(&conflicting)
            }),
            Err(JournalError::ReplayOrFork)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn later_phase_signing_request_is_refused_before_any_write() {
        let root =
            std::env::temp_dir().join(format!("o3k-restore-request-phase-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let mut later = binding();
        later.intended_transition = RestorePhase::SourceFenced;
        assert_eq!(
            persist_or_retry_request_inner(&root, &later, uid, gid, false, || Err(
                JournalError::Io
            )),
            Err(JournalError::InvalidTransition)
        );
        let mut second = binding();
        second.sequence = 2;
        second.previous_signed_hash = "cd".repeat(32);
        assert_eq!(
            persist_or_retry_request_inner(&root, &second, uid, gid, false, || Err(
                JournalError::Io
            )),
            Err(JournalError::InvalidTransition)
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn response_request_hash_must_match_before_signature_is_accepted() {
        let key = SigningKey::from_bytes(&[43; 32]);
        let req = request(1, "", RestorePhase::Preflighted);
        let mut response = signed(&req, &key).response;
        response.signature = hex::encode(key.sign(b"different request").to_bytes());
        assert_eq!(
            verify_response(&req, &response, TEST_KEY_ID, &key.verifying_key()),
            Err(JournalError::SignatureInvalid)
        );
        let value = json!({"test_signer":"disposable; no production custody"});
        assert!(
            value["test_signer"]
                .as_str()
                .unwrap()
                .contains("no production custody")
        );
    }

    #[test]
    fn atomic_create_is_exclusive_and_never_replaces_a_symlink() {
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("o3k-restore-journal-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let directory = open_dir(&root).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let bytes = b"canonical fixture";
        let record = root.join("restore-signing-request.json");
        atomic_create(&directory, &record, bytes, uid, gid).unwrap();
        assert_eq!(read_regular(&record, uid, gid).unwrap(), bytes);
        assert_eq!(
            atomic_create(&directory, &record, b"changed", uid, gid),
            Err(JournalError::ReplayOrFork)
        );
        let victim = root.join("victim");
        fs::write(&victim, b"must remain unchanged").unwrap();
        let link = root.join("link");
        symlink(&victim, &link).unwrap();
        assert_eq!(
            atomic_create(&directory, &link, b"replacement", uid, gid),
            Err(JournalError::ReplayOrFork)
        );
        assert_eq!(fs::read(&victim).unwrap(), b"must remain unchanged");
        fs::remove_dir_all(root).unwrap();
    }

    fn reservation_fixture() -> (PathBuf, PathBuf, u32, u32) {
        let root = std::env::temp_dir().join(format!("o3k-restore-reservation-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let recovery = root.join("recovery");
        let target = root.join("target");
        fs::create_dir(&recovery).unwrap();
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        (
            recovery,
            target,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    fn acquire_test_reservation(
        recovery: &Path,
        target: &Path,
        operation_id: Uuid,
        uid: u32,
        gid: u32,
    ) -> Result<TargetReservation, JournalError> {
        TargetReservation::acquire_inner(
            recovery,
            target,
            operation_id,
            &"ab".repeat(32),
            uid,
            gid,
            ReservationPolicy {
                require_ext4: false,
                require_root_ancestors: false,
                authenticated: None,
            },
        )
    }

    #[test]
    fn reservation_excludes_concurrent_operation_and_binds_operation_and_artifact() {
        let (recovery, target, uid, gid) = reservation_fixture();
        let root = recovery.parent().unwrap().to_path_buf();
        let operation = Uuid::from_u128(1001);
        let reservation =
            acquire_test_reservation(&recovery, &target, operation, uid, gid).unwrap();
        assert_eq!(reservation.verify_empty_before_mutation(), Ok(()));
        assert_eq!(
            acquire_test_reservation(&recovery, &target, operation, uid, gid)
                .err()
                .unwrap(),
            JournalError::ReservationBusy
        );
        let target_metadata = fs::metadata(&target).unwrap();
        let mut initial = request(1, "", RestorePhase::Preflighted);
        initial.operation_id = operation;
        initial.target_device = target_metadata.dev();
        initial.target_inode = target_metadata.ino();
        let key = SigningKey::from_bytes(&[52; 32]);
        let transition = signed(&initial, &key);
        let bytes = persist_chain(
            &reservation,
            &[transition],
            TEST_KEY_ID,
            &key.verifying_key(),
            uid,
            gid,
        )
        .unwrap();
        let authenticated = authenticate_chain(&bytes, TEST_KEY_ID, &key.verifying_key()).unwrap();
        drop(reservation);
        assert_eq!(
            acquire_test_reservation(&recovery, &target, operation, uid, gid).err(),
            Some(JournalError::ReplayOrFork),
            "a free process lock is not sufficient evidence to reacquire ownership"
        );
        let rebound = TargetReservation::acquire_inner(
            &recovery,
            &target,
            operation,
            &"ab".repeat(32),
            uid,
            gid,
            ReservationPolicy {
                require_ext4: false,
                require_root_ancestors: false,
                authenticated: Some(&authenticated),
            },
        )
        .unwrap();
        rebound.revalidate(uid, gid).unwrap();
        drop(rebound);
        assert_eq!(
            acquire_test_reservation(&recovery, &target, Uuid::from_u128(1002), uid, gid)
                .err()
                .unwrap(),
            JournalError::ReplayOrFork
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reservation_detects_target_replacement_and_nonempty_target() {
        let (recovery, target, uid, gid) = reservation_fixture();
        let root = recovery.parent().unwrap().to_path_buf();
        let reservation =
            acquire_test_reservation(&recovery, &target, Uuid::from_u128(2001), uid, gid).unwrap();
        fs::write(target.join("unexpected"), b"foreign writer").unwrap();
        assert_eq!(
            reservation.verify_empty_before_mutation(),
            Err(JournalError::TargetNotEmpty)
        );
        fs::remove_file(target.join("unexpected")).unwrap();
        let moved = root.join("old-target");
        fs::rename(&target, &moved).unwrap();
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            reservation.revalidate(uid, gid),
            Err(JournalError::TargetChanged)
        );
        drop(reservation);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn signed_chain_persists_atomically_under_the_held_target_reservation() {
        let (recovery, target, uid, gid) = reservation_fixture();
        let root = recovery.parent().unwrap().to_path_buf();
        let operation = Uuid::from_u128(3001);
        let reservation =
            acquire_test_reservation(&recovery, &target, operation, uid, gid).unwrap();
        let metadata = fs::metadata(&target).unwrap();
        let mut request = request(1, "", RestorePhase::Preflighted);
        request.operation_id = operation;
        request.target_device = metadata.dev();
        request.target_inode = metadata.ino();
        let key = SigningKey::from_bytes(&[51; 32]);
        let transition = signed(&request, &key);
        let first = persist_chain(
            &reservation,
            std::slice::from_ref(&transition),
            TEST_KEY_ID,
            &key.verifying_key(),
            uid,
            gid,
        )
        .unwrap();
        assert_eq!(
            authenticate_chain(&first, TEST_KEY_ID, &key.verifying_key())
                .unwrap()
                .phase,
            RestorePhase::Preflighted
        );
        assert_eq!(
            persist_chain(
                &reservation,
                std::slice::from_ref(&transition),
                TEST_KEY_ID,
                &key.verifying_key(),
                uid,
                gid,
            )
            .unwrap(),
            first
        );
        let journal = fs::metadata(recovery.join("restore-journal.json")).unwrap();
        assert_eq!(journal.permissions().mode() & 0o7777, 0o600);
        let mut conflicting = request.clone();
        conflicting.request_nonce = hex::encode([99; 32]);
        let response = signed(&conflicting, &key);
        assert_eq!(
            persist_chain(
                &reservation,
                &[response],
                TEST_KEY_ID,
                &key.verifying_key(),
                uid,
                gid,
            ),
            Err(JournalError::ReplayOrFork)
        );
        drop(reservation);
        fs::remove_dir_all(root).unwrap();
    }
}
