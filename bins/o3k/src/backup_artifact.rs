//! Operator-usable PP.6 backup artifact driver (SPEC-0050 §8, ADR-0189 D2/D4/D8/D9/D12).
//!
//! This module turns the provisional capture from the handoff slice into a real
//! authenticated artifact, using the accepted **offline custody** signing flow
//! (Option A, ADR-0190). The command boundary never sees the custody-held
//! Ed25519 private key, so artifact creation is a two-phase protocol over
//! host-local files.
//!
//! # Option A exclusion: the controller stays stopped through publication
//!
//! ADR-0190 Option A states that "the controller remains stopped throughout
//! signing", and SPEC-0050 §5 requires the capture exclusion and staging
//! reservation to remain in force "through verified publication or safe
//! abort". The executor therefore does not release the store lock after the
//! capture:
//!
//! 1. `o3k backup create --destination DIR --operation-id UUID` receives the
//!    authenticated handoff, captures a quiesced SQLite snapshot, stages the
//!    encrypted artifact with an unsigned manifest and writes
//!    `<destination>/.o3k-backup-artifact-<operation>/signing-request.json`.
//!    **The same process keeps the `StoreAccessLock` and the denial-only
//!    interrupted-backup marker**, prints one stable line
//!    `o3k backup create: awaiting-signature <operation-id>` on stderr
//!    (SPEC-0050 §8: the operation id, never a filesystem path), and polls for
//!    `signing-response.json` until the request's own TTL (24h). A response
//!    that is present but not yet parsable is retried until the deadline; a
//!    response that never parses performs the same safe abort as an expired
//!    request (`signing-response-invalid`, exit 3).
//! 2. When the custodian writes the response: verify the detached signature,
//!    finalize, publish, remove the marker, exit 0 with the normal JSON.
//! 3. On timeout: **safe abort** — the staging tree is removed, the journal is
//!    marked `aborted`, the marker is removed and the command exits 3 with
//!    `signing-request-expired`.
//! 4. If the process dies during the wait: the kernel releases the lock but
//!    the marker (which denies controller startup) and the `staged` journal
//!    remain. Re-running the **same** command detects the journal *before*
//!    contacting any controller, acquires `StoreAccessLock` directly
//!    (`WouldBlock` → exit 2 `controller-active`), re-creates the marker if an
//!    operator removed it, and resumes the wait/publication. A published
//!    operation is never recaptured: its destination is re-verified and the
//!    replay succeeds idempotently, or rejects `published-artifact-missing`
//!    when the artifact is gone.
//!
//! The CLI surface is unchanged: exactly `--destination` and `--operation-id`.
//! There is deliberately no `--complete-signature` flag and no test signer in
//! production builds; the signing response is a file convention.
//!
//! # Honest limits
//!
//! * Two-of-three custodian confirmation is an **operator process** on the
//!   offline workstation. This tool accepts a signature produced under the
//!   configured custody process; it does not itself attest custody, threshold
//!   approval, or the workstation's integrity.
//! * This module makes **no restore claim**. It produces and publishes the
//!   encrypted artifact; restore is a separate contract.
//! * The staged unsigned artifact is not a backup artifact and must never be
//!   treated as one (the manifest carries no signature and the verifier
//!   rejects it).
//! * Signing delays extend API downtime (the controller cannot start while the
//!   marker exists). That is the accepted Option A trade-off.
//!
//! # Configuration
//!
//! Everything is loaded from root-owned installation configuration after the
//! store-access lock has been received and before the capture begins.
//!
//! A root process (`euid == 0`) ignores `O3K_BACKUP_TRUST_CONFIG`,
//! `O3K_INSTALL_PREFIX`, `O3K_UPGRADE_PREFIX` and `O3K_DATA_DIR` overrides and
//! uses the canonical `/etc/o3k/backup-trust.json` plus the canonical install
//! prefix `/usr/local`. A non-root caller may use the documented overrides, but
//! the loaded document and key files must still pass the private-file posture
//! in [`crate::backup_trust`]. This is the SPEC-0050 §8 root/non-root rule.
//!
//! * Trust document: site/installation identity, profile, artifact-signing key
//!   id/public key, mandatory custody deadline and the recovery recipient key
//!   material (private key path, optional declared public key).
//! * `<install prefix>/share/o3k/release-manifest.json`: the exact release
//!   identity (`o3k_version`, `source_sha`, `release_artifact_sha256`,
//!   `profile_id`, `schema_version`), read with a bounded no-follow descriptor.
//!
//! The trust document must bind the canonical site/installation identities
//! derived from the data directory; a copied document fails closed with
//! `identity-mismatch`. The recipient public key is declared by the document
//! (and validated against the private key when both are present) or derived
//! from the configured X25519 private key file, so the document cannot wrap
//! artifacts for a recipient it does not name.
//!
//! # Staging content
//!
//! After the capture the staging tree holds only the encrypted artifact, the
//! offline signing request, the phase-2 `operation.lock` and (after the
//! custodian acts) the response. The plaintext SQLite snapshot is unlinked as
//! soon as the encrypted artifact is staged; an expired signing request removes
//! the whole staging tree because no publication is pending.
//!
//! # Manifest population
//!
//! * `database/o3k.sqlite` — the quiesced snapshot from
//!   `SqliteStore::backup_to_file` (member bytes are the snapshot file).
//! * `metadata/capture.json` — bounded capture provenance (source hashes,
//!   snapshot hash, journal mode, D9 measurements, in-flight operation
//!   classification, CLI version). This is provenance, not canonical state.
//! * `release/release-manifest.json` — the installed release manifest the
//!   identity was read from.
//! * `trust/backup-trust.json` — the trust document (public keys and the
//!   recipient key *path*; it contains no private key material).
//!
//! `store.migrations` comes from the **snapshot's** `_sqlx_migrations` through
//! [`crate::backup_verify::migration_checksum`], the single documented mapping
//! (lowercase hex SHA-256 of the raw 48-byte SQLx checksum blob).
//! `store.server_version` is `SELECT sqlite_version()` on the snapshot.
//! `store.schema_version` is the release's declared maximum migration prefix,
//! and capture fails closed if the snapshot's newest migration does not match
//! it.
//!
//! `state_inventory` is `o3k_store::state_inventory::baseline_state_inventory()`
//! with `empty_state_included` computed per repository from the snapshot
//! (`EXISTS(SELECT 1 FROM t)` for every table the repository owns; true means
//! every table is empty).
//!
//! `consistency.in_flight_operations` is read from the **snapshot** (the
//! quiesced capture taken under the store lock): `drained` when no durable
//! Operation is non-terminal, otherwise `recorded_unknown` with the stable
//! operation ids recorded in the capture metadata member.
//!
//! # Journal
//!
//! `<data_dir>/backup-operations/<operation_id>.json` records
//! `capturing → captured → staged → publishing → published` (or `aborted`) via
//! [`o3k_store::backup_journal`], with forward-only transitions. The journal is
//! durable operation metadata, not canonical state: `staged`/`publishing` never
//! deny controller startup on their own. Under Option A the *marker* denies
//! startup until verified publication or safe abort; `published` refuses a
//! *new* capture under the same operation id.
//!
//! # Publication
//!
//! The finished artifact is linked into the destination through the retained
//! destination descriptor (`linkat` of the exact verified inode, then the staged
//! name is unlinked); an existing final artifact is never replaced. The staged
//! file is opened `O_NOFOLLOW`, `fstat`ed through the descriptor and verified
//! through that same descriptor before publication, so a path swap or symlink
//! cannot publish unverified bytes. A `publishing` journal replay repeats the
//! full signature/trust/release/member verification: the journal is never the
//! authority for "already verified". Publication observation is
//! **destination-first**: a crash after publication but before the `published`
//! journal write (including a crash that already removed the staging tree) is
//! classified from the destination inode and its digest. A pre-existing
//! non-regular or symlinked destination entry is a rejected precondition
//! (`artifact-destination-exists`, exit 2).
//!
//! # Concurrency
//!
//! Phase 1 holds the lifetime store lock for the whole wait. Phase 2 acquires
//! the same lock directly (a live controller ⇒ exit 2 `controller-active`) and
//! additionally holds `operation.lock` (`flock`, non-blocking) inside the
//! staging directory so two phase-2 invocations cannot interleave (exit 3
//! `operation-busy`).
//!
//! Linux-only, mirroring the handoff primitives in `o3k-store`.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use o3k_store::{
    backup_journal::{self, BackupOperationPhase, BackupOperationRecord},
    state_inventory::{
        baseline_state_inventory, sqlite_live_catalog_objects,
        verify_sqlite_catalog_against_baseline,
    },
};
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{
        AtFlags, FileType, FlockOperation, Mode, OFlags, flock, fstat, fsync, linkat, open, openat,
        unlinkat,
    },
    process::geteuid,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{
    Row,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use uuid::Uuid;

use crate::{
    backup::{
        ArtifactIntegrityExpectations, ArtifactTrust, CreateOptions, Manifest, MigrationIdentity,
        StreamMember, finish_signed_artifact, manifest_signing_input,
        read_unsigned_staged_artifact, stage_unsigned_artifact, unsigned_manifest_digest,
    },
    backup_reservation::Reservation,
    backup_trust::{
        BackupTrustConfig, BackupTrustError, default_trust_config_path_for, install_prefix_for,
        site_and_installation_ids,
    },
    output::now_utc_rfc3339,
    upgrade::release_identity::{BackupReleaseIdentity, backup_release_identity},
};

/// Dot-prefixed operation staging directory inside the destination.
pub const OPERATION_STAGING_PREFIX: &str = ".o3k-backup-artifact-";
/// Published artifact filename prefix.
pub const ARTIFACT_FILE_PREFIX: &str = "backup-";
/// Published artifact filename suffix.
pub const ARTIFACT_FILE_SUFFIX: &str = ".o3k";
/// Offline signing request written into the operation staging directory.
pub const SIGNING_REQUEST_FILE: &str = "signing-request.json";
/// Detached signing response the operator places next to the request.
pub const SIGNING_RESPONSE_FILE: &str = "signing-response.json";
/// `flock` file that serializes phase-2 invocations for one operation.
pub const OPERATION_LOCK_FILE: &str = "operation.lock";
/// Stable stderr prefix emitted once when the executor starts waiting for the
/// detached signature. The operation id follows on the same line (SPEC-0050
/// §8); no path is emitted.
pub const AWAITING_SIGNATURE_LINE: &str = "o3k backup create: awaiting-signature";
/// Versioned signing-request format marker.
pub const SIGNING_REQUEST_FORMAT: &str = "o3k-backup-signing-request-v1";
/// Versioned signing-response format marker.
pub const SIGNING_RESPONSE_FORMAT: &str = "o3k-backup-signing-response-v1";
/// Versioned capture-record member format marker.
pub const CAPTURE_RECORD_FORMAT: &str = "o3k-backup-capture-record-v1";
/// `encryption.key_id` of the artifact content key (the key itself is a
/// per-artifact random key wrapped to the recipient, never a stored key).
pub const ARTIFACT_CONTENT_KEY_ID: &str = "artifact-content-key-v1";
/// Default installation prefix when `O3K_INSTALL_PREFIX` is unset (re-exported
/// from the trust module so root and non-root callers share one value).
pub use crate::backup_trust::DEFAULT_INSTALL_PREFIX;
/// How long an offline signing request remains acceptable.
pub const SIGNING_REQUEST_TTL: Duration = Duration::hours(24);

/// Default poll interval while the executor waits for `signing-response.json`.
pub const DEFAULT_AWAIT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Waiting policy for the detached signature.
///
/// The production policy waits until the request's own `expires_at`
/// ([`SIGNING_REQUEST_TTL`] after the snapshot completed). Tests and the
/// feature-gated harness hook may cap the wait with [`Self::timeout`]; the
/// effective deadline is the earlier of the two.
#[derive(Debug, Clone, Copy)]
pub struct AwaitPolicy {
    /// Optional cap on the wait, independent of the request lifetime.
    pub timeout: Option<std::time::Duration>,
    /// Poll interval for the response file.
    pub poll_interval: std::time::Duration,
}

impl Default for AwaitPolicy {
    fn default() -> Self {
        Self {
            timeout: None,
            poll_interval: DEFAULT_AWAIT_POLL_INTERVAL,
        }
    }
}

impl AwaitPolicy {
    /// Effective deadline: the earlier of the request expiry and the optional
    /// timeout.
    fn deadline(&self, expires_at: &str) -> Result<DateTime<Utc>, ArtifactFailure> {
        let expires = DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| ArtifactFailure::rejected("signing-request-invalid"))?
            .with_timezone(&Utc);
        let now = Utc::now();
        let capped = self
            .timeout
            .and_then(|timeout| {
                chrono::Duration::from_std(timeout)
                    .ok()
                    .and_then(|duration| now.checked_add_signed(duration))
            })
            .unwrap_or(expires);
        Ok(capped.min(expires))
    }
}

/// Crash-injection hooks for the artifact phase campaign; compiled only with
/// the `backup-test-hooks` feature. The environment variables force a hard
/// process exit at the named durable transition so a real-process test can
/// exercise the recovery path without a production-visible switch.
#[cfg(feature = "backup-test-hooks")]
macro_rules! test_hook_exit {
    ($var:literal, $code:expr) => {
        if std::env::var_os($var).is_some_and(|value| value == "1") {
            std::process::exit($code);
        }
    };
}

#[cfg(not(feature = "backup-test-hooks"))]
macro_rules! test_hook_exit {
    ($var:literal, $code:expr) => {{}};
}

const MEMBERS_DIR_PREFIX: &str = "members-";
const DATABASE_MEMBER: &str = "database/o3k.sqlite";
const DATABASE_MEDIA_TYPE: &str = "application/vnd.sqlite3";
const CAPTURE_RECORD_MEMBER: &str = "metadata/capture.json";
const RELEASE_MANIFEST_MEMBER: &str = "release/release-manifest.json";
const TRUST_CONFIG_MEMBER: &str = "trust/backup-trust.json";
const JSON_MEDIA_TYPE: &str = "application/json";
const MAX_SIGNING_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SIGNING_RESPONSE_BYTES: u64 = 64 * 1024;
/// Bound for one captured metadata member (capture record, trust document,
/// release manifest).
pub const MAX_METADATA_MEMBER_BYTES: u64 = 1024 * 1024;

/// Failure classification mapped to the SPEC-0050 §8 exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactFailureClass {
    /// Exit 2: a rejected precondition; nothing was published.
    Rejected,
    /// Exit 3: a recoverable failure; staging is kept for inspection.
    Recoverable,
    /// Exit 4: the outcome is unknown and must be observed before retrying.
    Unknown,
}

/// A stable, secret-free failure with its exit classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactFailure {
    class: ArtifactFailureClass,
    reason: &'static str,
}

impl ArtifactFailure {
    /// Rejected precondition (exit 2).
    #[must_use]
    pub const fn rejected(reason: &'static str) -> Self {
        Self {
            class: ArtifactFailureClass::Rejected,
            reason,
        }
    }

    /// Recoverable failure (exit 3).
    #[must_use]
    pub const fn recoverable(reason: &'static str) -> Self {
        Self {
            class: ArtifactFailureClass::Recoverable,
            reason,
        }
    }

    /// Unknown outcome (exit 4).
    #[must_use]
    pub const fn unknown(reason: &'static str) -> Self {
        Self {
            class: ArtifactFailureClass::Unknown,
            reason,
        }
    }

    /// Exit classification.
    #[must_use]
    pub const fn class(self) -> ArtifactFailureClass {
        self.class
    }

    /// Stable reason string for operator output.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.reason
    }
}

impl From<BackupTrustError> for ArtifactFailure {
    fn from(error: BackupTrustError) -> Self {
        // Missing configuration/key material is recoverable (exit 3) in both
        // `create` and `verify`; a document that is present but untrusted or
        // mismatched is a rejected precondition (exit 2).
        if error.is_recoverable() {
            Self::recoverable(error.reason())
        } else {
            Self::rejected(error.reason())
        }
    }
}

/// Validated installation configuration for one artifact.
#[derive(Debug)]
pub struct ArtifactConfig {
    trust: BackupTrustConfig,
    release: BackupReleaseIdentity,
    signing_key: VerifyingKey,
    recipient_public_key: [u8; 32],
    recipient_public_key_sha256: String,
    site_id: String,
    installation_id: String,
    trust_config_path: PathBuf,
    release_manifest_path: PathBuf,
}

impl ArtifactConfig {
    /// Loads the trust document and the installed release identity and checks
    /// they describe this data directory.
    pub fn load(data_dir: &Path) -> Result<Self, ArtifactFailure> {
        Self::load_from(
            data_dir,
            &default_trust_config_path_for(
                data_dir,
                std::env::var_os(crate::backup_trust::TRUST_CONFIG_ENV),
                std::env::var_os(crate::backup_trust::INSTALL_PREFIX_ENV),
            ),
            &install_prefix_for(
                data_dir,
                std::env::var_os(crate::backup_trust::INSTALL_PREFIX_ENV),
            ),
        )
    }

    /// [`Self::load`] with explicit paths, so the derivation is testable
    /// without mutating the process environment.
    pub fn load_from(
        data_dir: &Path,
        trust_config_path: &Path,
        install_prefix: &Path,
    ) -> Result<Self, ArtifactFailure> {
        let trust = BackupTrustConfig::load(trust_config_path)?;
        trust.verify_identity(data_dir)?;
        if trust
            .signing_key_is_revoked(trust.artifact_signing_key_id())
            .map_err(|_| ArtifactFailure::rejected("trust-key-unavailable"))?
        {
            return Err(ArtifactFailure::rejected("trust-key-revoked"));
        }
        let release_manifest_path = release_manifest_path(install_prefix);
        let release = backup_release_identity(install_prefix)
            .map_err(|_| ArtifactFailure::recoverable("release-identity-unavailable"))?;
        if release.profile_id != trust.profile_id() {
            return Err(ArtifactFailure::rejected("release-profile-mismatch"));
        }
        let signing_key = trust.artifact_signing_public_key()?;
        let recipient_public_key = trust.recipient_public_key()?;
        let recipient_public_key_sha256 = hex::encode(Sha256::digest(recipient_public_key));
        let (site_id, installation_id) = site_and_installation_ids(data_dir)
            .map_err(|_| ArtifactFailure::recoverable("identity-unavailable"))?;
        Ok(Self {
            trust,
            release,
            signing_key,
            recipient_public_key,
            recipient_public_key_sha256,
            site_id,
            installation_id,
            trust_config_path: trust_config_path.to_path_buf(),
            release_manifest_path,
        })
    }

    /// Configured profile id.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        self.trust.profile_id()
    }

    /// Canonical site identity bound into the manifest.
    #[must_use]
    pub fn site_id(&self) -> &str {
        &self.site_id
    }

    /// Canonical installation identity bound into the manifest.
    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Artifact-signing key id (the custody key the operator signs with).
    #[must_use]
    pub fn signing_key_id(&self) -> &str {
        self.trust.artifact_signing_key_id()
    }

    /// Recovery recipient key id.
    #[must_use]
    pub fn recipient_key_id(&self) -> &str {
        self.trust.recipient_key_id()
    }

    /// Trusted artifact-signing public key.
    #[must_use]
    pub fn signing_key(&self) -> &VerifyingKey {
        &self.signing_key
    }

    /// X25519 recipient public key derived from (or declared by) the trust
    /// document.
    #[must_use]
    pub fn recipient_public_key(&self) -> [u8; 32] {
        self.recipient_public_key
    }

    /// Lowercase hex SHA-256 of the configured recipient public key.
    ///
    /// This is published in the signing request so the custodian can compare
    /// it against the trusted trust document before approving a signature.
    #[must_use]
    pub fn recipient_public_key_sha256(&self) -> &str {
        &self.recipient_public_key_sha256
    }

    /// Trust policy used by artifact verification (revocation and key binding).
    #[must_use]
    pub fn trust(&self) -> &dyn ArtifactTrust {
        &self.trust
    }

    /// Path the trust document was read from (captured as a member).
    #[must_use]
    pub fn trust_config_path(&self) -> &Path {
        &self.trust_config_path
    }

    /// Installed release manifest path (captured as a member).
    #[must_use]
    pub fn release_manifest_path(&self) -> &Path {
        &self.release_manifest_path
    }

    /// Exact release identity supplied to the manifest.
    #[must_use]
    pub fn release(&self) -> &BackupReleaseIdentity {
        &self.release
    }
}

/// Resolves the installation prefix with the root/non-root posture of the
/// trust module: a root process uses the canonical `/usr/local`, a non-root
/// caller may honor `O3K_INSTALL_PREFIX`.
#[must_use]
pub fn install_prefix() -> PathBuf {
    crate::backup_trust::install_prefix()
}

fn release_manifest_path(install_prefix: &Path) -> PathBuf {
    install_prefix.join("share/o3k/release-manifest.json")
}

/// Facts read from the captured snapshot that populate `store` and
/// `state_inventory`.
#[derive(Debug)]
pub struct SnapshotFacts {
    pub sqlite_version: String,
    pub migrations: Vec<MigrationIdentity>,
    pub state_inventory: Vec<Value>,
    /// `drained` (no non-terminal Operation), `recorded_unknown` (at least one
    /// non-terminal Operation identity was preserved) or `none` (the
    /// `operations` table is absent in this schema generation).
    pub in_flight_operations: &'static str,
    /// Stable ids of the non-terminal Operations, sorted.
    pub in_flight_operation_ids: Vec<String>,
}

/// Reads the store identity and repository inventory from the snapshot.
///
/// The snapshot is opened **read-only**; the live store is never touched. The
/// newest applied migration must match the release's declared schema version,
/// otherwise the artifact would claim a schema the release did not produce.
pub fn snapshot_facts(
    runtime: &tokio::runtime::Runtime,
    snapshot_path: &Path,
    release: &BackupReleaseIdentity,
) -> Result<SnapshotFacts, ArtifactFailure> {
    runtime.block_on(async {
        let options = SqliteConnectOptions::new()
            .filename(snapshot_path)
            .create_if_missing(false)
            .read_only(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| ArtifactFailure::rejected("snapshot-unreadable"))?;
        let result = read_snapshot_facts(&pool, release).await;
        pool.close().await;
        result
    })
}

/// In-flight Operation classification read from a captured snapshot.
///
/// Phase 1 calls this before the manifest is built; the same query backs
/// [`SnapshotFacts::in_flight_operations`]. The snapshot is opened read-only,
/// so the live store is never touched.
pub fn snapshot_in_flight_operations(
    runtime: &tokio::runtime::Runtime,
    snapshot_path: &Path,
) -> Result<(&'static str, Vec<String>), ArtifactFailure> {
    runtime.block_on(async {
        let options = SqliteConnectOptions::new()
            .filename(snapshot_path)
            .create_if_missing(false)
            .read_only(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| ArtifactFailure::rejected("snapshot-unreadable"))?;
        let result = query_in_flight_operations(&pool).await;
        pool.close().await;
        result
    })
}

/// Reads the durable non-terminal Operation identities from an open snapshot
/// pool.
///
/// `succeeded` and `failed` are the store's terminal states; every other state
/// (`pending`, `running`, `retryable`, `unknown_outcome`) is preserved as
/// `recorded_unknown`.
async fn query_in_flight_operations(
    pool: &sqlx::SqlitePool,
) -> Result<(&'static str, Vec<String>), ArtifactFailure> {
    let rows = sqlx::query(
        "SELECT id FROM operations WHERE state NOT IN ('succeeded', 'failed') ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| ArtifactFailure::rejected("snapshot-operation-inventory-unavailable"))?;
    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row
            .try_get(0)
            .map_err(|_| ArtifactFailure::rejected("snapshot-operation-inventory-unavailable"))?;
        if Uuid::parse_str(&id).is_err() {
            return Err(ArtifactFailure::rejected(
                "snapshot-operation-inventory-unavailable",
            ));
        }
        ids.push(id);
    }
    let classification = if ids.is_empty() {
        "drained"
    } else {
        "recorded_unknown"
    };
    Ok((classification, ids))
}

/// Reads the store identity and repository inventory from an open snapshot
/// pool.
async fn read_snapshot_facts(
    pool: &sqlx::SqlitePool,
    release: &BackupReleaseIdentity,
) -> Result<SnapshotFacts, ArtifactFailure> {
    let sqlite_version: String = sqlx::query_scalar("SELECT sqlite_version()")
        .fetch_one(pool)
        .await
        .map_err(|_| ArtifactFailure::rejected("snapshot-unreadable"))?;
    let rows = sqlx::query("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .map_err(|_| ArtifactFailure::rejected("snapshot-migration-inventory-unavailable"))?;
    let mut migrations = Vec::with_capacity(rows.len());
    for row in rows {
        let version: i64 = row
            .try_get(0)
            .map_err(|_| ArtifactFailure::rejected("migration-version-invalid"))?;
        let checksum: Vec<u8> = row
            .try_get(1)
            .map_err(|_| ArtifactFailure::rejected("migration-checksum-invalid"))?;
        migrations.push(MigrationIdentity {
            version: u64::try_from(version)
                .map_err(|_| ArtifactFailure::rejected("migration-version-invalid"))?,
            // One documented mapping shared with `o3k backup verify`; the two
            // paths must never compute different digests for the same row.
            checksum: crate::backup_verify::migration_checksum(&checksum),
        });
    }
    if migrations.is_empty() {
        return Err(ArtifactFailure::rejected(
            "snapshot-migration-inventory-empty",
        ));
    }
    if migrations.last().map(|migration| migration.version) != Some(release.schema_version) {
        return Err(ArtifactFailure::rejected("migration-schema-mismatch"));
    }
    let mut inventory = baseline_state_inventory()
        .map_err(|_| ArtifactFailure::rejected("state-inventory-unavailable"))?;
    // D13 capture-time catalog check: the snapshot's live sqlite_master must
    // match the committed baseline exactly (names and normalized definitions)
    // before anything is staged. This catches missing, extra or redefined
    // tables/indexes/triggers in the bytes that will be encrypted.
    let live_catalog = sqlite_live_catalog_objects(pool)
        .await
        .map_err(|_| ArtifactFailure::rejected("snapshot-catalog-unavailable"))?;
    verify_sqlite_catalog_against_baseline(&inventory, &live_catalog)
        .map_err(|_| ArtifactFailure::rejected("store-catalog-mismatch"))?;
    for entry in &mut inventory {
        let tables =
            repository_tables(entry).ok_or(ArtifactFailure::rejected("state-inventory-invalid"))?;
        let mut included = true;
        for table in tables {
            if !is_table_identifier(&table) {
                return Err(ArtifactFailure::rejected("state-inventory-invalid"));
            }
            let exists: i64 =
                sqlx::query_scalar(&format!("SELECT EXISTS(SELECT 1 FROM \"{table}\")"))
                    .fetch_one(pool)
                    .await
                    .map_err(|_| {
                        ArtifactFailure::rejected("snapshot-repository-table-unavailable")
                    })?;
            if exists != 0 {
                included = false;
                break;
            }
        }
        if let Some(fields) = entry.as_object_mut() {
            fields.insert("empty_state_included".to_owned(), Value::Bool(included));
        }
    }
    // In-flight Operations are read from the same quiesced snapshot under the
    // store lock: the classification must describe the captured bytes, never a
    // live store that may have moved on.
    let (in_flight_operations, in_flight_operation_ids) = query_in_flight_operations(pool).await?;
    Ok(SnapshotFacts {
        sqlite_version,
        migrations,
        state_inventory: inventory,
        in_flight_operations,
        in_flight_operation_ids,
    })
}

/// SQLite table names a baseline inventory entry owns, in catalog order.
fn repository_tables(entry: &Value) -> Option<Vec<String>> {
    let objects = entry.get("sqlite_objects")?.as_array()?;
    let tables = objects
        .iter()
        .filter(|object| object.get("kind").and_then(Value::as_str) == Some("table"))
        .filter_map(|object| object.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if tables.is_empty() {
        None
    } else {
        Some(tables)
    }
}

fn is_table_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Inputs for phase 1 (capture and stage).
pub struct CaptureInputs<'a> {
    pub config: &'a ArtifactConfig,
    pub operation_id: Uuid,
    pub reservation: Reservation,
    /// Operation staging directory addressed as `/proc/self/fd/<n>`.
    pub staging_dir: &'a Path,
    /// Durable path of the same staging directory, reported to the operator.
    pub durable_staging_dir: &'a Path,
    /// Snapshot file addressed as `/proc/self/fd/<n>/o3k.sqlite`.
    pub snapshot_path: &'a Path,
    pub snapshot_sha256: &'a str,
    pub source_before: &'a str,
    pub source_after: &'a str,
    pub journal_mode: &'a str,
    pub snapshot_started_at: &'a str,
    pub snapshot_completed_at: &'a str,
    /// `drained`, `recorded_unknown` or `none`; see [`SnapshotFacts`].
    pub in_flight_operations: &'a str,
    /// Stable identities of the non-terminal Operations recorded at capture.
    pub in_flight_operation_ids: &'a [String],
    pub runtime: &'a tokio::runtime::Runtime,
}

/// Result of a successful phase 1.
pub struct StagedSigning {
    pub backup_id: String,
    pub manifest_digest: String,
    pub signing_input_sha256: String,
    pub payload_sha256: String,
    pub artifact_size_bytes: u64,
    pub expires_at: String,
    pub request_path: PathBuf,
    pub request_sha256: String,
    pub source_bytes: u64,
    pub reserved_bytes: u64,
}

/// Builds the manifest, stages the encrypted artifact, and writes the offline
/// signing request. Nothing is published and no journal state is written here;
/// the caller owns the journal and the marker.
pub fn stage_capture(inputs: &CaptureInputs<'_>) -> Result<StagedSigning, ArtifactFailure> {
    let config = inputs.config;
    let backup_id = inputs.operation_id.to_string();
    let facts = snapshot_facts(inputs.runtime, inputs.snapshot_path, config.release())?;
    let record = capture_record_bytes(inputs)?;

    let snapshot_metadata = fs::symlink_metadata(inputs.snapshot_path)
        .map_err(|_| ArtifactFailure::recoverable("snapshot-unavailable"))?;
    if !snapshot_metadata.file_type().is_file() {
        return Err(ArtifactFailure::recoverable("snapshot-not-regular-file"));
    }
    let options = CreateOptions {
        backup_id: backup_id.clone(),
        created_at: inputs.snapshot_completed_at.to_owned(),
        site_id: config.site_id().to_owned(),
        installation_id: config.installation_id().to_owned(),
        source: json!({
            "o3k_version": config.release().o3k_version,
            "source_sha": config.release().source_sha,
            "release_artifact_sha256": config.release().release_artifact_sha256,
            "profile_id": config.release().profile_id,
        }),
        store: json!({
            "backend": "sqlite",
            "server_version": facts.sqlite_version,
            "schema_version": config.release().schema_version,
            "migrations": facts
                .migrations
                .iter()
                .map(|migration| json!({
                    "version": migration.version,
                    "checksum": migration.checksum,
                }))
                .collect::<Vec<_>>(),
        }),
        consistency: json!({
            "method": "sqlite_vacuum_into",
            "write_quiescence": true,
            "worker_quiescence": true,
            "in_flight_operations": inputs.in_flight_operations,
            "quiescence_generation": quiescence_generation(inputs),
            "snapshot_started_at": inputs.snapshot_started_at,
            "snapshot_completed_at": inputs.snapshot_completed_at,
        }),
        state_inventory: facts.state_inventory,
        consistency_generation: quiescence_generation(inputs),
        recipient_key_id: config.recipient_key_id().to_owned(),
        recipient_public_key: config.recipient_public_key(),
        artifact_key_id: ARTIFACT_CONTENT_KEY_ID.to_owned(),
        signing_key_id: config.signing_key_id().to_owned(),
    };

    let release_manifest = read_bounded_private(inputs.config.release_manifest_path())?;
    let trust_config = read_bounded_private(inputs.config.trust_config_path())?;
    let members: Vec<StreamMember<Box<dyn Read>>> = vec![
        StreamMember {
            name: DATABASE_MEMBER.to_owned(),
            media_type: DATABASE_MEDIA_TYPE.to_owned(),
            plaintext_size_bytes: snapshot_metadata.len(),
            source: Box::new(
                fs::File::open(inputs.snapshot_path)
                    .map_err(|_| ArtifactFailure::recoverable("snapshot-unavailable"))?,
            ),
        },
        StreamMember {
            name: CAPTURE_RECORD_MEMBER.to_owned(),
            media_type: JSON_MEDIA_TYPE.to_owned(),
            plaintext_size_bytes: record.len() as u64,
            source: Box::new(std::io::Cursor::new(record)),
        },
        StreamMember {
            name: RELEASE_MANIFEST_MEMBER.to_owned(),
            media_type: JSON_MEDIA_TYPE.to_owned(),
            plaintext_size_bytes: release_manifest.len() as u64,
            source: Box::new(std::io::Cursor::new(release_manifest)),
        },
        StreamMember {
            name: TRUST_CONFIG_MEMBER.to_owned(),
            media_type: JSON_MEDIA_TYPE.to_owned(),
            plaintext_size_bytes: trust_config.len() as u64,
            source: Box::new(std::io::Cursor::new(trust_config)),
        },
    ];
    if members.len() > 64 {
        return Err(ArtifactFailure::rejected("member-count-invalid"));
    }

    let unsigned = stage_unsigned_artifact(&options, members, inputs.staging_dir)
        .map_err(|_| ArtifactFailure::recoverable("artifact-staging-failed"))?;
    let signing_input_sha256 = hex::encode(Sha256::digest(&unsigned.signing_input));
    let expires_at = signing_expiry(inputs.snapshot_completed_at)?;
    let request = SigningRequest {
        format: SIGNING_REQUEST_FORMAT.to_owned(),
        operation_id: operation_id_for(inputs),
        backup_id: backup_id.clone(),
        manifest_digest: unsigned.manifest_digest.clone(),
        signing_input_sha256: signing_input_sha256.clone(),
        signing_input_base64url: URL_SAFE_NO_PAD.encode(&unsigned.signing_input),
        key_id: config.signing_key_id().to_owned(),
        site_id: config.site_id().to_owned(),
        installation_id: config.installation_id().to_owned(),
        created_at: inputs.snapshot_completed_at.to_owned(),
        expires_at: expires_at.clone(),
        payload_sha256: unsigned.sha256.clone(),
        recipient_public_key_sha256: config.recipient_public_key_sha256().to_owned(),
    };
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|_| ArtifactFailure::rejected("request-encoding-failed"))?;
    // The member staging directory holds the artifact the request describes;
    // make it durable before the request that names it becomes durable.
    sync_directory(&unsigned.staging_directory)
        .map_err(|_| ArtifactFailure::recoverable("artifact-staging-sync-failed"))?;
    // The request is written through the descriptor-anchored path and reported
    // under the durable staging path, which is what the operator can use after
    // this process exits.
    write_exclusive_private(
        &inputs.staging_dir.join(SIGNING_REQUEST_FILE),
        &request_bytes,
    )
    .map_err(|_| ArtifactFailure::recoverable("signing-request-write-failed"))?;
    sync_directory(inputs.staging_dir)
        .map_err(|_| ArtifactFailure::recoverable("signing-request-sync-failed"))?;
    let request_path = inputs.durable_staging_dir.join(SIGNING_REQUEST_FILE);

    Ok(StagedSigning {
        backup_id,
        manifest_digest: unsigned.manifest_digest,
        signing_input_sha256,
        payload_sha256: unsigned.sha256,
        artifact_size_bytes: unsigned.size_bytes,
        expires_at,
        request_path,
        request_sha256: hex::encode(Sha256::digest(&request_bytes)),
        source_bytes: inputs.reservation.source_bytes,
        reserved_bytes: inputs.reservation.reserved_bytes,
    })
}

/// Manifest `created_at` and `quiescence_generation` come from the operation
/// id; kept in one place so every phase agrees.
fn quiescence_generation(inputs: &CaptureInputs<'_>) -> String {
    inputs.operation_id.to_string()
}

/// Inputs for the signature-verification and publication step.
pub struct CompletionInputs<'a> {
    pub data_dir: &'a Path,
    pub config: &'a ArtifactConfig,
    pub destination_dir: &'a Path,
    pub destination_fd: &'a OwnedFd,
    pub operation_id: Uuid,
    pub record: &'a BackupOperationRecord,
    /// Denial-only interrupted-backup marker owned by this operation. It is
    /// removed only after verified publication or safe abort.
    pub marker_path: &'a Path,
    /// D9 staging reservation accepted by the capture preflight.
    pub reservation: Reservation,
    /// How long to wait for `signing-response.json`.
    pub await_policy: AwaitPolicy,
}

/// A durably published artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedArtifact {
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Holds the per-operation phase-2 lock for its lifetime.
///
/// The store-access lock already excludes a live controller and a concurrent
/// capture; this second lock keeps two phase-2 invocations that reach the same
/// staging tree (for example from different data directories) from
/// interleaving verification, journal writes and publication.
#[derive(Debug)]
struct OperationLock {
    _file: fs::File,
}

impl OperationLock {
    fn acquire(staging_path: &Path) -> Result<Self, ArtifactFailure> {
        let path = staging_path.join(OPERATION_LOCK_FILE);
        let descriptor = open(
            &path,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| ArtifactFailure::recoverable("operation-lock-unavailable"))?;
        let metadata = fstat(&descriptor)
            .map_err(|_| ArtifactFailure::recoverable("operation-lock-unavailable"))?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || !private_file_posture(&metadata)
        {
            return Err(ArtifactFailure::recoverable("operation-lock-unavailable"));
        }
        match flock(&descriptor, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self {
                _file: fs::File::from(descriptor),
            }),
            Err(rustix::io::Errno::WOULDBLOCK) => {
                Err(ArtifactFailure::recoverable("operation-busy"))
            }
            Err(_) => Err(ArtifactFailure::recoverable("operation-lock-unavailable")),
        }
    }
}

/// Root-or-effective-uid owned and not group/other accessible.
fn private_file_posture(metadata: &rustix::fs::Stat) -> bool {
    let euid = rustix::process::geteuid().as_raw();
    (metadata.st_uid == 0 || metadata.st_uid == euid) && metadata.st_mode & 0o077 == 0
}

/// Waits for the detached signature (Option A: the controller stays stopped)
/// and then verifies, finishes and publishes the artifact.
///
/// The journal is **never** the authority for "already verified". Both the
/// `publishing` replay and the `staged` crash-recovery path parse the canonical
/// signed artifact from a `O_NOFOLLOW` descriptor, validate the manifest
/// (schema/JCS/limits), bind it to the configured site, installation, profile,
/// release and signing/recipient key ids, consult trust and revocation
/// fail-closed, verify the Ed25519 signature over the D1 input and re-digest
/// every member before any publication. Only then is the journal digest
/// compared and the verified inode linked into the destination.
///
/// A request that expires while waiting is a **safe abort**: the staging tree,
/// the pending reservation and the marker are removed and the command reports
/// the recoverable `signing-request-expired` reason.
pub fn complete_staged(
    inputs: &CompletionInputs<'_>,
) -> Result<PublishedArtifact, ArtifactFailure> {
    let staging_leaf = staging_leaf(inputs.operation_id);
    let staging_path = destination_staging_path(inputs.destination_dir, inputs.operation_id)?;
    // The publication name is derived from the validated operation UUID, never
    // from a journal-provided free-form field. The journal backup id must agree
    // with the operation the staged artifact was built for.
    let backup_id = inputs.operation_id.to_string();
    if inputs.record.backup_id != backup_id {
        return Err(ArtifactFailure::rejected("operation-backup-id-mismatch"));
    }
    let final_name = artifact_file_name(&backup_id);
    if final_name.is_empty() || final_name.contains('/') {
        return Err(ArtifactFailure::rejected("artifact-name-invalid"));
    }
    let final_path = inputs.destination_dir.join(&final_name);

    match inputs.record.phase {
        BackupOperationPhase::Published => {
            let staging_path =
                destination_staging_path(inputs.destination_dir, inputs.operation_id)?;
            return replay_published(inputs, &final_name, &final_path, &staging_path);
        }
        BackupOperationPhase::Publishing => {
            let Some(expected) = inputs.record.artifact_sha256.as_deref() else {
                return Err(ArtifactFailure::rejected("publishing-record-incomplete"));
            };
            // Observe the destination **before** requiring the staging tree:
            // a crash after publication may already have removed it (and may
            // have unlinked the staged name). The destination entry is hashed
            // through an `O_NOFOLLOW` descriptor and must also pass the full
            // signature/trust/member verification.
            if let Some(mut existing) = existing_destination(inputs.destination_fd, &final_name)? {
                let verified = verify_open_signed_artifact(inputs, &mut existing)
                    .map_err(|_| ArtifactFailure::rejected("artifact-destination-exists"))?;
                if verified.sha256 != expected {
                    return Err(ArtifactFailure::rejected("artifact-destination-exists"));
                }
                mark_published(inputs, &verified.sha256)?;
                finish_publication(inputs, &staging_path)?;
                return Ok(PublishedArtifact {
                    path: final_path,
                    sha256: verified.sha256,
                    size_bytes: verified.size_bytes,
                });
            }
            validate_staging_directory(inputs.destination_dir, &staging_path, &staging_leaf)?;
            if inputs.record.staging_path != staging_path.to_string_lossy().as_ref() {
                return Err(ArtifactFailure::rejected("operation-staging-path-mismatch"));
            }
            let _operation_lock = OperationLock::acquire(&staging_path)?;
            ensure_marker(inputs)?;
            let staged = verify_publishable_staged_artifact(inputs, &staging_path)?;
            if staged.sha256 != expected {
                return Err(ArtifactFailure::rejected("staged-artifact-changed"));
            }
            ensure_staging_space(inputs, &staging_path)?;
            publish(
                inputs.destination_fd,
                &staging_leaf,
                &staged.members_leaf,
                &staged.file,
                &final_name,
                &staged.sha256,
            )?;
            mark_published(inputs, &staged.sha256)?;
            finish_publication(inputs, &staging_path)?;
            return Ok(PublishedArtifact {
                path: final_path,
                sha256: staged.sha256,
                size_bytes: staged.size_bytes,
            });
        }
        BackupOperationPhase::Staged => {}
        _ => return Err(ArtifactFailure::rejected("backup-operation-phase-invalid")),
    }

    validate_staging_directory(inputs.destination_dir, &staging_path, &staging_leaf)?;
    if inputs.record.staging_path != staging_path.to_string_lossy().as_ref() {
        return Err(ArtifactFailure::rejected("operation-staging-path-mismatch"));
    }
    let _operation_lock = OperationLock::acquire(&staging_path)?;
    // The marker is the denial authority for the whole signing window. A
    // resumed invocation re-creates it if an operator removed it, so the
    // controller can never start while a publication is pending.
    ensure_marker(inputs)?;

    // Crash recovery for the window between `finish_signed_artifact` (which
    // removes `artifact.unsigned`) and the durable `publishing` transition: a
    // signed `artifact.partial` is re-verified in full and published.
    //
    // `artifact.partial` is only the recovery candidate when the unsigned
    // artifact is gone. While `artifact.unsigned` still exists, any
    // `artifact.partial` is debris from an earlier failed finalize (M5) and is
    // removed before a fresh finalize, so a stale file can never wedge the
    // retry.
    if !unsigned_staged_artifact_present(&staging_path)
        && staged_signed_artifact_present(&staging_path)
    {
        // The signed partial is only publishable when it is still bound to the
        // durable signing request the journal recorded. This runs before any
        // journal advance or publication and leaves the staging tree intact on
        // a mismatch.
        let (request, signing_input) = load_recovery_signing_request(inputs, &staging_path)?;
        let staged = verify_publishable_staged_artifact(inputs, &staging_path)?;
        bind_signed_artifact_to_request(&staged.manifest, &request, &signing_input)?;
        if let Some(expected) = inputs.record.artifact_sha256.as_deref()
            && staged.sha256 != expected
        {
            return Err(ArtifactFailure::rejected("staged-artifact-changed"));
        }
        update_journal(
            inputs,
            BackupOperationPhase::Publishing,
            Some(staged.sha256.clone()),
        )?;
        ensure_staging_space(inputs, &staging_path)?;
        publish(
            inputs.destination_fd,
            &staging_leaf,
            &staged.members_leaf,
            &staged.file,
            &final_name,
            &staged.sha256,
        )?;
        mark_published(inputs, &staged.sha256)?;
        finish_publication(inputs, &staging_path)?;
        return Ok(PublishedArtifact {
            path: final_path,
            sha256: staged.sha256,
            size_bytes: staged.size_bytes,
        });
    }
    if unsigned_staged_artifact_present(&staging_path) {
        remove_stale_finalize_outputs(&staging_path)?;
    }

    let request_path = staging_path.join(SIGNING_REQUEST_FILE);
    let request_bytes = read_bounded_file(&request_path, MAX_SIGNING_REQUEST_BYTES)
        .map_err(|_| ArtifactFailure::rejected("signing-request-unavailable"))?;
    let request_sha256 = hex::encode(Sha256::digest(&request_bytes));
    if inputs
        .record
        .request_sha256
        .as_deref()
        .is_some_and(|digest| digest != request_sha256)
    {
        return Err(ArtifactFailure::rejected("signing-request-changed"));
    }
    let request: SigningRequest = serde_json::from_slice(&request_bytes)
        .map_err(|_| ArtifactFailure::rejected("signing-request-invalid"))?;
    let expectations = RequestExpectations {
        operation_id: inputs.operation_id,
        backup_id: &backup_id,
        key_id: inputs.config.signing_key_id(),
        site_id: inputs.config.site_id(),
        installation_id: inputs.config.installation_id(),
        payload_sha256: None,
        recipient_public_key_sha256: inputs.config.recipient_public_key_sha256(),
    };
    let signing_input = match validate_signing_request(&request, &expectations) {
        Ok(input) => input,
        Err(failure) if failure.reason() == "signing-request-expired" => {
            return Err(safe_abort(inputs, &staging_path, "signing-request-expired"));
        }
        Err(failure) => return Err(failure),
    };

    let unsigned = read_unsigned_staged_artifact(&staging_path)
        .map_err(|_| ArtifactFailure::rejected("staged-artifact-invalid"))?;
    if unsigned.sha256 != request.payload_sha256
        || unsigned.manifest_digest != request.manifest_digest
        || unsigned.manifest.backup_id != request.backup_id
        || unsigned.manifest.site_id != inputs.config.site_id()
        || unsigned.manifest.installation_id != inputs.config.installation_id()
        || unsigned.manifest.authentication.key_id != inputs.config.signing_key_id()
        || unsigned.signing_input != signing_input
    {
        return Err(ArtifactFailure::rejected("staged-artifact-mismatch"));
    }

    let deadline = inputs.await_policy.deadline(&request.expires_at)?;
    // One stable stderr line announces the wait. The operator watches for it to
    // know the controller is stopped and the artifact is awaiting signature.
    // SPEC-0050 §8 requires the operation id only; emitting the staging path
    // would leak filesystem layout to the operator-facing diagnostics.
    let _ = writeln!(
        std::io::stderr(),
        "{AWAITING_SIGNATURE_LINE} {}",
        inputs.operation_id
    );
    // Test-only: die while the lock and marker are held, leaving the exact
    // crash-during-wait state a real process can only reach by being killed.
    test_hook_exit!("O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE", 91);

    let response_path = staging_path.join(SIGNING_RESPONSE_FILE);
    let response_bytes = match wait_for_signing_response(
        &response_path,
        &deadline,
        inputs.await_policy.poll_interval,
    ) {
        SignatureWait::Response(bytes) => bytes,
        SignatureWait::Unreadable => {
            return Err(ArtifactFailure::rejected("signing-response-unavailable"));
        }
        SignatureWait::Unparsable => {
            // The request deadline passed while an entry existed that never
            // became a parseable signing response. No publication is pending,
            // so this follows the same safe abort as an expired request rather
            // than leaving the controller denial permanently in place.
            return Err(safe_abort(
                inputs,
                &staging_path,
                "signing-response-invalid",
            ));
        }
        SignatureWait::TimedOut => {
            return Err(safe_abort(inputs, &staging_path, "signing-request-expired"));
        }
    };
    let signature = verify_signing_response(
        &response_bytes,
        &request_sha256,
        inputs.config.signing_key_id(),
        &signing_input,
        inputs.config.signing_key(),
        &request.created_at,
        &request.expires_at,
    )?;

    ensure_staging_space(inputs, &staging_path)?;
    finish_signed_artifact(
        unsigned,
        signature,
        inputs.config.signing_key_id(),
        inputs.config.signing_key(),
    )
    .map_err(|_| ArtifactFailure::rejected("artifact-finalize-failed"))?;
    // Test-only: crash after finalize removed `artifact.unsigned` and before
    // the durable `publishing` transition. A retry must detect the signed
    // `artifact.partial`, re-verify it and publish.
    test_hook_exit!("O3K_BACKUP_TEST_EXIT_AFTER_FINALIZE", 90);

    // Verify the exact bytes that will be published, from a fresh no-follow
    // descriptor. `finish_signed_artifact`'s digest is only a cross-check.
    let staged = verify_publishable_staged_artifact(inputs, &staging_path)?;
    ensure_staging_space(inputs, &staging_path)?;

    update_journal(
        inputs,
        BackupOperationPhase::Publishing,
        Some(staged.sha256.clone()),
    )?;
    // Test-only: crash after the durable `publishing` transition and before
    // publication. A retry must re-verify the staged signed artifact and finish
    // publication without a second publication.
    test_hook_exit!("O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_PUBLISHING", 88);
    publish(
        inputs.destination_fd,
        &staging_leaf,
        &staged.members_leaf,
        &staged.file,
        &final_name,
        &staged.sha256,
    )?;
    mark_published(inputs, &staged.sha256)?;
    finish_publication(inputs, &staging_path)?;
    // Test-only: crash after the artifact is durably published, the journal
    // says `published` and the staging tree and marker are gone, before the
    // success document is emitted.
    test_hook_exit!("O3K_BACKUP_TEST_EXIT_AFTER_PUBLICATION", 89);
    Ok(PublishedArtifact {
        path: final_path,
        sha256: staged.sha256,
        size_bytes: staged.size_bytes,
    })
}

/// Idempotent replay of a journal already at `published` (contract L5).
///
/// The destination is observed before any cleanup. If it holds the exact
/// artifact the journal recorded, the stale marker/staging debris is removed
/// and the command exits successfully instead of wedging on
/// `operation-already-published`. A missing or changed destination is a clear
/// rejected precondition; nothing is deleted.
fn replay_published(
    inputs: &CompletionInputs<'_>,
    final_name: &str,
    final_path: &Path,
    staging_path: &Path,
) -> Result<PublishedArtifact, ArtifactFailure> {
    let expected = inputs
        .record
        .artifact_sha256
        .as_deref()
        .ok_or_else(|| ArtifactFailure::rejected("published-record-incomplete"))?;
    let Some(mut existing) = existing_destination(inputs.destination_fd, final_name)? else {
        return Err(ArtifactFailure::rejected("published-artifact-missing"));
    };
    let verified = verify_open_signed_artifact(inputs, &mut existing)
        .map_err(|_| ArtifactFailure::rejected("published-artifact-changed"))?;
    if verified.sha256 != expected {
        return Err(ArtifactFailure::rejected("published-artifact-changed"));
    }
    finish_publication(inputs, staging_path)?;
    Ok(PublishedArtifact {
        path: final_path.to_path_buf(),
        sha256: verified.sha256,
        size_bytes: verified.size_bytes,
    })
}

/// Outcome of the bounded wait for `signing-response.json`.
enum SignatureWait {
    Response(Vec<u8>),
    /// An entry exists but cannot be read as a bounded regular file.
    Unreadable,
    /// An entry exists at the deadline but never parsed as a signing response.
    /// An operator/custodian writing non-atomically can leave a partial file;
    /// the wait retries it instead of failing on the first partial read.
    Unparsable,
    TimedOut,
}

/// Polls for the response file until `deadline`.
///
/// A symlinked or non-regular entry is a rejected precondition (never
/// followed); a missing entry is polled. A present entry is returned only once
/// it parses as a [`SigningResponse`]; a partially written (unparsable) file is
/// retried until the deadline so a non-atomic writer cannot cause a spurious
/// failure. The wait is bounded by the request TTL and by the optional
/// [`AwaitPolicy::timeout`].
fn wait_for_signing_response(
    response_path: &Path,
    deadline: &DateTime<Utc>,
    poll_interval: std::time::Duration,
) -> SignatureWait {
    let poll = poll_interval.max(std::time::Duration::from_millis(10));
    let mut saw_unparsable = false;
    loop {
        match read_bounded_file(response_path, MAX_SIGNING_RESPONSE_BYTES) {
            Ok(bytes) => {
                if serde_json::from_slice::<SigningResponse>(&bytes).is_ok() {
                    return SignatureWait::Response(bytes);
                }
                saw_unparsable = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return SignatureWait::Unreadable,
        }
        let now = Utc::now();
        if now >= *deadline {
            return if saw_unparsable {
                SignatureWait::Unparsable
            } else {
                SignatureWait::TimedOut
            };
        }
        let remaining = (*deadline - now)
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        std::thread::sleep(poll.min(remaining));
    }
}

/// Fails closed when the destination no longer holds the remaining D9
/// reservation (preflight + boundary re-check, never a filesystem quota).
fn ensure_staging_space(
    inputs: &CompletionInputs<'_>,
    staging_path: &Path,
) -> Result<(), ArtifactFailure> {
    let staged = directory_bytes(staging_path);
    crate::backup_reservation::ensure_reserved_space(
        inputs.destination_dir,
        inputs.reservation.reserved_bytes,
        staged,
    )
    .map_err(|_| ArtifactFailure::recoverable("space-unavailable"))
}

/// Aggregate size of the regular files under `path` (best effort: an
/// unreadable entry counts as zero, which only makes the check stricter).
fn directory_bytes(path: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => directory_bytes(&entry.path()),
            Ok(file_type) if file_type.is_file() => entry.metadata().map(|m| m.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

/// Post-publication cleanup: remove the staging tree and the denial marker.
///
/// A failure here cannot invalidate the published artifact, but the controller
/// must not be left blocked (marker) or plaintext staging left behind, so the
/// outcome is quarantined (exit 4) instead of being reported as success. A
/// directory `fsync` failure on the success path is reported as a stable
/// warning on stderr; the artifact is already durable in the destination.
fn finish_publication(
    inputs: &CompletionInputs<'_>,
    staging_path: &Path,
) -> Result<(), ArtifactFailure> {
    if fs::remove_dir_all(staging_path).is_err() && fs::symlink_metadata(staging_path).is_ok() {
        return Err(ArtifactFailure::unknown("post-publication-cleanup-failed"));
    }
    remove_marker(inputs.marker_path)?;
    if sync_directory(inputs.destination_dir).is_err() || sync_directory(inputs.data_dir).is_err() {
        let _ = writeln!(
            std::io::stderr(),
            "o3k backup create: warning post-publication-sync-failed"
        );
    }
    Ok(())
}

/// Removes the denial marker; an already-absent marker is success.
fn remove_marker(marker_path: &Path) -> Result<(), ArtifactFailure> {
    match fs::remove_file(marker_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ArtifactFailure::unknown("marker-removal-failed")),
    }
}

/// Ensures the denial marker exists for this operation.
///
/// It is created with `O_CREAT|O_EXCL` when absent (a resumed phase 2 after an
/// operator removed it), and an existing entry must be this operation's private
/// regular file.
fn ensure_marker(inputs: &CompletionInputs<'_>) -> Result<(), ArtifactFailure> {
    match fs::symlink_metadata(inputs.marker_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(ArtifactFailure::recoverable(
                    "backup-in-progress-marker-invalid",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                let euid = rustix::process::geteuid().as_raw();
                if (metadata.uid() != 0 && metadata.uid() != euid)
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(ArtifactFailure::recoverable(
                        "backup-in-progress-marker-invalid",
                    ));
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let body = json!({
                "operation_id": inputs.operation_id,
                "pid": std::process::id(),
                "resumed_at": now_utc_rfc3339(),
            });
            let bytes = serde_json::to_vec(&body)
                .map_err(|_| ArtifactFailure::recoverable("marker-write-failed"))?;
            write_exclusive_private(inputs.marker_path, &bytes)
                .map_err(|_| ArtifactFailure::recoverable("marker-write-failed"))?;
            sync_directory(inputs.data_dir)
                .map_err(|_| ArtifactFailure::recoverable("marker-sync-failed"))?;
            Ok(())
        }
        Err(_) => Err(ArtifactFailure::recoverable(
            "backup-in-progress-marker-invalid",
        )),
    }
}

/// Safe abort: no publication is pending, so the staging tree, the reservation
/// and the marker are removed and the journal records `aborted`.
///
/// If any of those cannot be proven, the outcome is quarantined (exit 4)
/// instead of being reported as a clean recoverable failure.
fn safe_abort(
    inputs: &CompletionInputs<'_>,
    staging_path: &Path,
    reason: &'static str,
) -> ArtifactFailure {
    let staging_removed =
        fs::remove_dir_all(staging_path).is_err() && fs::symlink_metadata(staging_path).is_ok();
    let mut record = inputs.record.clone();
    record.phase = BackupOperationPhase::Aborted;
    record.updated_at = now_utc_rfc3339();
    let journal = backup_journal::advance_backup_operation(inputs.data_dir, &record).is_ok();
    let marker = remove_marker(inputs.marker_path).is_ok();
    let _ = sync_directory(inputs.destination_dir);
    let _ = sync_directory(inputs.data_dir);
    if staging_removed || !journal || !marker {
        return ArtifactFailure::unknown("safe-abort-cleanup-failed");
    }
    ArtifactFailure::recoverable(reason)
}

fn update_journal(
    inputs: &CompletionInputs<'_>,
    phase: BackupOperationPhase,
    artifact_sha256: Option<String>,
) -> Result<(), ArtifactFailure> {
    let mut record = inputs.record.clone();
    record.phase = phase;
    record.updated_at = now_utc_rfc3339();
    if artifact_sha256.is_some() {
        record.artifact_sha256 = artifact_sha256;
    }
    // Forward-only: a replay that finds the phase already durable is
    // idempotent, any backwards move fails closed.
    backup_journal::advance_backup_operation(inputs.data_dir, &record)
        .map_err(|error| ArtifactFailure::recoverable(error.reason()))
}

/// Persists the terminal `published` phase together with the exact verified
/// artifact digest, so a later replay can re-verify the destination without
/// trusting a journal-only digest.
fn mark_published(
    inputs: &CompletionInputs<'_>,
    artifact_sha256: &str,
) -> Result<(), ArtifactFailure> {
    update_journal(
        inputs,
        BackupOperationPhase::Published,
        Some(artifact_sha256.to_owned()),
    )
}

/// The only signed artifact file name inside a `members-*` staging directory.
const STAGED_SIGNED_ARTIFACT_NAME: &str = "artifact.partial";
/// Temporary file name prefix used while a signed artifact is assembled.
const SIGNED_ARTIFACT_TEMP_PREFIX: &str = "artifact.partial.tmp-";
/// The unsigned staged artifact name inside a `members-*` directory.
const UNSIGNED_STAGED_ARTIFACT_NAME: &str = "artifact.unsigned";

/// A staged signed artifact that passed full integrity verification. The open
/// descriptor is the exact inode that must be published; publication links this
/// descriptor, never a path.
struct VerifiedStagedArtifact {
    file: fs::File,
    /// `members-<uuid>` leaf under the operation staging directory, used to
    /// remove the staged name relative to a verified directory descriptor.
    members_leaf: std::ffi::OsString,
    sha256: String,
    size_bytes: u64,
    manifest: Manifest,
}

/// Header facts of an already-open, fully verified signed artifact.
struct VerifiedOpenArtifact {
    size_bytes: u64,
    sha256: String,
    manifest: Manifest,
}

/// Verifies the staged signed artifact in full from a no-follow descriptor.
///
/// This is the single verification path shared by the `staged` and
/// `publishing` phases (and by crash recovery). It re-reads the canonical
/// bytes, validates the schema, canonical encoding and limits, binds the
/// manifest to the configured site/installation/profile/release and signing and
/// recipient key ids, evaluates trust and revocation fail-closed, verifies the
/// Ed25519 signature over the D1 input and re-digests every member. It does not
/// decrypt members; no recipient private key is read during publication.
fn verify_publishable_staged_artifact(
    inputs: &CompletionInputs<'_>,
    staging_path: &Path,
) -> Result<VerifiedStagedArtifact, ArtifactFailure> {
    let (members_leaf, mut file) = open_staged_signed_artifact(staging_path)
        .map_err(|_| ArtifactFailure::rejected("staged-artifact-invalid"))?;
    let verified = verify_open_signed_artifact(inputs, &mut file)?;
    Ok(VerifiedStagedArtifact {
        file,
        members_leaf,
        sha256: verified.sha256,
        size_bytes: verified.size_bytes,
        manifest: verified.manifest,
    })
}

/// [`verify_publishable_staged_artifact`] over an already-open descriptor.
fn verify_open_signed_artifact(
    inputs: &CompletionInputs<'_>,
    file: &mut fs::File,
) -> Result<VerifiedOpenArtifact, ArtifactFailure> {
    let backup_id = inputs.operation_id.to_string();
    let release = inputs.config.release();
    let expectations = ArtifactIntegrityExpectations {
        signing_key_id: inputs.config.signing_key_id(),
        signer: inputs.config.signing_key(),
        trust: inputs.config.trust(),
        recipient_key_id: inputs.config.recipient_key_id(),
        backup_id: &backup_id,
        site_id: inputs.config.site_id(),
        installation_id: inputs.config.installation_id(),
        profile_id: inputs.config.profile_id(),
        o3k_version: &release.o3k_version,
        source_sha: &release.source_sha,
        release_artifact_sha256: &release.release_artifact_sha256,
        schema_version: release.schema_version,
    };
    let header = crate::backup::verify_signed_artifact_integrity(file, &expectations)
        .map_err(|_| ArtifactFailure::rejected("staged-artifact-invalid"))?;
    Ok(VerifiedOpenArtifact {
        size_bytes: header.size_bytes,
        sha256: header.sha256,
        manifest: header.manifest,
    })
}

/// True when a `members-*/artifact.partial` entry exists, including a
/// symlinked one (which verification then rejects).
fn staged_signed_artifact_present(staging_path: &Path) -> bool {
    staging_entries(staging_path, STAGED_SIGNED_ARTIFACT_NAME)
}

/// True when the unique `members-*/artifact.unsigned` still exists.
fn unsigned_staged_artifact_present(staging_path: &Path) -> bool {
    staging_entries(staging_path, UNSIGNED_STAGED_ARTIFACT_NAME)
}

/// True when any `members-*` directory (not followed if symlinked) holds the
/// named entry, including a symlinked or otherwise unsafe one.
fn staging_entries(staging_path: &Path, name: &str) -> bool {
    let Ok(entries) = fs::read_dir(staging_path) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(MEMBERS_DIR_PREFIX.as_bytes())
            && entry.file_type().is_ok_and(|file_type| file_type.is_dir())
            && fs::symlink_metadata(entry.path().join(name)).is_ok()
    })
}

/// Removes stale finalize debris (`artifact.partial` and
/// `artifact.partial.tmp-*`) from every `members-*` directory.
///
/// This runs only when `artifact.unsigned` is present, i.e. before a fresh
/// finalize. A symlink or non-regular entry is refused instead of followed; an
/// unremovable entry fails closed so the next step never builds on debris.
fn remove_stale_finalize_outputs(staging_path: &Path) -> Result<(), ArtifactFailure> {
    let entries = fs::read_dir(staging_path)
        .map_err(|_| ArtifactFailure::rejected("staged-artifact-invalid"))?;
    for entry in entries.filter_map(Result::ok) {
        if !entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(MEMBERS_DIR_PREFIX.as_bytes())
            || !entry.file_type().is_ok_and(|file_type| file_type.is_dir())
        {
            continue;
        }
        let directory = entry.path();
        let Ok(files) = fs::read_dir(&directory) else {
            continue;
        };
        for file in files.filter_map(Result::ok) {
            let name = file.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name != STAGED_SIGNED_ARTIFACT_NAME && !name.starts_with(SIGNED_ARTIFACT_TEMP_PREFIX)
            {
                continue;
            }
            let metadata = fs::symlink_metadata(file.path())
                .map_err(|_| ArtifactFailure::rejected("staged-artifact-invalid"))?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(ArtifactFailure::rejected("staged-artifact-invalid"));
            }
            fs::remove_file(file.path())
                .map_err(|_| ArtifactFailure::recoverable("staged-artifact-cleanup-failed"))?;
        }
    }
    Ok(())
}

/// Opens the unique `members-*/artifact.partial` with `O_NOFOLLOW` and
/// `fstat`s the descriptor, so a symlink or non-regular entry is never read.
fn open_staged_signed_artifact(
    staging_path: &Path,
) -> Result<(std::ffi::OsString, fs::File), String> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir(staging_path)
        .map_err(|_| "staged signing request has no unique unsigned artifact".to_owned())?
    {
        let entry = entry.map_err(|_| "backup staging entry is unavailable".to_owned())?;
        let file_name = entry.file_name();
        if !file_name
            .as_encoded_bytes()
            .starts_with(MEMBERS_DIR_PREFIX.as_bytes())
        {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|_| "backup staging entry is unavailable".to_owned())?;
        if !file_type.is_dir() {
            continue;
        }
        let directory = open(
            entry.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| "staged artifact directory is unavailable".to_owned())?;
        match openat(
            &directory,
            STAGED_SIGNED_ARTIFACT_NAME,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => {
                let metadata =
                    fstat(&descriptor).map_err(|_| "staged artifact is unavailable".to_owned())?;
                if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
                    return Err("staged artifact is not a regular file".to_owned());
                }
                candidates.push((file_name, fs::File::from(descriptor)));
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(rustix::io::Errno::LOOP) => {
                return Err("staged artifact is a symbolic link".to_owned());
            }
            Err(_) => return Err("staged artifact is unavailable".to_owned()),
        }
    }
    if candidates.len() != 1 {
        return Err("staged signing request has no unique signed artifact".to_owned());
    }
    let (members_leaf, file) = candidates.remove(0);
    Ok((members_leaf, file))
}

/// Atomic no-replace publication through the retained destination descriptor.
///
/// The exact verified inode is linked into the destination and then the staged
/// name is removed. An existing final entry is never replaced; if it already
/// holds the expected artifact, publication is classified complete. The
/// destination check hashes through the descriptor it opened `O_NOFOLLOW`, so a
/// symlink is never followed.
fn publish(
    destination_fd: &OwnedFd,
    staging_leaf: &str,
    members_leaf: &std::ffi::OsStr,
    staged: &fs::File,
    final_name: &str,
    expected_sha256: &str,
) -> Result<(), ArtifactFailure> {
    if final_name.is_empty() || final_name.contains('/') {
        return Err(ArtifactFailure::rejected("artifact-name-invalid"));
    }
    if let Some(existing) = existing_destination(destination_fd, final_name)? {
        let (_, existing_sha256) = hash_fd(&existing)
            .map_err(|_| ArtifactFailure::unknown("destination-artifact-unreadable"))?;
        if existing_sha256 == expected_sha256 {
            return Ok(());
        }
        return Err(ArtifactFailure::rejected("artifact-destination-exists"));
    }
    let staging_fd = openat(
        destination_fd,
        staging_leaf,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ArtifactFailure::unknown("staged-artifact-unavailable"))?;
    let members_fd = openat(
        &staging_fd,
        members_leaf,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ArtifactFailure::unknown("staged-artifact-unavailable"))?;
    match link_staged_inode(staged, destination_fd, final_name) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            // Raced with another publisher: only an identical artifact is
            // acceptable, and it is already durable.
            let Some(existing) = existing_destination(destination_fd, final_name)? else {
                return Err(ArtifactFailure::recoverable("publication-failed"));
            };
            let (_, existing_sha256) = hash_fd(&existing)
                .map_err(|_| ArtifactFailure::unknown("destination-artifact-unreadable"))?;
            if existing_sha256 == expected_sha256 {
                return Ok(());
            }
            return Err(ArtifactFailure::rejected("artifact-destination-exists"));
        }
        Err(_) => return Err(ArtifactFailure::recoverable("publication-failed")),
    }
    match unlinkat(&members_fd, STAGED_SIGNED_ARTIFACT_NAME, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(_) => return Err(ArtifactFailure::unknown("staged-artifact-unlink-failed")),
    }
    fsync(destination_fd).map_err(|_| ArtifactFailure::unknown("publication-sync-failed"))?;
    Ok(())
}

/// Returns the open destination entry when `final_name` already exists.
///
/// A symlink or other non-regular entry is a rejected precondition
/// (`artifact-destination-exists`, exit 2), never a file to hash through a
/// path and never an unknown outcome. A regular entry must be `0600` and owned
/// by the effective uid (`artifact-destination-posture-invalid`, exit 2).
fn existing_destination(
    destination_fd: &OwnedFd,
    final_name: &str,
) -> Result<Option<fs::File>, ArtifactFailure> {
    match openat(
        destination_fd,
        final_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => {
            let metadata = fstat(&descriptor)
                .map_err(|_| ArtifactFailure::unknown("destination-artifact-unreadable"))?;
            if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
                return Err(ArtifactFailure::rejected("artifact-destination-exists"));
            }
            let expected_uid = geteuid().as_raw();
            if metadata.st_uid != expected_uid || metadata.st_mode & 0o777 != 0o600 {
                return Err(ArtifactFailure::rejected(
                    "artifact-destination-posture-invalid",
                ));
            }
            Ok(Some(fs::File::from(descriptor)))
        }
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(rustix::io::Errno::LOOP) => {
            Err(ArtifactFailure::rejected("artifact-destination-exists"))
        }
        Err(_) => Err(ArtifactFailure::unknown("destination-artifact-unreadable")),
    }
}

/// Links the exact inode behind `staged` into the destination.
///
/// `AT_EMPTY_PATH` is the direct form. Kernels/userspaces that refuse it
/// (notably without `CAP_DAC_READ_SEARCH`) fall back to this process's own
/// `/proc/self/fd/<n>` magic link with `AT_SYMLINK_FOLLOW`; the kernel resolves
/// that against the descriptor we hold, so no path component is swappable.
fn link_staged_inode(
    staged: &fs::File,
    destination_fd: &OwnedFd,
    final_name: &str,
) -> rustix::io::Result<()> {
    match linkat(staged, "", destination_fd, final_name, AtFlags::EMPTY_PATH) {
        Ok(()) => Ok(()),
        Err(
            rustix::io::Errno::PERM
            | rustix::io::Errno::NOENT
            | rustix::io::Errno::INVAL
            | rustix::io::Errno::OPNOTSUPP,
        ) => {
            let proc_path = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(staged));
            linkat(
                rustix::fs::CWD,
                proc_path.as_str(),
                destination_fd,
                final_name,
                AtFlags::SYMLINK_FOLLOW,
            )
        }
        Err(error) => Err(error),
    }
}

/// Streams a descriptor into SHA-256. The descriptor is duplicated so the
/// caller's handle (and any later `linkat`) is unaffected.
fn hash_fd(fd: &impl AsFd) -> std::io::Result<(u64, String)> {
    use std::io::Seek;
    let mut file = fs::File::from(fd.as_fd().try_clone_to_owned()?);
    file.seek(std::io::SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("size overflow"))?;
        digest.update(&buffer[..read]);
    }
    Ok((size, hex::encode(digest.finalize())))
}

/// Detached signing request persisted for the offline custodian.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    pub format: String,
    pub operation_id: Uuid,
    pub backup_id: String,
    pub manifest_digest: String,
    pub signing_input_sha256: String,
    /// Base64url (unpadded) of the exact D1 signing input. It is public
    /// artifact metadata; the digest above binds it to the request.
    pub signing_input_base64url: String,
    pub key_id: String,
    pub site_id: String,
    pub installation_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub payload_sha256: String,
    /// Lowercase hex SHA-256 of the configured X25519 recipient public key.
    ///
    /// The custodian compares this with the trusted trust document; the frozen
    /// v1 artifact manifest does not bind the recipient public key, so this is
    /// the operator-visible substitution check.
    pub recipient_public_key_sha256: String,
}

/// Detached signing response produced on the offline workstation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningResponse {
    pub format: String,
    pub request_sha256: String,
    pub key_id: String,
    /// 128 lowercase hex characters (64-byte Ed25519 signature).
    pub signature: String,
    pub signed_at: String,
}

struct RequestExpectations<'a> {
    operation_id: Uuid,
    backup_id: &'a str,
    key_id: &'a str,
    site_id: &'a str,
    installation_id: &'a str,
    payload_sha256: Option<&'a str>,
    recipient_public_key_sha256: &'a str,
}

/// Validates a signing request against the local operation and returns the
/// decoded signing input. Expiry is a recoverable failure: the staged artifact
/// is kept, and the operator must start a new operation.
fn validate_signing_request(
    request: &SigningRequest,
    expected: &RequestExpectations<'_>,
) -> Result<Vec<u8>, ArtifactFailure> {
    validate_signing_request_with_expiry(request, expected, true)
}

/// [`validate_signing_request`] with expiry enforcement optional.
///
/// The staged crash-recovery path must bind an already signed partial to its
/// request even when the request TTL has since elapsed: the signature was made
/// inside the TTL and rejecting it after the fact would strand a valid
/// publication. Normal phase 2 always enforces expiry.
fn validate_signing_request_with_expiry(
    request: &SigningRequest,
    expected: &RequestExpectations<'_>,
    enforce_expiry: bool,
) -> Result<Vec<u8>, ArtifactFailure> {
    if request.format != SIGNING_REQUEST_FORMAT
        || request.operation_id != expected.operation_id
        || request.backup_id != expected.backup_id
        || request.key_id != expected.key_id
        || request.site_id != expected.site_id
        || request.installation_id != expected.installation_id
        || expected
            .payload_sha256
            .is_some_and(|digest| digest != request.payload_sha256)
        || request.recipient_public_key_sha256 != expected.recipient_public_key_sha256
    {
        return Err(ArtifactFailure::rejected("signing-request-mismatch"));
    }
    for digest in [
        &request.manifest_digest,
        &request.signing_input_sha256,
        &request.payload_sha256,
        &request.recipient_public_key_sha256,
    ] {
        if !is_sha256(digest) {
            return Err(ArtifactFailure::rejected("signing-request-invalid"));
        }
    }
    if DateTime::parse_from_rfc3339(&request.created_at).is_err() {
        return Err(ArtifactFailure::rejected("signing-request-invalid"));
    }
    let expires_at = DateTime::parse_from_rfc3339(&request.expires_at)
        .map_err(|_| ArtifactFailure::rejected("signing-request-invalid"))?;
    let signing_input = URL_SAFE_NO_PAD
        .decode(&request.signing_input_base64url)
        .map_err(|_| ArtifactFailure::rejected("signing-request-invalid"))?;
    if hex::encode(Sha256::digest(&signing_input)) != request.signing_input_sha256 {
        return Err(ArtifactFailure::rejected("signing-request-invalid"));
    }
    if enforce_expiry && expires_at <= Utc::now() {
        return Err(ArtifactFailure::recoverable("signing-request-expired"));
    }
    Ok(signing_input)
}

/// Loads and validates the persisted signing request for the staged recovery
/// branch, returning the request and its decoded D1 input.
///
/// Every problem (missing file, digest mismatch, malformed or stale identity)
/// is the same rejected `signing-request-mismatch` reason and leaves the
/// staging tree untouched.
fn load_recovery_signing_request(
    inputs: &CompletionInputs<'_>,
    staging_path: &Path,
) -> Result<(SigningRequest, Vec<u8>), ArtifactFailure> {
    let request_path = staging_path.join(SIGNING_REQUEST_FILE);
    let request_bytes = read_bounded_file(&request_path, MAX_SIGNING_REQUEST_BYTES)
        .map_err(|_| ArtifactFailure::rejected("signing-request-mismatch"))?;
    let request_sha256 = hex::encode(Sha256::digest(&request_bytes));
    if inputs.record.request_sha256.as_deref() != Some(request_sha256.as_str()) {
        return Err(ArtifactFailure::rejected("signing-request-mismatch"));
    }
    let request: SigningRequest = serde_json::from_slice(&request_bytes)
        .map_err(|_| ArtifactFailure::rejected("signing-request-mismatch"))?;
    let backup_id = inputs.operation_id.to_string();
    let expectations = RequestExpectations {
        operation_id: inputs.operation_id,
        backup_id: &backup_id,
        key_id: inputs.config.signing_key_id(),
        site_id: inputs.config.site_id(),
        installation_id: inputs.config.installation_id(),
        payload_sha256: None,
        recipient_public_key_sha256: inputs.config.recipient_public_key_sha256(),
    };
    let signing_input = validate_signing_request_with_expiry(&request, &expectations, false)
        .map_err(|_| ArtifactFailure::rejected("signing-request-mismatch"))?;
    Ok((request, signing_input))
}

/// Requires a signed manifest to be the one the persisted request described.
///
/// This binds the unsigned-manifest digest and the exact D1 signing input, so
/// a validly signed artifact from a different request or manifest cannot be
/// substituted into another operation's staging tree.
fn bind_signed_artifact_to_request(
    manifest: &Manifest,
    request: &SigningRequest,
    request_signing_input: &[u8],
) -> Result<(), ArtifactFailure> {
    let manifest_digest = unsigned_manifest_digest(manifest)
        .map_err(|_| ArtifactFailure::rejected("signing-request-mismatch"))?;
    let signed_input = manifest_signing_input(manifest)
        .map_err(|_| ArtifactFailure::rejected("signing-request-mismatch"))?;
    if manifest_digest != request.manifest_digest
        || signed_input != request_signing_input
        || hex::encode(Sha256::digest(&signed_input)) != request.signing_input_sha256
        || manifest.backup_id != request.backup_id
    {
        return Err(ArtifactFailure::rejected("signing-request-mismatch"));
    }
    Ok(())
}

/// Validates a detached signing response and verifies the signature over the
/// exact signing input with the configured trust key.
fn verify_signing_response(
    response_bytes: &[u8],
    request_sha256: &str,
    key_id: &str,
    signing_input: &[u8],
    verifying_key: &VerifyingKey,
    created_at: &str,
    expires_at: &str,
) -> Result<[u8; 64], ArtifactFailure> {
    let response: SigningResponse = serde_json::from_slice(response_bytes)
        .map_err(|_| ArtifactFailure::rejected("signing-response-invalid"))?;
    if response.format != SIGNING_RESPONSE_FORMAT
        || response.request_sha256 != request_sha256
        || response.key_id != key_id
    {
        return Err(ArtifactFailure::rejected("signing-response-mismatch"));
    }
    let signed_at = DateTime::parse_from_rfc3339(&response.signed_at)
        .map_err(|_| ArtifactFailure::rejected("signing-response-invalid"))?;
    // The signature must have been produced inside the request's lifetime.
    // Both bounds are host-clock based (the request records when the snapshot
    // completed and the fixed TTL); this is not HSM time attestation.
    let created_at = DateTime::parse_from_rfc3339(created_at)
        .map_err(|_| ArtifactFailure::rejected("signing-request-invalid"))?;
    let expires_at = DateTime::parse_from_rfc3339(expires_at)
        .map_err(|_| ArtifactFailure::rejected("signing-request-invalid"))?;
    if signed_at < created_at || signed_at > expires_at {
        return Err(ArtifactFailure::rejected(
            "signing-response-clock-inconsistent",
        ));
    }
    if response.signature.len() != 128
        || !response
            .signature
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ArtifactFailure::rejected("signing-response-invalid"));
    }
    let signature_bytes = hex::decode(&response.signature)
        .map_err(|_| ArtifactFailure::rejected("signing-response-invalid"))?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| ArtifactFailure::rejected("signing-response-invalid"))?;
    verifying_key
        .verify(signing_input, &Signature::from_bytes(&signature))
        .map_err(|_| ArtifactFailure::rejected("signature-invalid"))?;
    Ok(signature)
}

fn signing_expiry(completed_at: &str) -> Result<String, ArtifactFailure> {
    let completed = DateTime::parse_from_rfc3339(completed_at)
        .map_err(|_| ArtifactFailure::rejected("snapshot-timestamp-invalid"))?;
    Ok(completed
        .with_timezone(&Utc)
        .checked_add_signed(SIGNING_REQUEST_TTL)
        .ok_or(ArtifactFailure::rejected("snapshot-timestamp-invalid"))?
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Stable artifact file name for one operation.
#[must_use]
pub fn artifact_file_name(backup_id: &str) -> String {
    format!("{ARTIFACT_FILE_PREFIX}{backup_id}{ARTIFACT_FILE_SUFFIX}")
}

/// Staging directory leaf name for one operation.
#[must_use]
pub fn staging_leaf(operation_id: Uuid) -> String {
    format!("{OPERATION_STAGING_PREFIX}{operation_id}")
}

/// Canonical staging path for one operation inside `destination`.
pub fn destination_staging_path(
    destination: &Path,
    operation_id: Uuid,
) -> Result<PathBuf, ArtifactFailure> {
    let canonical = fs::canonicalize(destination)
        .map_err(|_| ArtifactFailure::rejected("destination-unavailable"))?;
    Ok(canonical.join(staging_leaf(operation_id)))
}

fn validate_staging_directory(
    destination_dir: &Path,
    staging_path: &Path,
    expected_leaf: &str,
) -> Result<(), ArtifactFailure> {
    if staging_path.parent() != Some(destination_dir)
        || staging_path.file_name().and_then(|name| name.to_str()) != Some(expected_leaf)
    {
        return Err(ArtifactFailure::rejected("operation-staging-path-mismatch"));
    }
    let metadata = fs::symlink_metadata(staging_path)
        .map_err(|_| ArtifactFailure::rejected("operation-staging-unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ArtifactFailure::rejected("operation-staging-not-directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != 0 && metadata.uid() != uid {
            return Err(ArtifactFailure::rejected(
                "operation-staging-owner-untrusted",
            ));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(ArtifactFailure::rejected(
                "operation-staging-permissions-too-open",
            ));
        }
    }
    Ok(())
}

fn capture_record_bytes(inputs: &CaptureInputs<'_>) -> Result<Vec<u8>, ArtifactFailure> {
    let record = json!({
        "format": CAPTURE_RECORD_FORMAT,
        "operation_id": operation_id_for(inputs),
        "backup_id": backup_id_for(inputs),
        "quiescence_generation": quiescence_generation(inputs),
        "snapshot_started_at": inputs.snapshot_started_at,
        "snapshot_completed_at": inputs.snapshot_completed_at,
        "source_db_sha256_before": inputs.source_before,
        "source_db_sha256_after": inputs.source_after,
        "snapshot_sha256": inputs.snapshot_sha256,
        "journal_mode": inputs.journal_mode,
        "in_flight_operations": {
            "classification": inputs.in_flight_operations,
            "operation_ids": inputs.in_flight_operation_ids,
        },
        "reservation": {
            "source_bytes": inputs.reservation.source_bytes,
            "reserved_bytes": inputs.reservation.reserved_bytes,
        },
        "cli_version": env!("CARGO_PKG_VERSION"),
        "provisional": false,
    });
    let bytes = serde_json::to_vec(&record)
        .map_err(|_| ArtifactFailure::rejected("capture-record-encoding-failed"))?;
    if bytes.len() as u64 > MAX_METADATA_MEMBER_BYTES {
        return Err(ArtifactFailure::rejected("capture-record-too-large"));
    }
    Ok(bytes)
}

fn backup_id_for(inputs: &CaptureInputs<'_>) -> String {
    inputs.operation_id.to_string()
}

fn operation_id_for(inputs: &CaptureInputs<'_>) -> Uuid {
    inputs.operation_id
}

/// Bounded read of an installation metadata member (no-follow final
/// component, regular file, trusted size).
fn read_bounded_private(path: &Path) -> Result<Vec<u8>, ArtifactFailure> {
    read_bounded_file(path, MAX_METADATA_MEMBER_BYTES)
        .map_err(|_| ArtifactFailure::rejected("metadata-member-unavailable"))
}

fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, std::io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds the bound",
        ));
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let metadata = fstat(&descriptor).map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if metadata.st_size > 0 && u64::try_from(metadata.st_size).unwrap_or(u64::MAX) > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds the bound",
        ));
    }
    let mut file = fs::File::from(descriptor);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds the bound",
        ));
    }
    Ok(bytes)
}

/// Writes a bounded JSON document with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600.
fn write_exclusive_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let descriptor = open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )?;
    let mut file = fs::File::from(descriptor);
    file.write_all(bytes)?;
    file.sync_all()
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    // `/proc/self/fd/<n>` is itself a magic symlink; the kernel resolves it
    // against the descriptor this process holds, so `O_NOFOLLOW` (which would
    // refuse the link itself) is only used for ordinary paths.
    let flags = if is_process_descriptor_path(path) {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC
    } else {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
    };
    let descriptor = open(path, flags, Mode::empty())?;
    fs::File::from(descriptor).sync_all()
}

/// True for the exact `/proc/self/fd/<digits>` form the executor builds from a
/// descriptor it holds.
fn is_process_descriptor_path(path: &Path) -> bool {
    path.parent() == Some(Path::new("/proc/self/fd"))
        && path.file_name().is_some_and(|name| {
            name.to_str()
                .is_some_and(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()))
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::backup_trust::site_and_installation_ids;
    use ed25519_dalek::{Signer, SigningKey};
    use hpke::{Kem, Serializable, kem::X25519HkdfSha256};

    const TRUST_FORMAT: &str = "o3k-backup-trust-v1";
    const SIGNING_KEY_ID: &str = "signing-1";
    const RECIPIENT_KEY_ID: &str = "recovery-1";

    struct Fixture {
        root: PathBuf,
        trust_config: PathBuf,
        install_prefix: PathBuf,
        signing: SigningKey,
        data_dir: PathBuf,
        site_id: String,
        installation_id: String,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn private_dir(path: &Path) {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path).expect("create private directory");
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write fixture file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("restrict fixture file");
        }
    }

    fn latest_sqlite_schema_version() -> u64 {
        let directory = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../crates/o3k-store/migrations"
        ));
        fs::read_dir(directory)
            .expect("migration directory")
            .filter_map(|entry| {
                let name = entry.ok()?.file_name();
                name.to_str()?.split('_').next()?.parse::<u64>().ok()
            })
            .max()
            .expect("at least one migration")
    }

    fn fixture() -> Fixture {
        let root = std::env::temp_dir().join(format!("o3k-pp6-artifact-{}", Uuid::now_v7()));
        private_dir(&root);
        let data_dir = root.join("data");
        private_dir(&data_dir);
        let signing = SigningKey::from_bytes(&[17_u8; 32]);
        let (recipient, _public) = <X25519HkdfSha256 as Kem>::gen_keypair();
        let recipient_key = root.join("recipient.key");
        write_private(&recipient_key, &recipient.to_bytes());
        let (site_id, installation_id) =
            site_and_installation_ids(&data_dir).expect("identity tokens");
        let public_key = signing.verifying_key().to_bytes();
        let trust_config = root.join("backup-trust.json");
        write_private(
            &trust_config,
            &serde_json::to_vec_pretty(&json!({
                "format": TRUST_FORMAT,
                "site_id": site_id,
                "installation_id": installation_id,
                "profile_id": "o3k-demo-v1",
                "artifact_signing": {
                    "key_id": SIGNING_KEY_ID,
                    "ed25519_public_key": hex::encode(public_key),
                },
                "recipient": {
                    "key_id": RECIPIENT_KEY_ID,
                    "x25519_private_key_file": recipient_key.display().to_string(),
                },
                "revoked_key_ids": [],
                "custody": {
                    "record_id": "custody-1",
                    "purpose": "artifact-signing",
                    "key_fingerprint": hex::encode(Sha256::digest(public_key)),
                    "threshold": "2-of-3",
                    "custodians": ["principal-a", "principal-b", "principal-c"],
                    "storage_class": "offline-safe",
                    "expires_at": "2035-01-01T00:00:00Z",
                },
            }))
            .expect("encode trust document"),
        );
        let install_prefix = root.join("install");
        let share = install_prefix.join("share/o3k");
        fs::create_dir_all(&share).expect("create install prefix");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // A production install is root-owned 0755 here; the ambient umask
            // must not make the release-manifest parent group-writable.
            for directory in [
                install_prefix.clone(),
                install_prefix.join("share"),
                share.clone(),
            ] {
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))
                    .expect("restrict install prefix");
            }
        }
        write_private(
            &share.join("release-manifest.json"),
            &serde_json::to_vec(&json!({
                "version": "0.4.0",
                "profile": "demo",
                "profile_id": "o3k-demo-v1",
                "source_commit": "0123456789abcdef0123456789abcdef01234567",
                "release_artifact_sha256": "a".repeat(64),
                "schema_version": latest_sqlite_schema_version().to_string(),
            }))
            .expect("encode release manifest"),
        );
        Fixture {
            root,
            trust_config,
            install_prefix,
            signing,
            data_dir,
            site_id,
            installation_id,
        }
    }

    fn request(operation_id: Uuid, expires_at: &str) -> SigningRequest {
        let signing_input = b"exact D1 signing input".to_vec();
        SigningRequest {
            format: SIGNING_REQUEST_FORMAT.to_owned(),
            operation_id,
            backup_id: operation_id.to_string(),
            manifest_digest: "b".repeat(64),
            signing_input_sha256: hex::encode(Sha256::digest(&signing_input)),
            signing_input_base64url: URL_SAFE_NO_PAD.encode(&signing_input),
            key_id: SIGNING_KEY_ID.to_owned(),
            site_id: "site-1".to_owned(),
            installation_id: "install-1".to_owned(),
            created_at: "2026-10-23T12:00:00Z".to_owned(),
            expires_at: expires_at.to_owned(),
            payload_sha256: "c".repeat(64),
            recipient_public_key_sha256: "e".repeat(64),
        }
    }

    fn expectations<'a>(operation_id: Uuid, backup_id: &'a str) -> RequestExpectations<'a> {
        RequestExpectations {
            operation_id,
            backup_id,
            key_id: SIGNING_KEY_ID,
            site_id: "site-1",
            installation_id: "install-1",
            payload_sha256: Some("c".repeat(64).leak()),
            recipient_public_key_sha256: "e".repeat(64).leak(),
        }
    }

    #[test]
    fn signing_request_validation_binds_identity_digests_and_expiry() {
        let operation_id = Uuid::new_v4();
        let backup_id = operation_id.to_string();
        let valid = request(operation_id, "2999-01-01T00:00:00Z");
        let input = validate_signing_request(&valid, &expectations(operation_id, &backup_id))
            .expect("valid request");
        assert_eq!(
            hex::encode(Sha256::digest(&input)),
            valid.signing_input_sha256
        );

        let expired = request(operation_id, "2020-01-01T00:00:00Z");
        let failure = validate_signing_request(&expired, &expectations(operation_id, &backup_id))
            .expect_err("expired request");
        assert_eq!(failure.reason(), "signing-request-expired");
        assert_eq!(failure.class(), ArtifactFailureClass::Recoverable);

        for field in 0..8 {
            let mut tampered = request(operation_id, "2999-01-01T00:00:00Z");
            match field {
                0 => tampered.operation_id = Uuid::new_v4(),
                1 => tampered.backup_id = "other-backup".to_owned(),
                2 => tampered.key_id = "signing-2".to_owned(),
                3 => tampered.site_id = "other-site".to_owned(),
                4 => tampered.installation_id = "other-installation".to_owned(),
                5 => tampered.payload_sha256 = "d".repeat(64),
                6 => tampered.recipient_public_key_sha256 = "f".repeat(64),
                _ => tampered.format = "o3k-backup-signing-request-v2".to_owned(),
            }
            let failure =
                validate_signing_request(&tampered, &expectations(operation_id, &backup_id))
                    .expect_err("tampered request");
            assert_eq!(
                failure.reason(),
                "signing-request-mismatch",
                "field {field}"
            );
        }

        let mut tampered = request(operation_id, "2999-01-01T00:00:00Z");
        tampered.signing_input_base64url = URL_SAFE_NO_PAD.encode(b"another input");
        let failure = validate_signing_request(&tampered, &expectations(operation_id, &backup_id))
            .expect_err("digest mismatch");
        assert_eq!(failure.reason(), "signing-request-invalid");

        let mut tampered = request(operation_id, "2999-01-01T00:00:00Z");
        tampered.manifest_digest = "A".repeat(64);
        let failure = validate_signing_request(&tampered, &expectations(operation_id, &backup_id))
            .expect_err("uppercase digest");
        assert_eq!(failure.reason(), "signing-request-invalid");
    }

    #[test]
    fn signing_response_is_bound_to_the_request_and_the_trust_key() {
        let signing_input = b"exact D1 signing input";
        let request_sha256 = "d".repeat(64);
        let key = SigningKey::from_bytes(&[17_u8; 32]);
        let response = json!({
            "format": SIGNING_RESPONSE_FORMAT,
            "request_sha256": request_sha256,
            "key_id": SIGNING_KEY_ID,
            "signature": hex::encode(key.sign(signing_input).to_bytes()),
            "signed_at": "2026-10-23T12:10:00Z",
        });
        let created_at = "2026-10-23T12:00:00Z";
        let expires_at = "2026-10-24T12:00:00Z";
        let bytes = serde_json::to_vec(&response).expect("encode response");
        let signature = verify_signing_response(
            &bytes,
            &request_sha256,
            SIGNING_KEY_ID,
            signing_input,
            &key.verifying_key(),
            created_at,
            expires_at,
        )
        .expect("valid response");
        assert_eq!(
            hex::encode(signature),
            response["signature"].as_str().expect("signature")
        );

        // Wrong request digest, wrong key id and a foreign signer all fail
        // closed with no signature accepted.
        let cases = [
            (
                "request_sha256",
                json!("e".repeat(64)),
                "signing-response-mismatch",
            ),
            ("key_id", json!("signing-2"), "signing-response-mismatch"),
            (
                "format",
                json!("o3k-backup-signing-response-v2"),
                "signing-response-mismatch",
            ),
            ("signature", json!("00".repeat(64)), "signature-invalid"),
            (
                "signature",
                json!("A".repeat(128)),
                "signing-response-invalid",
            ),
            ("signed_at", json!("not-a-time"), "signing-response-invalid"),
        ];
        for (field, value, reason) in cases {
            let mut tampered: Value = response.clone();
            tampered[field] = value;
            let bytes = serde_json::to_vec(&tampered).expect("encode response");
            let failure = verify_signing_response(
                &bytes,
                &request_sha256,
                SIGNING_KEY_ID,
                signing_input,
                &key.verifying_key(),
                created_at,
                expires_at,
            )
            .expect_err("tampered response");
            assert_eq!(failure.reason(), reason, "field {field}");
        }

        // A signature timestamp outside the request lifetime is rejected even
        // though the signature itself is valid: a custodian cannot backdate or
        // postdate approval outside the request window.
        for (signed_at, label) in [
            ("2026-10-23T11:59:59Z", "before creation"),
            ("2026-10-24T12:00:01Z", "after expiry"),
        ] {
            let mut tampered: Value = response.clone();
            tampered["signed_at"] = json!(signed_at);
            let bytes = serde_json::to_vec(&tampered).expect("encode response");
            assert_eq!(
                verify_signing_response(
                    &bytes,
                    &request_sha256,
                    SIGNING_KEY_ID,
                    signing_input,
                    &key.verifying_key(),
                    created_at,
                    expires_at,
                )
                .expect_err(label)
                .reason(),
                "signing-response-clock-inconsistent"
            );
        }

        // A signature from a different key never verifies.
        let foreign = SigningKey::from_bytes(&[18_u8; 32]);
        let mut tampered: Value = response;
        tampered["signature"] = json!(hex::encode(foreign.sign(signing_input).to_bytes()));
        let bytes = serde_json::to_vec(&tampered).expect("encode response");
        assert_eq!(
            verify_signing_response(
                &bytes,
                &request_sha256,
                SIGNING_KEY_ID,
                signing_input,
                &key.verifying_key(),
                created_at,
                expires_at,
            )
            .expect_err("foreign signature")
            .reason(),
            "signature-invalid"
        );
    }

    #[test]
    fn config_loads_the_installed_release_and_binds_the_data_directory() {
        let fixture = fixture();
        let config = ArtifactConfig::load_from(
            &fixture.data_dir,
            &fixture.trust_config,
            &fixture.install_prefix,
        )
        .expect("valid configuration");
        assert_eq!(config.site_id(), fixture.site_id);
        assert_eq!(config.installation_id(), fixture.installation_id);
        assert_eq!(config.profile_id(), "o3k-demo-v1");
        assert_eq!(config.signing_key_id(), SIGNING_KEY_ID);
        assert_eq!(config.recipient_key_id(), RECIPIENT_KEY_ID);
        assert_eq!(config.signing_key(), &fixture.signing.verifying_key());
        assert_eq!(config.release().source_sha.len(), 40);

        let failure = ArtifactConfig::load_from(
            &fixture.data_dir,
            &fixture.root.join("absent.json"),
            &fixture.install_prefix,
        )
        .expect_err("missing trust document");
        assert_eq!(failure.reason(), "trust-config-unavailable");

        let failure = ArtifactConfig::load_from(
            &fixture.data_dir,
            &fixture.trust_config,
            &fixture.root.join("absent-prefix"),
        )
        .expect_err("missing release manifest");
        assert_eq!(failure.reason(), "release-identity-unavailable");

        // A trust document copied from another installation fails closed.
        let other = fixture.root.join("other-data");
        private_dir(&other);
        let failure =
            ArtifactConfig::load_from(&other, &fixture.trust_config, &fixture.install_prefix)
                .expect_err("identity mismatch");
        assert_eq!(failure.reason(), "identity-mismatch");
    }

    #[test]
    fn snapshot_facts_read_store_identity_and_repository_emptiness() {
        let fixture = fixture();
        let snapshot = fixture.data_dir.join("o3k.sqlite");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime
            .block_on(o3k_store::testkit::open_file(&snapshot))
            .expect("migrated store");
        let schema_version = latest_sqlite_schema_version();
        let release = BackupReleaseIdentity {
            o3k_version: "0.4.0".to_owned(),
            source_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            release_artifact_sha256: "a".repeat(64),
            profile_id: "o3k-demo-v1".to_owned(),
            schema_version,
        };
        let facts = snapshot_facts(&runtime, &snapshot, &release).expect("snapshot facts");
        assert!(!facts.sqlite_version.is_empty());
        assert!(!facts.migrations.is_empty());
        assert_eq!(
            facts.migrations.last().map(|migration| migration.version),
            Some(schema_version)
        );
        assert!(
            facts
                .migrations
                .iter()
                .all(|migration| is_sha256(&migration.checksum))
        );
        let baseline = baseline_state_inventory().expect("baseline inventory");
        assert_eq!(facts.state_inventory.len(), baseline.len());
        assert!(facts.state_inventory.iter().all(|entry| {
            entry
                .get("empty_state_included")
                .and_then(Value::as_bool)
                .is_some()
        }));
        for entry in &facts.state_inventory {
            let repository = entry["repository_id"].as_str().expect("repository id");
            let expected_empty = repository != "release_and_install_metadata";
            assert_eq!(
                entry["empty_state_included"],
                Value::Bool(expected_empty),
                "repository {repository}"
            );
        }

        let mut stale = release.clone();
        stale.schema_version = 0;
        assert_eq!(
            snapshot_facts(&runtime, &snapshot, &stale)
                .expect_err("schema mismatch")
                .reason(),
            "migration-schema-mismatch"
        );
    }

    #[test]
    fn snapshot_catalog_rejects_an_extra_index() {
        assert_snapshot_catalog_fails(
            "CREATE INDEX extra_probe_idx ON resources(project_id)",
            "extra index",
        );
    }

    #[test]
    fn snapshot_catalog_rejects_an_extra_table() {
        assert_snapshot_catalog_fails(
            "CREATE TABLE extra_probe (id TEXT PRIMARY KEY)",
            "extra table",
        );
    }

    #[test]
    fn snapshot_catalog_rejects_a_changed_definition() {
        assert_snapshot_catalog_fails(
            "DROP INDEX resources_project_kind_idx;\n\
             CREATE INDEX resources_project_kind_idx ON resources(kind)",
            "redefined index",
        );
    }

    /// Opens a normally migrated snapshot, applies `ddl`, and requires
    /// `snapshot_facts` to fail closed with `store-catalog-mismatch` (exit 2)
    /// before any capture staging could start.
    fn assert_snapshot_catalog_fails(ddl: &str, label: &str) {
        let fixture = fixture();
        let snapshot = fixture.data_dir.join("o3k.sqlite");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        drop(
            runtime
                .block_on(o3k_store::testkit::open_file(&snapshot))
                .expect("migrated store"),
        );
        runtime.block_on(async {
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(SqliteConnectOptions::new().filename(&snapshot))
                .await
                .expect("snapshot writer");
            sqlx::raw_sql(ddl)
                .execute(&pool)
                .await
                .expect("catalog mutation");
            pool.close().await;
        });
        let release = BackupReleaseIdentity {
            o3k_version: "0.4.0".to_owned(),
            source_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            release_artifact_sha256: "a".repeat(64),
            profile_id: "o3k-demo-v1".to_owned(),
            schema_version: latest_sqlite_schema_version(),
        };
        let failure = snapshot_facts(&runtime, &snapshot, &release)
            .expect_err("catalog drift must fail closed");
        assert_eq!(failure.reason(), "store-catalog-mismatch", "{label}");
        assert_eq!(failure.class(), ArtifactFailureClass::Rejected, "{label}");
    }

    #[test]
    fn publication_is_no_replace_and_replay_safe() {
        let fixture = fixture();
        let destination = fixture.root.join("destination");
        private_dir(&destination);
        let destination_fd = open(
            &destination,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("destination descriptor");
        let operation_id = Uuid::new_v4();
        let staging_leaf = staging_leaf(operation_id);
        let staging = destination.join(&staging_leaf);
        private_dir(&staging);
        let members_leaf =
            std::ffi::OsString::from(format!("{MEMBERS_DIR_PREFIX}{}", Uuid::now_v7()));
        let members = staging.join(&members_leaf);
        private_dir(&members);
        let artifact = members.join("artifact.partial");
        let bytes = b"authenticated artifact bytes";
        write_private(&artifact, bytes);
        let digest = hex::encode(Sha256::digest(bytes));
        let final_name = artifact_file_name(&operation_id.to_string());

        let staged = open(
            &artifact,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(fs::File::from)
        .expect("staged descriptor");
        publish(
            &destination_fd,
            &staging_leaf,
            &members_leaf,
            &staged,
            &final_name,
            &digest,
        )
        .expect("publish");
        assert_eq!(
            fs::read(destination.join(&final_name)).expect("published"),
            bytes
        );
        assert!(!artifact.exists(), "publication removes the staged name");

        // A replay classifies the identical final artifact as already
        // published instead of failing or duplicating it.
        publish(
            &destination_fd,
            &staging_leaf,
            &members_leaf,
            &staged,
            &final_name,
            &digest,
        )
        .expect("idempotent replay");

        // A different artifact never replaces an existing one.
        let other_digest = hex::encode(Sha256::digest(b"another artifact"));
        let failure = publish(
            &destination_fd,
            &staging_leaf,
            &members_leaf,
            &staged,
            &final_name,
            &other_digest,
        )
        .expect_err("existing destination");
        assert_eq!(failure.reason(), "artifact-destination-exists");
        assert_eq!(
            fs::read(destination.join(&final_name)).expect("published"),
            bytes
        );

        // A publication name that could escape the destination is refused
        // before any filesystem operation.
        assert_eq!(
            publish(
                &destination_fd,
                &staging_leaf,
                &members_leaf,
                &staged,
                "backup-x/../../escaped.o3k",
                &digest,
            )
            .expect_err("escaping name")
            .reason(),
            "artifact-name-invalid"
        );
    }

    #[test]
    fn symlinked_staged_artifact_is_never_published() {
        let root = std::env::temp_dir().join(format!("o3k-pp6-symlink-{}", Uuid::now_v7()));
        private_dir(&root);
        let staging = root.join(".o3k-backup-artifact-op");
        private_dir(&staging);
        let members = staging.join(format!("{MEMBERS_DIR_PREFIX}{}", Uuid::now_v7()));
        private_dir(&members);
        let target = root.join("matching-content.o3k");
        write_private(&target, b"authenticated artifact bytes");
        std::os::unix::fs::symlink(&target, members.join("artifact.partial"))
            .expect("staged symlink");
        assert!(
            open_staged_signed_artifact(&staging).is_err(),
            "a symlinked staged artifact must never be opened for publication"
        );
        assert!(staged_signed_artifact_present(&staging));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn naming_and_prefix_resolution_are_stable() {
        assert_eq!(artifact_file_name("abc"), "backup-abc.o3k");
        let operation_id = Uuid::nil();
        assert_eq!(
            staging_leaf(operation_id),
            format!(".o3k-backup-artifact-{operation_id}")
        );
        let testlab = Path::new("/tmp/o3k-artifact-prefix-test");
        assert_eq!(
            crate::backup_trust::install_prefix_for(testlab, None),
            PathBuf::from(DEFAULT_INSTALL_PREFIX)
        );
        assert_eq!(
            crate::backup_trust::install_prefix_for(testlab, Some(std::ffi::OsString::new())),
            PathBuf::from(DEFAULT_INSTALL_PREFIX)
        );
        assert_eq!(
            crate::backup_trust::install_prefix_for(
                testlab,
                Some(std::ffi::OsString::from("/opt/o3k"))
            ),
            PathBuf::from("/opt/o3k")
        );
        assert_eq!(
            crate::backup_trust::install_prefix_for(
                Path::new("/var/lib/o3k"),
                Some(std::ffi::OsString::from("/opt/o3k"))
            ),
            PathBuf::from(DEFAULT_INSTALL_PREFIX)
        );
        assert_eq!(
            release_manifest_path(Path::new("/opt/o3k")),
            PathBuf::from("/opt/o3k/share/o3k/release-manifest.json")
        );
    }

    #[test]
    fn repository_table_mapping_covers_the_committed_baseline() {
        let inventory = baseline_state_inventory().expect("baseline inventory");
        assert!(!inventory.is_empty());
        for entry in &inventory {
            let tables = repository_tables(entry).expect("repository tables");
            assert!(!tables.is_empty());
            assert!(tables.iter().all(|table| is_table_identifier(table)));
        }
        assert!(!is_table_identifier("table; DROP TABLE x"));
        assert!(!is_table_identifier(""));
    }

    /// Creates a migrated SQLite store and returns its path.
    fn migrated_store(root: &Path) -> PathBuf {
        let data_dir = root.join("data");
        private_dir(&data_dir);
        let path = data_dir.join("o3k.sqlite");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(o3k_store::testkit::open_file(&path))
            .expect("migrated store");
        path
    }

    /// Seeds one durable resource and one Operation in `state`.
    fn seed_operation(store_path: &Path, state: &str) -> String {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let options = SqliteConnectOptions::new()
                    .filename(store_path)
                    .create_if_missing(false);
                let pool = SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect_with(options)
                    .await
                    .expect("seed connection");
                let resource_id = Uuid::now_v7().to_string();
                let operation_id = Uuid::now_v7().to_string();
                sqlx::query(
                    "INSERT INTO resources (id, kind, project_id, generation, observed_generation, desired_state, observed_state) VALUES (?1, 'network', 'project-1', 1, 1, '{}', '{}')",
                )
                .bind(&resource_id)
                .execute(&pool)
                .await
                .expect("seed resource");
                sqlx::query(
                    "INSERT INTO operations (id, resource_id, kind, state) VALUES (?1, ?2, 'create', ?3)",
                )
                .bind(&operation_id)
                .bind(&resource_id)
                .bind(state)
                .execute(&pool)
                .await
                .expect("seed operation");
                pool.close().await;
                operation_id
            })
    }

    #[test]
    fn snapshot_facts_reuse_the_verify_migration_mapping() {
        let root = std::env::temp_dir().join(format!("o3k-pp6-mapping-{}", Uuid::now_v7()));
        private_dir(&root);
        let store_path = migrated_store(&root);
        let fixture = fixture();
        let release = crate::upgrade::release_identity::BackupReleaseIdentity {
            o3k_version: "0.4.0".to_owned(),
            source_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            release_artifact_sha256: "a".repeat(64),
            profile_id: "o3k-demo-v1".to_owned(),
            schema_version: latest_sqlite_schema_version(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let facts = snapshot_facts(&runtime, &store_path, &release).expect("snapshot facts");
        let raw = runtime.block_on(async {
            let options = SqliteConnectOptions::new()
                .filename(&store_path)
                .create_if_missing(false)
                .read_only(true);
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(options)
                .await
                .expect("read connection");
            let rows: Vec<(i64, Vec<u8>)> =
                sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
                    .fetch_all(&pool)
                    .await
                    .expect("raw migrations");
            pool.close().await;
            rows
        });
        assert_eq!(raw.len(), facts.migrations.len());
        for (index, (version, checksum)) in raw.iter().enumerate() {
            assert_eq!(facts.migrations[index].version, *version as u64);
            // L3: capture and verify share one documented mapping.
            assert_eq!(
                facts.migrations[index].checksum,
                crate::backup_verify::migration_checksum(checksum),
                "migration {version}"
            );
        }
        assert_eq!(facts.in_flight_operations, "drained");
        assert!(facts.in_flight_operation_ids.is_empty());
        drop(fixture);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn non_terminal_operations_are_recorded_as_unknown() {
        let root = std::env::temp_dir().join(format!("o3k-pp6-inflight-{}", Uuid::now_v7()));
        private_dir(&root);
        let store_path = migrated_store(&root);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (classification, ids) =
            snapshot_in_flight_operations(&runtime, &store_path).expect("empty classification");
        assert_eq!(classification, "drained");
        assert!(ids.is_empty());

        let operation_id = seed_operation(&store_path, "running");
        let (classification, ids) =
            snapshot_in_flight_operations(&runtime, &store_path).expect("running classification");
        assert_eq!(classification, "recorded_unknown");
        assert_eq!(ids, vec![operation_id.clone()]);

        // Terminal states drain the classification again.
        runtime.block_on(async {
            let options = SqliteConnectOptions::new()
                .filename(&store_path)
                .create_if_missing(false);
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(options)
                .await
                .expect("write connection");
            sqlx::query("UPDATE operations SET state = 'succeeded' WHERE id = ?1")
                .bind(&operation_id)
                .execute(&pool)
                .await
                .expect("settle operation");
            pool.close().await;
        });
        let (classification, ids) =
            snapshot_in_flight_operations(&runtime, &store_path).expect("drained classification");
        assert_eq!(classification, "drained");
        assert!(ids.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    /// P1-4: the capture metadata member records the stable identities of the
    /// non-terminal Operations alongside the manifest classification.
    #[test]
    fn capture_records_in_flight_operation_identities() {
        let fixture = fixture();
        let config = ArtifactConfig::load_from(
            &fixture.data_dir,
            &fixture.trust_config,
            &fixture.install_prefix,
        )
        .expect("artifact configuration");
        let reservation = Reservation {
            source_bytes: 1234,
            reserved_bytes: 6 * 1024 * 1024 * 1024,
        };
        let operation_id = Uuid::new_v4();
        let ids = vec![
            "11111111-1111-4111-8111-111111111111".to_owned(),
            "22222222-2222-4222-8222-222222222222".to_owned(),
        ];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let staging = fixture.root.join("staging");
        private_dir(&staging);
        let snapshot = fixture.root.join("o3k.sqlite");
        write_private(&snapshot, b"snapshot");
        let inputs = CaptureInputs {
            config: &config,
            operation_id,
            reservation,
            staging_dir: &staging,
            durable_staging_dir: &staging,
            snapshot_path: &snapshot,
            snapshot_sha256: &"a".repeat(64),
            source_before: &"b".repeat(64),
            source_after: &"b".repeat(64),
            journal_mode: "wal",
            snapshot_started_at: "2026-10-24T00:00:00Z",
            snapshot_completed_at: "2026-10-24T00:00:05Z",
            in_flight_operations: "recorded_unknown",
            in_flight_operation_ids: &ids,
            runtime: &runtime,
        };
        let record: Value = serde_json::from_slice(&capture_record_bytes(&inputs).expect("record"))
            .expect("record JSON");
        assert_eq!(
            record["in_flight_operations"]["classification"],
            "recorded_unknown"
        );
        assert_eq!(
            record["in_flight_operations"]["operation_ids"]
                .as_array()
                .expect("ids")
                .len(),
            2
        );
        assert_eq!(record["in_flight_operations"]["operation_ids"][0], ids[0]);
        assert_eq!(
            record["reservation"]["reserved_bytes"],
            reservation.reserved_bytes
        );
        assert_eq!(record["provisional"], false);

        let drained = CaptureInputs {
            in_flight_operations: "drained",
            in_flight_operation_ids: &[],
            ..inputs
        };
        let record: Value =
            serde_json::from_slice(&capture_record_bytes(&drained).expect("record")).expect("json");
        assert_eq!(record["in_flight_operations"]["classification"], "drained");
        assert_eq!(
            record["in_flight_operations"]["operation_ids"]
                .as_array()
                .expect("ids")
                .len(),
            0
        );
    }

    /// F37: a non-regular entry at the final publication name is a rejected
    /// precondition, not an unknown outcome.
    #[test]
    fn destination_symlink_is_a_rejected_precondition() {
        let fixture = fixture();
        let destination = fixture.root.join("destination-symlink");
        private_dir(&destination);
        let destination_fd = open(
            &destination,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("destination descriptor");
        let target = fixture.root.join("outside");
        write_private(&target, b"outside");
        std::os::unix::fs::symlink(&target, destination.join("backup-x.o3k"))
            .expect("destination symlink");
        let failure = existing_destination(&destination_fd, "backup-x.o3k")
            .expect_err("a symlinked destination entry is refused");
        assert_eq!(failure.reason(), "artifact-destination-exists");
        assert_eq!(failure.class(), ArtifactFailureClass::Rejected);
        assert_eq!(fs::read(&target).expect("target"), b"outside");
    }

    /// A non-regular (directory) entry at the final name is classified the same
    /// way, so a retry reports a rejected precondition instead of exit 4.
    #[test]
    fn destination_directory_is_a_rejected_precondition() {
        let fixture = fixture();
        let destination = fixture.root.join("destination-directory");
        private_dir(&destination);
        let destination_fd = open(
            &destination,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("destination descriptor");
        private_dir(&destination.join("backup-x.o3k"));
        let failure = existing_destination(&destination_fd, "backup-x.o3k")
            .expect_err("a directory at the final name is refused");
        assert_eq!(failure.reason(), "artifact-destination-exists");
        assert_eq!(failure.class(), ArtifactFailureClass::Rejected);
    }

    #[test]
    fn destination_artifact_requires_owner_mode_and_never_blocks_on_a_fifo() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = fixture();
        let destination = fixture.root.join("destination-posture");
        private_dir(&destination);
        let destination_fd = open(
            &destination,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("destination descriptor");
        let artifact = destination.join("backup-x.o3k");
        write_private(&artifact, b"artifact");
        existing_destination(&destination_fd, "backup-x.o3k")
            .expect("0600 artifact")
            .expect("present");
        for mode in [0o644, 0o640, 0o600 | 0o010] {
            fs::set_permissions(&artifact, fs::Permissions::from_mode(mode))
                .expect("relax artifact mode");
            let failure = existing_destination(&destination_fd, "backup-x.o3k")
                .expect_err("unsafe destination posture");
            assert_eq!(failure.reason(), "artifact-destination-posture-invalid");
        }

        // A FIFO at the final name must be rejected immediately: the open is
        // O_NONBLOCK and the descriptor is checked with fstat.
        let fifo = destination.join("backup-fifo.o3k");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .expect("create fifo");
        let failure = existing_destination(&destination_fd, "backup-fifo.o3k")
            .expect_err("fifo is not an artifact");
        assert_eq!(failure.reason(), "artifact-destination-exists");
    }

    #[test]
    fn staged_recovery_binds_the_signed_manifest_to_the_persisted_request() {
        let manifest: Manifest = serde_json::from_value(json!({
            "format_version": "1",
            "backup_id": "operation-1",
            "created_at": "2026-10-19T12:00:00Z",
            "site_id": "site-1",
            "installation_id": "install-1",
            "source": {},
            "store": {},
            "consistency": {},
            "state_inventory": [],
            "members": [],
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_id": "artifact-1",
                "key_is_external": true,
                "key_wrapping": {
                    "algorithm": "HPKE-v1-X25519-HKDF-SHA256-AES-256-GCM",
                    "recipient_key_id": "recovery-1",
                    "enc": "",
                    "ciphertext": ""
                }
            },
            "authentication": {"algorithm": "Ed25519", "key_id": "signing-1", "signature": "sig"},
            "excluded_state": []
        }))
        .expect("manifest fixture");
        let signing_input = manifest_signing_input(&manifest).expect("D1 input");
        let matching = SigningRequest {
            format: SIGNING_REQUEST_FORMAT.to_owned(),
            operation_id: Uuid::nil(),
            backup_id: manifest.backup_id.clone(),
            manifest_digest: unsigned_manifest_digest(&manifest).expect("manifest digest"),
            signing_input_sha256: hex::encode(Sha256::digest(&signing_input)),
            signing_input_base64url: URL_SAFE_NO_PAD.encode(&signing_input),
            key_id: SIGNING_KEY_ID.to_owned(),
            site_id: "site-1".to_owned(),
            installation_id: "install-1".to_owned(),
            created_at: "2026-10-19T12:00:00Z".to_owned(),
            expires_at: "2999-01-01T00:00:00Z".to_owned(),
            payload_sha256: "c".repeat(64),
            recipient_public_key_sha256: "e".repeat(64),
        };
        bind_signed_artifact_to_request(&manifest, &matching, &signing_input)
            .expect("matching request");

        // A different operation/request and a different manifest cannot be
        // substituted, even though the artifact itself is validly signed.
        let mut different_request = matching.clone();
        different_request.operation_id = Uuid::new_v4();
        different_request.backup_id = different_request.operation_id.to_string();
        assert_eq!(
            bind_signed_artifact_to_request(&manifest, &different_request, &signing_input)
                .expect_err("different request")
                .reason(),
            "signing-request-mismatch"
        );
        let mut different_manifest = manifest.clone();
        different_manifest.created_at = "2026-10-20T12:00:00Z".to_owned();
        assert_eq!(
            bind_signed_artifact_to_request(&different_manifest, &matching, &signing_input)
                .expect_err("different manifest")
                .reason(),
            "signing-request-mismatch"
        );
    }

    /// F20: the per-operation staging lock admits exactly one invoker.
    #[test]
    fn operation_lock_is_exclusive_and_released_on_drop() {
        let root = std::env::temp_dir().join(format!("o3k-pp6-oplck-{}", Uuid::now_v7()));
        private_dir(&root);
        let first = OperationLock::acquire(&root).expect("first operation lock");
        let second = OperationLock::acquire(&root).expect_err("second lock must be refused");
        assert_eq!(second.reason(), "operation-busy");
        assert_eq!(second.class(), ArtifactFailureClass::Recoverable);
        drop(first);
        let reacquired = OperationLock::acquire(&root).expect("lock is free after drop");
        drop(reacquired);
        // A symlinked lock file is refused instead of followed.
        let outside = root.join("outside.lock");
        write_private(&outside, b"");
        fs::remove_file(root.join(OPERATION_LOCK_FILE)).expect("remove lock");
        std::os::unix::fs::symlink(&outside, root.join(OPERATION_LOCK_FILE)).expect("lock symlink");
        let failure = OperationLock::acquire(&root).expect_err("symlinked lock is refused");
        assert_eq!(failure.reason(), "operation-lock-unavailable");
        let _ = fs::remove_dir_all(&root);
    }

    fn operation_record(
        operation_id: Uuid,
        staging_path: &Path,
        destination: &Path,
    ) -> BackupOperationRecord {
        BackupOperationRecord {
            format: o3k_store::backup_journal::BACKUP_OPERATION_FORMAT.to_owned(),
            operation_id,
            phase: BackupOperationPhase::Publishing,
            backup_id: operation_id.to_string(),
            destination: destination.display().to_string(),
            staging_path: staging_path.display().to_string(),
            request_sha256: Some("a".repeat(64)),
            artifact_sha256: Some("b".repeat(64)),
            reserved_bytes: None,
            site_id: "site-1".to_owned(),
            installation_id: "install-1".to_owned(),
            created_at: "2026-10-23T12:00:00Z".to_owned(),
            updated_at: "2026-10-23T12:00:01Z".to_owned(),
        }
    }

    /// F19: a staging tree that cannot be removed after publication is an
    /// unknown outcome (exit 4), never success, and the marker is preserved so
    /// the operator still sees the failed cleanup.
    #[test]
    fn post_publication_staging_cleanup_failure_is_an_unknown_outcome() {
        let fixture = fixture();
        let config = ArtifactConfig::load_from(
            &fixture.data_dir,
            &fixture.trust_config,
            &fixture.install_prefix,
        )
        .expect("valid configuration");
        let destination = fixture.root.join("destination");
        private_dir(&destination);
        let destination_fd = open(
            &destination,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("destination descriptor");
        let marker = fixture.root.join("marker");
        write_private(&marker, b"marker");
        // A regular file where the staging directory should be: removing it as
        // a directory fails for root and non-root alike, so this does not
        // depend on the test runner's uid.
        let staging = fixture.root.join("staging-is-a-file");
        write_private(&staging, b"not a directory");
        let operation_id = Uuid::new_v4();
        let record = operation_record(operation_id, &staging, &destination);
        let inputs = CompletionInputs {
            data_dir: &fixture.data_dir,
            config: &config,
            destination_dir: &destination,
            destination_fd: &destination_fd,
            operation_id,
            record: &record,
            marker_path: &marker,
            reservation: Reservation {
                source_bytes: 0,
                reserved_bytes: 0,
            },
            await_policy: AwaitPolicy::default(),
        };

        let failure = finish_publication(&inputs, &staging)
            .expect_err("unremovable staging tree must not report success");
        assert_eq!(failure.reason(), "post-publication-cleanup-failed");
        assert_eq!(failure.class(), ArtifactFailureClass::Unknown);
        assert!(marker.is_file(), "the failure must not remove the marker");
    }

    /// F19: a marker that cannot be removed is `marker-removal-failed` (exit 4)
    /// even though the artifact itself was published.
    #[test]
    fn post_publication_marker_removal_failure_is_an_unknown_outcome() {
        let fixture = fixture();
        let config = ArtifactConfig::load_from(
            &fixture.data_dir,
            &fixture.trust_config,
            &fixture.install_prefix,
        )
        .expect("valid configuration");
        let destination = fixture.root.join("destination");
        private_dir(&destination);
        let destination_fd = open(
            &destination,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("destination descriptor");
        // A directory in place of the marker file: `remove_file` fails with
        // EISDIR for every uid, which exercises the typed failure branch.
        let marker = fixture.root.join("marker-is-a-directory");
        private_dir(&marker);
        let staging = fixture.root.join("already-removed-staging");
        let operation_id = Uuid::new_v4();
        let record = operation_record(operation_id, &staging, &destination);
        let inputs = CompletionInputs {
            data_dir: &fixture.data_dir,
            config: &config,
            destination_dir: &destination,
            destination_fd: &destination_fd,
            operation_id,
            record: &record,
            marker_path: &marker,
            reservation: Reservation {
                source_bytes: 0,
                reserved_bytes: 0,
            },
            await_policy: AwaitPolicy::default(),
        };

        let failure = finish_publication(&inputs, &staging)
            .expect_err("an unremovable marker must not report success");
        assert_eq!(failure.reason(), "marker-removal-failed");
        assert_eq!(failure.class(), ArtifactFailureClass::Unknown);
    }

    /// A non-atomically written response is retried instead of failing on the
    /// first partial read; it becomes `Unparsable` only at the deadline.
    #[test]
    #[allow(clippy::panic)]
    fn signing_wait_retries_a_partially_written_response() {
        let root = std::env::temp_dir().join(format!("o3k-pp6-wait-{}", Uuid::now_v7()));
        private_dir(&root);
        let path = root.join(SIGNING_RESPONSE_FILE);

        // A partial JSON document is not a response yet.
        write_private(&path, br#"{"format":"o3k-backup-signing-response-v1""#);
        let deadline = Utc::now() + Duration::milliseconds(120);
        match wait_for_signing_response(&path, &deadline, std::time::Duration::from_millis(10)) {
            SignatureWait::Unparsable => {}
            SignatureWait::Response(_) => panic!("partial JSON must not be accepted"),
            SignatureWait::Unreadable => panic!("partial JSON must be retried"),
            SignatureWait::TimedOut => panic!("an entry existed, so this is unparsable"),
        }

        // The completed file is accepted on the next attempt.
        let response = serde_json::to_vec(&json!({
            "format": SIGNING_RESPONSE_FORMAT,
            "request_sha256": "a".repeat(64),
            "key_id": SIGNING_KEY_ID,
            "signature": "0".repeat(128),
            "signed_at": "2026-10-23T12:10:00Z",
        }))
        .expect("encode response");
        write_private(&path, &response);
        let deadline = Utc::now() + Duration::seconds(5);
        match wait_for_signing_response(&path, &deadline, std::time::Duration::from_millis(10)) {
            SignatureWait::Response(bytes) => assert_eq!(bytes, response),
            SignatureWait::Unparsable => panic!("the completed response must parse"),
            SignatureWait::Unreadable => panic!("the response is a readable regular file"),
            SignatureWait::TimedOut => panic!("the response exists"),
        }

        // No entry at all is a timeout, not an unparsable response.
        fs::remove_file(&path).expect("remove response");
        let deadline = Utc::now() + Duration::milliseconds(60);
        match wait_for_signing_response(&path, &deadline, std::time::Duration::from_millis(10)) {
            SignatureWait::TimedOut => {}
            _ => panic!("a missing response must time out"),
        }
        let _ = fs::remove_dir_all(&root);
    }
}
