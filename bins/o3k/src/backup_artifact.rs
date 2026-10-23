//! Operator-usable PP.6 backup artifact driver (SPEC-0050 §8, ADR-0189 D2/D4/D8/D9/D12).
//!
//! This module turns the provisional capture from the handoff slice into a real
//! authenticated artifact, using the accepted **offline custody** signing flow
//! (Option A). The command boundary never sees the custody-held Ed25519 private
//! key, so artifact creation is a two-phase protocol over host-local files:
//!
//! 1. `o3k backup create --destination DIR --operation-id UUID` receives the
//!    authenticated handoff, captures a quiesced SQLite snapshot, stages the
//!    encrypted artifact with an unsigned manifest, writes
//!    `<destination>/.o3k-backup-artifact-<operation>/.signing-request.json`,
//!    records the operation in `<data_dir>/backup-operations/`, removes the
//!    denial-only marker (capture is complete; publication is pending and is
//!    *not* canonical state), and exits 3 with `signing-required`.
//! 2. The operator consumes the signing request on the offline workstation,
//!    signs the exact D1 signing input under the configured custody process,
//!    and writes `signing-response.json` next to the request.
//! 3. The **same** command (`--destination` and `--operation-id` unchanged) is
//!    re-run: a staged signing request for that operation id is detected before
//!    any controller contact, the detached signature is verified against the
//!    configured trust document, the artifact is finished, published under
//!    `<destination>/backup-<backup_id>.o3k` with an atomic no-replace rename,
//!    and the command exits 0. Without the response it exits 3
//!    `signing-required` again — the retry is idempotent and costs no capture.
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
//!
//! # Configuration
//!
//! Everything is loaded from root-owned installation configuration after the
//! store-access lock has been received and before the capture begins:
//!
//! * `O3K_BACKUP_TRUST_CONFIG` (else `<O3K_INSTALL_PREFIX>/etc/o3k/backup-trust.json`,
//!   else `/etc/o3k/backup-trust.json`): site/installation identity, profile,
//!   artifact-signing key id/public key, custody record and the recovery
//!   recipient key path.
//! * `<O3K_INSTALL_PREFIX>/share/o3k/release-manifest.json` (prefix defaults to
//!   `/usr/local`): the exact release identity (`o3k_version`, `source_sha`,
//!   `release_artifact_sha256`, `profile_id`, `schema_version`).
//!
//! The trust document must bind the canonical site/installation identities
//! derived from the data directory; a copied document fails closed with
//! `identity-mismatch`. The recipient public key is derived from the configured
//! X25519 private key file, so the document cannot wrap artifacts for a
//! recipient it does not name.
//!
//! # Manifest population
//!
//! * `database/o3k.sqlite` — the quiesced snapshot from
//!   `SqliteStore::backup_to_file` (member bytes are the snapshot file).
//! * `metadata/capture.json` — bounded capture provenance (source hashes,
//!   snapshot hash, journal mode, D9 measurements, CLI version). This is
//!   provenance, not canonical state.
//! * `release/release-manifest.json` — the installed release manifest the
//!   identity was read from.
//! * `trust/backup-trust.json` — the trust document (public keys and the
//!   recipient key *path*; it contains no private key material).
//!
//! `store.migrations` comes from the **snapshot's** `_sqlx_migrations`: the
//! `checksum` field is the lowercase hex SHA-256 of the raw 48-byte SQLx
//! checksum blob. `store.server_version` is `SELECT sqlite_version()` on the
//! snapshot. `store.schema_version` is the release's declared maximum migration
//! prefix, and capture fails closed if the snapshot's newest migration does not
//! match it.
//!
//! `state_inventory` is `o3k_store::state_inventory::baseline_state_inventory()`
//! with `empty_state_included` computed per repository from the snapshot
//! (`EXISTS(SELECT 1 FROM t)` for every table the repository owns; true means
//! every table is empty).
//!
//! `consistency.in_flight_operations` is `drained`: the daemon only transfers
//! the store lock after the writer/worker drain proved quiescence, so no
//! operation is in flight or classified unknown at capture time.
//!
//! # Journal
//!
//! `<data_dir>/backup-operations/<operation_id>.json` records
//! `capturing → captured → staged → publishing → published` (or `aborted`) via
//! [`o3k_store::backup_journal`]. The journal is durable operation metadata, not
//! canonical state: `staged`/`publishing` never deny controller startup. Only
//! `published` is used to refuse a *new* capture under the same operation id.
//!
//! # Publication
//!
//! The finished artifact is renamed into the destination through the retained
//! destination descriptor with `RENAME_NOREPLACE`; an existing final artifact
//! is never replaced. If the final artifact already exists with the expected
//! digest (a crash after the rename, before the journal update), publication is
//! classified complete instead of duplicated.
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
    state_inventory::baseline_state_inventory,
};
use rustix::{
    fd::OwnedFd,
    fs::{Mode, OFlags, RenameFlags, fstat, fsync, open, openat, renameat_with},
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
        ArtifactTrust, CreateOptions, MigrationIdentity, StreamMember, finish_signed_artifact,
        read_unsigned_staged_artifact, stage_unsigned_artifact,
    },
    backup_reservation::Reservation,
    backup_trust::{
        BackupTrustConfig, BackupTrustError, INSTALL_PREFIX_ENV, default_trust_config_path,
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
/// Versioned signing-request format marker.
pub const SIGNING_REQUEST_FORMAT: &str = "o3k-backup-signing-request-v1";
/// Versioned signing-response format marker.
pub const SIGNING_RESPONSE_FORMAT: &str = "o3k-backup-signing-response-v1";
/// Versioned capture-record member format marker.
pub const CAPTURE_RECORD_FORMAT: &str = "o3k-backup-capture-record-v1";
/// `encryption.key_id` of the artifact content key (the key itself is a
/// per-artifact random key wrapped to the recipient, never a stored key).
pub const ARTIFACT_CONTENT_KEY_ID: &str = "artifact-content-key-v1";
/// Default installation prefix when `O3K_INSTALL_PREFIX` is unset.
pub const DEFAULT_INSTALL_PREFIX: &str = "/usr/local";
/// How long an offline signing request remains acceptable.
pub const SIGNING_REQUEST_TTL: Duration = Duration::hours(24);

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
const MAX_METADATA_MEMBER_BYTES: u64 = 1024 * 1024;

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
        Self::rejected(error.reason())
    }
}

/// Validated installation configuration for one artifact.
#[derive(Debug)]
pub struct ArtifactConfig {
    trust: BackupTrustConfig,
    release: BackupReleaseIdentity,
    signing_key: VerifyingKey,
    recipient_public_key: [u8; 32],
    site_id: String,
    installation_id: String,
    trust_config_path: PathBuf,
    release_manifest_path: PathBuf,
}

impl ArtifactConfig {
    /// Loads the trust document and the installed release identity and checks
    /// they describe this data directory.
    pub fn load(data_dir: &Path) -> Result<Self, ArtifactFailure> {
        Self::load_from(data_dir, &default_trust_config_path(), &install_prefix())
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
            .map_err(|_| ArtifactFailure::rejected("release-identity-unavailable"))?;
        if release.profile_id != trust.profile_id() {
            return Err(ArtifactFailure::rejected("release-profile-mismatch"));
        }
        let signing_key = trust.artifact_signing_public_key()?;
        let recipient_public_key = trust.recipient_public_key()?;
        let (site_id, installation_id) = site_and_installation_ids(data_dir)
            .map_err(|_| ArtifactFailure::rejected("identity-unavailable"))?;
        Ok(Self {
            trust,
            release,
            signing_key,
            recipient_public_key,
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

    /// X25519 recipient public key derived from the custody key file.
    #[must_use]
    pub fn recipient_public_key(&self) -> [u8; 32] {
        self.recipient_public_key
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

/// Resolves the installation prefix the same way the trust-document default
/// path does (`O3K_INSTALL_PREFIX`, else `/usr/local`).
#[must_use]
pub fn install_prefix() -> PathBuf {
    install_prefix_from(std::env::var_os(INSTALL_PREFIX_ENV))
}

fn install_prefix_from(value: Option<std::ffi::OsString>) -> PathBuf {
    value
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_INSTALL_PREFIX))
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
            checksum: hex::encode(Sha256::digest(&checksum)),
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
    Ok(SnapshotFacts {
        sqlite_version,
        migrations,
        state_inventory: inventory,
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
            "in_flight_operations": "drained",
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
    };
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|_| ArtifactFailure::rejected("request-encoding-failed"))?;
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

/// Inputs for phase 2 (verify the detached signature and publish).
pub struct CompletionInputs<'a> {
    pub data_dir: &'a Path,
    pub config: &'a ArtifactConfig,
    pub destination_dir: &'a Path,
    pub destination_fd: &'a OwnedFd,
    pub operation_id: Uuid,
    pub record: &'a BackupOperationRecord,
}

/// Result of a phase-2 invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionOutcome {
    /// No signing response (or an expired request): the operator must sign.
    SigningRequired {
        request_path: PathBuf,
        expires_at: String,
    },
    /// The artifact is durably published.
    Published {
        path: PathBuf,
        sha256: String,
        size_bytes: u64,
    },
}

/// Completes a staged operation: verifies the detached signature (or an
/// already-finished artifact during a publication replay) and publishes.
pub fn complete_staged(
    inputs: &CompletionInputs<'_>,
) -> Result<CompletionOutcome, ArtifactFailure> {
    let staging_leaf = staging_leaf(inputs.operation_id);
    let staging_path = destination_staging_path(inputs.destination_dir, inputs.operation_id)?;
    validate_staging_directory(inputs.destination_dir, &staging_path, &staging_leaf)?;
    if inputs.record.staging_path != staging_path.to_string_lossy().as_ref() {
        return Err(ArtifactFailure::rejected("operation-staging-path-mismatch"));
    }
    // A publication replay does not need the request, the unsigned artifact or
    // the signing response: the signed artifact was produced (and its
    // signature verified) by an earlier invocation, and the journal records
    // its digest. Only the staged signed file's digest is re-checked here.
    let final_name = artifact_file_name(&inputs.record.backup_id);
    let final_path = inputs.destination_dir.join(&final_name);
    if inputs.record.phase == BackupOperationPhase::Publishing {
        let Some(expected) = inputs.record.artifact_sha256.as_deref() else {
            return Err(ArtifactFailure::rejected("publishing-record-incomplete"));
        };
        let staged_path = staged_signed_artifact_path(&staging_path)
            .map_err(|_| ArtifactFailure::rejected("staged-artifact-invalid"))?;
        let (size_bytes, sha256) = hash_file(&staged_path)
            .map_err(|_| ArtifactFailure::unknown("staged-artifact-unavailable"))?;
        if sha256 != expected {
            return Err(ArtifactFailure::rejected("staged-artifact-changed"));
        }
        publish(
            inputs.destination_fd,
            &relative_artifact_path(inputs.destination_dir, &staging_leaf, &staged_path)?,
            &final_name,
            &staged_path,
            &sha256,
        )?;
        mark_published(inputs)?;
        let _ = fs::remove_dir_all(&staging_path);
        return Ok(CompletionOutcome::Published {
            path: final_path,
            sha256,
            size_bytes,
        });
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
        backup_id: &inputs.record.backup_id,
        key_id: inputs.config.signing_key_id(),
        site_id: inputs.config.site_id(),
        installation_id: inputs.config.installation_id(),
        payload_sha256: None,
    };
    let signing_input = validate_signing_request(&request, &expectations)?;

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

    let response_path = staging_path.join(SIGNING_RESPONSE_FILE);
    if !response_path.exists() {
        return Ok(CompletionOutcome::SigningRequired {
            request_path,
            expires_at: request.expires_at.clone(),
        });
    }
    let response_bytes = read_bounded_file(&response_path, MAX_SIGNING_RESPONSE_BYTES)
        .map_err(|_| ArtifactFailure::rejected("signing-response-unavailable"))?;
    let signature = verify_signing_response(
        &response_bytes,
        &request_sha256,
        inputs.config.signing_key_id(),
        &signing_input,
        inputs.config.signing_key(),
    )?;

    let staged = finish_signed_artifact(
        unsigned,
        signature,
        inputs.config.signing_key_id(),
        inputs.config.signing_key(),
    )
    .map_err(|_| ArtifactFailure::rejected("artifact-finalize-failed"))?;
    let staged_path = staged.path.clone();
    let sha256 = staged.sha256.clone();
    let size_bytes = staged.size_bytes;

    update_journal(
        inputs,
        BackupOperationPhase::Publishing,
        Some(sha256.clone()),
    )?;
    // Test-only: crash after the durable `publishing` transition and before the
    // no-replace rename. A retry must observe the staged signed artifact and
    // finish publication without a second rename.
    test_hook_exit!("O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_PUBLISHING", 88);
    publish(
        inputs.destination_fd,
        &relative_artifact_path(inputs.destination_dir, &staging_leaf, &staged_path)?,
        &final_name,
        &staged_path,
        &sha256,
    )?;
    mark_published(inputs)?;
    let _ = fs::remove_dir_all(&staging_path);
    // Test-only: crash after the artifact is durably published and the journal
    // says `published`, before the success document is emitted.
    test_hook_exit!("O3K_BACKUP_TEST_EXIT_AFTER_PUBLICATION", 89);
    Ok(CompletionOutcome::Published {
        path: final_path,
        sha256,
        size_bytes,
    })
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
    backup_journal::write_backup_operation(inputs.data_dir, &record)
        .map_err(|error| ArtifactFailure::recoverable(error.reason()))
}

fn mark_published(inputs: &CompletionInputs<'_>) -> Result<(), ArtifactFailure> {
    update_journal(inputs, BackupOperationPhase::Published, None)
}

/// Atomic no-replace publication through the retained destination descriptor.
///
/// The source name is resolved inside the destination descriptor (a relative
/// path that starts with the verified staging leaf), so a path swap cannot
/// redirect the publication. An existing final entry is never replaced; if it
/// already holds the expected artifact, publication is classified complete.
fn publish(
    destination_fd: &OwnedFd,
    source_relative: &str,
    final_name: &str,
    staged_path: &Path,
    expected_sha256: &str,
) -> Result<(), ArtifactFailure> {
    match openat(
        destination_fd,
        final_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(existing) => {
            let metadata = fstat(&existing)
                .map_err(|_| ArtifactFailure::unknown("destination-artifact-unreadable"))?;
            if rustix::fs::FileType::from_raw_mode(metadata.st_mode)
                != rustix::fs::FileType::RegularFile
            {
                return Err(ArtifactFailure::rejected(
                    "artifact-destination-not-regular-file",
                ));
            }
            let path = PathBuf::from(format!(
                "/proc/self/fd/{}/{final_name}",
                std::os::fd::AsRawFd::as_raw_fd(destination_fd)
            ));
            let (_, existing_sha256) = hash_file(&path)
                .map_err(|_| ArtifactFailure::unknown("destination-artifact-unreadable"))?;
            if existing_sha256 == expected_sha256 {
                return Ok(());
            }
            return Err(ArtifactFailure::rejected("artifact-destination-exists"));
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(_) => return Err(ArtifactFailure::unknown("destination-artifact-unreadable")),
    }
    // Only now is the staged artifact required: the destination is free, so
    // it must still be the exact artifact that was signed.
    let (_, staged_sha256) = hash_file(staged_path)
        .map_err(|_| ArtifactFailure::unknown("staged-artifact-unavailable"))?;
    if staged_sha256 != expected_sha256 {
        return Err(ArtifactFailure::rejected("staged-artifact-changed"));
    }
    match renameat_with(
        destination_fd,
        source_relative,
        destination_fd,
        final_name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            // Raced with another publisher: only an identical artifact is
            // acceptable, and it is already durable.
            let path = PathBuf::from(format!(
                "/proc/self/fd/{}/{final_name}",
                std::os::fd::AsRawFd::as_raw_fd(destination_fd)
            ));
            let (_, existing_sha256) = hash_file(&path)
                .map_err(|_| ArtifactFailure::unknown("destination-artifact-unreadable"))?;
            if existing_sha256 == expected_sha256 {
                return Ok(());
            }
            return Err(ArtifactFailure::rejected("artifact-destination-exists"));
        }
        Err(_) => return Err(ArtifactFailure::recoverable("publication-failed")),
    }
    fsync(destination_fd).map_err(|_| ArtifactFailure::unknown("publication-sync-failed"))?;
    Ok(())
}

/// Path of a staged artifact relative to the destination, restricted to the
/// operation staging directory. Both components are resolved inside the held
/// destination descriptor, so the rename cannot leave the destination.
fn relative_artifact_path(
    destination_dir: &Path,
    staging_leaf: &str,
    staged_path: &Path,
) -> Result<String, ArtifactFailure> {
    let relative = staged_path
        .strip_prefix(destination_dir)
        .map_err(|_| ArtifactFailure::rejected("staged-artifact-path-invalid"))?;
    let text = relative
        .to_str()
        .ok_or(ArtifactFailure::rejected("staged-artifact-path-invalid"))?;
    if !text.starts_with(&format!("{staging_leaf}/"))
        || text.contains("..")
        || text.starts_with('/')
    {
        return Err(ArtifactFailure::rejected("staged-artifact-path-invalid"));
    }
    Ok(text.to_owned())
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
}

/// Validates a signing request against the local operation and returns the
/// decoded signing input. Expiry is a recoverable failure: the staged artifact
/// is kept, and the operator must start a new operation.
fn validate_signing_request(
    request: &SigningRequest,
    expected: &RequestExpectations<'_>,
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
    {
        return Err(ArtifactFailure::rejected("signing-request-mismatch"));
    }
    for digest in [
        &request.manifest_digest,
        &request.signing_input_sha256,
        &request.payload_sha256,
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
    if expires_at <= Utc::now() {
        return Err(ArtifactFailure::recoverable("signing-request-expired"));
    }
    Ok(signing_input)
}

/// Validates a detached signing response and verifies the signature over the
/// exact signing input with the configured trust key.
fn verify_signing_response(
    response_bytes: &[u8],
    request_sha256: &str,
    key_id: &str,
    signing_input: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<[u8; 64], ArtifactFailure> {
    let response: SigningResponse = serde_json::from_slice(response_bytes)
        .map_err(|_| ArtifactFailure::rejected("signing-response-invalid"))?;
    if response.format != SIGNING_RESPONSE_FORMAT
        || response.request_sha256 != request_sha256
        || response.key_id != key_id
    {
        return Err(ArtifactFailure::rejected("signing-response-mismatch"));
    }
    if DateTime::parse_from_rfc3339(&response.signed_at).is_err() {
        return Err(ArtifactFailure::rejected("signing-response-invalid"));
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

fn staged_signed_artifact_path(staging_path: &Path) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir(staging_path).map_err(|_| "staging unavailable".to_owned())? {
        let entry = entry.map_err(|_| "staging unavailable".to_owned())?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(MEMBERS_DIR_PREFIX.as_bytes())
        {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|_| "staging entry unavailable".to_owned())?;
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path().join("artifact.partial");
        if path.is_file() {
            candidates.push(path);
        }
    }
    if candidates.len() != 1 {
        return Err("no unique signed artifact".to_owned());
    }
    Ok(candidates.remove(0))
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
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
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

fn hash_file(path: &Path) -> std::io::Result<(u64, String)> {
    let mut file = fs::File::open(path)?;
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
            fs::set_permissions(&install_prefix, fs::Permissions::from_mode(0o700))
                .expect("restrict install prefix");
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

        for field in 0..7 {
            let mut tampered = request(operation_id, "2999-01-01T00:00:00Z");
            match field {
                0 => tampered.operation_id = Uuid::new_v4(),
                1 => tampered.backup_id = "other-backup".to_owned(),
                2 => tampered.key_id = "signing-2".to_owned(),
                3 => tampered.site_id = "other-site".to_owned(),
                4 => tampered.installation_id = "other-installation".to_owned(),
                5 => tampered.payload_sha256 = "d".repeat(64),
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
        let bytes = serde_json::to_vec(&response).expect("encode response");
        let signature = verify_signing_response(
            &bytes,
            &request_sha256,
            SIGNING_KEY_ID,
            signing_input,
            &key.verifying_key(),
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
            )
            .expect_err("tampered response");
            assert_eq!(failure.reason(), reason, "field {field}");
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
        let members = staging.join(format!("{MEMBERS_DIR_PREFIX}{}", Uuid::now_v7()));
        private_dir(&members);
        let artifact = members.join("artifact.partial");
        let bytes = b"authenticated artifact bytes";
        write_private(&artifact, bytes);
        let digest = hex::encode(Sha256::digest(bytes));
        let relative =
            relative_artifact_path(&destination, &staging_leaf, &artifact).expect("relative path");
        let final_name = artifact_file_name(&operation_id.to_string());

        publish(&destination_fd, &relative, &final_name, &artifact, &digest).expect("publish");
        assert_eq!(
            fs::read(destination.join(&final_name)).expect("published"),
            bytes
        );
        assert!(!artifact.exists(), "publication moves the staged artifact");

        // A replay classifies the identical final artifact as already
        // published instead of failing or duplicating it.
        publish(&destination_fd, &relative, &final_name, &artifact, &digest)
            .expect("idempotent replay");

        // A different artifact never replaces an existing one.
        write_private(&artifact, b"another artifact");
        let other_digest = hex::encode(Sha256::digest(b"another artifact"));
        let failure = publish(
            &destination_fd,
            &relative,
            &final_name,
            &artifact,
            &other_digest,
        )
        .expect_err("existing destination");
        assert_eq!(failure.reason(), "artifact-destination-exists");
        assert_eq!(
            fs::read(destination.join(&final_name)).expect("published"),
            bytes
        );

        // A relative source outside the staging leaf is refused.
        let outside = destination.join("elsewhere.partial");
        write_private(&outside, bytes);
        assert_eq!(
            relative_artifact_path(&destination, &staging_leaf, &outside)
                .expect_err("outside staging")
                .reason(),
            "staged-artifact-path-invalid"
        );
    }

    #[test]
    fn naming_and_prefix_resolution_are_stable() {
        assert_eq!(artifact_file_name("abc"), "backup-abc.o3k");
        let operation_id = Uuid::nil();
        assert_eq!(
            staging_leaf(operation_id),
            format!(".o3k-backup-artifact-{operation_id}")
        );
        assert_eq!(
            install_prefix_from(None),
            PathBuf::from(DEFAULT_INSTALL_PREFIX)
        );
        assert_eq!(
            install_prefix_from(Some(std::ffi::OsString::new())),
            PathBuf::from(DEFAULT_INSTALL_PREFIX)
        );
        assert_eq!(
            install_prefix_from(Some(std::ffi::OsString::from("/opt/o3k"))),
            PathBuf::from("/opt/o3k")
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
}
