//! `o3k backup verify` — exact-release verification of an authenticated PP.6
//! backup artifact (SPEC-0050 §8, ADR-0189 D12).
//!
//! The command is read-only with respect to canonical state. It:
//!
//! 1. resolves the daemon data directory exactly as `o3k backup create` does
//!    (`O3K_DATA_DIR` when set and non-empty, else `./data`, canonicalized);
//! 2. loads the root-owned installation trust document
//!    ([`default_trust_config_path`], `O3K_BACKUP_TRUST_CONFIG` override) and
//!    proves its site/installation identity matches this data directory;
//! 3. pins the exact installed release from
//!    `<O3K_INSTALL_PREFIX>/share/o3k/release-manifest.json`
//!    (`/usr/local` by default) through
//!    [`crate::upgrade::release_identity::backup_release_identity`];
//! 4. opens the artifact with `O_NOFOLLOW`, verifies its canonical manifest,
//!    Ed25519 signature, HPKE key wrapping, member digests and AES-GCM tags
//!    through [`crate::backup::verify_artifact_stream`];
//! 5. removes the staged plaintext before reporting success.
//!
//! # Migration identity sourcing (known limitation)
//!
//! The installed release manifest carries a schema version but not the applied
//! migration identities. The verifier therefore reads the migration inventory
//! from this installation's canonical, already-migrated SQLite store and only
//! accepts it when its maximum migration version equals the release's
//! `schema_version`. The store is opened with a plain read-only sqlx
//! connection: no lifetime lock, no migration, no checkpoint, no mutation. If
//! the store or its `_sqlx_migrations` table is unavailable, or the schema
//! version differs, the expected release cannot be established and the
//! command fails closed with `expected-release-unavailable`. Like any SQLite
//! reader of a WAL database, the read-only connection needs access to the
//! store's sidecar files while a controller is live; if the operator cannot
//! read them the command rejects rather than guessing the release.
//!
//! The v1 contract stores a 64-character SHA-256 migration checksum while SQLx
//! records a 48-byte SHA-384 checksum. [`migration_checksum`] is the single
//! documented binding between the two: the manifest checksum is the lowercase
//! hex SHA-256 of the recorded SQLx checksum bytes. The capture path must use
//! the same mapping.
//!
//! # Staging and cleanup
//!
//! Decrypted members are staged under a private `0700` directory created
//! inside the data directory (`<data_dir>/.o3k-verify-staging-<uuid>`), never
//! next to the operator-supplied artifact and never in the system temporary
//! directory. The directory tree is removed after a successful verification
//! and, on a verification failure, the verifier's own staging directory is
//! already removed by [`crate::backup::verify_artifact_stream`]. If the final
//! cleanup cannot be proven, the command reports the quarantined outcome
//! (`verification-cleanup-failed`, exit 4) instead of success; removal of the
//! now-empty outer staging root is best effort on failure paths.
//!
//! # Output and exit codes
//!
//! Stdout carries exactly one bounded JSON line; stderr carries only a stable
//! reason code. No path, key material, token or provider payload is emitted.
//!
//! ```text
//! 0  artifact authenticated and matches the installed exact release
//! 2  rejected precondition (path, trust, identity, release, signature,
//!    schema, corruption or size limit)
//! 3  recoverable failure (artifact or configuration unavailable)
//! 4  unknown/quarantined outcome (verification succeeded but plaintext
//!    cleanup could not be proven)
//! ```
//!
//! Linux-only, mirroring the `o3k backup` command surface.

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use rustix::fs::{Mode, OFlags, open};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use uuid::Uuid;

use crate::backup::{
    ArtifactVerificationKeys, ExpectedRelease, MigrationIdentity, verify_artifact_stream,
};
use crate::backup_trust::{
    BackupTrustConfig, BackupTrustError, INSTALL_PREFIX_ENV, default_trust_config_path,
};
use crate::upgrade::release_identity::{BackupReleaseIdentity, backup_release_identity};

/// Default daemon data directory; mirrors `o3k-config`'s `DEFAULT_DATA_DIR`.
const DEFAULT_DATA_DIR: &str = "./data";
/// Database file name inside the data directory.
const DATABASE_FILE_NAME: &str = "o3k.sqlite";
/// Default installation prefix used by the installer.
const DEFAULT_INSTALL_PREFIX: &str = "/usr/local";
/// Private verification staging root inside the data directory.
const STAGING_DIR_PREFIX: &str = ".o3k-verify-staging-";

/// Exit codes defined by SPEC-0050 §8.
const EXIT_REJECTED: u8 = 2;
const EXIT_RECOVERABLE: u8 = 3;
const EXIT_UNKNOWN: u8 = 4;

/// Stable reason used whenever the local release/migration identity cannot be
/// established. It deliberately does not distinguish missing files, unreadable
/// stores and schema drift: all of them mean "this host is not the exact
/// release".
const REASON_EXPECTED_RELEASE_UNAVAILABLE: &str = "expected-release-unavailable";
const REASON_CLEANUP_FAILED: &str = "verification-cleanup-failed";

/// Arguments of `o3k backup verify`.
pub struct BackupVerifyArgs {
    /// Absolute path to the authenticated backup artifact.
    pub artifact: PathBuf,
}

/// Bounded machine-readable result of one verification run.
struct BackupVerifyOutcome {
    exit_code: u8,
    json: Value,
}

impl BackupVerifyOutcome {
    fn rejected(reason: &'static str) -> Self {
        Self::with_status(EXIT_REJECTED, "rejected", reason)
    }

    fn recoverable(reason: &'static str) -> Self {
        Self::with_status(EXIT_RECOVERABLE, "recoverable-failure", reason)
    }

    fn unknown(reason: &'static str) -> Self {
        Self::with_status(EXIT_UNKNOWN, "unknown", reason)
    }

    fn with_status(exit_code: u8, status: &'static str, reason: &'static str) -> Self {
        Self {
            exit_code,
            json: json!({
                "status": status,
                "reason": reason,
            }),
        }
    }
}

/// Runs `o3k backup verify`, printing the bounded JSON result on stdout and a
/// stable reason line on stderr, and returns the process exit code.
pub fn run_backup_verify(args: &BackupVerifyArgs) -> ExitCode {
    let outcome = execute(args);
    let line = serde_json::to_string(&outcome.json).unwrap_or_else(|_| {
        format!(
            "{{\"status\":\"recoverable-failure\",\"reason\":\"output-serialization-failed\",\"exit\":{}}}",
            outcome.exit_code
        )
    });
    // Write the result manually: `println!` panics (exit 101, outside the
    // SPEC-0050 §8 contract) when stdout is closed, e.g. `| head -0`.
    if writeln!(io::stdout(), "{line}").is_err() {
        return ExitCode::from(outcome.exit_code);
    }
    if outcome.exit_code != 0 {
        let reason = outcome
            .json
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("unspecified");
        // Best effort: stderr carries the stable reason line only.
        let _ = writeln!(io::stderr(), "o3k backup verify: {reason}");
    }
    if outcome.exit_code == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(outcome.exit_code)
    }
}

/// Validates the operator-supplied path, assembles the trusted expected
/// release and verifies the artifact.
fn execute(args: &BackupVerifyArgs) -> BackupVerifyOutcome {
    if let Err(reason) = validate_artifact_path(&args.artifact) {
        return path_failure(reason);
    }
    // The data directory is local I/O, not an artifact assertion: a resolution
    // failure is recoverable.
    let data_dir = match resolve_data_dir() {
        Ok(dir) => dir,
        Err(reason) => return BackupVerifyOutcome::recoverable(reason),
    };

    let trust = match BackupTrustConfig::load(&default_trust_config_path()) {
        Ok(config) => config,
        Err(error) => return trust_failure(error),
    };
    if let Err(error) = trust.verify_identity(&data_dir) {
        return trust_failure(error);
    }
    let signing_key = match trust.artifact_signing_public_key() {
        Ok(key) => key,
        Err(error) => return trust_failure(error),
    };
    let recipient = match trust.load_recipient_private_key() {
        Ok(key) => key,
        Err(error) => return trust_failure(error),
    };

    let identity = match resolve_release_identity() {
        Ok(identity) => identity,
        Err(reason) => return BackupVerifyOutcome::rejected(reason),
    };
    let migrations = match read_local_migrations(&data_dir, identity.schema_version) {
        Ok(migrations) => migrations,
        Err(reason) => return BackupVerifyOutcome::rejected(reason),
    };
    let inventory = match o3k_store::state_inventory::baseline_state_inventory() {
        Ok(inventory) => inventory,
        Err(_) => return BackupVerifyOutcome::rejected(REASON_EXPECTED_RELEASE_UNAVAILABLE),
    };

    let expected = ExpectedRelease {
        site_id: trust.site_id().to_owned(),
        installation_id: trust.installation_id().to_owned(),
        o3k_version: identity.o3k_version,
        source_sha: identity.source_sha,
        release_artifact_sha256: identity.release_artifact_sha256,
        profile_id: identity.profile_id,
        store_backend: "sqlite".to_owned(),
        schema_version: identity.schema_version,
        migrations,
        state_inventory: inventory,
    };
    let keys = ArtifactVerificationKeys {
        signing_key_id: trust.artifact_signing_key_id(),
        signer: &signing_key,
        trust: &trust,
        recipient_key_id: trust.recipient_key_id(),
        recipient: &recipient,
    };

    let mut artifact = match open_artifact(&args.artifact) {
        Ok(artifact) => artifact,
        Err(reason) => return BackupVerifyOutcome::recoverable(reason),
    };
    let staging_root = match create_staging_root(&data_dir) {
        Ok(path) => path,
        Err(reason) => return BackupVerifyOutcome::recoverable(reason),
    };
    let verified = match verify_artifact_stream(&mut artifact, &expected, &keys, &staging_root) {
        Ok(verified) => verified,
        Err(error) => {
            // The streaming verifier removes its own staging directory on
            // failure; this only removes the now-empty outer root.
            let _ = fs::remove_dir_all(&staging_root);
            return verification_failure(&error);
        }
    };
    let artifact_sha256 = artifact.finish();

    // Plaintext members are never exposed. Removing the outer root removes
    // the verifier's private staging directory with them.
    if fs::remove_dir_all(&staging_root).is_err() {
        return BackupVerifyOutcome::unknown(REASON_CLEANUP_FAILED);
    }

    BackupVerifyOutcome {
        exit_code: 0,
        json: verified_json(&verified, &artifact_sha256),
    }
}

/// Maps a trust-boundary failure to the SPEC-0050 outcome. Missing
/// configuration or an unavailable key file is recoverable; a document that is
/// present but untrusted, malformed, mismatched or expired is a rejected
/// precondition.
fn trust_failure(error: BackupTrustError) -> BackupVerifyOutcome {
    match error {
        BackupTrustError::ConfigUnavailable
        | BackupTrustError::RecipientKeyUnavailable
        | BackupTrustError::IdentityUnavailable => BackupVerifyOutcome::recoverable(error.reason()),
        _ => BackupVerifyOutcome::rejected(error.reason()),
    }
}

/// Maps a streaming-verification error to a stable reason. Verification errors
/// are bounded, secret-free strings; the mapping is part of the CLI contract.
fn verification_failure(error: &str) -> BackupVerifyOutcome {
    let (exit_code, reason) = classify_verification_failure(error);
    BackupVerifyOutcome::with_status(exit_code, status_for(exit_code), reason)
}

fn classify_verification_failure(error: &str) -> (u8, &'static str) {
    // A failed cleanup is quarantined even when the primary verification also
    // failed: safe removal of decrypted plaintext could not be proven.
    if error.contains("private verification cleanup failed") {
        return (EXIT_UNKNOWN, REASON_CLEANUP_FAILED);
    }
    let reason = if error.contains("signing key is revoked") {
        "revoked-signing-key"
    } else if error.contains("signing key is not trusted") {
        "untrusted-signing-key"
    } else if error.contains("key identity is not trusted") {
        "key-identity-mismatch"
    } else if error.contains("signature verification failed")
        || error.contains("signature is missing")
        || error.contains("signature encoding is invalid")
    {
        "signature-invalid"
    } else if error.contains("exact release") {
        "release-mismatch"
    } else if error.contains("does not match the v1 contract")
        || error.contains("manifest is malformed")
        || error.contains("backup manifest schema is")
    {
        "schema-invalid"
    } else if error.contains("exceeds the configured size limit")
        || error.contains("length is not supported")
    {
        "artifact-too-large"
    } else if error.contains("content key cannot be unwrapped") {
        "recipient-key-mismatch"
    } else {
        "corrupt-artifact"
    };
    (EXIT_REJECTED, reason)
}

const fn status_for(exit_code: u8) -> &'static str {
    match exit_code {
        EXIT_REJECTED => "rejected",
        EXIT_UNKNOWN => "unknown",
        _ => "recoverable-failure",
    }
}

/// Builds the bounded success document. Only schema-validated manifest fields
/// are copied, and member entries carry name and plaintext size only.
fn verified_json(verified: &crate::backup::VerifiedArtifact, artifact_sha256: &str) -> Value {
    let manifest = &verified.manifest;
    let members: Vec<Value> = manifest
        .members
        .iter()
        .map(|member| {
            json!({
                "name": member.name,
                "plaintext_size_bytes": member.plaintext_size_bytes,
            })
        })
        .collect();
    json!({
        "status": "verified",
        "backup_id": manifest.backup_id,
        "artifact_sha256": artifact_sha256,
        "manifest": {
            "format_version": manifest.format_version,
            "site_id": manifest.site_id,
            "installation_id": manifest.installation_id,
            "created_at": manifest.created_at,
            "o3k_version": field(&manifest.source, "o3k_version"),
            "source_sha": field(&manifest.source, "source_sha"),
            "release_artifact_sha256": field(&manifest.source, "release_artifact_sha256"),
            "profile_id": field(&manifest.source, "profile_id"),
            "store_backend": field(&manifest.store, "backend"),
            "schema_version": field(&manifest.store, "schema_version"),
        },
        "members": members,
        "release_match": true,
        "signing_key_id": manifest.authentication.key_id,
        "recipient_key_id": manifest.encryption.key_wrapping.recipient_key_id,
    })
}

fn field(value: &Value, key: &str) -> Value {
    value.get(key).cloned().unwrap_or(Value::Null)
}

/// Maps an artifact-path validation code to its outcome. An unreadable entry
/// is local I/O; every other code is an explicit precondition on the argument.
fn path_failure(reason: &'static str) -> BackupVerifyOutcome {
    if reason == "artifact-unreadable" {
        BackupVerifyOutcome::recoverable(reason)
    } else {
        BackupVerifyOutcome::rejected(reason)
    }
}

/// Validates `--artifact`: absolute, existing, a real regular file, and never
/// a symbolic link (the final component is opened with `O_NOFOLLOW` later).
fn validate_artifact_path(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute() {
        return Err("artifact-not-absolute");
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err("artifact-missing"),
        Err(_) => return Err("artifact-unreadable"),
    };
    if metadata.file_type().is_symlink() {
        return Err("artifact-symlink");
    }
    if !metadata.file_type().is_file() {
        return Err("artifact-not-regular-file");
    }
    Ok(())
}

/// Opens the validated artifact with `O_NOFOLLOW` and hashes every byte the
/// verifier reads, so the reported digest covers exactly the verified stream.
fn open_artifact(path: &Path) -> Result<HashingReader<File>, &'static str> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| "artifact-unreadable")?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| "artifact-unreadable")?;
    if !metadata.file_type().is_file() {
        return Err("artifact-not-regular-file");
    }
    Ok(HashingReader {
        inner: file,
        hasher: Sha256::new(),
    })
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

impl<R> HashingReader<R> {
    fn finish(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

/// Resolves the daemon data directory the way `o3k-config` does for the
/// SQLite default: non-empty `O3K_DATA_DIR`, else `./data`, canonicalized.
fn resolve_data_dir() -> Result<PathBuf, &'static str> {
    let configured = std::env::var("O3K_DATA_DIR")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    resolve_data_dir_from(configured.as_deref())
}

fn resolve_data_dir_from(configured: Option<&str>) -> Result<PathBuf, &'static str> {
    fs::canonicalize(data_dir_from(configured)).map_err(|_| "data-dir-unavailable")
}

fn data_dir_from(configured: Option<&str>) -> PathBuf {
    configured
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR))
}

/// Reads the exact installed release identity from the installation prefix
/// shared with the artifact capture path and the trust-document default.
fn resolve_release_identity() -> Result<BackupReleaseIdentity, &'static str> {
    let prefix = std::env::var_os(INSTALL_PREFIX_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_INSTALL_PREFIX));
    backup_release_identity(&prefix).map_err(|_| REASON_EXPECTED_RELEASE_UNAVAILABLE)
}

/// Creates a private staging root inside the canonical data directory.
fn create_staging_root(data_dir: &Path) -> Result<PathBuf, &'static str> {
    let path = data_dir.join(format!("{STAGING_DIR_PREFIX}{}", Uuid::now_v7()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| "staging-unavailable")?;
    Ok(path)
}

/// Reads the applied migration identities from the local canonical store with
/// a plain read-only connection. The store must already be at the release's
/// schema version; nothing is created, migrated, checkpointed or locked.
fn read_local_migrations(
    data_dir: &Path,
    release_schema_version: u64,
) -> Result<Vec<MigrationIdentity>, &'static str> {
    let path = data_dir.join(DATABASE_FILE_NAME);
    let metadata = fs::symlink_metadata(&path).map_err(|_| REASON_EXPECTED_RELEASE_UNAVAILABLE)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(REASON_EXPECTED_RELEASE_UNAVAILABLE);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| REASON_EXPECTED_RELEASE_UNAVAILABLE)?;
    let rows = runtime.block_on(async {
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .read_only(true)
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(options)
            .await
            .map_err(|_| REASON_EXPECTED_RELEASE_UNAVAILABLE)?;
        let rows: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&pool)
                .await
                .map_err(|_| REASON_EXPECTED_RELEASE_UNAVAILABLE)?;
        pool.close().await;
        Ok::<_, &'static str>(rows)
    })?;

    if rows.is_empty() {
        return Err(REASON_EXPECTED_RELEASE_UNAVAILABLE);
    }
    let mut migrations = Vec::with_capacity(rows.len());
    let mut previous = None;
    for (version, checksum) in rows {
        let version = u64::try_from(version).map_err(|_| REASON_EXPECTED_RELEASE_UNAVAILABLE)?;
        if previous.is_some_and(|prior| prior >= version) {
            return Err(REASON_EXPECTED_RELEASE_UNAVAILABLE);
        }
        previous = Some(version);
        migrations.push(MigrationIdentity {
            version,
            checksum: migration_checksum(&checksum),
        });
    }
    if migrations.last().map(|migration| migration.version) != Some(release_schema_version) {
        return Err(REASON_EXPECTED_RELEASE_UNAVAILABLE);
    }
    Ok(migrations)
}

/// Binds a recorded SQLx migration checksum to the manifest contract.
///
/// The v1 manifest stores a 64-character lowercase hex SHA-256. SQLx records a
/// 48-byte (SHA-384) checksum in `_sqlx_migrations`; the binding is the SHA-256
/// of those recorded bytes. Capture and verification must use this one
/// mapping.
#[must_use]
pub fn migration_checksum(sqlx_checksum: &[u8]) -> String {
    hex::encode(Sha256::digest(sqlx_checksum))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::backup::{
        Authentication, Encryption, KeyWrapping, Manifest, MemberRecord, VerifiedArtifact,
    };
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    struct TempRoot(PathBuf);

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl TempRoot {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("o3k-backup-verify-{label}-{}", Uuid::now_v7()));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .expect("create private test directory");
            Self(path)
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            format_version: "1".to_owned(),
            backup_id: "backup-1".to_owned(),
            created_at: "2026-10-19T12:00:00Z".to_owned(),
            site_id: "site-1".to_owned(),
            installation_id: "install-1".to_owned(),
            source: json!({
                "o3k_version": "0.4.0",
                "source_sha": "0123456789abcdef0123456789abcdef01234567",
                "release_artifact_sha256": "a".repeat(64),
                "profile_id": "o3k-demo-v1",
            }),
            store: json!({
                "backend": "sqlite",
                "server_version": "3.50.0",
                "schema_version": 53,
                "migrations": [{"version": 1, "checksum": "b".repeat(64)}],
            }),
            consistency: json!({}),
            state_inventory: Vec::new(),
            members: vec![MemberRecord {
                name: "database/state.sqlite".to_owned(),
                plaintext_size_bytes: 8,
                size_bytes: 24,
                sha256: "c".repeat(64),
                media_type: "application/vnd.sqlite3".to_owned(),
                encrypted: true,
                consistency_generation: "generation-1".to_owned(),
                nonce: "nonce".to_owned(),
            }],
            encryption: Encryption {
                algorithm: "AES-256-GCM".to_owned(),
                key_id: "artifact-1".to_owned(),
                key_is_external: true,
                key_wrapping: KeyWrapping {
                    algorithm: "HPKE-v1-X25519-HKDF-SHA256-AES-256-GCM".to_owned(),
                    recipient_key_id: "recovery-1".to_owned(),
                    enc: "enc".to_owned(),
                    ciphertext: "wrapped".to_owned(),
                },
            },
            authentication: Authentication {
                algorithm: "Ed25519".to_owned(),
                key_id: "signing-1".to_owned(),
                signature: Some("signature".to_owned()),
            },
            excluded_state: Vec::new(),
        }
    }

    #[test]
    fn success_json_is_bounded_and_carries_the_expected_fields() {
        let verified = VerifiedArtifact {
            manifest: manifest(),
            staging_directory: PathBuf::from("/nonexistent"),
            members: Vec::new(),
        };
        let digest = "d".repeat(64);
        let value = verified_json(&verified, &digest);
        let encoded = serde_json::to_string(&value).expect("serialize success document");
        assert!(!encoded.contains('\n'), "output must be one line");
        assert_eq!(value["status"], "verified");
        assert_eq!(value["artifact_sha256"], digest);
        assert_eq!(value["release_match"], true);
        assert_eq!(value["signing_key_id"], "signing-1");
        assert_eq!(value["recipient_key_id"], "recovery-1");
        assert_eq!(value["manifest"]["o3k_version"], "0.4.0");
        assert_eq!(value["manifest"]["store_backend"], "sqlite");
        assert_eq!(value["manifest"]["schema_version"], 53);
        assert_eq!(value["members"][0]["name"], "database/state.sqlite");
        assert_eq!(value["members"][0]["plaintext_size_bytes"], 8);
    }

    #[test]
    fn reason_mapping_is_stable_for_every_failure_class() {
        let cases = [
            (
                "backup signing key is revoked",
                EXIT_REJECTED,
                "revoked-signing-key",
            ),
            (
                "backup signing key is not trusted for this site and profile",
                EXIT_REJECTED,
                "untrusted-signing-key",
            ),
            (
                "backup key identity is not trusted by this verifier",
                EXIT_REJECTED,
                "key-identity-mismatch",
            ),
            (
                "backup signature verification failed",
                EXIT_REJECTED,
                "signature-invalid",
            ),
            (
                "backup artifact does not match the verifier's exact release",
                EXIT_REJECTED,
                "release-mismatch",
            ),
            (
                "backup manifest does not match the v1 contract",
                EXIT_REJECTED,
                "schema-invalid",
            ),
            (
                "backup manifest is malformed",
                EXIT_REJECTED,
                "schema-invalid",
            ),
            (
                "backup artifact exceeds the configured size limit",
                EXIT_REJECTED,
                "artifact-too-large",
            ),
            (
                "backup content key cannot be unwrapped",
                EXIT_REJECTED,
                "recipient-key-mismatch",
            ),
            (
                "backup member authentication failed",
                EXIT_REJECTED,
                "corrupt-artifact",
            ),
            (
                "backup signature verification failed; private verification cleanup failed",
                EXIT_UNKNOWN,
                "verification-cleanup-failed",
            ),
        ];
        for (error, exit_code, reason) in cases {
            let (mapped_exit, mapped_reason) = classify_verification_failure(error);
            assert_eq!(mapped_exit, exit_code, "{error}");
            assert_eq!(mapped_reason, reason, "{error}");
        }
    }

    #[test]
    fn artifact_path_validation_rejects_relative_missing_symlinks_and_directories() {
        let root = TempRoot::new("paths");
        let artifact = root.0.join("artifact.bin");
        fs::write(&artifact, b"artifact").expect("write artifact");
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600))
            .expect("restrict artifact");
        assert_eq!(validate_artifact_path(&artifact), Ok(()));

        assert_eq!(
            validate_artifact_path(Path::new("relative/artifact.bin")),
            Err("artifact-not-absolute")
        );
        assert_eq!(
            validate_artifact_path(&root.0.join("missing.bin")),
            Err("artifact-missing")
        );

        let link = root.0.join("artifact.link");
        std::os::unix::fs::symlink(&artifact, &link).expect("create symlink");
        assert_eq!(validate_artifact_path(&link), Err("artifact-symlink"));
        assert_eq!(
            validate_artifact_path(&root.0),
            Err("artifact-not-regular-file")
        );
        assert_eq!(path_failure("artifact-missing").exit_code, EXIT_REJECTED);
        assert_eq!(
            path_failure("artifact-unreadable").exit_code,
            EXIT_RECOVERABLE
        );
    }

    #[test]
    fn migration_checksum_binds_sqlx_bytes_as_lowercase_sha256() {
        assert_eq!(
            migration_checksum(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let checksum = migration_checksum(&[0x01, 0x02, 0x03]);
        assert_eq!(checksum.len(), 64);
        assert!(
            checksum
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }

    #[test]
    fn data_dir_precedence_mirrors_the_capture_executor() {
        assert_eq!(data_dir_from(None), PathBuf::from(DEFAULT_DATA_DIR));
        assert_eq!(
            data_dir_from(Some("  /var/lib/o3k  ")),
            PathBuf::from("/var/lib/o3k")
        );
        assert_eq!(data_dir_from(Some("   ")), PathBuf::from(DEFAULT_DATA_DIR));
    }

    #[test]
    fn missing_local_store_fails_closed_as_expected_release_unavailable() {
        let root = TempRoot::new("missing-store");
        assert_eq!(
            read_local_migrations(&root.0, 53),
            Err(REASON_EXPECTED_RELEASE_UNAVAILABLE)
        );
    }
}
