//! `o3k backup verify` — exact-release verification of an authenticated PP.6
//! backup artifact (SPEC-0050 §8, ADR-0189 D12).
//!
//! The command never opens or mutates the live SQLite store. It:
//!
//! 1. resolves the daemon data directory exactly as `o3k backup create` does
//!    (root uses `/var/lib/o3k`; a non-root caller uses a non-empty
//!    `O3K_DATA_DIR`, else `O3K_DATA_DIR=` from `/etc/o3k/o3kd.env`, else the
//!    packaged `/var/lib/o3k` when it is owned by the effective uid, else
//!    `./data`, canonicalized); a resolution failure is recoverable (exit 3)
//!    in both commands;
//! 2. loads the installation trust document (default
//!    `/etc/o3k/backup-trust.json`; `O3K_BACKUP_TRUST_CONFIG` and
//!    `O3K_INSTALL_PREFIX` are honored only for a non-installed data
//!    directory) and proves its site/installation identity matches this data
//!    directory;
//! 3. pins the exact installed release from
//!    `<install prefix>/share/o3k/release-manifest.json` through
//!    [`crate::upgrade::release_identity::backup_release_identity`], which
//!    reads it bounded with `O_NOFOLLOW` and a trusted owner/mode check;
//! 4. copies the main SQLite database and a non-empty WAL sidecar into its
//!    private `0700` staging directory (under the store-access lock) and reads
//!    the copy, never the live database; `immutable=1` is used when no
//!    non-empty WAL exists;
//! 5. opens the artifact with `O_NOFOLLOW`, verifies its canonical manifest,
//!    Ed25519 signature, HPKE key wrapping, member digests and AES-GCM tags
//!    through [`crate::backup::verify_artifact_stream`];
//! 6. removes the staged plaintext and the database copy before reporting
//!    success.
//!
//! # Host boundary and required key material
//!
//! Full member verification decrypts every member, so it requires the X25519
//! recovery private key and must run on the operator/recovery host that holds
//! it. Signature, D1 signing-input and member-digest authenticity can be
//! checked independently without that key (the campaign does this with
//! `openssl` and a local JCS implementation), but this command intentionally
//! performs the full decryption and reports member plaintext sizes. A
//! public-key-only verify mode is a follow-up that needs a contract decision;
//! the controller-side capture path needs only the public key.
//!
//! # Migration identity sourcing (known limitation)
//!
//! The installed release manifest carries a schema version but not the applied
//! migration identities. The verifier therefore reads the migration inventory
//! from a private copy of this installation's already-migrated SQLite store
//! and only accepts it when its maximum migration version equals the release's
//! `schema_version`. The copy is taken while holding the lifetime store lock;
//! the copy is opened with a read-only sqlx connection (no migration, no
//! checkpoint, no mutation of the live store). If the store or its
//! `_sqlx_migrations` table is unavailable, or the schema version differs, the
//! expected release cannot be established and the command fails closed with
//! `expected-release-unavailable`.
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
//! outer staging root (which holds the private database copy) on failure
//! paths; a failed removal is an unknown outcome (exit 4).
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
    ArtifactVerificationKeys, ArtifactVerifyClass, ArtifactVerifyError, ExpectedRelease,
    MigrationIdentity, verify_artifact_stream,
};
use crate::backup_trust::{
    BackupTrustConfig, BackupTrustError, default_trust_config_path_for, install_prefix_for,
};
use crate::upgrade::release_identity::{BackupReleaseIdentity, backup_release_identity};
use o3k_store::StoreAccessLock;

/// Database file name inside the data directory.
const DATABASE_FILE_NAME: &str = "o3k.sqlite";
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
/// Quarantined post-verification cleanup, taken from the single reason table in
/// [`crate::backup::ArtifactVerifyClass`].
const REASON_CLEANUP_FAILED: &str = ArtifactVerifyClass::CleanupFailed.reason();

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
    let data_dir = match crate::backup_data_dir::resolve_data_dir() {
        Ok(dir) => dir,
        Err(reason) => return BackupVerifyOutcome::recoverable(reason),
    };

    if crate::backup_pg::configured_backend() == crate::backup::BACKEND_POSTGRESQL {
        return execute_postgres(args, &data_dir);
    }

    // D4 store-access guard. `verify` copies the canonical SQLite store to
    // read the applied migration identities, so it is a store-reading command
    // and must take the same lifetime lock the daemon and `backup create` use.
    // A live controller (or a capture that is waiting for its signature) means
    // the store copy would race the writer.
    //
    // The alternative — deriving the migration identities from the installed
    // release without opening the store — is not possible with the accepted
    // installed metadata: the release manifest carries `schema_version` but no
    // migration checksums, and the committed migration tree is not installed.
    let store_lock = match StoreAccessLock::acquire(&data_dir) {
        Ok(lock) => lock,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return BackupVerifyOutcome::rejected("controller-active");
        }
        Err(_) => return BackupVerifyOutcome::recoverable("store-lock-unavailable"),
    };

    let trust = match BackupTrustConfig::load(&default_trust_config_path_for(
        &data_dir,
        std::env::var_os(crate::backup_trust::TRUST_CONFIG_ENV),
        std::env::var_os(crate::backup_trust::INSTALL_PREFIX_ENV),
    )) {
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

    let identity = match resolve_release_identity(&data_dir) {
        Ok(identity) => identity,
        Err(reason) => return BackupVerifyOutcome::rejected(reason),
    };
    // The private staging root holds the database copy read under the lock and
    // later the decrypted members. It is removed on every outcome.
    let staging_root = match create_staging_root(&data_dir) {
        Ok(path) => path,
        Err(reason) => return BackupVerifyOutcome::recoverable(reason),
    };
    let migrations = match read_local_migrations(&data_dir, &staging_root, identity.schema_version)
    {
        Ok(migrations) => migrations,
        Err(reason) => {
            let _ = fs::remove_dir_all(&staging_root);
            return BackupVerifyOutcome::rejected(reason);
        }
    };
    // The store copy is complete; the remaining work only touches the artifact
    // and the private staging directory, so the lock is released here.
    drop(store_lock);
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
        Err(reason) => {
            if fs::remove_dir_all(&staging_root).is_err() {
                return BackupVerifyOutcome::unknown(REASON_CLEANUP_FAILED);
            }
            return BackupVerifyOutcome::recoverable(reason);
        }
    };
    let verified = match verify_artifact_stream(&mut artifact, &expected, &keys, &staging_root) {
        Ok(verified) => verified,
        Err(error) => {
            // The streaming verifier removes its own staging directory on
            // failure; this removes the outer root, which also holds the
            // private copy of the live database. A failed removal is an
            // unknown outcome because plaintext may survive.
            if fs::remove_dir_all(&staging_root).is_err() {
                return BackupVerifyOutcome::unknown(REASON_CLEANUP_FAILED);
            }
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

/// PostgreSQL artifact verification.
///
/// The installed release is still the authority, but the applied migration
/// identities are read from the configured PostgreSQL control database rather
/// than from a local SQLite copy. The `pg_hba` admission barrier is not
/// installed by verification: this is a read-only operator command against a
/// reachable database.
fn execute_postgres(args: &BackupVerifyArgs, data_dir: &Path) -> BackupVerifyOutcome {
    let install_prefix = install_prefix_for(
        data_dir,
        std::env::var_os(crate::backup_trust::INSTALL_PREFIX_ENV),
    );
    let trust = match BackupTrustConfig::load(&default_trust_config_path_for(
        data_dir,
        std::env::var_os(crate::backup_trust::TRUST_CONFIG_ENV),
        std::env::var_os(crate::backup_trust::INSTALL_PREFIX_ENV),
    )) {
        Ok(config) => config,
        Err(error) => return trust_failure(error),
    };
    if let Err(error) = trust.verify_identity(data_dir) {
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
    let identity = match backup_release_identity(&install_prefix) {
        Ok(identity) => identity,
        Err(_) => return BackupVerifyOutcome::rejected(REASON_EXPECTED_RELEASE_UNAVAILABLE),
    };
    if identity.profile_id != "o3k-small-edge-v1" {
        return BackupVerifyOutcome::rejected("postgres-profile-unsupported");
    }
    let pg_config = match crate::backup_pg::PgBackupConfig::load(&install_prefix) {
        Ok(config) => config,
        Err(error) => return BackupVerifyOutcome::rejected(error.reason()),
    };

    let store_lock = match StoreAccessLock::acquire(data_dir) {
        Ok(lock) => lock,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return BackupVerifyOutcome::rejected("controller-active");
        }
        Err(_) => return BackupVerifyOutcome::recoverable("store-lock-unavailable"),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return BackupVerifyOutcome::recoverable(REASON_EXPECTED_RELEASE_UNAVAILABLE),
    };
    let migrations = match runtime.block_on(crate::backup_pg::read_migrations(
        &pg_config,
        identity.schema_version,
    )) {
        Ok(migrations) => migrations,
        Err(error) => {
            return BackupVerifyOutcome::rejected(error.reason());
        }
    };
    drop(store_lock);
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
        store_backend: crate::backup::BACKEND_POSTGRESQL.to_owned(),
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
    let staging_root = match create_staging_root(data_dir) {
        Ok(path) => path,
        Err(reason) => return BackupVerifyOutcome::recoverable(reason),
    };
    let mut artifact = match open_artifact(&args.artifact) {
        Ok(artifact) => artifact,
        Err(reason) => {
            if fs::remove_dir_all(&staging_root).is_err() {
                return BackupVerifyOutcome::unknown(REASON_CLEANUP_FAILED);
            }
            return BackupVerifyOutcome::recoverable(reason);
        }
    };
    let verified = match verify_artifact_stream(&mut artifact, &expected, &keys, &staging_root) {
        Ok(verified) => verified,
        Err(error) => {
            if fs::remove_dir_all(&staging_root).is_err() {
                return BackupVerifyOutcome::unknown(REASON_CLEANUP_FAILED);
            }
            return verification_failure(&error);
        }
    };
    let artifact_sha256 = artifact.finish();
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
    // One shared predicate with `o3k backup create`: missing configuration or
    // key material is recoverable, everything else rejects the precondition.
    if error.is_recoverable() {
        BackupVerifyOutcome::recoverable(error.reason())
    } else {
        BackupVerifyOutcome::rejected(error.reason())
    }
}

/// Maps a streaming-verification failure to a stable reason. The mapping uses
/// the typed failure class from [`crate::backup`], never a substring of the
/// free-text detail, so reworded diagnostics cannot change the operator reason
/// or exit status.
fn verification_failure(error: &ArtifactVerifyError) -> BackupVerifyOutcome {
    let class = error.class();
    let exit_code = exit_code_for(class);
    BackupVerifyOutcome::with_status(exit_code, status_for(exit_code), class.reason())
}

/// Only a failed plaintext-staging cleanup is quarantined (exit 4); every other
/// verification failure is a rejected artifact (exit 2).
const fn exit_code_for(class: ArtifactVerifyClass) -> u8 {
    match class {
        ArtifactVerifyClass::CleanupFailed => EXIT_UNKNOWN,
        _ => EXIT_REJECTED,
    }
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
///
/// `O_NONBLOCK` keeps a FIFO swapped in after path validation from blocking the
/// open forever; the `fstat` check below then rejects the non-regular inode.
fn open_artifact(path: &Path) -> Result<HashingReader<File>, &'static str> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
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

/// Reads the exact installed release identity from the installation prefix
/// shared with the artifact capture path and the trust-document default.
fn resolve_release_identity(data_dir: &Path) -> Result<BackupReleaseIdentity, &'static str> {
    // The install-prefix override is honored only for a non-installed
    // (TestLab/temporary) data directory; the packaged data directory always
    // uses the canonical prefix (see `backup_trust::trust_overrides_allowed`).
    let prefix = install_prefix_for(
        data_dir,
        std::env::var_os(crate::backup_trust::INSTALL_PREFIX_ENV),
    );
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

/// Copies the canonical database and a non-empty WAL sidecar into the private
/// verify staging directory. The live store is never opened.
fn copy_store_for_verification(
    data_dir: &Path,
    staging_root: &Path,
) -> Result<(PathBuf, bool), &'static str> {
    let source = data_dir.join(DATABASE_FILE_NAME);
    let copy = staging_root.join(DATABASE_FILE_NAME);
    copy_regular_nofollow(&source, &copy)?;
    let wal_source = data_dir.join(format!("{DATABASE_FILE_NAME}-wal"));
    let has_wal = match fs::symlink_metadata(&wal_source) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => return Err(REASON_EXPECTED_RELEASE_UNAVAILABLE),
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(REASON_EXPECTED_RELEASE_UNAVAILABLE);
            }
            if metadata.len() == 0 {
                false
            } else {
                copy_regular_nofollow(
                    &wal_source,
                    &staging_root.join(format!("{DATABASE_FILE_NAME}-wal")),
                )?;
                true
            }
        }
    };
    Ok((copy, has_wal))
}

/// Copies one regular, no-follow source file into a fresh private file.
fn copy_regular_nofollow(source: &Path, destination: &Path) -> Result<(), &'static str> {
    let input = open(
        source,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| REASON_EXPECTED_RELEASE_UNAVAILABLE)?;
    let metadata = rustix::fs::fstat(&input).map_err(|_| REASON_EXPECTED_RELEASE_UNAVAILABLE)?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(REASON_EXPECTED_RELEASE_UNAVAILABLE);
    }
    let output = open(
        destination,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| "staging-unavailable")?;
    let mut input = File::from(input);
    let mut output = File::from(output);
    io::copy(&mut input, &mut output).map_err(|_| "staging-unavailable")?;
    output.sync_all().map_err(|_| "staging-unavailable")?;
    Ok(())
}

/// Reads the applied migration identities from a private copy of the canonical
/// store with a read-only connection. The store must already be at the
/// release's schema version; the live database is not opened, migrated,
/// checkpointed or locked. The copy is taken under the store-access lock.
fn read_local_migrations(
    data_dir: &Path,
    staging_root: &Path,
    release_schema_version: u64,
) -> Result<Vec<MigrationIdentity>, &'static str> {
    let (path, has_wal) = copy_store_for_verification(data_dir, staging_root)?;
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
        // `immutable=1` skips locking/WAL recovery and is only valid when the
        // copied database has no non-empty WAL sidecar. With a WAL, SQLite
        // needs to open the copy normally so committed frames are replayed.
        let options = if has_wal {
            options
        } else {
            options.immutable(true)
        };
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(options)
            .await
            .map_err(|_| REASON_EXPECTED_RELEASE_UNAVAILABLE)?;
        let rows = crate::db::sqlite_migration_inventory(&pool)
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
        // The exact operator strings are part of the CLI contract. They come
        // from one table and are asserted here literally, so a wording change
        // in a diagnostic can never silently rename a reason code.
        let cases = [
            (
                ArtifactVerifyClass::RevokedSigningKey,
                EXIT_REJECTED,
                "revoked-signing-key",
            ),
            (
                ArtifactVerifyClass::UntrustedSigningKey,
                EXIT_REJECTED,
                "untrusted-signing-key",
            ),
            (
                ArtifactVerifyClass::KeyIdentityMismatch,
                EXIT_REJECTED,
                "key-identity-mismatch",
            ),
            (
                ArtifactVerifyClass::SignatureInvalid,
                EXIT_REJECTED,
                "signature-invalid",
            ),
            (
                ArtifactVerifyClass::ReleaseMismatch,
                EXIT_REJECTED,
                "release-mismatch",
            ),
            (
                ArtifactVerifyClass::MissingRequiredMember,
                EXIT_REJECTED,
                "missing-required-member",
            ),
            (
                ArtifactVerifyClass::SchemaInvalid,
                EXIT_REJECTED,
                "schema-invalid",
            ),
            (
                ArtifactVerifyClass::ArtifactTooLarge,
                EXIT_REJECTED,
                "artifact-too-large",
            ),
            (
                ArtifactVerifyClass::RecipientKeyMismatch,
                EXIT_REJECTED,
                "recipient-key-mismatch",
            ),
            (
                ArtifactVerifyClass::CorruptArtifact,
                EXIT_REJECTED,
                "corrupt-artifact",
            ),
            (
                ArtifactVerifyClass::CleanupFailed,
                EXIT_UNKNOWN,
                "verification-cleanup-failed",
            ),
        ];
        for (class, exit_code, reason) in cases {
            assert_eq!(class.reason(), reason, "{class:?}");
            let outcome = verification_failure(&ArtifactVerifyError::new(class, "detail"));
            assert_eq!(outcome.exit_code, exit_code, "{class:?}");
            assert_eq!(outcome.json["reason"], reason, "{class:?}");
            assert_eq!(outcome.json["status"], status_for(exit_code), "{class:?}");
        }
        assert_eq!(REASON_CLEANUP_FAILED, "verification-cleanup-failed");
        // Only cleanup is quarantined; everything else is a rejected artifact.
        assert_eq!(exit_code_for(ArtifactVerifyClass::CleanupFailed), 4);
        assert_eq!(exit_code_for(ArtifactVerifyClass::CorruptArtifact), 2);
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
    fn artifact_open_never_blocks_on_a_fifo() {
        // A FIFO swapped in after path validation must fail the regular-file
        // check instead of blocking the open until a writer appears.
        let root = TempRoot::new("fifo");
        let fifo = root.0.join("artifact.fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .expect("create fifo");
        let started = std::time::Instant::now();
        assert!(open_artifact(&fifo).is_err_and(|reason| reason == "artifact-not-regular-file"));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "opening a fifo blocked for {:?}",
            started.elapsed()
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
    fn missing_local_store_fails_closed_as_expected_release_unavailable() {
        let root = TempRoot::new("missing-store");
        let staging = root.0.join("staging");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&staging)
            .expect("staging");
        assert_eq!(
            read_local_migrations(&root.0, &staging, 53),
            Err(REASON_EXPECTED_RELEASE_UNAVAILABLE)
        );
    }

    #[test]
    fn verification_reads_a_private_copy_including_a_non_empty_wal() {
        let root = TempRoot::new("copy-store");
        fs::write(root.0.join(DATABASE_FILE_NAME), b"main-database").expect("main database");
        fs::write(
            root.0.join(format!("{DATABASE_FILE_NAME}-wal")),
            b"wal-frames",
        )
        .expect("wal");
        let staging = root.0.join("staging");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&staging)
            .expect("staging");
        let (copy, has_wal) = copy_store_for_verification(&root.0, &staging).expect("copy store");
        assert!(has_wal);
        assert_eq!(fs::read(&copy).expect("copied database"), b"main-database");
        assert_eq!(
            fs::read(staging.join(format!("{DATABASE_FILE_NAME}-wal"))).expect("copied wal"),
            b"wal-frames"
        );
        // The source files are untouched by the copy.
        assert_eq!(
            fs::read(root.0.join(DATABASE_FILE_NAME)).expect("source database"),
            b"main-database"
        );
        // The copy is private, not a link to the live file.
        let mode = fs::metadata(&copy)
            .expect("copy metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
