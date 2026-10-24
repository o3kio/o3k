//! Process-level tests for `o3k backup verify`.
//!
//! The library keeps the artifact format contract module crate-private until
//! the capture slice lands its public surface, so this test compiles the same
//! source file privately to build a real artifact. That keeps the test honest:
//! the artifact is produced by the accepted builder, written to disk, and then
//! verified by the real `o3k` binary through `CARGO_BIN_EXE_o3k`.
//!
//! Every fixture lives in one private temporary directory. The trust document
//! and recipient key are 0600, the containing directory is 0700, and the site
//! and installation identities are derived from the fixture data directory
//! exactly as the verifier derives them.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "../src/backup.rs"]
#[allow(dead_code)]
mod backup;

use std::{
    fs,
    io::Cursor,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    time::Duration,
};

use backup::{ArtifactSigner, CreateOptions, StreamMember, create_artifact_stream};
use ed25519_dalek::{Signer, SigningKey};
use hpke::{Kem, Serializable, kem::X25519HkdfSha256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use uuid::Uuid;

const SITE_PROFILE: &str = "o3k-demo-v1";
const SIGNING_KEY_ID: &str = "signing-1";
const RECIPIENT_KEY_ID: &str = "recovery-1";
const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

struct TestSigner(SigningKey);

impl ArtifactSigner for TestSigner {
    fn key_id(&self) -> &str {
        SIGNING_KEY_ID
    }

    fn sign_manifest(&self, signature_input: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(signature_input).to_bytes())
    }

    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}

struct Scenario {
    root: PathBuf,
    data_dir: PathBuf,
    prefix: PathBuf,
    config_path: PathBuf,
    recipient_key_path: PathBuf,
    release_manifest_path: PathBuf,
    artifact_path: PathBuf,
    db_path: PathBuf,
    trust_document: Value,
    release_manifest: Value,
    artifact: Vec<u8>,
}

impl Drop for Scenario {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn create_private_dir(path: &Path) {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .expect("create private fixture directory");
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write fixture file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("restrict fixture file");
}

fn write_private_json(path: &Path, value: &Value) {
    let encoded = serde_json::to_vec_pretty(value).expect("serialize fixture JSON");
    write_private_file(path, &encoded);
}

impl Scenario {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("o3k-backup-verify-it-{label}-{}", Uuid::now_v7()));
        create_private_dir(&root);
        let data_dir = root.join("data");
        create_private_dir(&data_dir);
        let prefix = root.join("prefix");
        let share = prefix.join("share/o3k");
        fs::create_dir_all(&share).expect("create release prefix");
        for directory in [prefix.clone(), prefix.join("share"), share] {
            // 0755 like a production install; the ambient umask must not make
            // the release-manifest parent group-writable.
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))
                .expect("restrict release prefix");
        }
        let release_manifest_path = prefix.join("share/o3k/release-manifest.json");
        let config_path = root.join("backup-trust.json");
        let recipient_key_path = root.join("recipient.key");
        let artifact_path = root.join("artifact.bin");
        let db_path = data_dir.join("o3k.sqlite");

        let StoreFixture {
            signing,
            recipient_private,
            recipient_public,
            migrations,
            schema_version,
        } = build_keys_and_store(&db_path);
        // Hex encoding keeps the fixture deterministic: the trust parser trims
        // ASCII whitespace before inspecting the key bytes, so a raw 32-byte
        // key that happens to begin or end with a whitespace byte would be
        // rejected.
        write_private_file(
            &recipient_key_path,
            hex::encode(recipient_private.to_bytes()).as_bytes(),
        );

        let (installation_token, site_token) =
            o3k_store::identity_tokens(&data_dir).expect("derive canonical identity");
        let site_id = hex::encode(site_token);
        let installation_id = hex::encode(installation_token);

        let release_artifact_sha256 = "a".repeat(64);
        let source = json!({
            "o3k_version": "0.4.0",
            "source_sha": SOURCE_SHA,
            "release_artifact_sha256": release_artifact_sha256,
            "profile_id": SITE_PROFILE,
        });
        let store = json!({
            "backend": "sqlite",
            "server_version": "3.50.0",
            "schema_version": schema_version,
            "migrations": migrations,
        });
        let options = CreateOptions {
            backup_id: "backup-verify-test-1".to_owned(),
            created_at: "2026-10-19T12:00:00Z".to_owned(),
            site_id: site_id.clone(),
            installation_id: installation_id.clone(),
            source,
            store,
            consistency: json!({
                "method": "sqlite_vacuum_into",
                "write_quiescence": true,
                "worker_quiescence": true,
                "in_flight_operations": "none",
                "quiescence_generation": "generation-1",
                "snapshot_started_at": "2026-10-19T12:00:00Z",
                "snapshot_completed_at": "2026-10-19T12:00:01Z",
            }),
            state_inventory: o3k_store::state_inventory::baseline_state_inventory()
                .expect("committed state inventory"),
            consistency_generation: "generation-1".to_owned(),
            recipient_key_id: RECIPIENT_KEY_ID.to_owned(),
            recipient_public_key: recipient_public.to_bytes().into(),
            artifact_key_id: "artifact-1".to_owned(),
            signing_key_id: SIGNING_KEY_ID.to_owned(),
        };
        let members = vec![
            StreamMember {
                name: "database/state.sqlite".to_owned(),
                media_type: "application/vnd.sqlite3".to_owned(),
                plaintext_size_bytes: 8,
                source: Cursor::new(b"snapshot".to_vec()),
            },
            StreamMember {
                name: "config/o3kd.env".to_owned(),
                media_type: "text/plain".to_owned(),
                plaintext_size_bytes: 23,
                source: Cursor::new(b"O3K_PROFILE=o3k-demo-v1".to_vec()),
            },
        ];
        let builder_staging = root.join(".builder-staging");
        create_private_dir(&builder_staging);
        let staged = create_artifact_stream(
            &options,
            members,
            &builder_staging,
            &TestSigner(signing.clone()),
        )
        .expect("build artifact");
        let artifact = fs::read(&staged.path).expect("read built artifact");
        fs::remove_dir_all(&staged.staging_directory).expect("remove builder staging");
        fs::remove_dir_all(&builder_staging).expect("remove builder staging root");
        write_private_file(&artifact_path, &artifact);

        let release_manifest = json!({
            "version": "0.4.0",
            "source_commit": SOURCE_SHA,
            "release_artifact_sha256": release_artifact_sha256,
            "profile_id": SITE_PROFILE,
            "schema_version": schema_version,
        });
        write_private_json(&release_manifest_path, &release_manifest);

        let trust_document = json!({
            "format": "o3k-backup-trust-v1",
            "site_id": site_id,
            "installation_id": installation_id,
            "profile_id": SITE_PROFILE,
            "artifact_signing": {
                "key_id": SIGNING_KEY_ID,
                "ed25519_public_key": hex::encode(signing.verifying_key().to_bytes()),
            },
            "recipient": {
                "key_id": RECIPIENT_KEY_ID,
                "x25519_private_key_file": recipient_key_path.display().to_string(),
            },
            "revoked_key_ids": [],
            "custody": {
                "record_id": "custody-1",
                "purpose": "artifact-signing",
                "key_fingerprint": hex::encode(Sha256::digest(signing.verifying_key().to_bytes())),
                "threshold": "2-of-3",
                "custodians": ["principal-a", "principal-b", "principal-c"],
                "storage_class": "offline-safe",
                "expires_at": "2035-01-01T00:00:00Z",
            },
        });
        write_private_json(&config_path, &trust_document);

        Self {
            root,
            data_dir,
            prefix,
            config_path,
            recipient_key_path,
            release_manifest_path,
            artifact_path,
            db_path,
            trust_document,
            release_manifest,
            artifact,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_o3k"));
        command
            .arg("backup")
            .arg("verify")
            .arg("--artifact")
            .arg(&self.artifact_path)
            .env("O3K_DATA_DIR", &self.data_dir)
            .env("O3K_BACKUP_TRUST_CONFIG", &self.config_path)
            .env("O3K_INSTALL_PREFIX", &self.prefix);
        command
    }

    fn run(&self) -> Output {
        self.command().output().expect("run o3k backup verify")
    }

    fn write_trust(&self) {
        write_private_json(&self.config_path, &self.trust_document);
    }

    fn write_release(&self) {
        write_private_json(&self.release_manifest_path, &self.release_manifest);
    }

    fn write_artifact(&self, bytes: &[u8]) {
        write_private_file(&self.artifact_path, bytes);
    }
}

struct StoreFixture {
    signing: SigningKey,
    recipient_private: <X25519HkdfSha256 as Kem>::PrivateKey,
    recipient_public: <X25519HkdfSha256 as Kem>::PublicKey,
    migrations: Vec<Value>,
    schema_version: u64,
}

fn build_keys_and_store(db_path: &Path) -> StoreFixture {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test runtime");
    let rows = runtime.block_on(async {
        let store = o3k_store::testkit::open_file(db_path)
            .await
            .expect("create migrated fixture store");
        // The store's own connection keeps the WAL sidecars materialized while
        // this separate read-only connection reads the applied migrations.
        let options = SqliteConnectOptions::new()
            .filename(db_path)
            .read_only(true)
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("open read-only migration reader");
        let rows: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&pool)
                .await
                .expect("read applied migrations");
        pool.close().await;
        drop(store);
        rows
    });
    let schema_version = u64::try_from(rows.last().expect("applied migrations").0)
        .expect("non-negative migration version");
    let migrations = rows
        .into_iter()
        .map(|(version, checksum)| {
            json!({
                "version": u64::try_from(version).expect("non-negative migration version"),
                "checksum": o3k::backup_verify::migration_checksum(&checksum),
            })
        })
        .collect();

    let signing = SigningKey::from_bytes(&[17_u8; 32]);
    let (recipient_private, recipient_public) = X25519HkdfSha256::gen_keypair();
    StoreFixture {
        signing,
        recipient_private,
        recipient_public,
        migrations,
        schema_version,
    }
}

fn stdout_json(output: &Output) -> Value {
    let stdout = String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout");
    assert_eq!(
        stdout.lines().count(),
        1,
        "stdout must be exactly one line: {stdout:?}"
    );
    serde_json::from_str(stdout.trim_end()).expect("bounded JSON stdout")
}

fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_reason(output: &Output, expected_exit: i32, expected_reason: &str) -> Value {
    assert_exit(output, expected_exit);
    let value = stdout_json(output);
    assert_eq!(value["reason"], expected_reason);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(expected_reason),
        "stderr must carry the stable reason: {stderr}"
    );
    assert!(
        !stderr.contains('/'),
        "stderr must not contain a path: {stderr}"
    );
    value
}

fn assert_no_staging_left(data_dir: &std::path::Path) {
    let leftovers: Vec<_> = fs::read_dir(data_dir)
        .expect("read data directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".o3k-verify-staging-")
        })
        .collect();
    assert!(leftovers.is_empty(), "verification staging was not removed");
}

#[test]
fn verifies_a_trusted_artifact_against_the_installed_release() {
    let scenario = Scenario::new("success");
    let output = scenario.run();
    assert_exit(&output, 0);
    assert!(
        output.stderr.is_empty(),
        "success must not write stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = stdout_json(&output);
    assert_eq!(value["status"], "verified");
    assert_eq!(value["backup_id"], "backup-verify-test-1");
    assert_eq!(value["release_match"], true);
    assert_eq!(value["signing_key_id"], SIGNING_KEY_ID);
    assert_eq!(value["recipient_key_id"], RECIPIENT_KEY_ID);
    assert_eq!(value["manifest"]["profile_id"], SITE_PROFILE);
    assert_eq!(value["manifest"]["store_backend"], "sqlite");
    assert_eq!(value["members"].as_array().map(Vec::len), Some(2));
    assert_eq!(value["members"][0]["name"], "config/o3kd.env");
    assert_eq!(value["members"][0]["plaintext_size_bytes"], 23);
    let digest = value["artifact_sha256"].as_str().expect("artifact digest");
    assert_eq!(digest.len(), 64);
    assert_no_staging_left(&scenario.data_dir);
}

#[test]
fn rejects_a_revoked_signing_key() {
    let mut scenario = Scenario::new("revoked");
    scenario.trust_document["revoked_key_ids"] = json!([SIGNING_KEY_ID]);
    scenario.write_trust();
    assert_reason(&scenario.run(), 2, "revoked-signing-key");
}

#[test]
fn rejects_a_signing_key_not_trusted_for_the_release_profile() {
    let mut scenario = Scenario::new("untrusted-profile");
    scenario.trust_document["profile_id"] = json!("o3k-small-edge-v1");
    scenario.write_trust();
    assert_reason(&scenario.run(), 2, "untrusted-signing-key");
}

#[test]
fn rejects_a_different_release_manifest() {
    let mut scenario = Scenario::new("release-mismatch");
    scenario.release_manifest["version"] = json!("0.4.1");
    scenario.write_release();
    assert_reason(&scenario.run(), 2, "release-mismatch");
}

#[test]
fn rejects_a_corrupted_artifact() {
    let scenario = Scenario::new("corrupt");
    let mut corrupted = scenario.artifact.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xff;
    scenario.write_artifact(&corrupted);
    assert_reason(&scenario.run(), 2, "corrupt-artifact");
}

#[test]
fn rejects_a_mismatched_recipient_key() {
    let scenario = Scenario::new("recipient-mismatch");
    let (replacement, _public) = X25519HkdfSha256::gen_keypair();
    write_private_file(
        &scenario.recipient_key_path,
        hex::encode(replacement.to_bytes()).as_bytes(),
    );
    assert_reason(&scenario.run(), 2, "recipient-key-mismatch");
}

#[test]
fn rejects_a_foreign_installation_identity() {
    let mut scenario = Scenario::new("identity-mismatch");
    scenario.trust_document["site_id"] = json!("other-site");
    scenario.write_trust();
    assert_reason(&scenario.run(), 2, "identity-mismatch");
}

#[test]
fn reports_an_unavailable_local_store_as_expected_release_unavailable() {
    let scenario = Scenario::new("missing-store");
    fs::remove_file(&scenario.db_path).expect("remove fixture store");
    assert_reason(&scenario.run(), 2, "expected-release-unavailable");
}

#[test]
fn reports_a_missing_release_manifest_as_expected_release_unavailable() {
    let scenario = Scenario::new("missing-release");
    fs::remove_file(&scenario.release_manifest_path).expect("remove release manifest");
    assert_reason(&scenario.run(), 2, "expected-release-unavailable");
}

#[test]
fn reports_a_missing_trust_document_as_recoverable() {
    let scenario = Scenario::new("missing-trust");
    fs::remove_file(&scenario.config_path).expect("remove trust document");
    assert_reason(&scenario.run(), 3, "trust-config-unavailable");
}

/// D4: `verify` is a store-opening command, so a live controller (or a capture
/// that is waiting for its signature) must reject it before any store read.
#[test]
fn rejects_verification_while_the_store_lock_is_held() {
    let scenario = Scenario::new("controller-active");
    let live_owner = o3k_store::StoreAccessLock::acquire(&scenario.data_dir)
        .expect("hold the lifetime store lock");
    let output = scenario.run();
    drop(live_owner);
    assert_reason(&output, 2, "controller-active");
    // A rejected run must not leave plaintext staging behind.
    assert_no_staging_left(&scenario.data_dir);
}

#[test]
fn rejects_a_relative_artifact_path() {
    let scenario = Scenario::new("relative");
    let output = Command::new(env!("CARGO_BIN_EXE_o3k"))
        .arg("backup")
        .arg("verify")
        .arg("--artifact")
        .arg("relative.bin")
        .env("O3K_DATA_DIR", &scenario.data_dir)
        .env("O3K_BACKUP_TRUST_CONFIG", &scenario.config_path)
        .env("O3K_INSTALL_PREFIX", &scenario.prefix)
        .output()
        .expect("run o3k backup verify");
    assert_reason(&output, 2, "artifact-not-absolute");
}

#[test]
fn rejects_a_missing_artifact_file() {
    let scenario = Scenario::new("missing-artifact");
    let missing = scenario.root.join("absent.bin");
    let output = Command::new(env!("CARGO_BIN_EXE_o3k"))
        .arg("backup")
        .arg("verify")
        .arg("--artifact")
        .arg(&missing)
        .env("O3K_DATA_DIR", &scenario.data_dir)
        .env("O3K_BACKUP_TRUST_CONFIG", &scenario.config_path)
        .env("O3K_INSTALL_PREFIX", &scenario.prefix)
        .output()
        .expect("run o3k backup verify");
    assert_reason(&output, 2, "artifact-missing");
}

#[test]
fn help_lists_the_verify_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_o3k"))
        .arg("backup")
        .arg("verify")
        .arg("--help")
        .output()
        .expect("run o3k backup verify --help");
    assert_exit(&output, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--artifact"), "{stdout}");
    assert!(stdout.contains("Absolute path"), "{stdout}");
}
