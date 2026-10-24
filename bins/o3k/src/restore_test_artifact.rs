//! Test-only construction of a genuinely authenticated PostgreSQL artifact.
//!
//! This deliberately uses the production artifact writer and streaming verifier;
//! it is a software-key fixture, not evidence for the production HSM signer.

#![cfg(test)]
#![allow(clippy::expect_used)]

use std::{io::Cursor, os::unix::fs::PermissionsExt, path::Path};

use ed25519_dalek::{Signer, SigningKey};
use hpke::Serializable;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::backup::{
    ArtifactSigner, ArtifactTrust, ArtifactVerificationKeys, CreateOptions, ExpectedRelease,
    MigrationIdentity, PlainMember, VerifiedArtifact, create_artifact, verify_artifact_stream,
};

const SITE: &str = "site-1";
const INSTALLATION: &str = "install-1";
const PROFILE: &str = "o3k-small-edge-v1";
const VERSION: &str = "0.4.0";
const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const RELEASE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct FixtureSigner(SigningKey);
impl ArtifactSigner for FixtureSigner {
    fn key_id(&self) -> &str {
        "test-signing-key"
    }
    fn sign_manifest(&self, input: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(input).to_bytes())
    }
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}

struct FixtureTrust;
impl ArtifactTrust for FixtureTrust {
    fn signing_key_is_trusted(
        &self,
        key_id: &str,
        site_id: &str,
        profile_id: &str,
        _key: &ed25519_dalek::VerifyingKey,
    ) -> Result<bool, String> {
        Ok(key_id == "test-signing-key" && site_id == SITE && profile_id == PROFILE)
    }
    fn signing_key_is_revoked(&self, _key_id: &str) -> Result<bool, String> {
        Ok(false)
    }
}

fn migrations() -> Vec<MigrationIdentity> {
    let migrator = sqlx::migrate!("../../crates/o3k-store/migrations_postgres");
    migrator
        .migrations
        .iter()
        .map(|m| MigrationIdentity {
            version: m.version as u64,
            checksum: format!("{:x}", Sha256::digest(m.checksum.as_ref())),
        })
        .collect()
}

fn inventory() -> Vec<Value> {
    o3k_store::state_inventory::baseline_state_inventory()
        .expect("baseline state inventory is part of the test release")
}

/// Build, encrypt, sign, and independently verify a PostgreSQL artifact.
/// The returned members are private staged plaintexts produced by the verifier.
pub(super) fn build_and_authenticate(
    dump: Vec<u8>,
    staging: &Path,
) -> Result<VerifiedArtifact, String> {
    let signing = FixtureSigner(SigningKey::from_bytes(&[0x31; 32]));
    let (recipient_private, recipient_public) =
        <hpke::kem::X25519HkdfSha256 as hpke::Kem>::gen_keypair();
    let inv = inventory();
    let migs = migrations();
    let schema_version = migs.last().map(|m| m.version).unwrap_or(0);
    let options = CreateOptions {
        backup_id: "restore-test-operation".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        site_id: SITE.into(),
        installation_id: INSTALLATION.into(),
        source: json!({"o3k_version": VERSION, "source_sha": SOURCE_SHA,
            "release_artifact_sha256": RELEASE_SHA, "profile_id": PROFILE}),
        store: json!({"backend":"postgresql", "server_version":"16",
            "schema_version":schema_version, "migrations":migs.iter().map(|m|
                json!({"version":m.version,"checksum":m.checksum})).collect::<Vec<_>>() }),
        consistency: json!({"method":"postgresql_native_dump",
            "write_quiescence":true,"worker_quiescence":true,"in_flight_operations":"none",
            "quiescence_generation":"test-generation",
            "snapshot_started_at":"2026-01-01T00:00:00Z",
            "snapshot_completed_at":"2026-01-01T00:00:01Z"}),
        state_inventory: inv.clone(),
        consistency_generation: "test-generation".into(),
        recipient_key_id: "test-recovery-key".into(),
        recipient_public_key: recipient_public.to_bytes().into(),
        artifact_key_id: "artifact-content-key-v1".into(),
        signing_key_id: "test-signing-key".into(),
    };
    let members = vec![
        PlainMember {
            name: "database/o3k.dump".into(),
            media_type: "application/vnd.postgresql.custom".into(),
            bytes: dump,
        },
        PlainMember {
            name: "metadata/capture.json".into(),
            media_type: "application/json".into(),
            bytes: b"{}".to_vec(),
        },
        PlainMember {
            name: "release/release-manifest.json".into(),
            media_type: "application/json".into(),
            bytes: b"{}".to_vec(),
        },
        PlainMember {
            name: "trust/backup-trust.json".into(),
            media_type: "application/json".into(),
            bytes: b"{}".to_vec(),
        },
    ];
    let (artifact, _) = create_artifact(&options, members, &signing)?;
    let expected = ExpectedRelease {
        site_id: SITE.into(),
        installation_id: INSTALLATION.into(),
        o3k_version: VERSION.into(),
        source_sha: SOURCE_SHA.into(),
        release_artifact_sha256: RELEASE_SHA.into(),
        profile_id: PROFILE.into(),
        store_backend: "postgresql".into(),
        schema_version,
        migrations: migs,
        state_inventory: inv,
    };
    // Explicit fixture export for the disposable process campaign only.
    // Key bytes remain in a private file, never argv/environment/stdout.
    if let Some(directory) = std::env::var_os("O3K_D10_TEST_EXPORT_DIR") {
        let directory = std::path::PathBuf::from(directory);
        if !directory.join("artifact.o3k").exists() {
            let public = signing.verifying_key();
            std::fs::write(directory.join("artifact.o3k"), &artifact)
                .map_err(|_| "fixture export failed")?;
            std::fs::write(
                directory.join("recipient.key"),
                recipient_private.to_bytes(),
            )
            .map_err(|_| "fixture export failed")?;
            let trust = json!({"format":"o3k-backup-trust-v1","site_id":SITE,"installation_id":INSTALLATION,
                "profile_id":PROFILE,"artifact_signing":{"key_id":"test-signing-key","ed25519_public_key":hex::encode(public.as_bytes())},
                "recipient":{"key_id":"test-recovery-key","x25519_private_key_file":directory.join("recipient.key"),"x25519_public_key":hex::encode(recipient_public.to_bytes())},
                "revoked_key_ids":[],"custody":{"record_id":"fixture-only","purpose":"artifact-signing",
                    "key_fingerprint":hex::encode(Sha256::digest(public.as_bytes())),"threshold":"2-of-3",
                    "custodians":["test-a","test-b","test-c"],"storage_class":"offline-safe","expires_at":"2035-01-01T00:00:00Z"}});
            std::fs::write(
                directory.join("backup-trust.json"),
                serde_json::to_vec(&trust).map_err(|_| "fixture serialization")?,
            )
            .map_err(|_| "fixture export failed")?;
            let release = json!({"version":VERSION,"source_commit":SOURCE_SHA,"release_artifact_sha256":RELEASE_SHA,"profile_id":PROFILE,"schema_version":schema_version});
            std::fs::write(
                directory.join("release-manifest.json"),
                serde_json::to_vec(&release).map_err(|_| "fixture serialization")?,
            )
            .map_err(|_| "fixture export failed")?;
        }
    }
    if let Some(directory) = std::env::var_os("O3K_D10_TEST_EXPORT_DIR") {
        for name in [
            "artifact.o3k",
            "recipient.key",
            "backup-trust.json",
            "release-manifest.json",
        ] {
            std::fs::set_permissions(
                std::path::Path::new(&directory).join(name),
                std::fs::Permissions::from_mode(0o600),
            )
            .map_err(|_| "fixture protection failed")?;
        }
    }
    let trust = FixtureTrust;
    let keys = ArtifactVerificationKeys {
        signing_key_id: "test-signing-key",
        signer: &signing.verifying_key(),
        trust: &trust,
        recipient_key_id: "test-recovery-key",
        recipient: &recipient_private,
    };
    verify_artifact_stream(&mut Cursor::new(artifact), &expected, &keys, staging)
        .map_err(|e| e.to_string())
}
