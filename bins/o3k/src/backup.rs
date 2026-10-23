//! Authenticated PP.6 artifact format primitives.
//!
//! This module deliberately accepts already-captured members. The command
//! boundary owns store quiescence and capture; callers must not pass live
//! database paths or secret-bearing values to logging code.

use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::DateTime;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::AesGcm256, kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use openssl::symm::{Cipher, Crypter, Mode};
#[cfg(not(test))]
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(test)]
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
#[cfg(test)]
use zeroize::Zeroize;
use zeroize::Zeroizing;

const MAGIC: &[u8; 12] = b"O3KPP6BK\x00\x00\x00\x01";
const FORMAT_VERSION: &str = "1";
const MAX_MEMBERS: usize = 64;
const MAX_MEMBER_BYTES: usize = 1_073_741_824;
const MAX_TOTAL_PLAINTEXT: usize = 4_294_967_296;
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 5 * 1024 * 1024 * 1024;
const HPKE_INFO: &[u8] = b"O3K-PP6-ARTIFACT-KEY-WRAP-V1\0";
const SIGN_DOMAIN: &[u8] = b"O3K-PP6-BACKUP-MANIFEST-V1\0";
const STREAM_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: String,
    pub backup_id: String,
    pub created_at: String,
    pub site_id: String,
    pub installation_id: String,
    pub source: Value,
    pub store: Value,
    pub consistency: Value,
    pub state_inventory: Vec<Value>,
    pub members: Vec<MemberRecord>,
    pub encryption: Encryption,
    pub authentication: Authentication,
    pub excluded_state: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberRecord {
    pub name: String,
    pub plaintext_size_bytes: u64,
    pub size_bytes: u64,
    pub sha256: String,
    pub media_type: String,
    pub encrypted: bool,
    pub consistency_generation: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Encryption {
    pub algorithm: String,
    pub key_id: String,
    pub key_is_external: bool,
    pub key_wrapping: KeyWrapping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyWrapping {
    pub algorithm: String,
    pub recipient_key_id: String,
    pub enc: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authentication {
    pub algorithm: String,
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg(test)]
pub struct PlainMember {
    pub name: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

#[cfg(test)]
impl Drop for PlainMember {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Encrypts one manifest member using one AES-256-GCM invocation while
/// retaining only a fixed-size input/output window. The writer must be private
/// staging: GCM ciphertext is not committed until the tag has been written and
/// the staged member has passed independent verification.
fn encrypt_member_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    expected_plaintext_size: u64,
) -> Result<(u64, u64, String), String> {
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Encrypt, key, Some(nonce))
        .map_err(|_| "backup encryption initialization failed".to_owned())?;
    crypter.pad(false);
    crypter
        .aad_update(aad)
        .map_err(|_| "backup encryption initialization failed".to_owned())?;
    let mut digest = Sha256::new();
    let mut input = [0_u8; STREAM_CHUNK_BYTES];
    let mut output = [0_u8; STREAM_CHUNK_BYTES + 16];
    let mut plaintext_size = 0_u64;
    loop {
        let read = reader
            .read(&mut input)
            .map_err(|_| "backup member source could not be read".to_owned())?;
        if read == 0 {
            break;
        }
        let read_bytes = u64::try_from(read).map_err(|_| "backup member size is invalid")?;
        plaintext_size = plaintext_size
            .checked_add(read_bytes)
            .ok_or("backup member size overflow")?;
        if plaintext_size > expected_plaintext_size {
            return Err("backup member exceeds its captured size".to_owned());
        }
        let written = crypter
            .update(&input[..read], &mut output)
            .map_err(|_| "backup member encryption failed".to_owned())?;
        writer
            .write_all(&output[..written])
            .map_err(|_| "backup staging write failed".to_owned())?;
        digest.update(&output[..written]);
    }
    let written = crypter
        .finalize(&mut output)
        .map_err(|_| "backup member encryption failed".to_owned())?;
    writer
        .write_all(&output[..written])
        .map_err(|_| "backup staging write failed".to_owned())?;
    digest.update(&output[..written]);
    let mut tag = [0_u8; 16];
    crypter
        .get_tag(&mut tag)
        .map_err(|_| "backup member encryption failed".to_owned())?;
    writer
        .write_all(&tag)
        .map_err(|_| "backup staging write failed".to_owned())?;
    digest.update(tag);
    let ciphertext_size = plaintext_size
        .checked_add(16)
        .ok_or("backup member size overflow")?;
    Ok((
        plaintext_size,
        ciphertext_size,
        hex::encode(digest.finalize()),
    ))
}

/// Decrypts ciphertext to private staging. Plaintext bytes are provisional
/// until `finalize` authenticates the final GCM tag; callers must not expose or
/// use the output until the entire artifact has passed verification.
fn decrypt_member_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_size: u64,
) -> Result<(u64, String), String> {
    let encrypted_body_size = ciphertext_size
        .checked_sub(16)
        .ok_or("backup member ciphertext is truncated")?;
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, key, Some(nonce))
        .map_err(|_| "backup decryption initialization failed".to_owned())?;
    crypter.pad(false);
    crypter
        .aad_update(aad)
        .map_err(|_| "backup decryption initialization failed".to_owned())?;
    let mut digest = Sha256::new();
    let mut input = [0_u8; STREAM_CHUNK_BYTES];
    let mut output = [0_u8; STREAM_CHUNK_BYTES + 16];
    let mut remaining = encrypted_body_size;
    let mut plaintext_size = 0_u64;
    while remaining > 0 {
        let amount = usize::try_from(remaining.min(STREAM_CHUNK_BYTES as u64))
            .map_err(|_| "backup member size is invalid")?;
        reader
            .read_exact(&mut input[..amount])
            .map_err(|_| "backup member ciphertext is truncated".to_owned())?;
        digest.update(&input[..amount]);
        let written = crypter
            .update(&input[..amount], &mut output)
            .map_err(|_| "backup member decryption failed".to_owned())?;
        writer
            .write_all(&output[..written])
            .map_err(|_| "backup private staging write failed".to_owned())?;
        plaintext_size = plaintext_size
            .checked_add(written as u64)
            .ok_or("backup plaintext size overflow")?;
        remaining -= amount as u64;
    }
    let mut tag = [0_u8; 16];
    reader
        .read_exact(&mut tag)
        .map_err(|_| "backup member authentication tag is truncated".to_owned())?;
    digest.update(tag);
    crypter
        .set_tag(&tag)
        .map_err(|_| "backup member authentication failed".to_owned())?;
    let written = crypter
        .finalize(&mut output)
        .map_err(|_| "backup member authentication failed".to_owned())?;
    writer
        .write_all(&output[..written])
        .map_err(|_| "backup private staging write failed".to_owned())?;
    plaintext_size = plaintext_size
        .checked_add(written as u64)
        .ok_or("backup plaintext size overflow")?;
    Ok((plaintext_size, hex::encode(digest.finalize())))
}

#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub backup_id: String,
    pub created_at: String,
    pub site_id: String,
    pub installation_id: String,
    pub source: Value,
    pub store: Value,
    pub consistency: Value,
    pub state_inventory: Vec<Value>,
    pub consistency_generation: String,
    pub recipient_key_id: String,
    pub recipient_public_key: [u8; 32],
    pub artifact_key_id: String,
    pub signing_key_id: String,
}

/// Release identity pinned by the verifier's installed, trusted release.
/// Values are supplied by the caller from release-signed installation state,
/// never copied from the artifact being checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedRelease {
    /// Trusted site identity from release-signed installation configuration.
    pub site_id: String,
    /// Trusted installation identity from the same local authority.
    pub installation_id: String,
    pub o3k_version: String,
    pub source_sha: String,
    pub release_artifact_sha256: String,
    pub profile_id: String,
    pub store_backend: String,
    pub schema_version: u64,
    pub migrations: Vec<MigrationIdentity>,
    /// Exact repository-to-catalog mapping generated from this release's
    /// store registrations and migrations. `empty_state_included` is the
    /// only per-capture field and is normalized before comparison.
    pub state_inventory: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationIdentity {
    pub version: u64,
    pub checksum: String,
}

/// Signing authority supplied by the configured offline custody boundary.
/// Implementations must not export or persist private key material.
pub trait ArtifactSigner {
    fn key_id(&self) -> &str;
    fn sign_manifest(&self, signature_input: &[u8]) -> Result<[u8; 64], String>;
    /// Public half of the signing key, used to verify a freshly produced
    /// signature before the artifact leaves private staging. Public keys are
    /// not secret; private key material must never be returned here.
    fn verifying_key(&self) -> VerifyingKey;
}

/// Trust-store boundary required by streaming verification. Implementations
/// bind the key id and public key to the trusted site/profile and consult the
/// current revocation state; unknown or unavailable trust data must fail
/// closed. The backup module deliberately does not invent a certificate or
/// revocation format beyond the accepted external trust contract.
pub trait ArtifactTrust {
    fn signing_key_is_trusted(
        &self,
        key_id: &str,
        site_id: &str,
        profile_id: &str,
        public_key: &VerifyingKey,
    ) -> Result<bool, String>;

    fn signing_key_is_revoked(&self, key_id: &str) -> Result<bool, String>;
}

/// A stream-backed member descriptor. The declared size is part of AES-GCM
/// associated data and is checked against the bytes read from `source`.
pub struct StreamMember<R> {
    pub name: String,
    pub media_type: String,
    pub plaintext_size_bytes: u64,
    pub source: R,
}

/// Result of a private staged artifact build. The file remains under the
/// caller-provided private staging directory and is not a published backup.
pub struct StagedArtifact {
    pub manifest: Manifest,
    /// Private directory containing the incomplete artifact and encrypted
    /// members. The caller removes it after durable publication or recovery.
    pub staging_directory: PathBuf,
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
}

/// An encrypted artifact staged with an unsigned manifest.
///
/// This is the first half of the accepted offline signing flow (Option A):
/// the command boundary cannot reach the custody-held signing key, so it
/// stages the exact bytes that must be signed and hands the operator a
/// detached signing input. The staged file is **not** a backup artifact: its
/// manifest has no signature and the verifier rejects it.
pub struct UnsignedStagedArtifact {
    /// Manifest with `authentication.signature` unset.
    pub manifest: Manifest,
    /// Private directory containing the staged artifact and encrypted members.
    pub staging_directory: PathBuf,
    /// Staged unauthenticated artifact file.
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
    /// SHA-256 of the canonical (JCS) unsigned manifest. The signing request
    /// repeats this so the custodian can bind a signature to one manifest.
    pub manifest_digest: String,
    /// Exact byte string the custody boundary signs (D1 signing input).
    pub signing_input: Vec<u8>,
    /// Length of the canonical unsigned manifest inside the staged file.
    manifest_bytes_len: u64,
}

/// One authenticated member written to private staging after full tag and
/// digest validation. Paths are internal artifacts, not restore destinations.
pub struct VerifiedMember {
    pub record: MemberRecord,
    pub path: PathBuf,
}

/// Fully authenticated artifact contents held in a private staging directory.
/// The caller must remove the directory after inspection or restore.
pub struct VerifiedArtifact {
    pub manifest: Manifest,
    pub staging_directory: PathBuf,
    pub members: Vec<VerifiedMember>,
}

/// Verifier keys and trust policy supplied from the operator's local trusted
/// configuration, never resolved from the artifact manifest alone.
#[derive(Clone, Copy)]
pub struct ArtifactVerificationKeys<'a> {
    pub signing_key_id: &'a str,
    pub signer: &'a VerifyingKey,
    pub trust: &'a dyn ArtifactTrust,
    pub recipient_key_id: &'a str,
    pub recipient: &'a <X25519HkdfSha256 as Kem>::PrivateKey,
}

/// Builds a signed encrypted artifact with fixed-window reads and writes. The
/// staging directory must be pre-created, private, and on the destination
/// filesystem; publication is a separate verified operation. The signer is an
/// in-process authority: the operator command uses
/// [`stage_unsigned_artifact`]/[`finish_signed_artifact`] instead because the
/// custody key is offline.
pub fn create_artifact_stream<R: Read>(
    options: &CreateOptions,
    members: Vec<StreamMember<R>>,
    staging_directory: &Path,
    signer: &dyn ArtifactSigner,
) -> Result<StagedArtifact, String> {
    if signer.key_id() != options.signing_key_id {
        return Err("configured backup signer identity does not match the request".to_owned());
    }
    let unsigned = stage_unsigned_artifact(options, members, staging_directory)?;
    let signature = match signer.sign_manifest(&unsigned.signing_input) {
        Ok(signature) => signature,
        Err(error) => {
            if fs::remove_dir_all(&unsigned.staging_directory).is_err() {
                return Err(format!("{error}; encrypted staging cleanup failed"));
            }
            return Err(error);
        }
    };
    finish_signed_artifact(
        unsigned,
        signature,
        signer.key_id(),
        &signer.verifying_key(),
    )
}

/// Stages an encrypted artifact whose manifest carries no signature.
///
/// This is the first phase of the accepted offline signing flow: the command
/// boundary cannot reach the custody-held signing key, so it stages the exact
/// bytes that must be signed together with the D1 signing input. The returned
/// artifact is **not** a backup artifact — its manifest has no signature and
/// the verifier rejects it. [`finish_signed_artifact`] must add the detached
/// signature before publication.
///
/// `staging_parent` must be absolute. A regular path is resolved without
/// following symlinks; `/proc/self/fd/<n>` is accepted because the kernel
/// resolves that magic link against the descriptor the caller already holds,
/// so a path-component swap cannot redirect the staging write.
pub fn stage_unsigned_artifact<R: Read>(
    options: &CreateOptions,
    members: Vec<StreamMember<R>>,
    staging_parent: &Path,
) -> Result<UnsignedStagedArtifact, String> {
    if !staging_parent.is_absolute() {
        return Err("backup staging directory must be absolute".to_owned());
    }
    let staging_parent = resolve_staging_parent(staging_parent)?;
    validate_stream_members(&members)?;
    let member_staging = staging_parent.join(format!("members-{}", Uuid::now_v7()));
    create_private_dir(&member_staging)?;
    let stage_result = (|| {
        let mut content_key = Zeroizing::new([0_u8; 32]);
        SystemRandom::new()
            .fill(&mut content_key[..])
            .map_err(|_| "backup cryptographic random source unavailable".to_owned())?;
        let recipient =
            <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&options.recipient_public_key)
                .map_err(|_| "backup recipient key is malformed".to_owned())?;
        let wrap_aad = key_wrap_aad(options)?;
        let (encapped, mut hpke_context) = hpke::setup_sender::<
            AesGcm256,
            HkdfSha256,
            X25519HkdfSha256,
        >(&OpModeS::Base, &recipient, HPKE_INFO)
        .map_err(|_| "backup key wrapping failed".to_owned())?;
        let wrapped_key = hpke_context
            .seal(&content_key[..], &wrap_aad)
            .map_err(|_| "backup key wrapping failed".to_owned())?;

        let mut seen_nonces = BTreeSet::new();
        let mut encrypted_files = Vec::with_capacity(members.len());
        let mut records = Vec::with_capacity(members.len());
        for (index, mut member) in members.into_iter().enumerate() {
            let nonce = loop {
                let mut nonce = [0_u8; 12];
                SystemRandom::new()
                    .fill(&mut nonce)
                    .map_err(|_| "backup cryptographic random source unavailable".to_owned())?;
                if seen_nonces.insert(nonce) {
                    break nonce;
                }
            };
            let aad = member_aad(options, &member.name, member.plaintext_size_bytes)?;
            let encrypted_path = member_staging.join(format!("member-{index:02}.ciphertext"));
            let mut encrypted_file = create_private_file(&encrypted_path)?;
            let (plaintext_size, ciphertext_size, digest) = encrypt_member_stream(
                &mut member.source,
                &mut encrypted_file,
                &content_key,
                &nonce,
                &aad,
                member.plaintext_size_bytes,
            )?;
            if plaintext_size != member.plaintext_size_bytes {
                return Err("backup member size differs from its captured metadata".to_owned());
            }
            encrypted_file
                .sync_all()
                .map_err(|_| "backup member staging sync failed".to_owned())?;
            records.push(MemberRecord {
                name: member.name.clone(),
                plaintext_size_bytes: plaintext_size,
                size_bytes: ciphertext_size,
                sha256: digest,
                media_type: member.media_type.clone(),
                encrypted: true,
                consistency_generation: options.consistency_generation.clone(),
                nonce: URL_SAFE_NO_PAD.encode(nonce),
            });
            encrypted_files.push((member.name.clone(), encrypted_path));
        }
        records.sort_by(|left, right| left.name.cmp(&right.name));
        encrypted_files.sort_by(|left, right| left.0.cmp(&right.0));
        let manifest = Manifest {
            format_version: FORMAT_VERSION.to_owned(),
            backup_id: options.backup_id.clone(),
            created_at: options.created_at.clone(),
            site_id: options.site_id.clone(),
            installation_id: options.installation_id.clone(),
            source: options.source.clone(),
            store: options.store.clone(),
            consistency: options.consistency.clone(),
            state_inventory: options.state_inventory.clone(),
            members: records,
            encryption: Encryption {
                algorithm: "AES-256-GCM".to_owned(),
                key_id: options.artifact_key_id.clone(),
                key_is_external: true,
                key_wrapping: KeyWrapping {
                    algorithm: "HPKE-v1-X25519-HKDF-SHA256-AES-256-GCM".to_owned(),
                    recipient_key_id: options.recipient_key_id.clone(),
                    enc: URL_SAFE_NO_PAD.encode(encapped.to_bytes()),
                    ciphertext: URL_SAFE_NO_PAD.encode(wrapped_key),
                },
            },
            authentication: Authentication {
                algorithm: "Ed25519".to_owned(),
                key_id: options.signing_key_id.clone(),
                signature: None,
            },
            excluded_state: excluded_state(),
        };
        validate_manifest(&manifest, &options.consistency_generation)?;
        // The v1 contract schema requires `authentication.signature`, so the
        // unsigned manifest is validated semantically here and against the
        // schema only after the detached signature is attached.
        let signing_input = signature_input(&manifest)?;
        let manifest_digest = hex_sha256(
            &serde_jcs::to_vec(&manifest)
                .map_err(|_| "backup manifest canonicalization failed".to_owned())?,
        );
        let manifest_bytes = serde_jcs::to_vec(&manifest)
            .map_err(|_| "backup manifest canonicalization failed".to_owned())?;
        if manifest_bytes.len() > MAX_MANIFEST_BYTES {
            return Err("backup manifest exceeds the configured size limit".to_owned());
        }
        let mut complete_size = (MAGIC.len() as u64)
            .checked_add(8)
            .and_then(|size| size.checked_add(manifest_bytes.len() as u64))
            .ok_or("backup artifact size overflow")?;
        for record in &manifest.members {
            complete_size = complete_size
                .checked_add(8)
                .and_then(|size| size.checked_add(record.size_bytes))
                .ok_or("backup artifact size overflow")?;
        }
        if complete_size > MAX_ARTIFACT_BYTES as u64 {
            return Err("backup artifact exceeds the configured size limit".to_owned());
        }
        let artifact_path = member_staging.join("artifact.unsigned");
        let mut artifact = create_private_file(&artifact_path)?;
        artifact
            .write_all(MAGIC)
            .and_then(|()| artifact.write_all(&(manifest_bytes.len() as u64).to_be_bytes()))
            .and_then(|()| artifact.write_all(&manifest_bytes))
            .map_err(|_| "backup artifact staging write failed".to_owned())?;
        for (record, (_, encrypted_path)) in manifest.members.iter().zip(encrypted_files) {
            artifact
                .write_all(&record.size_bytes.to_be_bytes())
                .map_err(|_| "backup artifact staging write failed".to_owned())?;
            let mut encrypted_file = fs::File::open(encrypted_path)
                .map_err(|_| "backup encrypted staging member is unavailable".to_owned())?;
            let copied = std::io::copy(&mut encrypted_file, &mut artifact)
                .map_err(|_| "backup artifact staging write failed".to_owned())?;
            if copied != record.size_bytes {
                return Err("backup staged member size changed during assembly".to_owned());
            }
        }
        artifact
            .sync_all()
            .map_err(|_| "backup artifact staging sync failed".to_owned())?;
        drop(artifact);
        let (size_bytes, sha256) = hash_file(&artifact_path)?;
        if size_bytes != complete_size {
            return Err("backup artifact size changed during assembly".to_owned());
        }
        Ok(UnsignedStagedArtifact {
            manifest,
            staging_directory: member_staging.clone(),
            path: artifact_path,
            sha256,
            size_bytes,
            manifest_digest,
            signing_input,
            manifest_bytes_len: manifest_bytes.len() as u64,
        })
    })();
    match stage_result {
        Ok(artifact) => Ok(artifact),
        Err(error) => {
            if fs::remove_dir_all(&member_staging).is_err() {
                return Err(format!("{error}; encrypted staging cleanup failed"));
            }
            Err(error)
        }
    }
}

/// Completes a staged artifact with an externally produced Ed25519 signature.
///
/// The signature must verify against the trusted signing key before the
/// manifest changes at all, so a wrong signature, a wrong key id or a stale
/// signing input produces no publishable artifact. The signed manifest is
/// re-serialized as canonical JSON, re-validated against the v1 contract
/// schema, and the member blocks are copied from the unsigned staging file.
pub fn finish_signed_artifact(
    unsigned: UnsignedStagedArtifact,
    signature: [u8; 64],
    signer_key_id: &str,
    verifying_key: &VerifyingKey,
) -> Result<StagedArtifact, String> {
    if signer_key_id != unsigned.manifest.authentication.key_id {
        return Err("configured backup signer identity does not match the request".to_owned());
    }
    verifying_key
        .verify(&unsigned.signing_input, &Signature::from_bytes(&signature))
        .map_err(|_| "backup signature does not verify against the trusted key".to_owned())?;
    let mut manifest = unsigned.manifest;
    manifest.authentication.signature = Some(URL_SAFE_NO_PAD.encode(signature));
    if signature_input(&manifest)? != unsigned.signing_input {
        return Err("backup signature input changed after signing".to_owned());
    }
    validate_manifest_schema(&manifest)?;
    let manifest_bytes = serde_jcs::to_vec(&manifest)
        .map_err(|_| "backup manifest canonicalization failed".to_owned())?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err("backup manifest exceeds the configured size limit".to_owned());
    }
    let mut complete_size = (MAGIC.len() as u64)
        .checked_add(8)
        .and_then(|size| size.checked_add(manifest_bytes.len() as u64))
        .ok_or("backup artifact size overflow")?;
    for record in &manifest.members {
        complete_size = complete_size
            .checked_add(8)
            .and_then(|size| size.checked_add(record.size_bytes))
            .ok_or("backup artifact size overflow")?;
    }
    if complete_size > MAX_ARTIFACT_BYTES as u64 {
        return Err("backup artifact exceeds the configured size limit".to_owned());
    }

    let final_path = unsigned.staging_directory.join("artifact.partial");
    let mut artifact = create_private_file(&final_path)?;
    artifact
        .write_all(MAGIC)
        .and_then(|()| artifact.write_all(&(manifest_bytes.len() as u64).to_be_bytes()))
        .and_then(|()| artifact.write_all(&manifest_bytes))
        .map_err(|_| "backup artifact staging write failed".to_owned())?;
    let mut staged = fs::File::open(&unsigned.path)
        .map_err(|_| "backup staged unsigned artifact is unavailable".to_owned())?;
    let member_offset = (MAGIC.len() as u64)
        .checked_add(8)
        .and_then(|offset| offset.checked_add(unsigned.manifest_bytes_len))
        .ok_or("backup artifact size overflow")?;
    if member_offset > unsigned.size_bytes {
        return Err("backup staged unsigned artifact is truncated".to_owned());
    }
    staged
        .seek(SeekFrom::Start(member_offset))
        .map_err(|_| "backup staged unsigned artifact could not be read".to_owned())?;
    // The staged payload is re-digested record by record: the detached
    // signature covers the member digests in the manifest, so a staged file
    // modified after staging must never become a publishable artifact.
    let mut buffer = [0_u8; STREAM_CHUNK_BYTES];
    for record in &manifest.members {
        let mut length = [0_u8; 8];
        staged
            .read_exact(&mut length)
            .map_err(|_| "backup staged unsigned artifact is truncated".to_owned())?;
        if u64::from_be_bytes(length) != record.size_bytes {
            return Err("backup staged member length does not match the manifest".to_owned());
        }
        artifact
            .write_all(&length)
            .map_err(|_| "backup artifact staging write failed".to_owned())?;
        let mut digest = Sha256::new();
        let mut remaining = record.size_bytes;
        while remaining > 0 {
            let amount = usize::try_from(remaining.min(STREAM_CHUNK_BYTES as u64))
                .map_err(|_| "backup member size is invalid")?;
            staged
                .read_exact(&mut buffer[..amount])
                .map_err(|_| "backup staged unsigned artifact is truncated".to_owned())?;
            digest.update(&buffer[..amount]);
            artifact
                .write_all(&buffer[..amount])
                .map_err(|_| "backup artifact staging write failed".to_owned())?;
            remaining -= amount as u64;
        }
        if hex::encode(digest.finalize()) != record.sha256 {
            return Err("backup staged member digest does not match the manifest".to_owned());
        }
    }
    artifact
        .sync_all()
        .map_err(|_| "backup artifact staging sync failed".to_owned())?;
    drop(artifact);
    let (size_bytes, sha256) = hash_file(&final_path)?;
    if size_bytes != complete_size {
        return Err("backup artifact size changed during assembly".to_owned());
    }
    let _ = fs::remove_file(&unsigned.path);
    Ok(StagedArtifact {
        manifest,
        staging_directory: unsigned.staging_directory,
        path: final_path,
        sha256,
        size_bytes,
    })
}

/// Re-reads a staged unsigned artifact produced by
/// [`stage_unsigned_artifact`].
///
/// The staging directory must hold exactly one `members-<uuid>` directory.
/// Every structural property the signer relies on is re-derived from the file:
/// the manifest must be canonical, unsigned, semantically valid for its own
/// consistency generation, and the member blocks must exactly fill the file.
/// The returned signing input is what a detached signature must cover.
pub fn read_unsigned_staged_artifact(
    staging_directory: &Path,
) -> Result<UnsignedStagedArtifact, String> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir(staging_directory)
        .map_err(|_| "backup staging directory is unavailable".to_owned())?
    {
        let entry = entry.map_err(|_| "backup staging directory is unavailable".to_owned())?;
        let file_name = entry.file_name();
        if !file_name.as_encoded_bytes().starts_with(b"members-") {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|_| "backup staging entry is unavailable".to_owned())?;
        if !file_type.is_dir() {
            continue;
        }
        let artifact_path = entry.path().join("artifact.unsigned");
        if artifact_path.is_file() {
            candidates.push((entry.path(), artifact_path));
        }
    }
    if candidates.len() != 1 {
        return Err("staged signing request has no unique unsigned artifact".to_owned());
    }
    let (member_staging, artifact_path) = candidates.remove(0);
    let metadata = fs::symlink_metadata(&artifact_path)
        .map_err(|_| "backup staged unsigned artifact is unavailable".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err("backup staged unsigned artifact is not a regular file".to_owned());
    }
    if metadata.len() > MAX_ARTIFACT_BYTES as u64 {
        return Err("backup artifact exceeds the configured size limit".to_owned());
    }
    let mut file = fs::File::open(&artifact_path)
        .map_err(|_| "backup staged unsigned artifact is unavailable".to_owned())?;
    let mut magic = [0_u8; 12];
    file.read_exact(&mut magic)
        .map_err(|_| "backup artifact header is truncated".to_owned())?;
    if &magic != MAGIC {
        return Err("backup artifact format header is invalid".to_owned());
    }
    let manifest_len = read_stream_len(&mut file)?;
    if manifest_len > MAX_MANIFEST_BYTES {
        return Err("backup manifest length is invalid".to_owned());
    }
    let mut manifest_bytes = vec![0_u8; manifest_len];
    file.read_exact(&mut manifest_bytes)
        .map_err(|_| "backup manifest is truncated".to_owned())?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| "backup manifest is malformed".to_owned())?;
    if manifest.authentication.signature.is_some() {
        return Err("staged unsigned artifact already carries a signature".to_owned());
    }
    if serde_jcs::to_vec(&manifest).map_err(|_| "backup manifest canonicalization failed")?
        != manifest_bytes
    {
        return Err("backup manifest is not canonical JSON".to_owned());
    }
    validate_manifest(&manifest, &manifest.consistency_generation())?;
    let mut complete_size = (MAGIC.len() as u64)
        .checked_add(8)
        .and_then(|size| size.checked_add(manifest_len as u64))
        .ok_or("backup artifact size overflow")?;
    for record in &manifest.members {
        complete_size = complete_size
            .checked_add(8)
            .and_then(|size| size.checked_add(record.size_bytes))
            .ok_or("backup artifact size overflow")?;
    }
    if complete_size != metadata.len() {
        return Err("backup staged unsigned artifact has an invalid size".to_owned());
    }
    let signing_input = signature_input(&manifest)?;
    let (size_bytes, sha256) = hash_file(&artifact_path)?;
    if size_bytes != complete_size {
        return Err("backup artifact size changed during inspection".to_owned());
    }
    Ok(UnsignedStagedArtifact {
        manifest,
        staging_directory: member_staging,
        path: artifact_path,
        sha256,
        size_bytes,
        manifest_digest: hex_sha256(&manifest_bytes),
        signing_input,
        manifest_bytes_len: manifest_len as u64,
    })
}

fn validate_stream_members<R>(members: &[StreamMember<R>]) -> Result<(), String> {
    if members.is_empty() || members.len() > MAX_MEMBERS {
        return Err("backup member count is outside the supported bound".to_owned());
    }
    let mut names = BTreeSet::new();
    let mut total = 0_u64;
    for member in members {
        validate_path(&member.name)?;
        if !names.insert(member.name.as_str()) {
            return Err("backup contains a duplicate member name".to_owned());
        }
        if member.plaintext_size_bytes > MAX_MEMBER_BYTES as u64 {
            return Err("backup member exceeds the configured size limit".to_owned());
        }
        total = total
            .checked_add(member.plaintext_size_bytes)
            .ok_or("backup plaintext size overflow")?;
    }
    if total > MAX_TOTAL_PLAINTEXT as u64 {
        return Err("backup plaintext exceeds the configured aggregate limit".to_owned());
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<(u64, String), String> {
    let mut file = fs::File::open(path)
        .map_err(|_| "backup artifact staging file is unavailable".to_owned())?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; STREAM_CHUNK_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "backup artifact staging file could not be read".to_owned())?;
        if read == 0 {
            break;
        }
        let read_bytes = u64::try_from(read).map_err(|_| "backup artifact size overflow")?;
        size = size
            .checked_add(read_bytes)
            .ok_or("backup artifact size overflow")?;
        digest.update(&buffer[..read]);
    }
    Ok((size, hex::encode(digest.finalize())))
}

/// Verifies an artifact from a bounded stream. Ciphertext and plaintext are
/// read/written in fixed-size windows; plaintext stays private until this
/// function returns after every member tag, digest, signature, and identity
/// check succeeds.
pub fn verify_artifact_stream<R: Read>(
    source: &mut R,
    expected_release: &ExpectedRelease,
    keys: &ArtifactVerificationKeys<'_>,
    staging_parent: &Path,
) -> Result<VerifiedArtifact, String> {
    if !staging_parent.is_absolute() {
        return Err("backup staging directory must be absolute".to_owned());
    }
    let parent = resolve_private_staging_parent(staging_parent)?;
    validate_private_parent(&parent)?;
    let directory = parent.join(format!("verified-{}", Uuid::now_v7()));
    create_private_dir(&directory)?;
    let result = (|| {
        let mut magic = [0_u8; 12];
        source
            .read_exact(&mut magic)
            .map_err(|_| "backup artifact header is truncated".to_owned())?;
        if &magic != MAGIC {
            return Err("backup artifact format header is invalid".to_owned());
        }
        let manifest_len = read_stream_len(source)?;
        if manifest_len > MAX_MANIFEST_BYTES {
            return Err("backup manifest length is invalid".to_owned());
        }
        let mut manifest_bytes = vec![0_u8; manifest_len];
        source
            .read_exact(&mut manifest_bytes)
            .map_err(|_| "backup manifest is truncated".to_owned())?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| "backup manifest is malformed".to_owned())?;
        validate_manifest_schema(&manifest)?;
        let canonical = serde_jcs::to_vec(&manifest)
            .map_err(|_| "backup manifest canonicalization failed".to_owned())?;
        if canonical != manifest_bytes {
            return Err("backup manifest is not canonical JSON".to_owned());
        }
        validate_manifest(&manifest, &manifest.consistency_generation())?;
        if manifest.authentication.key_id != keys.signing_key_id
            || manifest.encryption.key_wrapping.recipient_key_id != keys.recipient_key_id
        {
            return Err("backup key identity is not trusted by this verifier".to_owned());
        }
        validate_expected_release(&manifest, expected_release)?;
        if keys.trust.signing_key_is_revoked(keys.signing_key_id)? {
            return Err("backup signing key is revoked".to_owned());
        }
        if !keys.trust.signing_key_is_trusted(
            keys.signing_key_id,
            &expected_release.site_id,
            &expected_release.profile_id,
            keys.signer,
        )? {
            return Err("backup signing key is not trusted for this site and profile".to_owned());
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(
                manifest
                    .authentication
                    .signature
                    .as_deref()
                    .ok_or("backup signature is missing")?,
            )
            .map_err(|_| "backup signature encoding is invalid".to_owned())?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| "backup signature encoding is invalid".to_owned())?;
        keys.signer
            .verify(&signature_input(&manifest)?, &signature)
            .map_err(|_| "backup signature verification failed".to_owned())?;
        let mut complete_size = (MAGIC.len() as u64)
            .checked_add(8)
            .and_then(|size| size.checked_add(manifest_len as u64))
            .ok_or("backup artifact size overflow")?;
        for record in &manifest.members {
            complete_size = complete_size
                .checked_add(8)
                .and_then(|size| size.checked_add(record.size_bytes))
                .ok_or("backup artifact size overflow")?;
        }
        if complete_size > MAX_ARTIFACT_BYTES as u64 {
            return Err("backup artifact exceeds the configured size limit".to_owned());
        }

        let enc_bytes = URL_SAFE_NO_PAD
            .decode(&manifest.encryption.key_wrapping.enc)
            .map_err(|_| "backup key encapsulation is malformed".to_owned())?;
        let encapped = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&enc_bytes)
            .map_err(|_| "backup key encapsulation is malformed".to_owned())?;
        let wrapped_key = URL_SAFE_NO_PAD
            .decode(&manifest.encryption.key_wrapping.ciphertext)
            .map_err(|_| "backup wrapped key is malformed".to_owned())?;
        let mut hpke_context = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            keys.recipient,
            &encapped,
            HPKE_INFO,
        )
        .map_err(|_| "backup content key cannot be unwrapped".to_owned())?;
        let content_key = Zeroizing::new(
            hpke_context
                .open(&wrapped_key, &key_wrap_aad_from_manifest(&manifest)?)
                .map_err(|_| "backup content key cannot be unwrapped".to_owned())?,
        );
        let content_key = Zeroizing::new(
            <[u8; 32]>::try_from(content_key.as_slice())
                .map_err(|_| "backup content key has an invalid size")?,
        );

        let mut members = Vec::with_capacity(manifest.members.len());
        let mut prior_name: Option<&str> = None;
        for (index, record) in manifest.members.iter().enumerate() {
            if prior_name.is_some_and(|prior| prior >= record.name.as_str()) {
                return Err("backup manifest members are not in canonical path order".to_owned());
            }
            prior_name = Some(&record.name);
            let size = read_stream_len(source)?;
            if u64::try_from(size).map_err(|_| "backup member length is invalid")?
                != record.size_bytes
            {
                return Err("backup member length does not match the manifest".to_owned());
            }
            let nonce_bytes = URL_SAFE_NO_PAD
                .decode(&record.nonce)
                .map_err(|_| "backup member nonce is malformed".to_owned())?;
            let nonce: [u8; 12] = nonce_bytes
                .try_into()
                .map_err(|_| "backup member nonce is malformed".to_owned())?;
            let path = directory.join(format!("member-{index:02}.plaintext"));
            let mut output = create_private_file(&path)?;
            let (plaintext_size, digest) = decrypt_member_stream(
                source,
                &mut output,
                &content_key,
                &nonce,
                &member_aad_from_manifest(&manifest, record)?,
                record.size_bytes,
            )?;
            if plaintext_size != record.plaintext_size_bytes || digest != record.sha256 {
                return Err("backup member digest or plaintext size is invalid".to_owned());
            }
            output
                .sync_all()
                .map_err(|_| "backup private staging sync failed".to_owned())?;
            members.push(VerifiedMember {
                record: record.clone(),
                path,
            });
        }
        let mut trailing = [0_u8; 1];
        if source
            .read(&mut trailing)
            .map_err(|_| "backup artifact could not be read".to_owned())?
            != 0
        {
            return Err("backup artifact has trailing bytes".to_owned());
        }
        Ok(VerifiedArtifact {
            manifest,
            staging_directory: directory.clone(),
            members,
        })
    })();
    match result {
        Ok(verified) => Ok(verified),
        Err(error) => {
            if fs::remove_dir_all(&directory).is_err() {
                return Err(format!("{error}; private verification cleanup failed"));
            }
            Err(error)
        }
    }
}

fn read_stream_len<R: Read>(source: &mut R) -> Result<usize, String> {
    let mut bytes = [0_u8; 8];
    source
        .read_exact(&mut bytes)
        .map_err(|_| "backup artifact length is truncated".to_owned())?;
    usize::try_from(u64::from_be_bytes(bytes))
        .map_err(|_| "backup length is not supported".to_owned())
}

/// Builds the complete bounded v1 binary artifact and returns its SHA-256.
/// The signing key is supplied by the caller's offline signing boundary.
#[cfg(test)]
pub fn create_artifact(
    options: &CreateOptions,
    members: Vec<PlainMember>,
    signer: &dyn ArtifactSigner,
) -> Result<(Vec<u8>, String), String> {
    if signer.key_id() != options.signing_key_id {
        return Err("configured backup signer identity does not match the request".to_owned());
    }
    validate_members(&members)?;
    let mut content_key = Zeroizing::new([0_u8; 32]);
    SystemRandom::new()
        .fill(&mut content_key[..])
        .map_err(|_| "backup cryptographic random source unavailable".to_owned())?;

    let recipient = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&options.recipient_public_key)
        .map_err(|_| "backup recipient key is malformed".to_owned())?;
    let wrap_aad = key_wrap_aad(options)?;
    let (encapped, mut hpke_context) =
        hpke::setup_sender::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &recipient,
            HPKE_INFO,
        )
        .map_err(|_| "backup key wrapping failed".to_owned())?;
    let wrapped_key = hpke_context
        .seal(&content_key[..], &wrap_aad)
        .map_err(|_| "backup key wrapping failed".to_owned())?;

    let mut encrypted = Vec::with_capacity(members.len());
    let mut seen_nonces = BTreeSet::new();
    let mut records = Vec::with_capacity(members.len());
    for member in members {
        let mut nonce = [0_u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "backup cryptographic random source unavailable".to_owned())?;
        if !seen_nonces.insert(nonce) {
            return Err("backup generated a duplicate encryption nonce".to_owned());
        }
        let aad = member_aad(options, &member.name, member.bytes.len() as u64)?;
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &content_key[..])
            .map_err(|_| "backup encryption initialization failed".to_owned())?;
        let key = aead::LessSafeKey::new(unbound);
        let mut ciphertext = member.bytes.clone();
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&aad[..]),
            &mut ciphertext,
        )
        .map_err(|_| "backup member encryption failed".to_owned())?;
        records.push(MemberRecord {
            name: member.name.clone(),
            plaintext_size_bytes: member.bytes.len() as u64,
            size_bytes: ciphertext.len() as u64,
            sha256: hex_sha256(&ciphertext),
            media_type: member.media_type.clone(),
            encrypted: true,
            consistency_generation: options.consistency_generation.clone(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
        });
        encrypted.push((member.name.clone(), ciphertext));
    }
    records.sort_by(|a, b| a.name.cmp(&b.name));
    encrypted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut manifest = Manifest {
        format_version: FORMAT_VERSION.to_owned(),
        backup_id: options.backup_id.clone(),
        created_at: options.created_at.clone(),
        site_id: options.site_id.clone(),
        installation_id: options.installation_id.clone(),
        source: options.source.clone(),
        store: options.store.clone(),
        consistency: options.consistency.clone(),
        state_inventory: options.state_inventory.clone(),
        members: records,
        encryption: Encryption {
            algorithm: "AES-256-GCM".to_owned(),
            key_id: options.artifact_key_id.clone(),
            key_is_external: true,
            key_wrapping: KeyWrapping {
                algorithm: "HPKE-v1-X25519-HKDF-SHA256-AES-256-GCM".to_owned(),
                recipient_key_id: options.recipient_key_id.clone(),
                enc: URL_SAFE_NO_PAD.encode(encapped.to_bytes()),
                ciphertext: URL_SAFE_NO_PAD.encode(wrapped_key),
            },
        },
        authentication: Authentication {
            algorithm: "Ed25519".to_owned(),
            key_id: options.signing_key_id.clone(),
            signature: None,
        },
        excluded_state: excluded_state(),
    };
    validate_manifest(&manifest, &options.consistency_generation)?;
    let signature = signer.sign_manifest(&signature_input(&manifest)?)?;
    manifest.authentication.signature = Some(URL_SAFE_NO_PAD.encode(signature));
    validate_manifest_schema(&manifest)?;
    let manifest_bytes = serde_jcs::to_vec(&manifest)
        .map_err(|_| "backup manifest canonicalization failed".to_owned())?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err("backup manifest exceeds the configured size limit".to_owned());
    }
    let mut artifact = Vec::new();
    artifact.extend_from_slice(MAGIC);
    artifact.extend_from_slice(&(manifest_bytes.len() as u64).to_be_bytes());
    artifact.extend_from_slice(&manifest_bytes);
    for (_, ciphertext) in encrypted {
        artifact.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
        artifact.extend_from_slice(&ciphertext);
    }
    if artifact.len() > MAX_ARTIFACT_BYTES {
        return Err("backup artifact exceeds the configured size limit".to_owned());
    }
    let digest = hex_sha256(&artifact);
    Ok((artifact, digest))
}

/// Verifies canonical encoding, signature, member inventory, ciphertext
/// digests, key wrapping and every member's AES-GCM tag before returning data.
#[cfg(test)]
pub fn verify_artifact(
    artifact: &[u8],
    expected_release: &ExpectedRelease,
    expected_signing_key_id: &str,
    signer: &VerifyingKey,
    expected_recipient_key_id: &str,
    recipient: &<X25519HkdfSha256 as Kem>::PrivateKey,
) -> Result<(Manifest, Vec<PlainMember>), String> {
    if artifact.len() > MAX_ARTIFACT_BYTES || artifact.len() < MAGIC.len() + 8 {
        return Err("backup artifact has an invalid size".to_owned());
    }
    if &artifact[..MAGIC.len()] != MAGIC {
        return Err("backup artifact format header is invalid".to_owned());
    }
    let manifest_len = read_len(artifact, MAGIC.len())?;
    let manifest_start = MAGIC.len() + 8;
    let manifest_end = manifest_start
        .checked_add(manifest_len)
        .ok_or("backup manifest length overflow")?;
    if manifest_len > MAX_MANIFEST_BYTES || manifest_end > artifact.len() {
        return Err("backup manifest length is invalid".to_owned());
    }
    let manifest_bytes = &artifact[manifest_start..manifest_end];
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|_| "backup manifest is malformed".to_owned())?;
    validate_manifest_schema(&manifest)?;
    let canonical = serde_jcs::to_vec(&manifest)
        .map_err(|_| "backup manifest canonicalization failed".to_owned())?;
    if canonical != manifest_bytes {
        return Err("backup manifest is not canonical JSON".to_owned());
    }
    validate_manifest(&manifest, &manifest.consistency_generation())?;
    if manifest.authentication.key_id != expected_signing_key_id
        || manifest.encryption.key_wrapping.recipient_key_id != expected_recipient_key_id
    {
        return Err("backup key identity is not trusted by this verifier".to_owned());
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(
            manifest
                .authentication
                .signature
                .as_deref()
                .ok_or("backup signature is missing")?,
        )
        .map_err(|_| "backup signature encoding is invalid".to_owned())?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| "backup signature encoding is invalid".to_owned())?;
    signer
        .verify(&signature_input(&manifest)?, &signature)
        .map_err(|_| "backup signature verification failed".to_owned())?;
    validate_expected_release(&manifest, expected_release)?;

    let mut offset = manifest_end;
    let mut ciphertexts = Vec::with_capacity(manifest.members.len());
    let mut prior_name: Option<&str> = None;
    for record in &manifest.members {
        if prior_name.is_some_and(|prior| prior >= record.name.as_str()) {
            return Err("backup manifest members are not in canonical path order".to_owned());
        }
        prior_name = Some(&record.name);
        let size = read_len(artifact, offset)?;
        offset = offset
            .checked_add(8)
            .ok_or("backup member length overflow")?;
        let end = offset
            .checked_add(size)
            .ok_or("backup member length overflow")?;
        let expected_size = usize::try_from(record.size_bytes)
            .map_err(|_| "backup member length does not fit this platform")?;
        if size != expected_size || end > artifact.len() {
            return Err("backup member length does not match the manifest".to_owned());
        }
        let ciphertext = &artifact[offset..end];
        if hex_sha256(ciphertext) != record.sha256 {
            return Err("backup member digest verification failed".to_owned());
        }
        ciphertexts.push(ciphertext.to_vec());
        offset = end;
    }
    if offset != artifact.len() {
        return Err("backup artifact has trailing bytes".to_owned());
    }

    let enc_bytes = URL_SAFE_NO_PAD
        .decode(&manifest.encryption.key_wrapping.enc)
        .map_err(|_| "backup key encapsulation is malformed".to_owned())?;
    let encapped = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&enc_bytes)
        .map_err(|_| "backup key encapsulation is malformed".to_owned())?;
    let wrapped_key = URL_SAFE_NO_PAD
        .decode(&manifest.encryption.key_wrapping.ciphertext)
        .map_err(|_| "backup wrapped key is malformed".to_owned())?;
    let mut hpke_context = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        recipient,
        &encapped,
        HPKE_INFO,
    )
    .map_err(|_| "backup content key cannot be unwrapped".to_owned())?;
    let content_key = Zeroizing::new(
        hpke_context
            .open(&wrapped_key, &key_wrap_aad_from_manifest(&manifest)?)
            .map_err(|_| "backup content key cannot be unwrapped".to_owned())?,
    );
    if content_key.len() != 32 {
        return Err("backup content key has an invalid size".to_owned());
    }
    let mut plaintext = Vec::with_capacity(ciphertexts.len());
    for (record, mut ciphertext) in manifest.members.iter().zip(ciphertexts) {
        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(&record.nonce)
            .map_err(|_| "backup member nonce is malformed".to_owned())?;
        let nonce_array: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| "backup member nonce is malformed".to_owned())?;
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &content_key[..])
                .map_err(|_| "backup decryption initialization failed".to_owned())?,
        );
        let bytes = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce_array),
                aead::Aad::from(&member_aad_from_manifest(&manifest, record)?[..]),
                &mut ciphertext,
            )
            .map_err(|_| "backup member authentication failed".to_owned())?;
        if bytes.len() != record.plaintext_size_bytes as usize {
            return Err("backup plaintext member length is invalid".to_owned());
        }
        plaintext.push(PlainMember {
            name: record.name.clone(),
            media_type: record.media_type.clone(),
            bytes: bytes.to_vec(),
        });
    }
    Ok((manifest, plaintext))
}

fn validate_manifest_schema(manifest: &Manifest) -> Result<(), String> {
    let value = serde_json::to_value(manifest)
        .map_err(|_| "backup manifest could not be validated".to_owned())?;
    let schema: Value = serde_json::from_str(include_str!(
        "../../../contracts/control-plane-backup-v1.proposed.schema.json"
    ))
    .map_err(|_| "backup manifest schema is unavailable".to_owned())?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|_| "backup manifest schema is invalid".to_owned())?;
    if validator.is_valid(&value) {
        Ok(())
    } else {
        Err("backup manifest does not match the v1 contract".to_owned())
    }
}

fn validate_expected_release(
    manifest: &Manifest,
    expected: &ExpectedRelease,
) -> Result<(), String> {
    let migrations = manifest
        .store
        .get("migrations")
        .and_then(Value::as_array)
        .ok_or("backup migration inventory is missing")?;
    let actual_migrations = migrations
        .iter()
        .map(|migration| {
            Ok(MigrationIdentity {
                version: migration
                    .get("version")
                    .and_then(Value::as_u64)
                    .ok_or("backup migration version is invalid")?,
                checksum: migration
                    .get("checksum")
                    .and_then(Value::as_str)
                    .ok_or("backup migration checksum is invalid")?
                    .to_owned(),
            })
        })
        .collect::<Result<Vec<_>, &str>>()?;
    let mut actual_inventory = manifest.state_inventory.clone();
    for entry in &mut actual_inventory {
        if let Some(fields) = entry.as_object_mut() {
            fields.insert("empty_state_included".to_owned(), Value::Bool(false));
        }
    }
    let mut expected_inventory = expected.state_inventory.clone();
    for entry in &mut expected_inventory {
        if let Some(fields) = entry.as_object_mut() {
            fields.insert("empty_state_included".to_owned(), Value::Bool(false));
        }
    }
    if manifest.site_id != expected.site_id
        || manifest.installation_id != expected.installation_id
        || manifest.source.get("o3k_version").and_then(Value::as_str)
            != Some(expected.o3k_version.as_str())
        || manifest.source.get("source_sha").and_then(Value::as_str)
            != Some(expected.source_sha.as_str())
        || manifest
            .source
            .get("release_artifact_sha256")
            .and_then(Value::as_str)
            != Some(expected.release_artifact_sha256.as_str())
        || manifest.source.get("profile_id").and_then(Value::as_str)
            != Some(expected.profile_id.as_str())
        || manifest.store.get("backend").and_then(Value::as_str)
            != Some(expected.store_backend.as_str())
        || manifest.store.get("schema_version").and_then(Value::as_u64)
            != Some(expected.schema_version)
        || actual_migrations != expected.migrations
        || actual_inventory != expected_inventory
    {
        return Err("backup artifact does not match the verifier's exact release".to_owned());
    }
    Ok(())
}

/// Writes a fully constructed artifact through a private sibling stage and
/// publishes it with an atomic no-replace hard link. The caller must retain
/// its store-access guard until this function returns.
#[cfg(test)]
pub fn publish_atomic(destination: &Path, artifact: &[u8]) -> Result<String, String> {
    if !destination.is_absolute() || destination.file_name().is_none() {
        return Err("backup destination must be an absolute file path".to_owned());
    }
    if artifact.len() > MAX_ARTIFACT_BYTES {
        return Err("backup artifact exceeds the configured size limit".to_owned());
    }
    let parent = destination
        .parent()
        .ok_or("backup destination has no parent directory")?;
    let parent =
        fs::canonicalize(parent).map_err(|_| "backup destination directory is unavailable")?;
    validate_private_parent(&parent)?;
    let destination = parent.join(
        destination
            .file_name()
            .ok_or("backup destination filename is missing")?,
    );
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            return Err(
                "backup destination already exists; existing content was preserved".to_owned(),
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("backup destination cannot be inspected".to_owned()),
    }
    let stage = parent.join(format!(".o3k-backup-stage-{}", Uuid::now_v7()));
    create_private_dir(&stage)?;
    let stage_file = stage.join("artifact.partial");
    let mut file = create_private_file(&stage_file)?;
    let result = (|| {
        file.write_all(artifact)
            .map_err(|_| "backup staging write failed")?;
        file.sync_all().map_err(|_| "backup staging sync failed")?;
        drop(file);
        fs::hard_link(&stage_file, &destination)
            .map_err(|_| "backup destination already exists or cannot be published")?;
        fs::File::open(&parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "backup publication directory sync failed")?;
        Ok::<(), &str>(())
    })();
    let digest = hex_sha256(artifact);
    let cleanup = fs::remove_dir_all(&stage);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(digest),
        (Err(error), _) => Err(error.to_owned()),
        (Ok(()), Err(_)) => Err("backup staging cleanup failed".to_owned()),
    }
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|_| "backup private staging directory could not be created".to_owned())
}

/// Resolves the caller-supplied staging root.
///
/// A `/proc/self/fd/<n>` magic link is accepted unchanged: the kernel resolves
/// it against the descriptor the caller already holds, so there is no path
/// component that another process could swap. Every other path is rejected if
/// it is a symlink or not a directory before canonicalization, because
/// canonicalizing first would silently follow a substituted link.
fn resolve_staging_parent(path: &Path) -> Result<PathBuf, String> {
    if is_process_descriptor_path(path) {
        let metadata =
            fs::metadata(path).map_err(|_| "backup staging directory is unavailable".to_owned())?;
        validate_private_directory_metadata(&metadata)?;
        return Ok(path.to_path_buf());
    }
    resolve_private_staging_parent(path)
}

/// Returns true for the exact `/proc/self/fd/<digits>` form built from a
/// descriptor this process holds. Anything else is treated as an ordinary
/// path and must pass the no-symlink resolution.
fn is_process_descriptor_path(path: &Path) -> bool {
    path.parent() == Some(Path::new("/proc/self/fd"))
        && path.file_name().is_some_and(|name| {
            name.to_str()
                .is_some_and(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Validates the caller-supplied staging root before resolving it. Calling
/// `canonicalize` first would silently accept a symlink as the configured
/// private staging directory and redirect secret-bearing files elsewhere.
fn resolve_private_staging_parent(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("backup staging directory must be absolute".to_owned());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "backup staging directory is unavailable".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("backup staging directory must be a regular directory".to_owned());
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| "backup staging directory is unavailable".to_owned())?;
    validate_private_parent(&canonical)?;
    Ok(canonical)
}

fn create_private_file(path: &Path) -> Result<fs::File, String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| "backup private staging file could not be created".to_owned())
}

fn validate_private_parent(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "backup destination directory is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("backup destination directory is not a regular directory".to_owned());
    }
    validate_private_directory_metadata(&metadata)
}

/// Owner and permission posture shared by every private directory the
/// artifact builder writes into.
fn validate_private_directory_metadata(metadata: &fs::Metadata) -> Result<(), String> {
    if !metadata.is_dir() {
        return Err("backup destination directory is not a regular directory".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode();
        let uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != 0 && metadata.uid() != uid {
            return Err("backup destination directory owner is not trusted".to_owned());
        }
        if mode & 0o022 != 0 && !(metadata.uid() == 0 && mode & 0o1000 != 0) {
            return Err("backup destination directory is writable by untrusted users".to_owned());
        }
    }
    Ok(())
}

impl Manifest {
    fn consistency_generation(&self) -> String {
        self.members
            .first()
            .map(|m| m.consistency_generation.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
fn validate_members(members: &[PlainMember]) -> Result<(), String> {
    if members.is_empty() || members.len() > MAX_MEMBERS {
        return Err("backup member count is outside the supported bound".to_owned());
    }
    let mut names = BTreeSet::new();
    let mut total = 0_usize;
    for member in members {
        validate_path(&member.name)?;
        if !names.insert(member.name.as_str()) {
            return Err("backup contains a duplicate member name".to_owned());
        }
        if member.bytes.len() > MAX_MEMBER_BYTES {
            return Err("backup member exceeds the configured size limit".to_owned());
        }
        total = total
            .checked_add(member.bytes.len())
            .ok_or("backup size overflow")?;
    }
    if total > MAX_TOTAL_PLAINTEXT {
        return Err("backup plaintext exceeds the configured aggregate limit".to_owned());
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > 1024 || !path.is_ascii() || path.starts_with('/') {
        return Err("backup member path is invalid".to_owned());
    }
    let mut segments = path.split('/');
    let allowed_root = [
        "database", "config", "release", "identity", "trust", "metadata",
    ];
    if !allowed_root.contains(&segments.next().unwrap_or_default()) {
        return Err("backup member path is not allowlisted".to_owned());
    }
    for segment in path.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || !segment
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        {
            return Err("backup member path is invalid".to_owned());
        }
    }
    Ok(())
}

fn validate_manifest(manifest: &Manifest, generation: &str) -> Result<(), String> {
    if manifest.format_version != FORMAT_VERSION
        || manifest.backup_id.is_empty()
        || manifest.site_id.is_empty()
        || manifest.installation_id.is_empty()
    {
        return Err("backup manifest identity is invalid".to_owned());
    }
    if manifest.members.is_empty() || manifest.members.len() > MAX_MEMBERS {
        return Err("backup member count is outside the supported bound".to_owned());
    }
    if manifest
        .consistency
        .get("quiescence_generation")
        .and_then(Value::as_str)
        != Some(generation)
    {
        return Err("backup members do not match the captured consistency generation".to_owned());
    }
    if DateTime::parse_from_rfc3339(&manifest.created_at).is_err()
        || manifest.site_id.len() > 128
        || manifest.installation_id.len() > 128
    {
        return Err("backup manifest timestamp or installation identity is invalid".to_owned());
    }
    let source_sha = manifest
        .source
        .get("source_sha")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let source_digest = manifest
        .source
        .get("release_artifact_sha256")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let profile = manifest
        .source
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if manifest
        .source
        .get("o3k_version")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || source_sha.len() != 40
        || !source_sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || !is_sha256(source_digest)
        || !["o3k-demo-v1", "o3k-small-edge-v1"].contains(&profile)
    {
        return Err("backup source release identity is invalid for SQLite".to_owned());
    }
    if manifest.store.get("backend").and_then(Value::as_str) != Some("sqlite")
        || manifest
            .store
            .get("server_version")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || manifest
            .store
            .get("schema_version")
            .and_then(Value::as_u64)
            .is_none()
    {
        return Err("backup SQLite store identity is invalid".to_owned());
    }
    let migrations = manifest
        .store
        .get("migrations")
        .and_then(Value::as_array)
        .ok_or("backup migration inventory is missing")?;
    if migrations.is_empty() {
        return Err("backup migration inventory is empty".to_owned());
    }
    let mut migration_versions = BTreeSet::new();
    let mut last_migration = None;
    for migration in migrations {
        let version = migration
            .get("version")
            .and_then(Value::as_u64)
            .ok_or("backup migration version is invalid")?;
        let checksum = migration
            .get("checksum")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !migration_versions.insert(version)
            || last_migration.is_some_and(|last| last >= version)
            || !is_sha256(checksum)
        {
            return Err("backup migration inventory is invalid".to_owned());
        }
        last_migration = Some(version);
    }
    let consistency = &manifest.consistency;
    if consistency.get("method").and_then(Value::as_str) != Some("sqlite_vacuum_into")
        || consistency.get("write_quiescence").and_then(Value::as_bool) != Some(true)
        || consistency
            .get("worker_quiescence")
            .and_then(Value::as_bool)
            != Some(true)
        || consistency
            .get("in_flight_operations")
            .and_then(Value::as_str)
            .is_none_or(|v| !["none", "drained", "recorded_unknown"].contains(&v))
    {
        return Err("backup consistency record is incomplete".to_owned());
    }
    let started = consistency
        .get("snapshot_started_at")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let completed = consistency
        .get("snapshot_completed_at")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let started = DateTime::parse_from_rfc3339(started)
        .map_err(|_| "backup snapshot start time is invalid")?;
    let completed = DateTime::parse_from_rfc3339(completed)
        .map_err(|_| "backup snapshot completion time is invalid")?;
    if completed < started {
        return Err("backup snapshot completion precedes its start".to_owned());
    }
    let mut names = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    let mut total = 0_u64;
    for member in &manifest.members {
        validate_path(&member.name)?;
        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(&member.nonce)
            .map_err(|_| "backup member nonce is malformed")?;
        let nonce: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| "backup member nonce is malformed")?;
        if !names.insert(member.name.as_str()) || !nonces.insert(nonce) {
            return Err("backup manifest contains duplicate member names or nonces".to_owned());
        }
        if member.consistency_generation != generation
            || member.plaintext_size_bytes.checked_add(16) != Some(member.size_bytes)
            || member.plaintext_size_bytes > MAX_MEMBER_BYTES as u64
            || member.sha256.len() != 64
            || !member
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("backup member metadata is inconsistent".to_owned());
        }
        total = total
            .checked_add(member.plaintext_size_bytes)
            .ok_or("backup size overflow")?;
    }
    if total > MAX_TOTAL_PLAINTEXT as u64 || manifest.excluded_state != excluded_state() {
        return Err("backup manifest inventory or size is invalid".to_owned());
    }
    validate_inventory(&manifest.state_inventory)?;
    if manifest.encryption.algorithm != "AES-256-GCM"
        || !manifest.encryption.key_is_external
        || manifest.encryption.key_wrapping.algorithm != "HPKE-v1-X25519-HKDF-SHA256-AES-256-GCM"
        || manifest.authentication.algorithm != "Ed25519"
    {
        return Err("backup manifest declares an unsupported cryptographic profile".to_owned());
    }
    Ok(())
}

fn validate_inventory(inventory: &[Value]) -> Result<(), String> {
    const FAMILIES: [&str; 9] = [
        "canonical_resources",
        "operations_and_reconciliation",
        "placement_allocations_and_provider_mappings",
        "topology_and_building_blocks",
        "iam_and_security_scope",
        "bootstrap_enrollment_and_revocation",
        "audit_and_governance",
        "o3k_owned_configuration",
        "release_and_install_metadata",
    ];
    if inventory.is_empty() || inventory.len() > 512 {
        return Err("backup repository inventory size is invalid".to_owned());
    }
    let mut ids = BTreeSet::new();
    let mut families = BTreeSet::new();
    for entry in inventory {
        let id = entry
            .get("repository_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let family = entry
            .get("state_family")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if id.is_empty() || !ids.insert(id) || !FAMILIES.contains(&family) {
            return Err("backup repository inventory has an invalid or duplicate entry".to_owned());
        }
        families.insert(family);
        if entry
            .get("empty_state_included")
            .and_then(Value::as_bool)
            .is_none()
            || !valid_objects(entry, "sqlite_objects")
            || !valid_objects(entry, "postgres_objects")
            || !valid_ids(entry, "migration_ids")
        {
            return Err("backup repository inventory is incomplete".to_owned());
        }
    }
    if FAMILIES.iter().any(|family| !families.contains(family)) {
        return Err("backup repository inventory omits a canonical state family".to_owned());
    }
    Ok(())
}

fn valid_objects(entry: &Value, field: &str) -> bool {
    let Some(objects) = entry.get(field).and_then(Value::as_array) else {
        return false;
    };
    if objects.is_empty() {
        return false;
    }
    let mut ids = BTreeSet::new();
    objects.iter().all(|object| {
        let kind = object
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let schema = object
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let digest = object
            .get("definition_sha256")
            .and_then(Value::as_str)
            .unwrap_or_default();
        [
            "table",
            "view",
            "sequence",
            "index",
            "constraint",
            "function",
            "trigger",
        ]
        .contains(&kind)
            && !schema.is_empty()
            && !name.is_empty()
            && is_sha256(digest)
            && ids.insert((kind, schema, name))
    })
}

fn valid_ids(entry: &Value, field: &str) -> bool {
    let Some(values) = entry.get(field).and_then(Value::as_array) else {
        return false;
    };
    if values.is_empty() {
        return false;
    }
    let mut ids = BTreeSet::new();
    values.iter().all(|value| {
        value
            .as_str()
            .is_some_and(|id| !id.is_empty() && ids.insert(id))
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn signature_input(manifest: &Manifest) -> Result<Vec<u8>, String> {
    let mut unsigned = manifest.clone();
    unsigned.authentication.signature = None;
    let canonical = serde_jcs::to_vec(&unsigned)
        .map_err(|_| "backup manifest canonicalization failed".to_owned())?;
    let mut input = Vec::new();
    input.extend_from_slice(SIGN_DOMAIN);
    input.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    input.extend_from_slice(&canonical);
    for member in &manifest.members {
        let name = member.name.as_bytes();
        input.extend_from_slice(&(name.len() as u32).to_be_bytes());
        input.extend_from_slice(name);
        let digest = hex::decode(&member.sha256)
            .map_err(|_| "backup member digest is invalid".to_owned())?;
        input.extend_from_slice(&digest);
    }
    Ok(input)
}

fn key_wrap_aad(options: &CreateOptions) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(&serde_json::json!({
        "format_version": FORMAT_VERSION,
        "profile_id": options.source.get("profile_id").and_then(Value::as_str).unwrap_or(""),
        "site_id": options.site_id,
        "backup_id": options.backup_id,
        "recipient_key_id": options.recipient_key_id,
    }))
    .map_err(|_| "backup key-wrap AAD encoding failed".to_owned())
}

fn key_wrap_aad_from_manifest(manifest: &Manifest) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(&serde_json::json!({
        "format_version": manifest.format_version,
        "profile_id": manifest.source.get("profile_id").and_then(Value::as_str).unwrap_or(""),
        "site_id": manifest.site_id,
        "backup_id": manifest.backup_id,
        "recipient_key_id": manifest.encryption.key_wrapping.recipient_key_id,
    }))
    .map_err(|_| "backup key-wrap AAD encoding failed".to_owned())
}

fn member_aad(options: &CreateOptions, name: &str, size: u64) -> Result<Vec<u8>, String> {
    aad_bytes(
        FORMAT_VERSION,
        options
            .source
            .get("profile_id")
            .and_then(Value::as_str)
            .unwrap_or(""),
        &options.site_id,
        &options.backup_id,
        name,
        size,
    )
}

fn member_aad_from_manifest(manifest: &Manifest, member: &MemberRecord) -> Result<Vec<u8>, String> {
    aad_bytes(
        &manifest.format_version,
        manifest
            .source
            .get("profile_id")
            .and_then(Value::as_str)
            .unwrap_or(""),
        &manifest.site_id,
        &manifest.backup_id,
        &member.name,
        member.plaintext_size_bytes,
    )
}

fn aad_bytes(
    format: &str,
    profile: &str,
    site: &str,
    id: &str,
    name: &str,
    size: u64,
) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(&serde_json::json!({"format_version":format,"profile_id":profile,"site_id":site,"backup_id":id,"member_name":name,"plaintext_size_bytes":size}))
        .map_err(|_| "backup member AAD encoding failed".to_owned())
}

#[cfg(test)]
fn read_len(bytes: &[u8], offset: usize) -> Result<usize, String> {
    let end = offset.checked_add(8).ok_or("backup length overflow")?;
    let raw: [u8; 8] = bytes
        .get(offset..end)
        .ok_or("backup artifact is truncated")?
        .try_into()
        .map_err(|_| "backup artifact is truncated")?;
    usize::try_from(u64::from_be_bytes(raw))
        .map_err(|_| "backup length is not supported".to_owned())
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn excluded_state() -> Vec<String> {
    [
        "tenant_vm_disks_and_guest_filesystems",
        "hypervisor_local_guest_runtime_state",
        "external_storage_payloads",
        "external_hosted_service_databases",
        "provider_local_caches",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    struct TestSigner(SigningKey);
    impl ArtifactSigner for TestSigner {
        fn key_id(&self) -> &str {
            "signing-1"
        }
        fn sign_manifest(&self, signature_input: &[u8]) -> Result<[u8; 64], String> {
            Ok(self.0.sign(signature_input).to_bytes())
        }
        fn verifying_key(&self) -> VerifyingKey {
            self.0.verifying_key()
        }
    }

    struct TestTrust {
        trusted: bool,
        revoked: bool,
    }

    impl ArtifactTrust for TestTrust {
        fn signing_key_is_trusted(
            &self,
            key_id: &str,
            site_id: &str,
            profile_id: &str,
            _public_key: &VerifyingKey,
        ) -> Result<bool, String> {
            Ok(self.trusted
                && key_id == "signing-1"
                && site_id == "site-1"
                && profile_id == "o3k-demo-v1")
        }

        fn signing_key_is_revoked(&self, key_id: &str) -> Result<bool, String> {
            Ok(self.revoked && key_id == "signing-1")
        }
    }

    fn test_trust() -> TestTrust {
        TestTrust {
            trusted: true,
            revoked: false,
        }
    }

    fn fixture() -> (
        CreateOptions,
        Vec<PlainMember>,
        TestSigner,
        <X25519HkdfSha256 as Kem>::PrivateKey,
    ) {
        let (recipient_private, recipient_public) = X25519HkdfSha256::gen_keypair();
        let signing = TestSigner(SigningKey::from_bytes(&[17_u8; 32]));
        let options = CreateOptions {
            backup_id: "backup-1".to_owned(),
            created_at: "2026-10-19T12:00:00Z".to_owned(),
            site_id: "site-1".to_owned(),
            installation_id: "install-1".to_owned(),
            source: json!({"o3k_version":"0.4.0","source_sha":"0123456789abcdef0123456789abcdef01234567","release_artifact_sha256":"a".repeat(64),"profile_id":"o3k-demo-v1"}),
            store: json!({"backend":"sqlite","server_version":"3.50","schema_version":53,"migrations":[{"version":1,"checksum":"b".repeat(64)}]}),
            consistency: json!({"method":"sqlite_vacuum_into","write_quiescence":true,"worker_quiescence":true,"in_flight_operations":"none","quiescence_generation":"generation-1","snapshot_started_at":"2026-10-19T12:00:00Z","snapshot_completed_at":"2026-10-19T12:00:01Z"}),
            state_inventory: [
                "canonical_resources", "operations_and_reconciliation", "placement_allocations_and_provider_mappings",
                "topology_and_building_blocks", "iam_and_security_scope", "bootstrap_enrollment_and_revocation",
                "audit_and_governance", "o3k_owned_configuration", "release_and_install_metadata",
            ].into_iter().enumerate().map(|(index, family)| json!({
                "repository_id":format!("repository-{index}"),"state_family":family,"empty_state_included":false,
                "sqlite_objects":[{"kind":"table","schema":"main","name":format!("table_{index}"),"definition_sha256":"c".repeat(64)}],
                "postgres_objects":[{"kind":"table","schema":"public","name":format!("table_{index}"),"definition_sha256":"d".repeat(64)}],
                "migration_ids":[format!("{index}")]
            })).collect(),
            consistency_generation: "generation-1".to_owned(),
            recipient_key_id: "recovery-1".to_owned(),
            recipient_public_key: recipient_public.to_bytes().into(),
            artifact_key_id: "artifact-1".to_owned(),
            signing_key_id: "signing-1".to_owned(),
        };
        let members = vec![
            PlainMember {
                name: "database/state.sqlite".to_owned(),
                media_type: "application/vnd.sqlite3".to_owned(),
                bytes: b"snapshot".to_vec(),
            },
            PlainMember {
                name: "config/o3kd.env".to_owned(),
                media_type: "text/plain".to_owned(),
                bytes: b"O3K_PROFILE=o3k-demo-v1".to_vec(),
            },
        ];
        (options, members, signing, recipient_private)
    }

    fn expected_release() -> ExpectedRelease {
        let families = [
            "canonical_resources",
            "operations_and_reconciliation",
            "placement_allocations_and_provider_mappings",
            "topology_and_building_blocks",
            "iam_and_security_scope",
            "bootstrap_enrollment_and_revocation",
            "audit_and_governance",
            "o3k_owned_configuration",
            "release_and_install_metadata",
        ];
        ExpectedRelease {
            site_id: "site-1".to_owned(),
            installation_id: "install-1".to_owned(),
            o3k_version: "0.4.0".to_owned(),
            source_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            release_artifact_sha256: "a".repeat(64),
            profile_id: "o3k-demo-v1".to_owned(),
            store_backend: "sqlite".to_owned(),
            schema_version: 53,
            migrations: vec![MigrationIdentity {
                version: 1,
                checksum: "b".repeat(64),
            }],
            state_inventory: families
                .into_iter()
                .enumerate()
                .map(|(index, family)| {
                    json!({
                        "repository_id":format!("repository-{index}"),
                        "state_family":family,
                        "empty_state_included":false,
                        "sqlite_objects":[{"kind":"table","schema":"main","name":format!("table_{index}"),"definition_sha256":"c".repeat(64)}],
                        "postgres_objects":[{"kind":"table","schema":"public","name":format!("table_{index}"),"definition_sha256":"d".repeat(64)}],
                        "migration_ids":[format!("{index}")]
                    })
                })
                .collect(),
        }
    }

    #[test]
    fn artifact_round_trip_authenticates_and_decrypts_members() {
        let (options, members, signing, recipient) = fixture();
        let (artifact, digest) =
            create_artifact(&options, members.clone(), &signing).expect("create");
        assert_eq!(digest, hex_sha256(&artifact));
        let (manifest, restored) = verify_artifact(
            &artifact,
            &expected_release(),
            "signing-1",
            &signing.0.verifying_key(),
            "recovery-1",
            &recipient,
        )
        .expect("verify");
        assert_eq!(manifest.backup_id, "backup-1");
        assert_eq!(
            restored.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            ["config/o3kd.env", "database/state.sqlite"]
        );
        assert_eq!(restored[1].bytes, members[0].bytes);
    }

    #[test]
    fn artifact_rejects_ciphertext_corruption_and_untrusted_signer() {
        let (options, members, signing, recipient) = fixture();
        let (mut artifact, _) = create_artifact(&options, members, &signing).expect("create");
        let last = artifact.len() - 1;
        artifact[last] ^= 1;
        assert!(
            verify_artifact(
                &artifact,
                &expected_release(),
                "signing-1",
                &signing.0.verifying_key(),
                "recovery-1",
                &recipient
            )
            .is_err()
        );
        let (artifact, _) = create_artifact(
            &options,
            vec![PlainMember {
                name: "database/state.sqlite".to_owned(),
                media_type: "application/vnd.sqlite3".to_owned(),
                bytes: b"state".to_vec(),
            }],
            &signing,
        )
        .expect("create");
        assert!(
            verify_artifact(
                &artifact,
                &expected_release(),
                "other-key",
                &signing.0.verifying_key(),
                "recovery-1",
                &recipient
            )
            .is_err()
        );
    }

    #[test]
    fn artifact_rejects_a_different_release_identity_or_migration_baseline() {
        let (options, members, signing, recipient) = fixture();
        let (artifact, _) = create_artifact(&options, members, &signing).expect("create");
        let mut expected = expected_release();
        expected.site_id = "other-site".to_owned();
        assert!(
            verify_artifact(
                &artifact,
                &expected,
                "signing-1",
                &signing.0.verifying_key(),
                "recovery-1",
                &recipient,
            )
            .is_err()
        );

        let mut expected = expected_release();
        expected.installation_id = "other-installation".to_owned();
        assert!(
            verify_artifact(
                &artifact,
                &expected,
                "signing-1",
                &signing.0.verifying_key(),
                "recovery-1",
                &recipient,
            )
            .is_err()
        );

        let mut expected = expected_release();
        expected.source_sha = "fedcba9876543210fedcba9876543210fedcba98".to_owned();
        assert!(
            verify_artifact(
                &artifact,
                &expected,
                "signing-1",
                &signing.0.verifying_key(),
                "recovery-1",
                &recipient,
            )
            .is_err()
        );

        let mut expected = expected_release();
        expected.migrations[0].checksum = "c".repeat(64);
        assert!(
            verify_artifact(
                &artifact,
                &expected,
                "signing-1",
                &signing.0.verifying_key(),
                "recovery-1",
                &recipient,
            )
            .is_err()
        );

        let mut expected = expected_release();
        expected.state_inventory[0]["sqlite_objects"][0]["definition_sha256"] =
            Value::String("e".repeat(64));
        assert!(
            verify_artifact(
                &artifact,
                &expected,
                "signing-1",
                &signing.0.verifying_key(),
                "recovery-1",
                &recipient,
            )
            .is_err()
        );
    }

    #[test]
    fn artifact_rejects_unsafe_paths_and_duplicate_members() {
        let (options, mut members, signing, _) = fixture();
        members[0].name = "database/../private".to_owned();
        assert!(create_artifact(&options, members, &signing).is_err());
        let (_, mut members, signing, _) = fixture();
        members[1].name = members[0].name.clone();
        assert!(create_artifact(&options, members, &signing).is_err());
    }

    #[test]
    fn artifact_rejects_manifest_fields_outside_the_contract_schema() {
        let (mut options, members, signing, _) = fixture();
        options.backup_id = "../outside".to_owned();
        assert!(create_artifact(&options, members, &signing).is_err());
    }

    #[test]
    fn artifact_rejects_replay_of_wrong_consistency_generation() {
        let (mut options, members, signing, _) = fixture();
        options.consistency_generation = "another-generation".to_owned();
        assert!(create_artifact(&options, members, &signing).is_err());
    }

    #[test]
    fn streaming_gcm_round_trip_and_rejects_a_bad_tag() {
        let plaintext = (0..(STREAM_CHUNK_BYTES * 2 + 37))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let key = [0x42_u8; 32];
        let nonce = [0x24_u8; 12];
        let aad = b"streaming-gcm-test-aad";
        let (mut input, mut encrypted) = (std::io::Cursor::new(&plaintext), Vec::new());
        let (plain_size, cipher_size, digest) = encrypt_member_stream(
            &mut input,
            &mut encrypted,
            &key,
            &nonce,
            aad,
            plaintext.len() as u64,
        )
        .expect("encrypt");
        assert_eq!(plain_size, plaintext.len() as u64);
        assert_eq!(cipher_size, encrypted.len() as u64);
        assert_eq!(digest, hex_sha256(&encrypted));

        let (mut encrypted_input, mut decrypted) =
            (std::io::Cursor::new(encrypted.clone()), Vec::new());
        let (decrypted_size, verified_digest) = decrypt_member_stream(
            &mut encrypted_input,
            &mut decrypted,
            &key,
            &nonce,
            aad,
            cipher_size,
        )
        .expect("decrypt");
        assert_eq!(decrypted_size, plain_size);
        assert_eq!(verified_digest, digest);
        assert_eq!(decrypted, plaintext);

        *encrypted.last_mut().expect("tag byte") ^= 1;
        let (mut encrypted_input, mut provisional_plaintext) =
            (std::io::Cursor::new(encrypted), Vec::new());
        assert!(
            decrypt_member_stream(
                &mut encrypted_input,
                &mut provisional_plaintext,
                &key,
                &nonce,
                aad,
                cipher_size,
            )
            .is_err()
        );
    }

    #[test]
    fn stream_builder_uses_private_unique_staging_and_checks_declared_size() {
        let (options, plain_members, signing, recipient) = fixture();
        let root = std::env::temp_dir().join(format!("o3k-pp6-stream-{}", Uuid::now_v7()));
        create_private_dir(&root).expect("private root");
        let trust = test_trust();
        let verifying_key = signing.0.verifying_key();
        let keys = ArtifactVerificationKeys {
            signing_key_id: "signing-1",
            signer: &verifying_key,
            trust: &trust,
            recipient_key_id: "recovery-1",
            recipient: &recipient,
        };
        let payload = (0..(STREAM_CHUNK_BYTES * 3 + 19))
            .map(|index| (index % 239) as u8)
            .collect::<Vec<_>>();
        let members = vec![
            StreamMember {
                name: "database/state.sqlite".to_owned(),
                media_type: "application/vnd.sqlite3".to_owned(),
                plaintext_size_bytes: payload.len() as u64,
                source: std::io::Cursor::new(payload.clone()),
            },
            StreamMember {
                name: "config/o3kd.env".to_owned(),
                media_type: "text/plain".to_owned(),
                plaintext_size_bytes: plain_members[1].bytes.len() as u64,
                source: std::io::Cursor::new(plain_members[1].bytes.clone()),
            },
        ];
        let staged =
            create_artifact_stream(&options, members, &root, &signing).expect("streamed artifact");
        assert!(staged.path.starts_with(&staged.staging_directory));
        assert_eq!(
            staged.size_bytes,
            fs::metadata(&staged.path).expect("artifact").len()
        );
        assert_eq!(staged.sha256, hash_file(&staged.path).expect("hash").1);
        let streamed_bytes = fs::read(&staged.path).expect("read bounded test fixture");
        let (_, ring_plaintext) = verify_artifact(
            &streamed_bytes,
            &expected_release(),
            "signing-1",
            &signing.0.verifying_key(),
            "recovery-1",
            &recipient,
        )
        .expect("ring verifies streamed AES-GCM artifact");
        assert_eq!(
            ring_plaintext
                .iter()
                .find(|member| member.name == "database/state.sqlite")
                .expect("database member")
                .bytes,
            payload
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&staged.staging_directory)
                    .expect("stage dir")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&staged.path)
                    .expect("artifact")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let mut artifact_file = fs::File::open(&staged.path).expect("open staged artifact");
        let verified =
            verify_artifact_stream(&mut artifact_file, &expected_release(), &keys, &root)
                .expect("verify staged artifact");
        let database = verified
            .members
            .iter()
            .find(|member| member.record.name == "database/state.sqlite")
            .expect("database member");
        assert_eq!(
            fs::read(&database.path).expect("database contents"),
            payload
        );
        fs::remove_dir_all(&verified.staging_directory).expect("remove verified staging");
        fs::remove_dir_all(&staged.staging_directory).expect("remove staged artifact");

        let bad_members = vec![StreamMember {
            name: "database/state.sqlite".to_owned(),
            media_type: "application/vnd.sqlite3".to_owned(),
            plaintext_size_bytes: 1,
            source: std::io::Cursor::new(vec![1, 2]),
        }];
        assert!(create_artifact_stream(&options, bad_members, &root, &signing).is_err());
        fs::remove_dir_all(root).expect("remove root");
    }

    fn stream_fixture_members(
        plain_members: &[PlainMember],
    ) -> Vec<StreamMember<std::io::Cursor<Vec<u8>>>> {
        plain_members
            .iter()
            .map(|member| StreamMember {
                name: member.name.clone(),
                media_type: member.media_type.clone(),
                plaintext_size_bytes: member.bytes.len() as u64,
                source: std::io::Cursor::new(member.bytes.clone()),
            })
            .collect()
    }

    #[test]
    fn unsigned_stage_finishes_with_a_detached_signature_only_after_verification() {
        let (options, plain_members, signing, recipient) = fixture();
        let root = std::env::temp_dir().join(format!("o3k-pp6-unsigned-{}", Uuid::now_v7()));
        create_private_dir(&root).expect("private root");
        let unsigned =
            stage_unsigned_artifact(&options, stream_fixture_members(&plain_members), &root)
                .expect("stage unsigned artifact");
        assert!(unsigned.manifest.authentication.signature.is_none());
        assert!(unsigned.path.ends_with("artifact.unsigned"));
        assert_eq!(
            unsigned.manifest_digest,
            hex_sha256(
                &serde_jcs::to_vec(&unsigned.manifest).expect("canonical unsigned manifest")
            )
        );
        assert_eq!(
            unsigned.signing_input,
            signature_input(&unsigned.manifest).expect("signing input")
        );

        // A different key must not be able to complete the artifact, and the
        // failure must not leave a publishable file behind.
        let foreign = SigningKey::from_bytes(&[18_u8; 32]);
        let foreign_signature = signing.0.sign(&unsigned.signing_input).to_bytes();
        assert!(
            finish_signed_artifact(
                unsigned,
                foreign_signature,
                "signing-1",
                &foreign.verifying_key()
            )
            .is_err()
        );
        let member_dirs = fs::read_dir(&root).expect("staging root").count();
        assert_eq!(member_dirs, 1, "unsigned staging is preserved on failure");

        // The offline custodian re-reads the staged artifact, signs the exact
        // signing input, and the operator completes from that detached data.
        let unsigned = read_unsigned_staged_artifact(&root).expect("re-read staged artifact");
        let signature = signing
            .sign_manifest(&unsigned.signing_input)
            .expect("offline signature");
        let staged =
            finish_signed_artifact(unsigned, signature, "signing-1", &signing.0.verifying_key())
                .expect("finish signed artifact");
        assert!(staged.manifest.authentication.signature.is_some());
        assert!(staged.path.ends_with("artifact.partial"));
        let bytes = fs::read(&staged.path).expect("signed artifact");
        assert_eq!(staged.sha256, hex_sha256(&bytes));
        assert_eq!(staged.size_bytes, bytes.len() as u64);
        let (manifest, restored) = verify_artifact(
            &bytes,
            &expected_release(),
            "signing-1",
            &signing.0.verifying_key(),
            "recovery-1",
            &recipient,
        )
        .expect("signed artifact verifies");
        assert_eq!(manifest.backup_id, "backup-1");
        assert_eq!(restored.len(), plain_members.len());
        assert!(!staged.staging_directory.join("artifact.unsigned").exists());
        fs::remove_dir_all(&root).expect("remove root");
    }

    #[test]
    fn unsigned_stage_rejects_a_wrong_key_id_and_a_tampered_payload() {
        let (options, plain_members, signing, _) = fixture();
        let root = std::env::temp_dir().join(format!("o3k-pp6-unsigned-{}", Uuid::now_v7()));
        create_private_dir(&root).expect("private root");
        let unsigned =
            stage_unsigned_artifact(&options, stream_fixture_members(&plain_members), &root)
                .expect("stage unsigned artifact");
        let signature = signing
            .sign_manifest(&unsigned.signing_input)
            .expect("signature");
        let unsigned_path = unsigned.path.clone();
        assert!(
            finish_signed_artifact(unsigned, signature, "other-key", &signing.0.verifying_key())
                .is_err()
        );
        assert!(!unsigned_path.with_file_name("artifact.partial").exists());

        // A same-size ciphertext modification keeps the file structurally
        // valid, so the detached signature still verifies; the payload is
        // re-digested against the signed manifest before anything is written.
        let mut bytes = fs::read(&unsigned_path).expect("staged bytes");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&unsigned_path, &bytes).expect("corrupt staged artifact");
        let unsigned = read_unsigned_staged_artifact(&root).expect("size is unchanged");
        let signature = signing
            .sign_manifest(&unsigned.signing_input)
            .expect("signature");
        assert!(
            finish_signed_artifact(unsigned, signature, "signing-1", &signing.0.verifying_key())
                .is_err()
        );

        // A truncated staged artifact is rejected by the reader itself.
        let mut bytes = fs::read(&unsigned_path).expect("staged bytes");
        bytes.truncate(bytes.len() - 1);
        fs::write(&unsigned_path, &bytes).expect("truncate staged artifact");
        assert!(read_unsigned_staged_artifact(&root).is_err());
        fs::remove_dir_all(&root).expect("remove root");
    }

    #[test]
    fn stream_verifier_authenticates_members_before_return_and_cleans_failed_stage() {
        let (options, members, signing, recipient) = fixture();
        let (artifact, _) = create_artifact(&options, members, &signing).expect("artifact");
        let root = std::env::temp_dir().join(format!("o3k-pp6-verify-{}", Uuid::now_v7()));
        create_private_dir(&root).expect("private root");
        let trust = test_trust();
        let verifying_key = signing.0.verifying_key();
        let keys = ArtifactVerificationKeys {
            signing_key_id: "signing-1",
            signer: &verifying_key,
            trust: &trust,
            recipient_key_id: "recovery-1",
            recipient: &recipient,
        };
        let mut input = std::io::Cursor::new(artifact.clone());
        let verified = verify_artifact_stream(&mut input, &expected_release(), &keys, &root)
            .expect("verify stream");
        assert_eq!(verified.members.len(), 2);
        let database = verified
            .members
            .iter()
            .find(|member| member.record.name == "database/state.sqlite")
            .expect("database member");
        assert_eq!(
            fs::read(&database.path).expect("private plaintext"),
            b"snapshot"
        );
        fs::remove_dir_all(&verified.staging_directory).expect("remove verified stage");

        let revoked_trust = TestTrust {
            trusted: true,
            revoked: true,
        };
        let revoked_keys = ArtifactVerificationKeys {
            trust: &revoked_trust,
            ..keys
        };
        let mut input = std::io::Cursor::new(artifact.clone());
        assert!(
            verify_artifact_stream(&mut input, &expected_release(), &revoked_keys, &root,).is_err()
        );
        assert_eq!(fs::read_dir(&root).expect("staging root").count(), 0);

        for malformed in [artifact[..artifact.len() - 1].to_vec(), {
            let mut trailing = artifact.clone();
            trailing.push(0);
            trailing
        }] {
            let mut input = std::io::Cursor::new(malformed);
            assert!(
                verify_artifact_stream(&mut input, &expected_release(), &keys, &root,).is_err()
            );
            assert_eq!(fs::read_dir(&root).expect("staging root").count(), 0);
        }

        let mut corrupted = artifact;
        *corrupted.last_mut().expect("tag") ^= 0x80;
        let mut input = std::io::Cursor::new(corrupted);
        assert!(verify_artifact_stream(&mut input, &expected_release(), &keys, &root,).is_err());
        assert_eq!(fs::read_dir(&root).expect("staging root").count(), 0);
        fs::remove_dir_all(root).expect("remove root");
    }

    #[cfg(unix)]
    #[test]
    fn streaming_builder_and_verifier_reject_symlink_staging_roots() {
        use std::os::unix::fs::symlink;

        let (options, members, signing, recipient) = fixture();
        let (artifact, _) = create_artifact(&options, members.clone(), &signing).expect("artifact");
        let root = std::env::temp_dir().join(format!("o3k-pp6-symlink-{}", Uuid::now_v7()));
        let target = root.join("target");
        let link = root.join("link");
        create_private_dir(&root).expect("private root");
        create_private_dir(&target).expect("private target");
        symlink(&target, &link).expect("create staging symlink");

        let stream_members = members
            .into_iter()
            .map(|member| StreamMember {
                name: member.name.clone(),
                media_type: member.media_type.clone(),
                plaintext_size_bytes: member.bytes.len() as u64,
                source: std::io::Cursor::new(member.bytes.clone()),
            })
            .collect();
        assert!(create_artifact_stream(&options, stream_members, &link, &signing).is_err());
        let trust = test_trust();
        let verifying_key = signing.0.verifying_key();
        let keys = ArtifactVerificationKeys {
            signing_key_id: "signing-1",
            signer: &verifying_key,
            trust: &trust,
            recipient_key_id: "recovery-1",
            recipient: &recipient,
        };
        let mut input = std::io::Cursor::new(artifact);
        assert!(verify_artifact_stream(&mut input, &expected_release(), &keys, &link).is_err());
        assert_eq!(fs::read_dir(&target).expect("symlink target").count(), 0);
        fs::remove_dir_all(root).expect("remove root");
    }

    #[test]
    fn manifest_rejects_duplicate_decoded_nonces_and_size_overflow() {
        let (options, members, signing, _) = fixture();
        let (artifact, _) = create_artifact(&options, members, &signing).expect("create");
        let manifest_start = MAGIC.len() + 8;
        let manifest_len = read_len(&artifact, MAGIC.len()).expect("manifest length");
        let manifest: Manifest =
            serde_json::from_slice(&artifact[manifest_start..manifest_start + manifest_len])
                .expect("generated manifest parses");

        let mut duplicate_nonce = manifest.clone();
        let first_nonce = duplicate_nonce.members[0].nonce.clone();
        duplicate_nonce.members[1].nonce = first_nonce;
        assert!(validate_manifest(&duplicate_nonce, "generation-1").is_err());

        let mut overflowed_size = manifest;
        overflowed_size.members[0].plaintext_size_bytes = u64::MAX;
        assert!(validate_manifest(&overflowed_size, "generation-1").is_err());
    }

    #[test]
    fn atomic_publisher_restricts_stage_and_preserves_existing_destination() {
        let (options, members, signing, _) = fixture();
        let (artifact, digest) = create_artifact(&options, members, &signing).expect("create");
        let directory = std::env::temp_dir().join(format!("o3k-pp6-publish-{}", Uuid::now_v7()));
        fs::create_dir(&directory).expect("create test destination directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("restrict test destination directory");
        }
        let destination = directory.join("backup.o3k");

        assert_eq!(
            publish_atomic(&destination, &artifact).expect("publish"),
            digest
        );
        assert_eq!(
            fs::read(&destination).expect("read published artifact"),
            artifact
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&destination)
                    .expect("published file metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let replacement = b"preserve prior backup";
        assert!(publish_atomic(&destination, replacement).is_err());
        assert_eq!(
            fs::read(&destination).expect("read original artifact"),
            artifact
        );
        assert_eq!(
            fs::read_dir(&directory)
                .expect("list publication directory")
                .count(),
            1,
            "successful publication removes its private staging directory"
        );
        fs::remove_dir_all(&directory).expect("remove test directory");
    }
}
