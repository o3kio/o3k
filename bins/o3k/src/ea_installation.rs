//! Early Access installation admission.
//!
//! The EA profile is selected by the authenticated release manifest and a
//! root-owned installation identity written by the installer. This module is
//! intentionally separate from C1: an EA identity never satisfies or
//! weakens the recovery-qualified selector.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::AsFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

use rustix::{
    fs::{Mode, OFlags, fstat, open},
    process::geteuid,
};

const MAX_IDENTITY_BYTES: usize = 16 * 1024;
pub const EA_IDENTITY_PATH: &str = "/etc/o3k/installation-identity.json";
const EA_KEY_PATH: &str = "/etc/o3k/installation-local.key";
const C1_POLICY_PATH: &str = "/etc/o3k/installation-policy.json";
const C1_TRUST_PATH: &str = "/etc/o3k/recovery-trust.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selector {
    Legacy,
    C1,
    EarlyAccess,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityPayload {
    format: String,
    profile: String,
    authority: String,
    backend: String,
    installation_id: String,
    site_id: String,
    release_version: String,
    release_artifact_sha256: String,
    data_root: String,
    config_root: String,
    data_root_device: u64,
    data_root_inode: u64,
    config_root_device: u64,
    config_root_inode: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityEnvelope {
    payload: IdentityPayload,
    verification_key: String,
    signature: String,
}

/// Validate authenticated release selection and the durable, root-owned EA
/// identity before an installed control-plane process opens state or listens.
pub fn verify_startup(
    data_root: &Path,
    expected_backend: Option<&str>,
) -> Result<(), &'static str> {
    let manifest_path = Path::new("/usr/local/share/o3k/release-manifest.json");
    let manifest = match crate::upgrade::release_identity::read_fixed_installed_release_manifest() {
        Ok(bytes) => bytes,
        Err(_) => {
            return match fs::symlink_metadata(manifest_path) {
                Ok(_) => Err("installed release manifest is unsafe or unavailable"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err("installed release manifest cannot be observed"),
            };
        }
    };
    let (object, selector) = selector_from_manifest(&manifest)?;
    match selector {
        Selector::Legacy | Selector::C1 => return Ok(()),
        Selector::EarlyAccess => {}
    }

    // Any C1 artifact, even malformed or partial state, blocks EA admission.
    for path in [
        Path::new(C1_POLICY_PATH),
        Path::new(C1_TRUST_PATH),
        Path::new("/var/lib/o3k-recovery"),
        Path::new("/var/lib/o3k-recovery-state"),
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err("C1 or recovery state blocks Early Access admission"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("C1 or recovery state cannot be safely observed"),
        }
    }

    let identity = read_identity(Path::new(EA_IDENTITY_PATH))?;
    let payload = &identity.payload;
    if payload.format != "o3k-installation-identity-v1"
        || payload.profile != "early-access-v1"
        || payload.authority != "installation-local"
        || payload.backend != "postgresql"
        || expected_backend.is_some_and(|backend| backend != payload.backend)
        || payload.data_root != data_root.to_string_lossy()
        || payload.config_root != "/etc/o3k"
    {
        return Err("Early Access installation identity does not match runtime configuration");
    }
    if object.get("version").and_then(|v| v.as_str()) != Some(payload.release_version.as_str())
        || object
            .get("release_artifact_sha256")
            .and_then(|v| v.as_str())
            != Some(payload.release_artifact_sha256.as_str())
    {
        return Err("Early Access installation identity does not match authenticated release");
    }
    let data_metadata =
        fs::symlink_metadata(data_root).map_err(|_| "Early Access state root is unavailable")?;
    let config_metadata =
        fs::symlink_metadata("/etc/o3k").map_err(|_| "Early Access config root is unavailable")?;
    if data_metadata.file_type().is_symlink()
        || !data_metadata.is_dir()
        || data_metadata.uid() != 0
        || data_metadata.mode() & 0o022 != 0
        || config_metadata.file_type().is_symlink()
        || !config_metadata.is_dir()
        || config_metadata.uid() != 0
        || config_metadata.mode() & 0o022 != 0
        || payload.data_root_device != data_metadata.dev()
        || payload.data_root_inode != data_metadata.ino()
        || payload.config_root_device != config_metadata.dev()
        || payload.config_root_inode != config_metadata.ino()
    {
        return Err("Early Access installation directory binding changed");
    }
    if !is_uuid(&payload.installation_id) || !is_uuid(&payload.site_id) {
        return Err("Early Access installation identity is malformed");
    }
    Ok(())
}

fn selector_from_manifest(
    bytes: &[u8],
) -> Result<(serde_json::Map<String, serde_json::Value>, Selector), &'static str> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "installed release manifest is malformed")?;
    let object = value
        .as_object()
        .ok_or("installed release manifest is malformed")?;
    let has_c1 = [
        "installation_policy_format",
        "installation_policy_path",
        "installation_policy_authority",
        "installation_policy_v2_authority",
    ]
    .iter()
    .any(|key| object.contains_key(*key));
    let has_ea_selector = object.contains_key("installation_security_profile")
        || object.contains_key("installation_authority");
    if has_c1 && has_ea_selector {
        return Err("release manifest contains conflicting installation authorities");
    }
    if has_c1 {
        return Ok((object.clone(), Selector::C1));
    }
    if !has_ea_selector {
        return Ok((object.clone(), Selector::Legacy));
    }
    if object
        .get("installation_security_profile")
        .and_then(|v| v.as_str())
        != Some("early-access-v1")
        || object
            .get("installation_authority")
            .and_then(|v| v.as_str())
            != Some("installation-local")
        || object.get("profile_id").and_then(|v| v.as_str()) != Some("o3k-early-access-v1")
    {
        return Err("release manifest installation profile or authority is unsupported");
    }
    Ok((object.clone(), Selector::EarlyAccess))
}

fn read_identity(path: &Path) -> Result<IdentityEnvelope, &'static str> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| "Early Access installation identity is unavailable")?;
    let stat = fstat(fd.as_fd()).map_err(|_| "Early Access installation identity is unsafe")?;
    if stat.st_mode & 0o170000 != 0o100000
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
        || (geteuid().as_raw() != 0 && stat.st_mode & 0o040 == 0)
        || stat.st_size < 2
        || stat.st_size as usize > MAX_IDENTITY_BYTES
    {
        return Err("Early Access installation identity is unsafe");
    }
    let file = fs::File::from(fd);
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    file.take((MAX_IDENTITY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "Early Access installation identity cannot be read")?;
    if bytes.len() > MAX_IDENTITY_BYTES || bytes.len() as i64 != stat.st_size {
        return Err("Early Access installation identity changed while reading");
    }
    let envelope: IdentityEnvelope = serde_json::from_slice(&bytes)
        .map_err(|_| "Early Access installation identity is malformed")?;
    verify_envelope(&envelope)?;
    Ok(envelope)
}

fn verify_envelope(envelope: &IdentityEnvelope) -> Result<(), &'static str> {
    let public_bytes: [u8; 32] = hex::decode(&envelope.verification_key)
        .map_err(|_| "Early Access installation trust is malformed")?
        .try_into()
        .map_err(|_| "Early Access installation trust is malformed")?;
    let signature_bytes: [u8; 64] = hex::decode(&envelope.signature)
        .map_err(|_| "Early Access installation trust is malformed")?
        .try_into()
        .map_err(|_| "Early Access installation trust is malformed")?;
    let key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| "Early Access installation trust is malformed")?;
    let signature = Signature::from_bytes(&signature_bytes);
    let bytes = serde_jcs::to_vec(&envelope.payload)
        .map_err(|_| "Early Access installation identity cannot be canonicalized")?;
    key.verify(&bytes, &signature)
        .map_err(|_| "Early Access installation identity signature is invalid")
}

/// Create the signed installation-local identity for an authenticated EA
/// release. Call only after installer preflight and before service startup.
pub fn provision(data_root: &Path) -> Result<(), &'static str> {
    if geteuid().as_raw() != 0 {
        return Err("Early Access installation trust provisioning requires root");
    }
    let manifest = crate::upgrade::release_identity::read_fixed_installed_release_manifest()
        .map_err(|_| "authenticated Early Access release manifest is unavailable")?;
    let (_, selector) = selector_from_manifest(&manifest)?;
    if selector != Selector::EarlyAccess {
        return Err("installation-local trust requires an authenticated Early Access release");
    }
    for path in [
        Path::new(C1_POLICY_PATH),
        Path::new(C1_TRUST_PATH),
        Path::new("/var/lib/o3k-recovery"),
        Path::new("/var/lib/o3k-recovery-state"),
        Path::new(EA_IDENTITY_PATH),
        Path::new(EA_KEY_PATH),
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err("existing installation or trust state blocks fresh EA provisioning");
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("installation trust state cannot be safely observed"),
        }
    }
    let data =
        fs::symlink_metadata(data_root).map_err(|_| "Early Access state root is unavailable")?;
    let config =
        fs::symlink_metadata("/etc/o3k").map_err(|_| "Early Access config root is unavailable")?;
    if data_root != Path::new("/var/lib/o3k")
        || data.file_type().is_symlink()
        || !data.is_dir()
        || data.uid() != 0
        || data.mode() & 0o022 != 0
        || config.file_type().is_symlink()
        || !config.is_dir()
        || config.uid() != 0
        || config.mode() & 0o022 != 0
    {
        return Err("Early Access installation directories are unsafe");
    }
    let manifest_value: serde_json::Value = serde_json::from_slice(&manifest)
        .map_err(|_| "authenticated Early Access release manifest is malformed")?;
    let version = manifest_value
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or("authenticated Early Access release version is missing")?;
    let digest = manifest_value
        .get("release_artifact_sha256")
        .and_then(|v| v.as_str())
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or("authenticated Early Access release digest is missing")?;
    let mut seed = [0u8; 32];
    openssl::rand::rand_bytes(&mut seed).map_err(|_| "cannot generate installation-local trust")?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let payload = IdentityPayload {
        format: "o3k-installation-identity-v1".into(),
        profile: "early-access-v1".into(),
        authority: "installation-local".into(),
        backend: "postgresql".into(),
        installation_id: uuid::Uuid::new_v4().to_string(),
        site_id: uuid::Uuid::new_v4().to_string(),
        release_version: version.into(),
        release_artifact_sha256: digest.into(),
        data_root: data_root.display().to_string(),
        config_root: "/etc/o3k".into(),
        data_root_device: data.dev(),
        data_root_inode: data.ino(),
        config_root_device: config.dev(),
        config_root_inode: config.ino(),
    };
    let signing_bytes = serde_jcs::to_vec(&payload)
        .map_err(|_| "Early Access installation identity cannot be canonicalized")?;
    let envelope = IdentityEnvelope {
        payload,
        verification_key: hex::encode(key.verifying_key().as_bytes()),
        signature: hex::encode(key.sign(&signing_bytes).to_bytes()),
    };
    let serialized = serde_json::to_vec(&envelope)
        .map_err(|_| "Early Access installation identity cannot be serialized")?;
    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    let mut key_file = options
        .open(EA_KEY_PATH)
        .map_err(|_| "cannot safely publish installation-local trust material")?;
    let mut signing_key_bytes = key.to_bytes();
    let key_write = key_file
        .write_all(&signing_key_bytes)
        .and_then(|_| key_file.sync_all());
    signing_key_bytes.fill(0);
    if key_write.is_err() {
        let _ = fs::remove_file(EA_KEY_PATH);
        return Err("cannot persist installation-local trust material");
    }
    let write_result = (|| {
        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        let mut identity_file = options
            .open(EA_IDENTITY_PATH)
            .map_err(|_| "cannot safely publish Early Access installation identity")?;
        identity_file
            .write_all(&serialized)
            .and_then(|_| identity_file.sync_all())
            .map_err(|_| "cannot persist Early Access installation identity")?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(EA_KEY_PATH);
    }
    if write_result.is_ok() {
        fs::File::open("/etc/o3k")
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "cannot persist Early Access installation identity directory")?;
    }
    write_result
}

fn is_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|uuid| uuid.to_string() == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_requires_canonical_spelling() {
        assert!(is_uuid("018f1f6d-7b7a-7cc2-9c1a-529c02c89a43"));
        assert!(!is_uuid("NOT-A-UUID"));
        assert!(!is_uuid("018F1F6D-7B7A-7CC2-9C1A-529C02C89A43"));
    }

    #[test]
    fn release_selector_is_explicit_and_exclusive() {
        let ea = br#"{"profile_id":"o3k-early-access-v1","installation_security_profile":"early-access-v1","installation_authority":"installation-local"}"#;
        assert_eq!(
            selector_from_manifest(ea).map(|(_, selector)| selector),
            Ok(Selector::EarlyAccess)
        );
        let c1 = br#"{"installation_policy_authority":{}}"#;
        assert_eq!(
            selector_from_manifest(c1).map(|(_, selector)| selector),
            Ok(Selector::C1)
        );
        let legacy = br#"{"profile_id":"o3k-small-edge-v1"}"#;
        assert_eq!(
            selector_from_manifest(legacy).map(|(_, selector)| selector),
            Ok(Selector::Legacy)
        );
        let conflict = br#"{"profile_id":"o3k-early-access-v1","installation_security_profile":"early-access-v1","installation_authority":"installation-local","installation_policy_authority":{}}"#;
        assert_eq!(
            selector_from_manifest(conflict).err(),
            Some("release manifest contains conflicting installation authorities")
        );
        let partial = br#"{"profile_id":"o3k-early-access-v1","installation_security_profile":"early-access-v1"}"#;
        assert_eq!(
            selector_from_manifest(partial).err(),
            Some("release manifest installation profile or authority is unsupported")
        );
    }

    #[test]
    fn local_identity_signature_authenticates_bound_payload() {
        let key = SigningKey::from_bytes(&[93; 32]);
        let payload = IdentityPayload {
            format: "o3k-installation-identity-v1".into(),
            profile: "early-access-v1".into(),
            authority: "installation-local".into(),
            backend: "postgresql".into(),
            installation_id: "018f1f6d-7b7a-7cc2-9c1a-529c02c89a43".into(),
            site_id: "018f1f6d-7b7a-7cc2-9c1a-529c02c89a44".into(),
            release_version: "v0.4.1".into(),
            release_artifact_sha256: "a".repeat(64),
            data_root: "/var/lib/o3k".into(),
            config_root: "/etc/o3k".into(),
            data_root_device: 1,
            data_root_inode: 2,
            config_root_device: 1,
            config_root_inode: 3,
        };
        let bytes = serde_jcs::to_vec(&payload);
        assert!(bytes.is_ok());
        let bytes = bytes.unwrap_or_default();
        let envelope = IdentityEnvelope {
            payload,
            verification_key: hex::encode(key.verifying_key().as_bytes()),
            signature: hex::encode(key.sign(&bytes).to_bytes()),
        };
        assert_eq!(verify_envelope(&envelope), Ok(()));
        let mut changed = envelope;
        changed.payload.site_id = "018f1f6d-7b7a-7cc2-9c1a-529c02c89a45".into();
        assert_eq!(
            verify_envelope(&changed),
            Err("Early Access installation identity signature is invalid")
        );
    }
}
