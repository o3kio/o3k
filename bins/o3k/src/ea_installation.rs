//! Early Access installation admission.
//!
//! The EA profile is selected by the authenticated release manifest and a
//! root-owned installation identity written by the installer. This module is
//! intentionally separate from C1: an EA identity never satisfies or
//! weakens the recovery-qualified selector.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{
    Deserialize, Serialize,
    de::{MapAccess, Visitor},
};
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{Read, Write},
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};

use rustix::{
    fs::{
        AtFlags, Mode, OFlags, RenameFlags, fchmod, fstat, open, openat, renameat_with, statat,
        unlinkat,
    },
    process::geteuid,
};

const MAX_IDENTITY_BYTES: usize = 16 * 1024;
pub const EA_IDENTITY_PATH: &str = "/etc/o3k/installation-identity.json";
const EA_KEY_PATH: &str = "/etc/o3k/installation-local.key";
const C1_POLICY_PATH: &str = "/etc/o3k/installation-policy.json";
const C1_TRUST_PATH: &str = "/etc/o3k/recovery-trust.json";

struct UniqueManifest(BTreeMap<String, serde_json::Value>);

impl<'de> Deserialize<'de> for UniqueManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ManifestVisitor;
        impl<'de> Visitor<'de> for ManifestVisitor {
            type Value = UniqueManifest;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object with unique manifest keys")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if values.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate manifest key"));
                    }
                }
                Ok(UniqueManifest(values))
            }
        }
        deserializer.deserialize_map(ManifestVisitor)
    }
}

fn publish_new_file(
    directory: &fs::File,
    name: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<(), &'static str> {
    let temporary = format!(".{name}.{}.tmp", uuid::Uuid::new_v4());
    let result = (|| {
        let fd = openat(
            directory.as_fd(),
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| "cannot create installation-local trust staging file")?;
        let mut file = fs::File::from(fd);
        fchmod(file.as_fd(), Mode::from_raw_mode(mode))
            .map_err(|_| "cannot set installation-local trust file mode")?;
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect installation-local trust staging file")?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != mode
            || metadata.nlink() != 1
        {
            return Err("installation-local trust staging file is unsafe");
        }
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "cannot persist installation-local trust staging file")?;
        renameat_with(
            directory.as_fd(),
            temporary.as_str(),
            directory.as_fd(),
            name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| "cannot safely publish installation-local trust file")?;
        directory
            .sync_all()
            .map_err(|_| "cannot persist installation-local trust directory")?;
        let published = statat(directory.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "cannot verify published installation-local trust file")?;
        if published.st_dev != metadata.dev() || published.st_ino != metadata.ino() {
            return Err("published installation-local trust file changed identity");
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(directory.as_fd(), temporary.as_str(), AtFlags::empty());
    }
    result
}

fn service_uid() -> Result<u32, &'static str> {
    let passwd_path = Path::new("/etc/passwd");
    let metadata = fs::symlink_metadata(passwd_path)
        .map_err(|_| "Early Access service identity cannot be observed")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err("Early Access service identity database is unsafe");
    }
    let contents = fs::read_to_string(passwd_path)
        .map_err(|_| "Early Access service identity cannot be read")?;
    let mut matches = contents.lines().filter_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == "o3k")
            .then(|| fields.nth(1)?.parse::<u32>().ok())
            .flatten()
    });
    let uid = matches
        .next()
        .ok_or("Early Access service identity is missing")?;
    if matches.next().is_some() {
        return Err("Early Access service identity is ambiguous");
    }
    Ok(uid)
}

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
) -> Result<bool, &'static str> {
    let manifest_path = Path::new("/usr/local/share/o3k/release-manifest.json");
    let manifest = match crate::upgrade::release_identity::read_fixed_installed_release_manifest() {
        Ok(bytes) => bytes,
        Err(_) => {
            return match fs::symlink_metadata(manifest_path) {
                Ok(_) => Err("installed release manifest is unsafe or unavailable"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(_) => Err("installed release manifest cannot be observed"),
            };
        }
    };
    let (object, selector) = selector_from_manifest(&manifest)?;
    match selector {
        Selector::Legacy | Selector::C1 => return Ok(false),
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
    verify_private_key_posture()?;
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
    let o3k_uid = service_uid()?;
    let config_metadata =
        fs::symlink_metadata("/etc/o3k").map_err(|_| "Early Access config root is unavailable")?;
    if data_metadata.file_type().is_symlink()
        || !data_metadata.is_dir()
        || (data_metadata.uid() != 0 && data_metadata.uid() != o3k_uid)
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
    Ok(true)
}

fn selector_from_manifest(
    bytes: &[u8],
) -> Result<(serde_json::Map<String, serde_json::Value>, Selector), &'static str> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let UniqueManifest(values) = UniqueManifest::deserialize(&mut deserializer)
        .map_err(|_| "installed release manifest is malformed")?;
    deserializer
        .end()
        .map_err(|_| "installed release manifest is malformed")?;
    let object = serde_json::Map::from_iter(values);
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
        return Ok((object, Selector::C1));
    }
    if !has_ea_selector {
        return Ok((object, Selector::Legacy));
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
    Ok((object, Selector::EarlyAccess))
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

fn verify_private_key_posture() -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(EA_KEY_PATH)
        .map_err(|_| "Early Access installation-local trust key is unavailable")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != 32
    {
        return Err("Early Access installation-local trust key is unsafe");
    }
    Ok(())
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
    let config_fd = open(
        "/etc/o3k",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| "Early Access config root is unavailable")?;
    let config_directory = fs::File::from(config_fd);
    let opened_config = config_directory
        .metadata()
        .map_err(|_| "Early Access config root is unsafe")?;
    if opened_config.dev() != config.dev() || opened_config.ino() != config.ino() {
        return Err("Early Access config root changed during provisioning");
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
    let mut signing_key_bytes = key.to_bytes();
    let key_result = publish_new_file(
        &config_directory,
        "installation-local.key",
        &signing_key_bytes,
        0o600,
    );
    signing_key_bytes.fill(0);
    key_result?;
    let write_result = publish_new_file(
        &config_directory,
        "installation-identity.json",
        &serialized,
        0o644,
    );
    if write_result.is_err() {
        let _ = unlinkat(
            config_directory.as_fd(),
            "installation-local.key",
            AtFlags::empty(),
        );
        let _ = config_directory.sync_all();
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
    fn duplicate_release_manifest_keys_fail_closed() {
        let manifest = br#"{"profile_id":"o3k-early-access-v1","profile_id":"legacy","installation_security_profile":"early-access-v1","installation_authority":"installation-local"}"#;
        assert!(selector_from_manifest(manifest).is_err());
    }

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

    #[test]
    fn postgres_url_uses_the_local_socket_without_a_password() {
        let options = "postgresql://o3k@%2Fvar%2Frun%2Fpostgresql/o3k"
            .parse::<sqlx::postgres::PgConnectOptions>();
        assert!(options.is_ok());
    }
}
