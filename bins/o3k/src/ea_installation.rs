//! Early Access installation admission.
//!
//! The EA profile is selected by the authenticated release manifest and a
//! root-owned installation identity written by the installer. This module is
//! intentionally separate from C1: an EA identity never satisfies or
//! weakens the recovery-qualified selector.

use serde::Deserialize;
use std::{fs, io::Read, os::fd::AsFd, path::Path};

use rustix::{
    fs::{Mode, OFlags, fstat, open},
    process::geteuid,
};

const MAX_IDENTITY_BYTES: usize = 16 * 1024;
pub const EA_IDENTITY_PATH: &str = "/etc/o3k/installation-identity.json";
const C1_POLICY_PATH: &str = "/etc/o3k/installation-policy.json";
const C1_TRUST_PATH: &str = "/etc/o3k/recovery-trust.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selector {
    Legacy,
    C1,
    EarlyAccess,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
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
        if fs::symlink_metadata(path).is_ok() {
            return Err("C1 or recovery state blocks Early Access admission");
        }
    }

    let identity = read_identity(Path::new(EA_IDENTITY_PATH))?;
    if identity.format != "o3k-installation-identity-v1"
        || identity.profile != "early-access-v1"
        || identity.authority != "installation-local"
        || identity.backend != "postgresql"
        || expected_backend.is_some_and(|backend| backend != identity.backend)
        || identity.data_root != data_root.to_string_lossy()
        || identity.config_root != "/etc/o3k"
    {
        return Err("Early Access installation identity does not match runtime configuration");
    }
    if object.get("version").and_then(|v| v.as_str()) != Some(identity.release_version.as_str())
        || object
            .get("release_artifact_sha256")
            .and_then(|v| v.as_str())
            != Some(identity.release_artifact_sha256.as_str())
    {
        return Err("Early Access installation identity does not match authenticated release");
    }
    if !is_uuid(&identity.installation_id) || !is_uuid(&identity.site_id) {
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

fn read_identity(path: &Path) -> Result<Identity, &'static str> {
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
    serde_json::from_slice(&bytes).map_err(|_| "Early Access installation identity is malformed")
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
}
