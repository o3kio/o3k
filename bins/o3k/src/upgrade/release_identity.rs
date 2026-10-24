//! Trusted exact-release identity for backup artifact binding.
//!
//! A backup artifact declares the release that produced it. The verifier must
//! compare those declarations against the release actually installed on this
//! host, never against values copied from the artifact under inspection. The
//! installed release manifest (`<prefix>/share/o3k/release-manifest.json`) is
//! written by the release pipeline and by the installer; this module is the
//! single reader for the subset the backup contract needs.
//!
//! The tarball digest cannot be embedded in the bundle's own manifest (the
//! manifest travels inside the tarball), so it is persisted into the
//! *installed* manifest by the installer and the upgrade engine from the
//! digest they actually verified. Manifests that predate that persistence
//! fail closed here instead of falling back to a fabricated digest.
//!
//! # Trust-boundary posture (SPEC-0050 §8)
//!
//! Every reader goes through [`read_installed_release_manifest`]: a bounded
//! (≤ 1 MiB) read through an `O_NOFOLLOW` descriptor whose own metadata must be
//! a regular file owned by root or the effective uid and not group/other-
//! writable, inside a directory with the same owner and write posture. A root
//! process resolves the canonical `/usr/local` prefix and ignores
//! `O3K_INSTALL_PREFIX`; the override is honored only for a non-root caller
//! (see `backup_trust::install_prefix`).

use serde_json::Value;
use std::{
    fs::File,
    io::{self, Read},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use rustix::{
    fs::{Mode, OFlags, open},
    process::geteuid,
};

/// Bound for the installed release manifest. It is a small JSON identity, so
/// the trust-boundary reader never buffers more than this.
const MAX_RELEASE_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Product profiles accepted by the backup artifact contract.
pub const SUPPORTED_PROFILE_IDS: [&str; 2] = ["o3k-demo-v1", "o3k-small-edge-v1"];

/// Exact release identity a backup artifact must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReleaseIdentity {
    pub o3k_version: String,
    pub source_sha: String,
    pub release_artifact_sha256: String,
    pub profile_id: String,
    pub schema_version: u64,
}

impl BackupReleaseIdentity {
    /// Parses and validates an installed release manifest.
    ///
    /// Missing historical fields fail closed with an explicit "incomplete"
    /// error: a verifier must never infer a release identity.
    pub fn from_manifest_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|_| "installed release manifest is not valid JSON".to_owned())?;
        let manifest = value
            .as_object()
            .ok_or_else(|| "installed release manifest is not a JSON object".to_owned())?;

        let o3k_version = manifest
            .get("version")
            .or_else(|| manifest.get("o3k_version"))
            .and_then(Value::as_str)
            .filter(|version| !version.trim().is_empty())
            .ok_or_else(|| "release identity incomplete: version missing".to_owned())?
            .to_owned();

        let source_sha = manifest
            .get("source_commit")
            .or_else(|| manifest.get("source_sha"))
            .and_then(Value::as_str)
            .ok_or_else(|| "release identity incomplete: source_sha missing".to_owned())?;
        if !is_lower_hex(source_sha, 40) {
            return Err(
                "release identity invalid: source_sha is not a 40-character lowercase hex SHA"
                    .to_owned(),
            );
        }

        let release_artifact_sha256 = manifest
            .get("release_artifact_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "release identity incomplete: release_artifact_sha256 missing".to_owned()
            })?;
        if !is_lower_hex(release_artifact_sha256, 64) {
            return Err(
                "release identity invalid: release_artifact_sha256 is not a 64-character lowercase hex SHA-256"
                    .to_owned(),
            );
        }

        let profile_id = manifest
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "release identity incomplete: profile_id missing".to_owned())?;
        if !SUPPORTED_PROFILE_IDS.contains(&profile_id) {
            return Err(format!(
                "release identity invalid: profile_id {profile_id} is not a supported product profile"
            ));
        }

        let schema_version = parse_schema_version(manifest.get("schema_version"))?;

        Ok(Self {
            o3k_version,
            source_sha: source_sha.to_owned(),
            release_artifact_sha256: release_artifact_sha256.to_owned(),
            profile_id: profile_id.to_owned(),
            schema_version,
        })
    }
}

/// Reads the exact release identity from the installed release manifest.
///
/// `prefix` is the installation prefix (`/usr/local` by default); the manifest
/// lives at `<prefix>/share/o3k/release-manifest.json`.
///
/// The manifest is installation trust data, so it is read with the same
/// posture as the trust document (SPEC-0050 §8):
///
/// * bounded read (≤ 1 MiB) through a descriptor opened `O_NOFOLLOW`;
/// * the descriptor's own metadata must be a regular file owned by root or the
///   effective uid and not group/other-writable;
/// * the containing directory must be a real directory owned by root or the
///   effective uid and not group/other-writable.
///
/// The release manifest is installed `0644`, so group/other *read* is allowed;
/// only write permission is refused. A root process resolves the canonical
/// prefix (see `backup_trust::install_prefix`), so the caller cannot redirect
/// it.
pub fn backup_release_identity(prefix: &Path) -> Result<BackupReleaseIdentity, String> {
    let bytes = read_installed_release_manifest(prefix)?;
    BackupReleaseIdentity::from_manifest_bytes(&bytes)
}

/// Reads the installed release manifest with the trust-boundary posture.
///
/// Every reader of `<prefix>/share/o3k/release-manifest.json` goes through this
/// function so no caller can reintroduce a path-following or unbounded read.
pub fn read_installed_release_manifest(prefix: &Path) -> Result<Vec<u8>, String> {
    let manifest = prefix.join("share/o3k/release-manifest.json");
    read_trusted_manifest(&manifest)
        .map_err(|error| format!("cannot read {}: {error}", manifest.display()))
}

/// Bounded, no-follow read of the installed release manifest.
fn read_trusted_manifest(path: &Path) -> io::Result<Vec<u8>> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let parent_metadata = std::fs::metadata(parent)?;
    if !parent_metadata.is_dir() || !trusted_owner(parent_metadata.uid()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "release manifest directory is not trusted",
        ));
    }
    if parent_metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "release manifest directory is writable by untrusted users",
        ));
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            io::Error::new(io::ErrorKind::InvalidInput, "release manifest is a symlink")
        } else {
            io::Error::from(error)
        }
    })?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || !trusted_owner(metadata.uid()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "release manifest is not a trusted regular file",
        ));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "release manifest is writable by untrusted users",
        ));
    }
    if metadata.len() > MAX_RELEASE_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "release manifest exceeds the size bound",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_RELEASE_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RELEASE_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "release manifest exceeds the size bound",
        ));
    }
    Ok(bytes)
}

/// Root, or the effective uid, owns installation metadata.
fn trusted_owner(uid: u32) -> bool {
    uid == 0 || uid == geteuid().as_raw()
}

/// Adds the verified release-tarball digest to a bundle manifest before it is
/// installed by the upgrade engine.
///
/// `verified` is the digest the engine computed over the downloaded tarball.
/// A manifest that already declares a different digest is rejected: the
/// installed identity must equal the artifact that was actually verified.
pub fn manifest_with_verified_artifact(
    manifest_bytes: &[u8],
    verified: &str,
) -> Result<Vec<u8>, String> {
    if !is_lower_hex(verified, 64) {
        return Err("verified release artifact digest is not a lowercase SHA-256".to_owned());
    }
    let mut value: Value = serde_json::from_slice(manifest_bytes)
        .map_err(|_| "bundle release manifest is not valid JSON".to_owned())?;
    let manifest = value
        .as_object_mut()
        .ok_or_else(|| "bundle release manifest is not a JSON object".to_owned())?;
    match manifest.get("release_artifact_sha256") {
        Some(existing) if existing.as_str() == Some(verified) => return Ok(manifest_bytes.to_vec()),
        Some(existing) => {
            return Err(format!(
                "bundle release manifest declares release_artifact_sha256 {existing}, but the verified tarball digest is {verified}"
            ));
        }
        None => {
            manifest.insert(
                "release_artifact_sha256".to_owned(),
                Value::String(verified.to_owned()),
            );
        }
    }
    let mut encoded = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot encode the release manifest: {error}"))?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn parse_schema_version(value: Option<&Value>) -> Result<u64, String> {
    match value {
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| "release identity invalid: schema_version is not an integer".to_owned()),
        Some(Value::String(text)) => text
            .parse::<u64>()
            .map_err(|_| "release identity invalid: schema_version is not an integer".to_owned()),
        Some(_) => Err("release identity invalid: schema_version is not an integer".to_owned()),
        None => Err("release identity incomplete: schema_version missing".to_owned()),
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn manifest(digest: Option<&str>, profile: &str) -> Vec<u8> {
        let digest_field = digest
            .map(|digest| format!(r#","release_artifact_sha256":"{digest}""#))
            .unwrap_or_default();
        format!(
            r#"{{"version":"0.4.0","profile":"libvirt","source_commit":"0123456789abcdef0123456789abcdef01234567","installer_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","profile_id":"{profile}","schema_version":"17"{digest_field}}}"#
        )
        .into_bytes()
    }

    fn temp_prefix() -> PathBuf {
        std::env::temp_dir().join(format!("o3k-release-identity-{}", Uuid::now_v7()))
    }

    /// A private install prefix whose directory chain passes the trust-boundary
    /// posture (0700, effective-uid owned). `/tmp` itself is sticky but not
    /// group/other-writable after the mode check on the direct parent.
    fn private_prefix() -> PathBuf {
        let prefix = temp_prefix();
        let share = prefix.join("share/o3k");
        std::fs::create_dir_all(&share).unwrap();
        std::fs::set_permissions(&prefix, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(prefix.join("share"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o700)).unwrap();
        prefix
    }

    #[test]
    fn parses_a_complete_manifest() {
        let digest = "a".repeat(64);
        let identity =
            BackupReleaseIdentity::from_manifest_bytes(&manifest(Some(&digest), "o3k-demo-v1"))
                .expect("complete manifest parses");
        assert_eq!(
            identity,
            BackupReleaseIdentity {
                o3k_version: "0.4.0".to_owned(),
                source_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                release_artifact_sha256: digest,
                profile_id: "o3k-demo-v1".to_owned(),
                schema_version: 17,
            }
        );
    }

    #[test]
    fn accepts_a_numeric_schema_version() {
        let digest = "a".repeat(64);
        let bytes = format!(
            r#"{{"version":"0.4.0","source_commit":"0123456789abcdef0123456789abcdef01234567","release_artifact_sha256":"{digest}","profile_id":"o3k-small-edge-v1","schema_version":18}}"#
        );
        let identity = BackupReleaseIdentity::from_manifest_bytes(bytes.as_bytes()).unwrap();
        assert_eq!(identity.schema_version, 18);
        assert_eq!(identity.profile_id, "o3k-small-edge-v1");
    }

    #[test]
    fn missing_digest_fails_closed() {
        let error = BackupReleaseIdentity::from_manifest_bytes(&manifest(None, "o3k-demo-v1"))
            .expect_err("missing digest is rejected");
        assert_eq!(
            error,
            "release identity incomplete: release_artifact_sha256 missing"
        );
    }

    #[test]
    fn malformed_digest_fails_closed() {
        for digest in ["abc", &"A".repeat(64), &"g".repeat(64)] {
            let error =
                BackupReleaseIdentity::from_manifest_bytes(&manifest(Some(digest), "o3k-demo-v1"))
                    .expect_err("malformed digest is rejected");
            assert!(
                error.contains("release_artifact_sha256 is not a 64-character lowercase hex SHA"),
                "{error}"
            );
        }
    }

    #[test]
    fn unsupported_profile_fails_closed() {
        let digest = "a".repeat(64);
        let error = BackupReleaseIdentity::from_manifest_bytes(&manifest(Some(&digest), "libvirt"))
            .expect_err("build profile is not a product profile");
        assert!(error.contains("profile_id libvirt is not a supported product profile"));
    }

    #[test]
    fn invalid_source_sha_fails_closed() {
        let digest = "a".repeat(64);
        let bytes = format!(
            r#"{{"version":"0.4.0","source_commit":"d6351864","release_artifact_sha256":"{digest}","profile_id":"o3k-demo-v1","schema_version":"17"}}"#
        );
        let error = BackupReleaseIdentity::from_manifest_bytes(bytes.as_bytes()).unwrap_err();
        assert!(error.contains("source_sha is not a 40-character lowercase hex SHA"));
    }

    #[test]
    fn reads_the_installed_manifest_from_the_prefix() {
        let prefix = private_prefix();
        let share = prefix.join("share/o3k");
        let digest = "c".repeat(64);
        let path = share.join("release-manifest.json");
        std::fs::write(&path, manifest(Some(&digest), "o3k-small-edge-v1")).unwrap();
        // The installer writes the manifest 0644; the ambient test umask is
        // not part of the contract.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let identity = backup_release_identity(&prefix).expect("installed manifest parses");
        assert_eq!(identity.release_artifact_sha256, digest);
        assert_eq!(identity.profile_id, "o3k-small-edge-v1");
        std::fs::remove_dir_all(&prefix).unwrap();
    }

    #[test]
    fn release_manifest_read_fails_closed_on_unsafe_entries() {
        let prefix = private_prefix();
        let share = prefix.join("share/o3k");
        let path = share.join("release-manifest.json");
        let digest = "c".repeat(64);
        std::fs::write(&path, manifest(Some(&digest), "o3k-demo-v1")).unwrap();

        // Symlink substitution of the final component.
        let link = share.join("linked-manifest.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        std::fs::rename(&path, share.join("real-manifest.json")).unwrap();
        std::os::unix::fs::symlink(share.join("real-manifest.json"), &path).unwrap();
        assert!(backup_release_identity(&prefix).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&link).unwrap();
        std::fs::rename(share.join("real-manifest.json"), &path).unwrap();

        // A group-writable manifest is installation metadata an untrusted
        // user could redirect.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(backup_release_identity(&prefix).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        backup_release_identity(&prefix).expect("0644 is the installed posture");

        // Oversized input is bounded before parsing.
        let oversized = vec![b' '; (MAX_RELEASE_MANIFEST_BYTES + 1) as usize];
        std::fs::write(&path, &oversized).unwrap();
        assert!(backup_release_identity(&prefix).is_err());

        std::fs::remove_dir_all(&prefix).unwrap();
    }

    #[test]
    fn missing_manifest_is_an_error() {
        let prefix = temp_prefix();
        let error = backup_release_identity(&prefix).expect_err("missing manifest is rejected");
        assert!(error.contains("cannot read"), "{error}");
    }

    #[test]
    fn upgrade_helper_adds_the_verified_digest() {
        let digest = "d".repeat(64);
        let bytes = manifest(None, "o3k-demo-v1");
        let augmented = manifest_with_verified_artifact(&bytes, &digest).unwrap();
        let identity = BackupReleaseIdentity::from_manifest_bytes(&augmented).unwrap();
        assert_eq!(identity.release_artifact_sha256, digest);
    }

    #[test]
    fn upgrade_helper_rejects_a_different_declared_digest() {
        let declared = "d".repeat(64);
        let verified = "e".repeat(64);
        let error =
            manifest_with_verified_artifact(&manifest(Some(&declared), "o3k-demo-v1"), &verified)
                .expect_err("mismatched digest is rejected");
        assert!(error.contains("verified tarball digest"), "{error}");
    }
}
