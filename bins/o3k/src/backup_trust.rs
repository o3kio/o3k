//! Root-owned installation trust and recipient-key configuration for the
//! authenticated PP.6 backup artifact.
//!
//! SPEC-0050 §8 requires site/profile, database roles, trust and key handles to
//! come only from root-owned installation configuration. This module is that
//! configuration boundary for backup artifacts: it loads one versioned JSON
//! document, validates the file posture (no-follow final component, regular
//! file, trusted owner, not group/other-writable) and every custody field, and
//! exposes the result as an [`ArtifactTrust`] implementation plus a bounded
//! recipient-key reader.
//!
//! ADR-0189 keeps the release Ed25519 key out of the backup trust chain. The
//! document has no field that can name a release or trust-root key; the only
//! signing key it can bind carries the `artifact-signing` custody purpose, and
//! an artifact-signing key is never accepted for release verification.
//!
//! Nothing here logs or embeds key material in an error message: errors are
//! typed and render a stable reason string only. The recipient private key is
//! read on demand into zeroizing memory. The parsed hpke private key is
//! `x25519_dalek::StaticSecret`, which implements `ZeroizeOnDrop`; the raw
//! 32-byte parsed copy is held in [`zeroize::Zeroizing`], so no serialized
//! private-key copy survives a drop.
//!
//! `custody.expires_at` is mandatory: a trust document without a custody
//! deadline fails closed with `trust-custody-incomplete`. Expiry is evaluated
//! against the host clock; the tool makes no HSM time-attestation claim.
//!
//! # Root and non-root posture
//!
//! SPEC-0050 §8 requires root-owned installation configuration. The posture is
//! therefore split by effective uid:
//!
//! * **Root (`euid == 0`)** ignores every environment override
//!   (`O3K_BACKUP_TRUST_CONFIG`, `O3K_INSTALL_PREFIX`, `O3K_UPGRADE_PREFIX`,
//!   `O3K_DATA_DIR`). Trust is read from `/etc/o3k/backup-trust.json` and the
//!   release identity from the canonical install prefix
//!   ([`DEFAULT_INSTALL_PREFIX`]). A privileged process must never let its
//!   caller redirect the trust root.
//! * **Non-root** (a test or service identity) may honor
//!   `O3K_BACKUP_TRUST_CONFIG` and `O3K_INSTALL_PREFIX`. Because the caller is
//!   then the authority anyway, the loaded document and key files must still be
//!   owned by root or the effective uid, mode `0600`, inside a parent that is
//!   root-or-effective-uid-owned and not group/other-writable. This is the
//!   documented non-root posture, not a weaker trust claim.
//!
//! When no override applies the document lives at
//! `<prefix>/etc/o3k/backup-trust.json` (prefix defaults to
//! [`DEFAULT_INSTALL_PREFIX`]), and `/etc/o3k/backup-trust.json` for root, the
//! installed layout's [`crate::context::DEFAULT_CONFIG_DIR`] shared with doctor
//! and upgrade.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fmt,
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use hpke::{Deserializable, Kem, Serializable, kem::X25519HkdfSha256};
use rustix::{
    fs::{Mode, OFlags, open},
    process::geteuid,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::backup::ArtifactTrust;

/// Versioned format marker for the installation trust document.
pub const TRUST_CONFIG_FORMAT: &str = "o3k-backup-trust-v1";

/// Environment override for the trust document path.
pub const TRUST_CONFIG_ENV: &str = "O3K_BACKUP_TRUST_CONFIG";

/// Environment override for the installation prefix.
pub const INSTALL_PREFIX_ENV: &str = "O3K_INSTALL_PREFIX";

/// Canonical installation prefix used by the installer and by a root process.
pub const DEFAULT_INSTALL_PREFIX: &str = "/usr/local";

const INSTALLED_CONFIG_SUBDIR: &str = "etc/o3k";
const TRUST_CONFIG_FILE_NAME: &str = "backup-trust.json";
const MAX_TRUST_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_RECIPIENT_KEY_BYTES: u64 = 4096;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_STORAGE_CLASS_BYTES: usize = 64;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const X25519_PRIVATE_KEY_BYTES: usize = 32;
const X25519_PUBLIC_KEY_BYTES: usize = 32;
const CUSTODY_PURPOSE: &str = "artifact-signing";
const CUSTODY_THRESHOLD: &str = "2-of-3";
const CUSTODY_PRINCIPALS: usize = 3;
const SUPPORTED_PROFILES: [&str; 2] = ["o3k-demo-v1", "o3k-small-edge-v1"];

/// Typed trust-boundary failure. [`Self::reason`] is the stable,
/// secret-free string callers may log or emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackupTrustError {
    /// The configured document cannot be opened or inspected.
    ConfigUnavailable,
    /// The final path component is a symbolic link.
    ConfigSymlink,
    /// The document is not a regular file.
    ConfigNotRegularFile,
    /// The document owner is neither root nor the effective uid.
    ConfigOwnerUntrusted,
    /// The document is group- or other-writable.
    ConfigPermissionsTooOpen,
    /// The containing directory is untrusted or group/other-writable.
    ConfigParentUntrusted,
    /// The document exceeds the supported size bound.
    ConfigTooLarge,
    /// The document is not valid JSON for this schema.
    ConfigMalformed,
    /// The document declares a different format version.
    ConfigFormatUnsupported,
    /// A site, installation, key or custody identifier is malformed.
    ConfigIdentityInvalid,
    /// The configured profile is not a backup-capable O3K profile.
    ProfileUnsupported,
    /// The configured artifact signing public key is malformed.
    ArtifactKeyInvalid,
    /// The custody record is missing, mismatched or incomplete.
    CustodyInvalid,
    /// The custody record carries no `expires_at` deadline.
    CustodyIncomplete,
    /// The custody record has expired.
    CustodyExpired,
    /// The recipient key path is not absolute.
    RecipientKeyPathInvalid,
    /// The recipient key file cannot be opened.
    RecipientKeyUnavailable,
    /// The recipient key file is a symbolic link.
    RecipientKeySymlink,
    /// The recipient key file is owned by an untrusted user.
    RecipientKeyOwnerUntrusted,
    /// The recipient key file is accessible to group or other.
    RecipientKeyPermissionsTooOpen,
    /// The recipient key directory is untrusted or group/other-writable.
    RecipientKeyParentUntrusted,
    /// The recipient key does not contain 32 bytes or 64 hex characters.
    RecipientKeyInvalid,
    /// The store data directory cannot be resolved for identity derivation.
    IdentityUnavailable,
    /// The configured identity does not match the local installation.
    IdentityMismatch,
}

impl BackupTrustError {
    /// True when the document can be fixed by the operator (missing
    /// configuration, missing key file) rather than proving the artifact or
    /// the installation wrong.
    ///
    /// Both `o3k backup create` and `o3k backup verify` classify on this one
    /// predicate so the same missing configuration is exit 3 in both commands.
    #[must_use]
    pub const fn is_recoverable(self) -> bool {
        matches!(
            self,
            Self::ConfigUnavailable | Self::RecipientKeyUnavailable | Self::IdentityUnavailable
        )
    }

    /// Stable reason string for operator output. It never contains key
    /// material, paths or provider payloads.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ConfigUnavailable => "trust-config-unavailable",
            Self::ConfigSymlink => "trust-config-symlink",
            Self::ConfigNotRegularFile => "trust-config-not-regular-file",
            Self::ConfigOwnerUntrusted => "trust-config-owner-untrusted",
            Self::ConfigPermissionsTooOpen => "trust-config-permissions-too-open",
            Self::ConfigParentUntrusted => "trust-config-parent-untrusted",
            Self::ConfigTooLarge => "trust-config-too-large",
            Self::ConfigMalformed => "trust-config-malformed",
            Self::ConfigFormatUnsupported => "trust-config-format-unsupported",
            Self::ConfigIdentityInvalid => "trust-config-identity-invalid",
            Self::ProfileUnsupported => "trust-profile-unsupported",
            Self::ArtifactKeyInvalid => "trust-artifact-key-invalid",
            Self::CustodyInvalid => "trust-custody-invalid",
            Self::CustodyIncomplete => "trust-custody-incomplete",
            Self::CustodyExpired => "trust-custody-expired",
            Self::RecipientKeyPathInvalid => "trust-recipient-key-path-invalid",
            Self::RecipientKeyUnavailable => "trust-recipient-key-unavailable",
            Self::RecipientKeySymlink => "trust-recipient-key-symlink",
            Self::RecipientKeyOwnerUntrusted => "trust-recipient-key-owner-untrusted",
            Self::RecipientKeyPermissionsTooOpen => "trust-recipient-key-permissions-too-open",
            Self::RecipientKeyParentUntrusted => "trust-recipient-key-parent-untrusted",
            Self::RecipientKeyInvalid => "trust-recipient-key-invalid",
            Self::IdentityUnavailable => "trust-identity-unavailable",
            Self::IdentityMismatch => "identity-mismatch",
        }
    }
}

impl fmt::Display for BackupTrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason())
    }
}

impl std::error::Error for BackupTrustError {}

/// The parsed installation trust document.
///
/// Fields are private so the document can only be obtained through
/// [`BackupTrustConfig::load`], which enforces the file posture and custody
/// schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupTrustConfig {
    format: String,
    site_id: String,
    installation_id: String,
    profile_id: String,
    artifact_signing: ArtifactSigning,
    recipient: Recipient,
    revoked_key_ids: Vec<String>,
    custody: Custody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactSigning {
    key_id: String,
    /// Lowercase or uppercase hex of the 32-byte Ed25519 public key.
    ed25519_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipient {
    key_id: String,
    /// Absolute path to the 32-byte or 64-hex-character X25519 private key.
    ///
    /// Optional so a capture-only installation can name just the public key.
    /// Verification still requires the private key to decrypt members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x25519_private_key_file: Option<String>,
    /// Optional lowercase or uppercase hex of the 32-byte X25519 public key.
    ///
    /// When present it is compared with the private key at load time, and the
    /// capture path uses it without reading the private key at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x25519_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Custody {
    record_id: String,
    purpose: String,
    /// Lowercase hex SHA-256 of the artifact signing public key.
    key_fingerprint: String,
    threshold: String,
    custodians: Vec<String>,
    storage_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

impl BackupTrustConfig {
    /// Loads and validates the installation trust document at `path`.
    ///
    /// Fails closed on any file-posture, schema, identity, key or custody
    /// discrepancy. The document is opened with `O_NOFOLLOW` and validated
    /// against the descriptor's own metadata, so a symlink swap cannot
    /// redirect the read.
    pub fn load(path: &Path) -> Result<Self, BackupTrustError> {
        Self::load_with_effective_uid(path, current_euid())
    }

    /// [`Self::load`] with an explicit effective uid. Production always passes
    /// the process's real effective uid; tests use it to exercise the
    /// foreign-owner branch without needing root.
    fn load_with_effective_uid(path: &Path, effective_uid: u32) -> Result<Self, BackupTrustError> {
        let opened = open_no_follow(path).map_err(|failure| match failure {
            OpenFailure::Unavailable => BackupTrustError::ConfigUnavailable,
            OpenFailure::Symlink => BackupTrustError::ConfigSymlink,
        })?;
        if !opened.metadata.file_type().is_file() {
            return Err(BackupTrustError::ConfigNotRegularFile);
        }
        if !is_trusted_owner(opened.metadata.uid(), effective_uid) {
            return Err(BackupTrustError::ConfigOwnerUntrusted);
        }
        if opened.metadata.permissions().mode() & 0o077 != 0 {
            return Err(BackupTrustError::ConfigPermissionsTooOpen);
        }
        validate_parent_directory(path, effective_uid).map_err(|failure| match failure {
            ParentFailure::Unavailable | ParentFailure::OwnerUntrusted => {
                BackupTrustError::ConfigParentUntrusted
            }
            ParentFailure::PermissionsTooOpen => BackupTrustError::ConfigPermissionsTooOpen,
        })?;
        if opened.metadata.len() > MAX_TRUST_CONFIG_BYTES {
            return Err(BackupTrustError::ConfigTooLarge);
        }
        let mut bytes = Vec::new();
        (&opened.file)
            .take(MAX_TRUST_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| BackupTrustError::ConfigUnavailable)?;
        if bytes.len() as u64 > MAX_TRUST_CONFIG_BYTES {
            return Err(BackupTrustError::ConfigTooLarge);
        }
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|_| BackupTrustError::ConfigMalformed)?;
        config.validate(effective_uid)?;
        Ok(config)
    }

    /// Configured site identity.
    #[must_use]
    pub fn site_id(&self) -> &str {
        &self.site_id
    }

    /// Configured installation identity.
    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Configured product/deployment profile.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Configured artifact signing key id.
    #[must_use]
    pub fn artifact_signing_key_id(&self) -> &str {
        &self.artifact_signing.key_id
    }

    /// Configured recovery recipient key id.
    #[must_use]
    pub fn recipient_key_id(&self) -> &str {
        &self.recipient.key_id
    }

    /// Configured revoked key ids.
    #[must_use]
    pub fn revoked_key_ids(&self) -> &[String] {
        &self.revoked_key_ids
    }

    /// Configured custody record id.
    #[must_use]
    pub fn custody_record_id(&self) -> &str {
        &self.custody.record_id
    }

    /// Decodes the configured 32-byte Ed25519 public key.
    fn signing_public_key(&self) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES], BackupTrustError> {
        decode_ed25519_public_key(&self.artifact_signing.ed25519_public_key)
    }

    /// Returns the configured artifact-signing public key.
    ///
    /// The document is validated at load time, so this normally succeeds. It
    /// stays fallible because a 32-byte value that is not a valid Ed25519
    /// point must never be turned into a verification key by panicking.
    pub fn artifact_signing_public_key(&self) -> Result<VerifyingKey, BackupTrustError> {
        let bytes = self.signing_public_key()?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| BackupTrustError::ArtifactKeyInvalid)
    }

    /// Returns the X25519 public key of the configured recovery recipient.
    ///
    /// When the document declares `recipient.x25519_public_key`, that value is
    /// used directly (and [`Self::validate`] has already proved it matches the
    /// private key when one is configured), so the capture path never needs to
    /// read private key material. Otherwise the public key is derived from the
    /// custody-held private key, exactly as before.
    pub fn recipient_public_key(&self) -> Result<[u8; X25519_PUBLIC_KEY_BYTES], BackupTrustError> {
        if let Some(encoded) = &self.recipient.x25519_public_key {
            return decode_x25519_public_key(encoded);
        }
        let private = self.load_recipient_private_key()?;
        derived_recipient_public_key(&private)
    }

    fn validate(&self, effective_uid: u32) -> Result<(), BackupTrustError> {
        if self.format != TRUST_CONFIG_FORMAT {
            return Err(BackupTrustError::ConfigFormatUnsupported);
        }
        for identifier in [
            &self.site_id,
            &self.installation_id,
            &self.profile_id,
            &self.artifact_signing.key_id,
            &self.recipient.key_id,
        ] {
            if !is_identifier(identifier) {
                return Err(BackupTrustError::ConfigIdentityInvalid);
            }
        }
        if !SUPPORTED_PROFILES.contains(&self.profile_id.as_str()) {
            return Err(BackupTrustError::ProfileUnsupported);
        }
        let public_key = self.signing_public_key()?;
        let declared_public = match &self.recipient.x25519_public_key {
            Some(encoded) => Some(decode_x25519_public_key(encoded)?),
            None => None,
        };
        match &self.recipient.x25519_private_key_file {
            Some(encoded_path) => {
                let recipient_path = Path::new(encoded_path);
                if !recipient_path.is_absolute() {
                    return Err(BackupTrustError::RecipientKeyPathInvalid);
                }
                // A declared public key must be the public half of the
                // configured private key; a mismatch means one document cannot
                // be trusted to describe a single recovery recipient.
                if let Some(declared) = declared_public {
                    let private =
                        self.load_recipient_private_key_with_effective_uid(effective_uid)?;
                    if derived_recipient_public_key(&private)? != declared {
                        return Err(BackupTrustError::RecipientKeyInvalid);
                    }
                }
            }
            None if declared_public.is_none() => {
                return Err(BackupTrustError::RecipientKeyInvalid);
            }
            None => {}
        }
        let mut revoked = BTreeSet::new();
        for key_id in &self.revoked_key_ids {
            if !is_identifier(key_id) || !revoked.insert(key_id.as_str()) {
                return Err(BackupTrustError::ConfigIdentityInvalid);
            }
        }
        validate_custody(&self.custody, &public_key)
    }

    /// Re-checks the custody record against the current clock. A record that
    /// expires while a long-lived process holds the configuration stops
    /// authorizing signatures.
    fn custody_is_current(&self) -> bool {
        self.signing_public_key()
            .is_ok_and(|public_key| validate_custody(&self.custody, &public_key).is_ok())
    }

    fn authorizes(
        &self,
        key_id: &str,
        site_id: &str,
        profile_id: &str,
        public_key: &VerifyingKey,
    ) -> bool {
        let Ok(configured) = self.signing_public_key() else {
            return false;
        };
        key_id == self.artifact_signing.key_id
            && site_id == self.site_id
            && profile_id == self.profile_id
            && public_key.to_bytes() == configured
            && self.custody_is_current()
    }

    /// Reads the configured X25519 recipient private key.
    ///
    /// The file must be an absolute path to a regular, no-follow file that is
    /// root- or effective-uid-owned with no group/other permission bits, in a
    /// trusted directory. Contents are 32 raw bytes or 64 hex characters;
    /// surrounding ASCII whitespace (for example a trailing newline) is
    /// ignored.
    pub fn load_recipient_private_key(
        &self,
    ) -> Result<<X25519HkdfSha256 as Kem>::PrivateKey, BackupTrustError> {
        self.load_recipient_private_key_with_effective_uid(current_euid())
    }

    /// [`Self::load_recipient_private_key`] with an explicit effective uid.
    fn load_recipient_private_key_with_effective_uid(
        &self,
        effective_uid: u32,
    ) -> Result<<X25519HkdfSha256 as Kem>::PrivateKey, BackupTrustError> {
        let encoded_path = self
            .recipient
            .x25519_private_key_file
            .as_deref()
            .ok_or(BackupTrustError::RecipientKeyUnavailable)?;
        let path = Path::new(encoded_path);
        if !path.is_absolute() {
            return Err(BackupTrustError::RecipientKeyPathInvalid);
        }
        let opened = open_no_follow(path).map_err(|failure| match failure {
            OpenFailure::Unavailable => BackupTrustError::RecipientKeyUnavailable,
            OpenFailure::Symlink => BackupTrustError::RecipientKeySymlink,
        })?;
        if !opened.metadata.file_type().is_file() {
            return Err(BackupTrustError::RecipientKeyInvalid);
        }
        if !is_trusted_owner(opened.metadata.uid(), effective_uid) {
            return Err(BackupTrustError::RecipientKeyOwnerUntrusted);
        }
        if opened.metadata.permissions().mode() & 0o077 != 0 {
            return Err(BackupTrustError::RecipientKeyPermissionsTooOpen);
        }
        validate_parent_directory(path, effective_uid).map_err(|failure| match failure {
            ParentFailure::Unavailable | ParentFailure::OwnerUntrusted => {
                BackupTrustError::RecipientKeyParentUntrusted
            }
            ParentFailure::PermissionsTooOpen => BackupTrustError::RecipientKeyParentUntrusted,
        })?;
        if opened.metadata.len() > MAX_RECIPIENT_KEY_BYTES {
            return Err(BackupTrustError::RecipientKeyInvalid);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        (&opened.file)
            .take(MAX_RECIPIENT_KEY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| BackupTrustError::RecipientKeyUnavailable)?;
        if bytes.len() as u64 > MAX_RECIPIENT_KEY_BYTES {
            return Err(BackupTrustError::RecipientKeyInvalid);
        }
        let raw = Zeroizing::new(parse_recipient_key(&bytes)?);
        <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&raw[..])
            .map_err(|_| BackupTrustError::RecipientKeyInvalid)
    }

    /// Verifies that the configured site and installation identities are the
    /// canonical ones derived from `data_dir` (`o3k_store::identity_tokens`).
    ///
    /// A trust document copied from another installation fails with
    /// [`BackupTrustError::IdentityMismatch`].
    pub fn verify_identity(&self, data_dir: &Path) -> Result<(), BackupTrustError> {
        let (site, installation) = site_and_installation_ids(data_dir)
            .map_err(|_| BackupTrustError::IdentityUnavailable)?;
        if site != self.site_id || installation != self.installation_id {
            return Err(BackupTrustError::IdentityMismatch);
        }
        Ok(())
    }
}

impl ArtifactTrust for BackupTrustConfig {
    fn signing_key_is_trusted(
        &self,
        key_id: &str,
        site_id: &str,
        profile_id: &str,
        public_key: &VerifyingKey,
    ) -> Result<bool, String> {
        Ok(self.authorizes(key_id, site_id, profile_id, public_key))
    }

    fn signing_key_is_revoked(&self, key_id: &str) -> Result<bool, String> {
        // Malformed revocation input is treated as revoked. The list itself is
        // validated at load time, so a missing or unparsable revocation state
        // never authorizes an artifact.
        Ok(!is_identifier(key_id) || self.revoked_key_ids.iter().any(|id| id == key_id))
    }
}

/// Default trust document path.
///
/// As root the canonical `/etc/o3k/backup-trust.json` is always used and every
/// environment override is ignored. Otherwise:
///
/// 1. `O3K_BACKUP_TRUST_CONFIG` when it is set and non-empty;
/// 2. `<O3K_INSTALL_PREFIX>/etc/o3k/backup-trust.json` when the install prefix
///    is set and non-empty;
/// 3. `/etc/o3k/backup-trust.json`, the installed layout's configuration
///    directory ([`crate::context::DEFAULT_CONFIG_DIR`]).
#[must_use]
pub fn default_trust_config_path() -> PathBuf {
    default_trust_config_path_for(
        current_euid(),
        std::env::var_os(TRUST_CONFIG_ENV),
        std::env::var_os(INSTALL_PREFIX_ENV),
    )
}

/// [`default_trust_config_path`] with the effective uid and environment values
/// passed explicitly, so the root/non-root split is testable without mutating
/// the process-global environment.
#[must_use]
pub fn default_trust_config_path_for(
    effective_uid: u32,
    config_override: Option<OsString>,
    install_prefix: Option<OsString>,
) -> PathBuf {
    if effective_uid == 0 {
        return Path::new(crate::context::DEFAULT_CONFIG_DIR).join(TRUST_CONFIG_FILE_NAME);
    }
    if let Some(path) = config_override.filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    default_trust_config_path_with_prefix(install_prefix)
}

/// [`default_trust_config_path_for`] without the explicit config override.
fn default_trust_config_path_with_prefix(install_prefix: Option<OsString>) -> PathBuf {
    match install_prefix.filter(|value| !value.is_empty()) {
        Some(prefix) => PathBuf::from(prefix)
            .join(INSTALLED_CONFIG_SUBDIR)
            .join(TRUST_CONFIG_FILE_NAME),
        None => Path::new(crate::context::DEFAULT_CONFIG_DIR).join(TRUST_CONFIG_FILE_NAME),
    }
}

/// Installation prefix used for the release identity and installed metadata.
///
/// A root process always uses the canonical [`DEFAULT_INSTALL_PREFIX`];
/// `O3K_INSTALL_PREFIX` is honored only for non-root callers.
#[must_use]
pub fn install_prefix() -> PathBuf {
    install_prefix_for(current_euid(), std::env::var_os(INSTALL_PREFIX_ENV))
}

/// [`install_prefix`] with the effective uid and override passed explicitly.
#[must_use]
pub fn install_prefix_for(effective_uid: u32, install_prefix: Option<OsString>) -> PathBuf {
    if effective_uid == 0 {
        return PathBuf::from(DEFAULT_INSTALL_PREFIX);
    }
    install_prefix
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_INSTALL_PREFIX))
}

/// Whether an environment path override may be honored by this process.
///
/// A privileged process must never let its caller redirect installation
/// configuration, so root ignores the overrides entirely.
#[must_use]
pub fn environment_overrides_allowed() -> bool {
    current_euid() != 0
}

/// Canonical site and installation identity strings for `data_dir`.
///
/// Each value is the lowercase hex of the corresponding 16-byte token derived
/// by `o3k_store::identity_tokens` from the canonical data-directory path, so
/// it is stable for the installation and never contains key material.
///
/// # Errors
///
/// Returns the underlying I/O error when `data_dir` cannot be canonicalized.
pub fn site_and_installation_ids(data_dir: &Path) -> io::Result<(String, String)> {
    let (installation, site) = o3k_store::identity_tokens(data_dir)?;
    Ok((hex::encode(site), hex::encode(installation)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenFailure {
    Unavailable,
    Symlink,
}

struct OpenedFile {
    file: File,
    metadata: fs::Metadata,
}

/// Opens `path` read-only with `O_NOFOLLOW` and returns the descriptor plus
/// its own metadata, so all checks apply to the inode actually read.
fn open_no_follow(path: &Path) -> Result<OpenedFile, OpenFailure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => return Err(OpenFailure::Symlink),
        Ok(_) => {}
        Err(_) => return Err(OpenFailure::Unavailable),
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            OpenFailure::Symlink
        } else {
            OpenFailure::Unavailable
        }
    })?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| OpenFailure::Unavailable)?;
    Ok(OpenedFile { file, metadata })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParentFailure {
    Unavailable,
    OwnerUntrusted,
    PermissionsTooOpen,
}

/// Requires the containing directory to be a real directory with a trusted
/// owner and no group/other write permission.
fn validate_parent_directory(path: &Path, effective_uid: u32) -> Result<(), ParentFailure> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let metadata = fs::metadata(parent).map_err(|_| ParentFailure::Unavailable)?;
    if !metadata.is_dir() {
        return Err(ParentFailure::Unavailable);
    }
    if !is_trusted_owner(metadata.uid(), effective_uid) {
        return Err(ParentFailure::OwnerUntrusted);
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(ParentFailure::PermissionsTooOpen);
    }
    Ok(())
}

fn current_euid() -> u32 {
    geteuid().as_raw()
}

fn is_trusted_owner(uid: u32, effective_uid: u32) -> bool {
    trusted_owner(uid, effective_uid)
}

/// Root, or the effective uid in the non-root posture, owns installation
/// configuration. Any other owner fails closed. For `euid == 0` this reduces to
/// root-only, matching the root posture.
fn trusted_owner(uid: u32, effective_uid: u32) -> bool {
    uid == 0 || uid == effective_uid
}

fn decode_ed25519_public_key(
    encoded: &str,
) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES], BackupTrustError> {
    if encoded.len() != ED25519_PUBLIC_KEY_BYTES * 2 {
        return Err(BackupTrustError::ArtifactKeyInvalid);
    }
    let decoded = hex::decode(encoded).map_err(|_| BackupTrustError::ArtifactKeyInvalid)?;
    <[u8; ED25519_PUBLIC_KEY_BYTES]>::try_from(decoded)
        .map_err(|_| BackupTrustError::ArtifactKeyInvalid)
}

fn decode_x25519_public_key(
    encoded: &str,
) -> Result<[u8; X25519_PUBLIC_KEY_BYTES], BackupTrustError> {
    if encoded.len() != X25519_PUBLIC_KEY_BYTES * 2 {
        return Err(BackupTrustError::RecipientKeyInvalid);
    }
    let decoded = hex::decode(encoded).map_err(|_| BackupTrustError::RecipientKeyInvalid)?;
    <[u8; X25519_PUBLIC_KEY_BYTES]>::try_from(decoded)
        .map_err(|_| BackupTrustError::RecipientKeyInvalid)
}

/// Public half of an X25519 private key. The private key itself is never
/// serialized outside this call and the hpke type zeroizes on drop.
fn derived_recipient_public_key(
    private: &<X25519HkdfSha256 as Kem>::PrivateKey,
) -> Result<[u8; X25519_PUBLIC_KEY_BYTES], BackupTrustError> {
    <[u8; X25519_PUBLIC_KEY_BYTES]>::try_from(
        <X25519HkdfSha256 as Kem>::sk_to_pk(private)
            .to_bytes()
            .as_slice(),
    )
    .map_err(|_| BackupTrustError::RecipientKeyInvalid)
}

fn validate_custody(
    custody: &Custody,
    public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
) -> Result<(), BackupTrustError> {
    if !is_identifier(&custody.record_id)
        || custody.purpose != CUSTODY_PURPOSE
        || custody.threshold != CUSTODY_THRESHOLD
        || !is_storage_class(&custody.storage_class)
        || custody.custodians.len() != CUSTODY_PRINCIPALS
    {
        return Err(BackupTrustError::CustodyInvalid);
    }
    let mut custodians = BTreeSet::new();
    for custodian in &custody.custodians {
        if !is_identifier(custodian) || !custodians.insert(custodian.as_str()) {
            return Err(BackupTrustError::CustodyInvalid);
        }
    }
    let fingerprint = hex::encode(Sha256::digest(public_key));
    if custody.key_fingerprint != fingerprint {
        return Err(BackupTrustError::CustodyInvalid);
    }
    // A custody record without a deadline can never be shown to be current.
    // Expiry is evaluated against the host clock; there is no HSM time
    // attestation, which is an explicit documented limit.
    let expires_at = custody
        .expires_at
        .as_deref()
        .ok_or(BackupTrustError::CustodyIncomplete)?;
    let expires_at =
        DateTime::parse_from_rfc3339(expires_at).map_err(|_| BackupTrustError::CustodyInvalid)?;
    if expires_at <= Utc::now() {
        return Err(BackupTrustError::CustodyExpired);
    }
    Ok(())
}

/// Minimal identifier syntax for site, installation, key, custody and
/// principal names: non-empty, bounded, printable ASCII without whitespace.
fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
}

fn is_storage_class(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_STORAGE_CLASS_BYTES && is_identifier(value)
}

fn parse_recipient_key(bytes: &[u8]) -> Result<[u8; X25519_PRIVATE_KEY_BYTES], BackupTrustError> {
    const HEX_KEY_BYTES: usize = X25519_PRIVATE_KEY_BYTES * 2;
    // A raw 32-byte key is accepted verbatim: trimming it would reject valid
    // keys whose first or last byte happens to be ASCII whitespace.
    if bytes.len() == X25519_PRIVATE_KEY_BYTES {
        return <[u8; X25519_PRIVATE_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| BackupTrustError::RecipientKeyInvalid);
    }
    // Otherwise the file is an encoded form where surrounding whitespace
    // (for example a trailing newline) is layout, not key material.
    let trimmed = bytes.trim_ascii();
    match trimmed.len() {
        X25519_PRIVATE_KEY_BYTES => <[u8; X25519_PRIVATE_KEY_BYTES]>::try_from(trimmed)
            .map_err(|_| BackupTrustError::RecipientKeyInvalid),
        HEX_KEY_BYTES => {
            let decoded =
                hex::decode(trimmed).map_err(|_| BackupTrustError::RecipientKeyInvalid)?;
            <[u8; X25519_PRIVATE_KEY_BYTES]>::try_from(decoded)
                .map_err(|_| BackupTrustError::RecipientKeyInvalid)
        }
        _ => Err(BackupTrustError::RecipientKeyInvalid),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use hpke::Serializable;
    use serde_json::{Value, json};
    use std::os::unix::fs::DirBuilderExt;
    use uuid::Uuid;

    const SITE_ID: &str = "site-1";
    const INSTALLATION_ID: &str = "install-1";
    const PROFILE_ID: &str = "o3k-demo-v1";
    const KEY_ID: &str = "signing-1";
    const RECIPIENT_KEY_ID: &str = "recovery-1";

    struct Fixture {
        root: PathBuf,
        config_path: PathBuf,
        key_path: PathBuf,
        signing: SigningKey,
        recipient: <X25519HkdfSha256 as Kem>::PrivateKey,
    }

    impl Drop for Fixture {
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
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("restrict fixture file");
    }

    fn new_fixture() -> Fixture {
        let root = std::env::temp_dir().join(format!("o3k-pp6-trust-{}", Uuid::now_v7()));
        create_private_dir(&root);
        let (recipient, _public) = X25519HkdfSha256::gen_keypair();
        let key_path = root.join("recipient.key");
        write_private_file(&key_path, &recipient.to_bytes());
        let signing = SigningKey::from_bytes(&[17_u8; 32]);
        let fixture = Fixture {
            config_path: root.join("backup-trust.json"),
            key_path,
            signing,
            recipient,
            root,
        };
        fixture.write(&fixture.document());
        fixture
    }

    impl Fixture {
        fn document(&self) -> Value {
            let public_key = self.signing.verifying_key().to_bytes();
            json!({
                "format": TRUST_CONFIG_FORMAT,
                "site_id": SITE_ID,
                "installation_id": INSTALLATION_ID,
                "profile_id": PROFILE_ID,
                "artifact_signing": {
                    "key_id": KEY_ID,
                    "ed25519_public_key": hex::encode(public_key),
                },
                "recipient": {
                    "key_id": RECIPIENT_KEY_ID,
                    "x25519_private_key_file": self.key_path.display().to_string(),
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
            })
        }

        fn write(&self, document: &Value) {
            let bytes = serde_json::to_vec_pretty(document).expect("serialize fixture document");
            write_private_file(&self.config_path, &bytes);
        }

        fn load(&self) -> Result<BackupTrustConfig, BackupTrustError> {
            BackupTrustConfig::load(&self.config_path)
        }
    }

    #[test]
    fn loads_valid_trust_and_authorizes_only_the_configured_key() {
        let fixture = new_fixture();
        let config = fixture.load().expect("valid trust configuration");
        assert_eq!(config.site_id(), SITE_ID);
        assert_eq!(config.installation_id(), INSTALLATION_ID);
        assert_eq!(config.profile_id(), PROFILE_ID);
        assert_eq!(config.artifact_signing_key_id(), KEY_ID);
        assert_eq!(config.recipient_key_id(), RECIPIENT_KEY_ID);
        assert_eq!(config.custody_record_id(), "custody-1");
        assert!(config.revoked_key_ids().is_empty());

        let key = fixture.signing.verifying_key();
        assert!(
            config
                .signing_key_is_trusted(KEY_ID, SITE_ID, PROFILE_ID, &key)
                .expect("trust check")
        );
        assert!(
            !config
                .signing_key_is_trusted("other-key", SITE_ID, PROFILE_ID, &key)
                .expect("trust check")
        );
        assert!(
            !config
                .signing_key_is_trusted(KEY_ID, "other-site", PROFILE_ID, &key)
                .expect("trust check")
        );
        assert!(
            !config
                .signing_key_is_trusted(KEY_ID, SITE_ID, "o3k-small-edge-v1", &key)
                .expect("trust check")
        );
        let other_key = SigningKey::from_bytes(&[18_u8; 32]).verifying_key();
        assert!(
            !config
                .signing_key_is_trusted(KEY_ID, SITE_ID, PROFILE_ID, &other_key)
                .expect("trust check")
        );
        assert!(
            !config
                .signing_key_is_revoked(KEY_ID)
                .expect("revocation check")
        );
    }

    #[test]
    fn derives_the_recipient_public_key_from_the_custody_key_file() {
        let fixture = new_fixture();
        let config = fixture.load().expect("valid trust configuration");
        let derived = config
            .recipient_public_key()
            .expect("derived recipient key");
        assert_eq!(
            derived.as_slice(),
            <X25519HkdfSha256 as Kem>::sk_to_pk(&fixture.recipient)
                .to_bytes()
                .as_slice()
        );

        // A key file that does not parse never yields a public key.
        write_private_file(&fixture.key_path, b"not-a-key");
        assert_eq!(
            config
                .recipient_public_key()
                .expect_err("malformed recipient key")
                .reason(),
            "trust-recipient-key-invalid"
        );
    }

    #[test]
    fn loads_the_recipient_key_from_raw_bytes_and_hex() {
        let fixture = new_fixture();
        let config = fixture.load().expect("valid trust configuration");
        let loaded = config
            .load_recipient_private_key()
            .expect("raw recipient key");
        assert_eq!(
            loaded.to_bytes().as_slice(),
            fixture.recipient.to_bytes().as_slice()
        );

        let mut hex_encoded = hex::encode(fixture.recipient.to_bytes());
        hex_encoded.push('\n');
        write_private_file(&fixture.key_path, hex_encoded.as_bytes());
        let loaded = config
            .load_recipient_private_key()
            .expect("hex recipient key");
        assert_eq!(
            loaded.to_bytes().as_slice(),
            fixture.recipient.to_bytes().as_slice()
        );
    }

    #[test]
    fn raw_recipient_key_with_whitespace_bytes_is_not_trimmed() {
        // A raw 32-byte key is key material end to end: leading/trailing
        // ASCII whitespace bytes are valid key bytes and must not be trimmed.
        let mut raw = [0u8; X25519_PRIVATE_KEY_BYTES];
        raw[0] = b' ';
        raw[X25519_PRIVATE_KEY_BYTES - 1] = b'\n';
        let parsed = parse_recipient_key(&raw).expect("raw key with whitespace bytes");
        assert_eq!(&parsed, &raw);

        let mut encoded = hex::encode(raw);
        encoded.push('\n');
        let parsed = parse_recipient_key(encoded.as_bytes()).expect("hex key with newline");
        assert_eq!(&parsed, &raw);
    }

    #[test]
    fn rejects_group_or_world_writable_configuration_and_key() {
        let fixture = new_fixture();
        fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o664))
            .expect("relax configuration permissions");
        assert_eq!(
            fixture.load().expect_err("writable configuration").reason(),
            "trust-config-permissions-too-open"
        );

        // The non-root posture requires a private document: group or other
        // readability is refused even though the bytes are not writable.
        fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o644))
            .expect("make configuration group-readable");
        assert_eq!(
            fixture
                .load()
                .expect_err("group-readable configuration")
                .reason(),
            "trust-config-permissions-too-open"
        );

        fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o600))
            .expect("restore configuration permissions");
        let config = fixture.load().expect("valid trust configuration");
        fs::set_permissions(&fixture.key_path, fs::Permissions::from_mode(0o640))
            .expect("relax key permissions");
        assert_eq!(
            config
                .load_recipient_private_key()
                .err()
                .expect("group-readable key")
                .reason(),
            "trust-recipient-key-permissions-too-open"
        );
    }

    #[test]
    fn rejects_a_group_or_world_writable_configuration_directory() {
        let fixture = new_fixture();
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o770))
            .expect("relax fixture directory");
        assert_eq!(
            fixture.load().expect_err("writable parent").reason(),
            "trust-config-permissions-too-open"
        );
    }

    #[test]
    fn rejects_symlinked_configuration_and_key_files() {
        let fixture = new_fixture();
        let config_link = fixture.root.join("backup-trust-link.json");
        std::os::unix::fs::symlink(&fixture.config_path, &config_link).expect("config symlink");
        assert_eq!(
            BackupTrustConfig::load(&config_link)
                .expect_err("symlinked configuration")
                .reason(),
            "trust-config-symlink"
        );

        let key_link = fixture.root.join("recipient-link.key");
        std::os::unix::fs::symlink(&fixture.key_path, &key_link).expect("key symlink");
        let mut document = fixture.document();
        document["recipient"]["x25519_private_key_file"] = json!(key_link.display().to_string());
        fixture.write(&document);
        let config = fixture.load().expect("valid trust configuration");
        assert_eq!(
            config
                .load_recipient_private_key()
                .err()
                .expect("symlinked key")
                .reason(),
            "trust-recipient-key-symlink"
        );
    }

    #[test]
    fn rejects_missing_or_malformed_recipient_keys() {
        let fixture = new_fixture();
        let mut document = fixture.document();
        document["recipient"]["x25519_private_key_file"] =
            json!(fixture.root.join("absent.key").display().to_string());
        fixture.write(&document);
        let config = fixture.load().expect("valid trust configuration");
        assert_eq!(
            config
                .load_recipient_private_key()
                .err()
                .expect("missing key")
                .reason(),
            "trust-recipient-key-unavailable"
        );

        write_private_file(&fixture.key_path, b"not-a-key");
        fixture.write(&fixture.document());
        let config = fixture.load().expect("valid trust configuration");
        assert_eq!(
            config
                .load_recipient_private_key()
                .err()
                .expect("malformed key")
                .reason(),
            "trust-recipient-key-invalid"
        );
    }

    #[test]
    fn rejects_a_relative_recipient_key_path() {
        let fixture = new_fixture();
        let mut document = fixture.document();
        document["recipient"]["x25519_private_key_file"] = json!("recipient.key");
        fixture.write(&document);
        assert_eq!(
            fixture.load().expect_err("relative key path").reason(),
            "trust-recipient-key-path-invalid"
        );
    }

    #[test]
    fn declared_recipient_public_key_is_used_and_must_match_the_private_key() {
        let fixture = new_fixture();
        let derived = <X25519HkdfSha256 as Kem>::sk_to_pk(&fixture.recipient)
            .to_bytes()
            .to_vec();
        let mut document = fixture.document();
        document["recipient"]["x25519_public_key"] = json!(hex::encode(&derived));
        fixture.write(&document);
        let config = fixture.load().expect("matching declared public key");
        assert_eq!(
            config.recipient_public_key().expect("declared public key"),
            <[u8; 32]>::try_from(derived.as_slice()).expect("32-byte key")
        );

        let mut document = fixture.document();
        document["recipient"]["x25519_public_key"] = json!("00".repeat(32));
        fixture.write(&document);
        assert_eq!(
            fixture
                .load()
                .expect_err("declared public key that does not match")
                .reason(),
            "trust-recipient-key-invalid"
        );

        // A capture-only document may name just the public key; the private
        // key is then unavailable for verification, which fails closed.
        let public_only = new_fixture();
        let derived = <X25519HkdfSha256 as Kem>::sk_to_pk(&public_only.recipient)
            .to_bytes()
            .to_vec();
        let mut document = public_only.document();
        document["recipient"]
            .as_object_mut()
            .expect("recipient object")
            .remove("x25519_private_key_file");
        document["recipient"]["x25519_public_key"] = json!(hex::encode(&derived));
        public_only.write(&document);
        let config = public_only.load().expect("public-key-only trust document");
        assert_eq!(
            config.recipient_public_key().expect("public key"),
            <[u8; 32]>::try_from(derived.as_slice()).expect("32-byte key")
        );
        assert_eq!(
            config
                .load_recipient_private_key()
                .err()
                .expect("no private key")
                .reason(),
            "trust-recipient-key-unavailable"
        );

        // A document with neither half is incomplete.
        let mut document = public_only.document();
        let recipient = document["recipient"]
            .as_object_mut()
            .expect("recipient object");
        recipient.remove("x25519_private_key_file");
        recipient.remove("x25519_public_key");
        public_only.write(&document);
        assert_eq!(
            public_only
                .load()
                .expect_err("recipient without key material")
                .reason(),
            "trust-recipient-key-invalid"
        );
    }

    #[test]
    fn owner_predicate_accepts_only_root_or_the_effective_uid() {
        assert!(trusted_owner(0, 1000));
        assert!(trusted_owner(1000, 1000));
        assert!(!trusted_owner(1001, 1000));
        assert!(!trusted_owner(u32::MAX, 1000));
        // Root accepts root only.
        assert!(trusted_owner(0, 0));
        assert!(!trusted_owner(1000, 0));
    }

    #[test]
    fn rejects_configuration_and_key_owned_by_another_user() {
        let fixture = new_fixture();
        let effective_uid = current_euid();
        BackupTrustConfig::load_with_effective_uid(&fixture.config_path, effective_uid)
            .expect("config owned by the effective uid");
        let foreign_uid = if effective_uid == 0 {
            1
        } else {
            effective_uid + 1
        };
        assert_eq!(
            BackupTrustConfig::load_with_effective_uid(&fixture.config_path, foreign_uid)
                .expect_err("foreign owner")
                .reason(),
            "trust-config-owner-untrusted"
        );

        let config = fixture.load().expect("valid trust configuration");
        assert_eq!(
            config
                .load_recipient_private_key_with_effective_uid(foreign_uid)
                .err()
                .expect("foreign key owner")
                .reason(),
            "trust-recipient-key-owner-untrusted"
        );
    }

    #[test]
    fn rejects_a_directory_as_configuration() {
        let fixture = new_fixture();
        assert_eq!(
            BackupTrustConfig::load(&fixture.root)
                .expect_err("directory configuration")
                .reason(),
            "trust-config-not-regular-file"
        );
    }

    #[test]
    fn revoked_keys_are_reported_and_malformed_queries_fail_closed() {
        let fixture = new_fixture();
        let mut document = fixture.document();
        document["revoked_key_ids"] = json!([KEY_ID]);
        fixture.write(&document);
        let config = fixture.load().expect("valid trust configuration");
        assert!(config.signing_key_is_revoked(KEY_ID).expect("revoked"));
        assert!(
            !config
                .signing_key_is_revoked("signing-2")
                .expect("not revoked")
        );
        assert!(
            config
                .signing_key_is_revoked("")
                .expect("malformed revoked")
        );
        assert!(
            config
                .signing_key_is_revoked("not a key id")
                .expect("malformed revoked")
        );
    }

    #[test]
    fn rejects_expired_or_incomplete_custody_records() {
        let fixture = new_fixture();
        let mut document = fixture.document();
        document["custody"]["expires_at"] = json!("2020-01-01T00:00:00Z");
        fixture.write(&document);
        assert_eq!(
            fixture.load().expect_err("expired custody").reason(),
            "trust-custody-expired"
        );

        let mut document = fixture.document();
        document["custody"]
            .as_object_mut()
            .expect("custody object")
            .remove("expires_at");
        fixture.write(&document);
        assert_eq!(
            fixture
                .load()
                .expect_err("custody without a deadline")
                .reason(),
            "trust-custody-incomplete"
        );

        let cases: [(&str, Value); 8] = [
            ("threshold", json!("1-of-3")),
            ("purpose", json!("recovery")),
            (
                "custodians",
                json!(["principal-a", "principal-b", "principal-b"]),
            ),
            ("custodians", json!(["principal-a", "principal-b"])),
            (
                "custodians",
                json!(["principal-a", "principal-b", "principal-c", "principal-d"]),
            ),
            ("key_fingerprint", json!("0".repeat(64))),
            ("storage_class", json!("")),
            ("record_id", json!("")),
        ];
        for (field, value) in cases {
            let mut document = fixture.document();
            document["custody"][field] = value;
            fixture.write(&document);
            assert_eq!(
                fixture.load().expect_err(field).reason(),
                "trust-custody-invalid",
                "custody field {field} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_wrong_format_malformed_documents_and_unsupported_profiles() {
        let fixture = new_fixture();
        let mut document = fixture.document();
        document["format"] = json!("o3k-backup-trust-v2");
        fixture.write(&document);
        assert_eq!(
            fixture.load().expect_err("version").reason(),
            "trust-config-format-unsupported"
        );

        let mut document = fixture.document();
        document["site_id"] = json!("");
        fixture.write(&document);
        assert_eq!(
            fixture.load().expect_err("empty site").reason(),
            "trust-config-identity-invalid"
        );

        let mut document = fixture.document();
        document["artifact_signing"]["ed25519_public_key"] = json!("00".repeat(31));
        fixture.write(&document);
        assert_eq!(
            fixture.load().expect_err("short key").reason(),
            "trust-artifact-key-invalid"
        );

        let mut document = fixture.document();
        document["profile_id"] = json!("o3k-libvirt-v1");
        fixture.write(&document);
        assert_eq!(
            fixture.load().expect_err("profile").reason(),
            "trust-profile-unsupported"
        );

        let mut document = fixture.document();
        document
            .as_object_mut()
            .expect("object")
            .insert("unknown".to_owned(), json!(true));
        fixture.write(&document);
        assert_eq!(
            fixture.load().expect_err("unknown field").reason(),
            "trust-config-malformed"
        );

        write_private_file(&fixture.config_path, b"{");
        assert_eq!(
            fixture.load().expect_err("truncated JSON").reason(),
            "trust-config-malformed"
        );
    }

    #[test]
    fn canonical_identity_is_deterministic_and_binds_the_configuration() {
        let data_dir = std::env::temp_dir().join(format!("o3k-pp6-trust-data-{}", Uuid::now_v7()));
        create_private_dir(&data_dir);
        let (site, installation) =
            site_and_installation_ids(&data_dir).expect("derive identity tokens");
        assert_eq!(site.len(), 32);
        assert_eq!(installation.len(), 32);
        assert!(
            site.bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert!(
            installation
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_eq!(
            (site.clone(), installation.clone()),
            site_and_installation_ids(&data_dir).expect("deterministic identity tokens")
        );

        let fixture = new_fixture();
        let mut document = fixture.document();
        document["site_id"] = json!(site);
        document["installation_id"] = json!(installation);
        fixture.write(&document);
        let config = fixture.load().expect("identity-bound trust configuration");
        config
            .verify_identity(&data_dir)
            .expect("matching installation identity");

        let mut document = fixture.document();
        document["site_id"] = json!("0".repeat(32));
        document["installation_id"] = json!(installation);
        fixture.write(&document);
        let config = fixture.load().expect("loaded mismatched configuration");
        assert_eq!(
            config
                .verify_identity(&data_dir)
                .expect_err("identity mismatch")
                .reason(),
            "identity-mismatch"
        );
        fs::remove_dir_all(&data_dir).expect("remove identity fixture");
    }

    #[test]
    fn default_path_prefers_the_explicit_override() {
        // The environment is process-global, so assert the derivation shape
        // without mutating it: the override branch is covered by every test
        // above that loads from an explicit path.
        let path = default_trust_config_path();
        assert!(path.is_absolute());
    }

    #[test]
    fn default_path_without_a_prefix_uses_the_installed_config_directory() {
        let installed = Path::new(crate::context::DEFAULT_CONFIG_DIR).join(TRUST_CONFIG_FILE_NAME);
        assert_eq!(installed, Path::new("/etc/o3k/backup-trust.json"));
        assert_eq!(default_trust_config_path_with_prefix(None), installed);
        assert_eq!(
            default_trust_config_path_with_prefix(Some(OsString::new())),
            installed
        );
        assert_eq!(
            default_trust_config_path_with_prefix(Some(OsString::from("/opt/o3k"))),
            PathBuf::from("/opt/o3k/etc/o3k/backup-trust.json")
        );
    }

    #[test]
    fn root_ignores_every_environment_override() {
        let canonical = Path::new("/etc/o3k/backup-trust.json").to_path_buf();
        assert_eq!(
            default_trust_config_path_for(
                0,
                Some(OsString::from("/tmp/attacker-trust.json")),
                Some(OsString::from("/tmp/attacker-prefix")),
            ),
            canonical
        );
        // Non-root keeps the documented override order.
        assert_eq!(
            default_trust_config_path_for(
                1000,
                Some(OsString::from("/tmp/service-trust.json")),
                Some(OsString::from("/opt/o3k")),
            ),
            PathBuf::from("/tmp/service-trust.json")
        );
        assert_eq!(
            default_trust_config_path_for(1000, None, Some(OsString::from("/opt/o3k")),),
            PathBuf::from("/opt/o3k/etc/o3k/backup-trust.json")
        );

        assert_eq!(
            install_prefix_for(0, Some(OsString::from("/tmp/attacker-prefix"))),
            PathBuf::from(DEFAULT_INSTALL_PREFIX)
        );
        assert_eq!(
            install_prefix_for(1000, Some(OsString::from("/opt/o3k"))),
            PathBuf::from("/opt/o3k")
        );
        assert_eq!(install_prefix_for(1000, None), PathBuf::from("/usr/local"));
    }
}
