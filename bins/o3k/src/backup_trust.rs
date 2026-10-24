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
//! # Installed and TestLab posture
//!
//! SPEC-0050 §8 requires root-owned installation configuration. The posture
//! depends on whether the resolved data directory is the packaged
//! `/var/lib/o3k` installation ([`is_installed_data_dir`]):
//!
//! * **Installed** (`/var/lib/o3k`): the document must be owned by uid `0`,
//!   owned by the packaged service group `o3k` (or gid `0` when the group
//!   cannot be resolved), and be exactly `0600` or `0640`. Any other owner,
//!   group or mode fails closed as `trust-config-posture-invalid`. The parent
//!   `/etc/o3k` must be root-owned and not group/other-writable.
//! * **Non-installed/TestLab**: the documented override path is preserved:
//!   owned by root **or** the effective uid, mode `0600`, or `0640` when the
//!   owning group is root or one of the process's groups (the service group),
//!   never group/other-writable and never other-readable; the parent must be
//!   owned by root or the effective uid and not group/other-writable.
//!
//! The packaged installation therefore uses `root:o3k 0640` (group read by the
//! service group); `0600` is the euid-owned TestLab mode and is also accepted
//! for a root-owned installed document used by a root caller. A root-owned
//! document that the non-root service user cannot read is reported as
//! `trust-config-unreadable-by-service-user` instead of the generic
//! `trust-config-unavailable`, so the operator knows to add the group-read bit
//! rather than look for a missing file. A service-user-owned document in the
//! installed data directory is never accepted.
//!
//! The recipient private key remains `0600` (or `0400`) on the
//! recovery/operator host and is never group-readable. The controller only
//! needs `recipient.x25519_public_key`; with that field configured,
//! [`BackupTrustConfig::load_for_data_dir`] and the capture path never open
//! the private key file. A private-key-only document still derives the public half on demand,
//! and verification always requires the private key to decrypt members.
//!
//! # Environment overrides
//!
//! `O3K_BACKUP_TRUST_CONFIG` and `O3K_INSTALL_PREFIX` are honored **only when
//! the resolved data directory is not the installed canonical path**
//! (`/var/lib/o3k`). For the installed data directory they are ignored
//! regardless of effective uid, so a packaged service or a privileged caller
//! cannot redirect the trust root. TestLab and temporary data directories keep
//! the overrides. The same rule applies to the upgrade runner's
//! `O3K_UPGRADE_*` overrides, which are additionally ignored whenever
//! `euid == 0` (see `upgrade::runner`).
//!
//! When no override applies the document lives at
//! `/etc/o3k/backup-trust.json`, the installed layout's
//! [`crate::context::DEFAULT_CONFIG_DIR`] shared with doctor and upgrade.

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
    process::{getegid, geteuid, getgroups},
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
    /// The document is root-owned but not readable by the non-root service
    /// user (`0600` where the packaged posture requires group read).
    ConfigUnreadableByServiceUser,
    /// The final path component is a symbolic link.
    ConfigSymlink,
    /// The document is not a regular file.
    ConfigNotRegularFile,
    /// The document does not match the installed ownership/group/mode posture.
    ConfigPostureInvalid,
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
    /// configuration, missing key file, unreadable configuration) rather than
    /// proving the artifact or the installation wrong.
    ///
    /// Both `o3k backup create` and `o3k backup verify` classify on this one
    /// predicate. The commands differ only in where they apply it: `create`
    /// loads the configuration in its read-only preflight, so a configuration
    /// failure there is a rejected precondition (exit 2) and the controller is
    /// never stopped; `verify` has no such preflight and reports the same
    /// failure as a recoverable configuration failure (exit 3).
    #[must_use]
    pub const fn is_recoverable(self) -> bool {
        matches!(
            self,
            Self::ConfigUnavailable
                | Self::ConfigUnreadableByServiceUser
                | Self::RecipientKeyUnavailable
                | Self::IdentityUnavailable
        )
    }

    /// Stable reason string for operator output. It never contains key
    /// material, paths or provider payloads.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ConfigUnavailable => "trust-config-unavailable",
            Self::ConfigUnreadableByServiceUser => "trust-config-unreadable-by-service-user",
            Self::ConfigSymlink => "trust-config-symlink",
            Self::ConfigNotRegularFile => "trust-config-not-regular-file",
            Self::ConfigPostureInvalid => "trust-config-posture-invalid",
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
/// [`BackupTrustConfig::load_for_data_dir`], which enforces the file posture
/// and custody schema.
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
    /// Loads and validates the installation trust document at `path` for the
    /// installation identified by `data_dir`.
    ///
    /// The file posture is selected from the data directory: the packaged
    /// `/var/lib/o3k` installation requires the installed posture (root-owned,
    /// service-group, `0600`/`0640`), while TestLab/temporary directories keep
    /// the documented euid-owned override posture.
    ///
    /// Fails closed on any file-posture, schema, identity, key or custody
    /// discrepancy. The document is opened with `O_NOFOLLOW` and validated
    /// against the descriptor's own metadata, so a symlink swap cannot
    /// redirect the read.
    pub fn load_for_data_dir(path: &Path, data_dir: &Path) -> Result<Self, BackupTrustError> {
        let posture = if is_installed_data_dir(data_dir) {
            TrustPosture::Installed {
                service_gid: installed_service_gid(),
            }
        } else {
            TrustPosture::TestLab
        };
        Self::load_with_posture(path, current_euid(), posture)
    }

    /// [`Self::load_for_data_dir`] with an explicit effective uid and posture.
    /// Production passes the process's real effective uid; tests use the
    /// explicit posture to exercise the installed branch without a real
    /// `/var/lib/o3k` or root-owned fixture.
    fn load_with_posture(
        path: &Path,
        effective_uid: u32,
        posture: TrustPosture,
    ) -> Result<Self, BackupTrustError> {
        let opened = open_no_follow(path).map_err(|failure| match failure {
            OpenFailure::Unavailable => unavailable_config_error(path, effective_uid, posture),
            OpenFailure::Symlink => BackupTrustError::ConfigSymlink,
        })?;
        if !opened.metadata.file_type().is_file() {
            return Err(BackupTrustError::ConfigNotRegularFile);
        }
        let uid = opened.metadata.uid();
        let gid = opened.metadata.gid();
        let mode = opened.metadata.permissions().mode();
        match posture {
            TrustPosture::Installed { service_gid } => {
                if !installed_posture_allowed(uid, gid, mode, service_gid) {
                    return Err(BackupTrustError::ConfigPostureInvalid);
                }
            }
            TrustPosture::TestLab => {
                if !is_trusted_owner(uid, effective_uid) {
                    return Err(BackupTrustError::ConfigOwnerUntrusted);
                }
                if !configuration_mode_allowed(mode, gid, &process_groups()) {
                    return Err(BackupTrustError::ConfigPermissionsTooOpen);
                }
            }
        }
        validate_parent_directory(path, effective_uid, posture).map_err(
            |failure| match failure {
                ParentFailure::Unavailable | ParentFailure::OwnerUntrusted => {
                    BackupTrustError::ConfigParentUntrusted
                }
                ParentFailure::PermissionsTooOpen => BackupTrustError::ConfigPermissionsTooOpen,
            },
        )?;
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
    /// used directly and no private key file is opened.
    /// [`Self::load_for_data_dir`] is therefore safe on a capture-only
    /// controller that has no private key at all. Only a private-key-only
    /// document derives the public half on demand, which reads the configured
    /// key file.
    pub fn recipient_public_key(&self) -> Result<[u8; X25519_PUBLIC_KEY_BYTES], BackupTrustError> {
        if let Some(encoded) = &self.recipient.x25519_public_key {
            return decode_x25519_public_key(encoded);
        }
        let private = self.load_recipient_private_key()?;
        derived_recipient_public_key(&private)
    }

    fn validate(&self, _effective_uid: u32) -> Result<(), BackupTrustError> {
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
                // Loading is deliberately lazy: only the path grammar is
                // checked here. The file is opened by
                // `load_recipient_private_key` on the recovery host, so a
                // capture-only installation can configure a public key and no
                // readable private key file.
                if !Path::new(encoded_path).is_absolute() {
                    return Err(BackupTrustError::RecipientKeyPathInvalid);
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
    /// root- or effective-uid-owned with mode `0600` or `0400`, in a trusted
    /// directory. The private key is never group-readable: only the recovery
    /// or operator host holds it. Contents are 32 raw bytes or 64 hex
    /// characters; surrounding ASCII whitespace (for example a trailing
    /// newline) is ignored. When the document also declares
    /// `recipient.x25519_public_key`, the derived public half must match it.
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
        if !recipient_key_mode_allowed(opened.metadata.permissions().mode()) {
            return Err(BackupTrustError::RecipientKeyPermissionsTooOpen);
        }
        validate_parent_directory(path, effective_uid, TrustPosture::TestLab).map_err(
            |failure| match failure {
                ParentFailure::Unavailable | ParentFailure::OwnerUntrusted => {
                    BackupTrustError::RecipientKeyParentUntrusted
                }
                ParentFailure::PermissionsTooOpen => BackupTrustError::RecipientKeyParentUntrusted,
            },
        )?;
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
        let private = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&raw[..])
            .map_err(|_| BackupTrustError::RecipientKeyInvalid)?;
        // The declared public key was validated at load time without touching
        // the private file. Prove the two halves still describe one recipient
        // now that the private key is actually being used.
        if let Some(encoded) = &self.recipient.x25519_public_key
            && derived_recipient_public_key(&private)? != decode_x25519_public_key(encoded)?
        {
            return Err(BackupTrustError::RecipientKeyInvalid);
        }
        Ok(private)
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

/// Canonical trust document path for the current process.
///
/// Resolves the data directory first: overrides are honored only for a
/// non-installed (TestLab/temporary) data directory. If the data directory is
/// unavailable the conservative installed path is returned.
#[must_use]
pub fn default_trust_config_path() -> PathBuf {
    match crate::backup_data_dir::resolve_data_dir() {
        Ok(data_dir) => default_trust_config_path_for(
            &data_dir,
            std::env::var_os(TRUST_CONFIG_ENV),
            std::env::var_os(INSTALL_PREFIX_ENV),
        ),
        Err(_) => installed_trust_config_path(),
    }
}

/// [`default_trust_config_path`] with the data directory and environment values
/// passed explicitly, so the installed/TestLab split is testable without
/// mutating the process-global environment.
///
/// For the installed canonical data directory (`/var/lib/o3k`) both overrides
/// are ignored regardless of effective uid. Otherwise:
///
/// 1. `O3K_BACKUP_TRUST_CONFIG` when it is set and non-empty;
/// 2. `<O3K_INSTALL_PREFIX>/etc/o3k/backup-trust.json` when the install prefix
///    is set and non-empty;
/// 3. `/etc/o3k/backup-trust.json`.
#[must_use]
pub fn default_trust_config_path_for(
    data_dir: &Path,
    config_override: Option<OsString>,
    install_prefix: Option<OsString>,
) -> PathBuf {
    if trust_overrides_allowed(data_dir) {
        if let Some(path) = config_override.filter(|value| !value.is_empty()) {
            return PathBuf::from(path);
        }
        if let Some(prefix) = install_prefix.filter(|value| !value.is_empty()) {
            return PathBuf::from(prefix)
                .join(INSTALLED_CONFIG_SUBDIR)
                .join(TRUST_CONFIG_FILE_NAME);
        }
    }
    installed_trust_config_path()
}

fn installed_trust_config_path() -> PathBuf {
    Path::new(crate::context::DEFAULT_CONFIG_DIR).join(TRUST_CONFIG_FILE_NAME)
}

/// Installation prefix used for the release identity and installed metadata.
///
/// Overrides are honored only for a non-installed (TestLab/temporary) data
/// directory; the packaged data directory always uses
/// [`DEFAULT_INSTALL_PREFIX`].
#[must_use]
pub fn install_prefix() -> PathBuf {
    match crate::backup_data_dir::resolve_data_dir() {
        Ok(data_dir) => install_prefix_for(&data_dir, std::env::var_os(INSTALL_PREFIX_ENV)),
        Err(_) => PathBuf::from(DEFAULT_INSTALL_PREFIX),
    }
}

/// [`install_prefix`] with the data directory and override passed explicitly.
#[must_use]
pub fn install_prefix_for(data_dir: &Path, install_prefix: Option<OsString>) -> PathBuf {
    if trust_overrides_allowed(data_dir) {
        return install_prefix
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_INSTALL_PREFIX));
    }
    PathBuf::from(DEFAULT_INSTALL_PREFIX)
}

/// Whether the trust/install environment overrides may be honored for
/// `data_dir`.
///
/// This is intentionally independent of the effective uid: the packaged data
/// directory is fixed even for root, while a TestLab/temporary data directory
/// keeps the documented overrides.
#[must_use]
pub fn trust_overrides_allowed(data_dir: &Path) -> bool {
    !is_installed_data_dir(data_dir)
}

/// True when `data_dir` is the packaged `/var/lib/o3k` installation directory.
///
/// The comparison uses the canonical form of the packaged directory as well as
/// its literal path, so an installation whose `/var/lib/o3k` is a symlink (for
/// example to a dedicated volume) cannot re-enable the TestLab overrides by
/// resolving to the link target.
#[must_use]
pub fn is_installed_data_dir(data_dir: &Path) -> bool {
    installed_data_dir_matches(data_dir, Path::new(crate::backup_data_dir::ROOT_DATA_DIR))
}

/// [`is_installed_data_dir`] with the packaged directory supplied explicitly,
/// so the symlinked-root rule is testable without a real `/var/lib/o3k`.
fn installed_data_dir_matches(data_dir: &Path, root_data_dir: &Path) -> bool {
    let canonical = fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    if canonical == root_data_dir {
        return true;
    }
    fs::canonicalize(root_data_dir).is_ok_and(|root| canonical == root)
}

/// Whether an environment path override may be honored by this process.
///
/// The upgrade runner uses this predicate: a privileged process must never let
/// its caller redirect installation paths, so root ignores every
/// `O3K_UPGRADE_*` override. The backup trust path has the stricter
/// data-directory rule in [`trust_overrides_allowed`].
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

/// Distinguishes "there is no document" from "the document exists but this
/// service user may not read it".
///
/// The packaged posture is `root:o3k 0640`: root owns the document and the
/// service group reads it. A root-owned regular file without the group-read
/// bit and a non-root caller is exactly that misconfiguration, so it gets its
/// own reason instead of the generic unavailable code. For an installed data
/// directory an unreadable document whose own metadata already violates the
/// installed posture (wrong owner, group or mode) is reported as
/// `trust-config-posture-invalid`, so a wrong group cannot hide behind
/// `trust-config-unavailable`. Everything else stays
/// `trust-config-unavailable`.
fn unavailable_config_error(
    path: &Path,
    effective_uid: u32,
    posture: TrustPosture,
) -> BackupTrustError {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let uid = metadata.uid();
            let gid = metadata.gid();
            let mode = metadata.permissions().mode();
            if let TrustPosture::Installed { service_gid } = posture
                && !installed_posture_allowed(uid, gid, mode, service_gid)
            {
                return BackupTrustError::ConfigPostureInvalid;
            }
            if unreadable_by_service_user(uid, mode, effective_uid) {
                BackupTrustError::ConfigUnreadableByServiceUser
            } else {
                BackupTrustError::ConfigUnavailable
            }
        }
        _ => BackupTrustError::ConfigUnavailable,
    }
}

/// Root owns the document, the caller is not root, and the group-read bit that
/// the packaged `0640` posture provides is missing.
fn unreadable_by_service_user(uid: u32, mode: u32, effective_uid: u32) -> bool {
    effective_uid != 0 && uid == 0 && mode & 0o040 == 0
}

/// Trust-document posture selected from the resolved data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustPosture {
    /// Packaged `/var/lib/o3k` installation. `service_gid` is the resolved
    /// packaged `o3k` group; `None` means resolution was unavailable and gid
    /// `0` is the only accepted fallback.
    Installed { service_gid: Option<u32> },
    /// Non-installed/TestLab or temporary data directory.
    TestLab,
}

/// The installed posture: root-owned, owned by the packaged service group (or
/// root when that group could not be resolved), and exactly `0600` or `0640`.
fn installed_posture_allowed(uid: u32, gid: u32, mode: u32, service_gid: Option<u32>) -> bool {
    uid == 0
        && service_gid.map_or(gid == 0, |wanted| gid == wanted)
        && matches!(mode & 0o777, 0o600 | 0o640)
}

/// Resolves the packaged `o3k` service group from the local account database.
///
/// The packaged installer creates a local system group, so `/etc/group` (and
/// `/etc/passwd` for the account's primary group) is sufficient. Resolution
/// failure is not an error: the installed posture then accepts only gid `0`.
fn installed_service_gid() -> Option<u32> {
    group_gid_by_name("/etc/group", "o3k").or_else(|| user_primary_gid("/etc/passwd", "o3k"))
}

/// Finds a group name in a bounded local `group(5)` file and returns its gid.
fn group_gid_by_name(path: &str, name: &str) -> Option<u32> {
    let contents = read_account_file(path)?;
    contents.lines().find_map(|line| {
        let mut fields = line.split(':');
        let group = fields.next()?;
        let _password = fields.next()?;
        let gid = fields.next()?;
        (group == name).then(|| gid.parse::<u32>().ok()).flatten()
    })
}

/// Finds a user name in a bounded local `passwd(5)` file and returns its
/// primary gid.
fn user_primary_gid(path: &str, name: &str) -> Option<u32> {
    let contents = read_account_file(path)?;
    contents.lines().find_map(|line| {
        let mut fields = line.split(':');
        let user = fields.next()?;
        let _password = fields.next()?;
        let _uid = fields.next()?;
        let gid = fields.next()?;
        (user == name).then(|| gid.parse::<u32>().ok()).flatten()
    })
}

/// Reads a local account database with a fixed size bound. Only the packaged
/// service account name is looked up, never caller-controlled data.
fn read_account_file(path: &str) -> Option<String> {
    const MAX_ACCOUNT_FILE_BYTES: u64 = 1024 * 1024;
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_ACCOUNT_FILE_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    String::from_utf8(bytes).ok()
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
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
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
///
/// The installed posture additionally requires the parent (the installed
/// `/etc/o3k`) to be root-owned; a service-user-owned parent never qualifies.
fn validate_parent_directory(
    path: &Path,
    effective_uid: u32,
    posture: TrustPosture,
) -> Result<(), ParentFailure> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let metadata = fs::metadata(parent).map_err(|_| ParentFailure::Unavailable)?;
    if !metadata.is_dir() {
        return Err(ParentFailure::Unavailable);
    }
    let owner_trusted = match posture {
        TrustPosture::Installed { .. } => metadata.uid() == 0,
        TrustPosture::TestLab => is_trusted_owner(metadata.uid(), effective_uid),
    };
    if !owner_trusted {
        return Err(ParentFailure::OwnerUntrusted);
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(ParentFailure::PermissionsTooOpen);
    }
    Ok(())
}

/// Groups this process may use for group-readable configuration: the
/// effective gid plus every supplementary group.
fn process_groups() -> Vec<u32> {
    let mut groups = vec![getegid().as_raw()];
    if let Ok(supplementary) = getgroups() {
        groups.extend(supplementary.into_iter().map(|gid| gid.as_raw()));
    }
    groups.sort_unstable();
    groups.dedup();
    groups
}

/// The accepted trust-document mode: `0600`, or `0640` when the owning group
/// is root or one of the process's groups (the service group). Anything else,
/// including any group/other write or other read bit, is refused.
fn configuration_mode_allowed(mode: u32, gid: u32, groups: &[u32]) -> bool {
    match mode & 0o777 {
        0o600 => true,
        0o640 => gid == 0 || groups.contains(&gid),
        _ => false,
    }
}

/// The private recipient key is never group-readable: exactly `0600` or
/// `0400`.
fn recipient_key_mode_allowed(mode: u32) -> bool {
    matches!(mode & 0o777, 0o600 | 0o400)
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
            BackupTrustConfig::load_for_data_dir(&self.config_path, &self.root)
        }

        fn load_testlab_with_effective_uid(
            &self,
            effective_uid: u32,
        ) -> Result<BackupTrustConfig, BackupTrustError> {
            BackupTrustConfig::load_with_posture(
                &self.config_path,
                effective_uid,
                TrustPosture::TestLab,
            )
        }

        fn load_installed(
            &self,
            service_gid: Option<u32>,
        ) -> Result<BackupTrustConfig, BackupTrustError> {
            self.load_installed_at(&self.config_path, service_gid)
        }

        fn load_installed_at(
            &self,
            path: &Path,
            service_gid: Option<u32>,
        ) -> Result<BackupTrustConfig, BackupTrustError> {
            BackupTrustConfig::load_with_posture(
                path,
                current_euid(),
                TrustPosture::Installed { service_gid },
            )
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
    fn accepts_the_service_group_mode_and_rejects_writable_or_other_readable() {
        let fixture = new_fixture();
        // The packaged layout is root:o3k 0640, read by the service user
        // through its group. The fixture's group is one of our groups, so this
        // exercises the same branch without needing root.
        fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o640))
            .expect("make configuration group-readable");
        fixture.load().expect("0640 in a service group");

        for mode in [0o664, 0o660, 0o644, 0o604] {
            fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(mode))
                .expect("relax configuration permissions");
            assert_eq!(
                fixture.load().expect_err("unsafe configuration").reason(),
                "trust-config-permissions-too-open",
                "mode {mode:o}"
            );
        }

        fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o600))
            .expect("restore configuration permissions");
        let config = fixture.load().expect("valid trust configuration");
        // The private key is recovery-host-only and never group-readable.
        for mode in [0o640, 0o604, 0o660] {
            fs::set_permissions(&fixture.key_path, fs::Permissions::from_mode(mode))
                .expect("relax key permissions");
            assert_eq!(
                config
                    .load_recipient_private_key()
                    .err()
                    .expect("group-readable key")
                    .reason(),
                "trust-recipient-key-permissions-too-open",
                "key mode {mode:o}"
            );
        }
        fs::set_permissions(&fixture.key_path, fs::Permissions::from_mode(0o400))
            .expect("read-only key");
        config
            .load_recipient_private_key()
            .expect("0400 private key is accepted");
    }

    #[test]
    fn installed_posture_accepts_only_root_service_group_0600_or_0640() {
        let service_gid = 4321;
        // Valid packaged postures: root:o3k 0640 and root:o3k 0600. Mode from
        // `MetadataExt::mode()` carries the file-type bits; only 0o777 counts.
        assert!(installed_posture_allowed(
            0,
            service_gid,
            0o100_640,
            Some(service_gid)
        ));
        assert!(installed_posture_allowed(
            0,
            service_gid,
            0o100_600,
            Some(service_gid)
        ));

        // A service-user-owned document is never an installed document, even
        // with the packaged mode and group.
        assert!(!installed_posture_allowed(
            service_gid,
            service_gid,
            0o100_600,
            Some(service_gid)
        ));
        // Wrong group: root:root, and an unrelated group.
        assert!(!installed_posture_allowed(
            0,
            0,
            0o100_640,
            Some(service_gid)
        ));
        assert!(!installed_posture_allowed(
            0,
            service_gid + 1,
            0o100_640,
            Some(service_gid)
        ));
        // 0644, 0660, 0604, 0400 and group/other execute are all refused.
        for mode in [0o644, 0o660, 0o664, 0o604, 0o400, 0o650] {
            assert!(
                !installed_posture_allowed(0, service_gid, mode, Some(service_gid)),
                "mode {mode:o}"
            );
        }

        // If the local account database cannot resolve `o3k`, only the root
        // group is an accepted fallback.
        assert!(installed_posture_allowed(0, 0, 0o640, None));
        assert!(!installed_posture_allowed(0, service_gid, 0o640, None));
    }

    #[test]
    fn installed_posture_rejects_a_service_user_owned_document() {
        let fixture = new_fixture();
        let metadata = fs::metadata(&fixture.config_path).expect("fixture metadata");
        let gid = metadata.gid();
        assert_eq!(
            fixture
                .load_installed(Some(gid))
                .expect_err("service-user-owned installed document")
                .reason(),
            "trust-config-posture-invalid"
        );

        fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o640))
            .expect("packaged group-read mode");
        assert_eq!(
            fixture
                .load_installed(Some(gid))
                .expect_err("service-user-owned installed document")
                .reason(),
            "trust-config-posture-invalid"
        );
    }

    #[test]
    fn installed_loader_accepts_root_service_group_posture_when_privileged() {
        if current_euid() != 0 {
            // Creating a root-owned fixture requires root; the predicate
            // matrix covers the valid root:o3k cases on unprivileged hosts.
            return;
        }
        let fixture = new_fixture();
        let gid = fs::metadata(&fixture.config_path)
            .expect("fixture metadata")
            .gid();
        for mode in [0o640, 0o600] {
            fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(mode))
                .expect("packaged installed mode");
            let config = fixture
                .load_installed(Some(gid))
                .expect("root-owned installed document");
            assert_eq!(config.site_id(), SITE_ID);
        }
    }

    #[test]
    fn installed_posture_rejects_symlink_and_non_0600_or_0640_modes() {
        let fixture = new_fixture();
        let gid = fs::metadata(&fixture.config_path)
            .expect("fixture metadata")
            .gid();
        let config_link = fixture.root.join("backup-trust-installed-link.json");
        std::os::unix::fs::symlink(&fixture.config_path, &config_link).expect("config symlink");
        assert_eq!(
            fixture
                .load_installed_at(&config_link, Some(gid))
                .expect_err("symlinked installed document")
                .reason(),
            "trust-config-symlink"
        );

        // The fixture owner is the effective uid, which is itself an installed
        // posture violation; these cases still prove 0644/0660 never pass.
        for mode in [0o644, 0o660] {
            fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(mode))
                .expect("relax installed fixture permissions");
            assert_eq!(
                fixture
                    .load_installed(Some(gid))
                    .expect_err("unsafe installed mode")
                    .reason(),
                "trust-config-posture-invalid",
                "mode {mode:o}"
            );
        }
    }

    #[test]
    fn service_group_resolution_reads_local_group_and_passwd_files() {
        let root = std::env::temp_dir().join(format!("o3k-group-fixture-{}", Uuid::now_v7()));
        create_private_dir(&root);
        let group_file = root.join("group");
        let passwd_file = root.join("passwd");
        fs::write(&group_file, "root:x:0:\nother:x:100:\no3k:x:4321:\n")
            .expect("write group fixture");
        fs::write(
            &passwd_file,
            "root:x:0:0:root:/root:/bin/sh\no3k:x:999:4321::/var/lib/o3k:/usr/sbin/nologin\n",
        )
        .expect("write passwd fixture");
        assert_eq!(
            group_gid_by_name(group_file.to_str().expect("utf-8 path"), "o3k"),
            Some(4321)
        );
        assert_eq!(
            user_primary_gid(passwd_file.to_str().expect("utf-8 path"), "o3k"),
            Some(4321)
        );
        assert_eq!(
            group_gid_by_name(group_file.to_str().expect("utf-8 path"), "absent"),
            None
        );
        fs::remove_dir_all(root).expect("remove group fixture");
    }

    #[test]
    fn root_owned_0640_for_a_service_user_and_group_write_rejection() {
        // Pure posture matrix: root owns the document and the service group
        // reads it; any group write or other read is refused.
        let service_groups = [1000_u32, 1001];
        assert!(configuration_mode_allowed(0o640, 1001, &service_groups));
        assert!(configuration_mode_allowed(0o640, 0, &service_groups));
        assert!(configuration_mode_allowed(0o600, 0, &service_groups));
        assert!(!configuration_mode_allowed(0o660, 1001, &service_groups));
        assert!(!configuration_mode_allowed(0o640, 1002, &service_groups));
        assert!(!configuration_mode_allowed(0o644, 1001, &service_groups));
        assert!(!configuration_mode_allowed(0o604, 1001, &service_groups));
        // Ownership still has to be root or the effective uid.
        assert!(trusted_owner(0, 1000));
        assert!(trusted_owner(1000, 1000));
        assert!(!trusted_owner(1001, 1000));
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
            BackupTrustConfig::load_for_data_dir(&config_link, &fixture.root)
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
        // Loading is lazy: the mismatch is detected when the private key is
        // actually needed, not when the document is read.
        let mismatched = fixture.load().expect("lazy document load");
        assert_eq!(
            mismatched
                .load_recipient_private_key()
                .err()
                .expect("declared public key that does not match")
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
    fn capture_loads_with_a_configured_public_key_and_no_private_key_file() {
        // The recovery key lives on another host. The controller's document
        // names an absent private-key path; loading and deriving the public
        // key must never open it.
        let fixture = new_fixture();
        let derived = <X25519HkdfSha256 as Kem>::sk_to_pk(&fixture.recipient)
            .to_bytes()
            .to_vec();
        let mut document = fixture.document();
        document["recipient"]["x25519_private_key_file"] = json!(
            fixture
                .root
                .join("absent-recovery.key")
                .display()
                .to_string()
        );
        document["recipient"]["x25519_public_key"] = json!(hex::encode(&derived));
        fixture.write(&document);
        let config = fixture.load().expect("capture-only trust document");
        assert_eq!(
            config.recipient_public_key().expect("declared public key"),
            <[u8; 32]>::try_from(derived.as_slice()).expect("32-byte key")
        );
        assert_eq!(
            config
                .load_recipient_private_key()
                .err()
                .expect("private key is absent on the controller")
                .reason(),
            "trust-recipient-key-unavailable"
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
        fixture
            .load_testlab_with_effective_uid(effective_uid)
            .expect("config owned by the effective uid");
        let foreign_uid = if effective_uid == 0 {
            1
        } else {
            effective_uid + 1
        };
        assert_eq!(
            fixture
                .load_testlab_with_effective_uid(foreign_uid)
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
            BackupTrustConfig::load_for_data_dir(&fixture.root, &fixture.root)
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

    fn temp_data_dir() -> PathBuf {
        std::env::temp_dir().join(format!("o3k-pp6-trust-data-{}", Uuid::now_v7()))
    }

    #[test]
    fn default_path_prefers_the_explicit_override_for_testlab_data() {
        let data_dir = temp_data_dir();
        let canonical = Path::new("/etc/o3k/backup-trust.json").to_path_buf();
        assert_eq!(
            default_trust_config_path_for(
                &data_dir,
                Some(OsString::from("/tmp/service-trust.json")),
                Some(OsString::from("/opt/o3k")),
            ),
            PathBuf::from("/tmp/service-trust.json")
        );
        assert_eq!(
            default_trust_config_path_for(&data_dir, None, Some(OsString::from("/opt/o3k"))),
            PathBuf::from("/opt/o3k/etc/o3k/backup-trust.json")
        );
        assert_eq!(
            default_trust_config_path_for(&data_dir, None, Some(OsString::new())),
            canonical
        );
        assert!(trust_overrides_allowed(&data_dir));
        assert_eq!(
            install_prefix_for(&data_dir, Some(OsString::from("/opt/o3k"))),
            PathBuf::from("/opt/o3k")
        );
    }

    #[test]
    fn installed_data_dir_ignores_the_environment_overrides_regardless_of_euid() {
        let installed = Path::new("/var/lib/o3k");
        let canonical = Path::new("/etc/o3k/backup-trust.json").to_path_buf();
        assert!(is_installed_data_dir(installed));
        assert!(!trust_overrides_allowed(installed));
        // No euid parameter exists precisely so the rule cannot be weakened by
        // a service user or by root.
        assert_eq!(
            default_trust_config_path_for(
                installed,
                Some(OsString::from("/tmp/attacker-trust.json")),
                Some(OsString::from("/tmp/attacker-prefix")),
            ),
            canonical
        );
        assert_eq!(
            install_prefix_for(installed, Some(OsString::from("/tmp/attacker-prefix"))),
            PathBuf::from(DEFAULT_INSTALL_PREFIX)
        );
        assert_eq!(
            install_prefix_for(installed, None),
            PathBuf::from(DEFAULT_INSTALL_PREFIX)
        );
    }

    #[test]
    fn default_path_without_a_prefix_uses_the_installed_config_directory() {
        let installed = Path::new(crate::context::DEFAULT_CONFIG_DIR).join(TRUST_CONFIG_FILE_NAME);
        assert_eq!(installed, Path::new("/etc/o3k/backup-trust.json"));
        let data_dir = temp_data_dir();
        assert_eq!(
            default_trust_config_path_for(&data_dir, None, None),
            installed
        );
        assert_eq!(
            default_trust_config_path_for(&data_dir, None, Some(OsString::new())),
            installed
        );
    }

    #[test]
    fn trust_path_without_a_resolvable_data_dir_is_conservative() {
        // `default_trust_config_path` cannot be redirected in-process; assert
        // only that a resolved or conservative path is absolute and installed.
        let path = default_trust_config_path();
        assert!(path.is_absolute());
    }

    #[test]
    fn installed_data_dir_detection_survives_a_symlinked_packaged_directory() {
        // The packaged directory may be a symlink to a dedicated volume. The
        // resolved data directory then canonicalizes to the link target, which
        // must still be recognized as the installation (otherwise the TestLab
        // overrides would be re-enabled for an installed service).
        let root = std::env::temp_dir().join(format!("o3k-pp6-trust-installed-{}", Uuid::now_v7()));
        create_private_dir(&root);
        let volume = root.join("volume");
        create_private_dir(&volume);
        let packaged_link = root.join("var-lib-o3k");
        std::os::unix::fs::symlink(&volume, &packaged_link).expect("packaged symlink");
        let other = root.join("testlab-data");
        create_private_dir(&other);

        assert!(installed_data_dir_matches(&volume, &packaged_link));
        assert!(installed_data_dir_matches(&packaged_link, &packaged_link));
        assert!(installed_data_dir_matches(&volume, &volume));
        assert!(!installed_data_dir_matches(&other, &packaged_link));
        // The literal packaged path still matches itself even when the entry
        // does not exist on the recording host.
        assert!(installed_data_dir_matches(
            Path::new("/var/lib/o3k"),
            Path::new("/var/lib/o3k")
        ));
        assert!(!installed_data_dir_matches(
            &other,
            Path::new("/var/lib/o3k")
        ));
        fs::remove_dir_all(&root).expect("remove installed-dir fixture");
    }

    #[test]
    fn root_owned_document_without_group_read_names_the_service_user_reason() {
        // Pure posture matrix: root owns the document, the caller is not root,
        // and the group-read bit decides between "unavailable" and the
        // dedicated service-user reason.
        assert!(unreadable_by_service_user(0, 0o600, 1000));
        assert!(!unreadable_by_service_user(0, 0o640, 1000));
        assert!(!unreadable_by_service_user(0, 0o600, 0));
        assert!(!unreadable_by_service_user(1000, 0o600, 1000));
        assert_eq!(
            BackupTrustError::ConfigUnreadableByServiceUser.reason(),
            "trust-config-unreadable-by-service-user"
        );
        // The recovery class is shared with the generic unavailable reason, so
        // `verify` keeps exit 3 and `create`'s preflight keeps exit 2.
        assert!(BackupTrustError::ConfigUnreadableByServiceUser.is_recoverable());

        // A document this process owns is a plain unavailable/malformed read,
        // never the service-user diagnosis.
        let fixture = new_fixture();
        let missing = fixture.root.join("absent-trust.json");
        assert_eq!(
            unavailable_config_error(&missing, current_euid(), TrustPosture::TestLab),
            BackupTrustError::ConfigUnavailable
        );
    }
}
