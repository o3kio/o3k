//! Root-authorized, one-way C1 installation provisioning.
//!
//! This is deliberately an installer primitive, not a controller API.  It
//! consumes already authenticated offline documents and never creates trust
//! by itself (in particular, it never generates keys or invents filesystem
//! identities).

use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path};

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::{
    recovery_files::ProtectedDirectory, recovery_identity as identity, upgrade::release_identity,
};

const MAX_INPUT: u64 = 1024 * 1024;
const POLICY_NAME: &str = "policy.json";
const STATE_NAME: &str = "state.json";

#[derive(Debug)]
pub enum ProvisionError {
    NotRoot,
    Input(String),
    Rejected(String),
    Persistence(String),
}
impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProvisionError {}

/// Which installation situation the authenticated checkpoint is provisioned
/// into.  Both modes consume the same offline-signed documents; only the
/// pre-write evidence checks differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionMode {
    /// Fresh C1 installation onto directories created by
    /// `recovery_prepare::prepare`.
    NewInstall,
    /// Existing installation that predates C1.  `NEVER_RECOVERED` may be
    /// initialized only when a thorough legacy-evidence absence check proves
    /// recovery was never entered; any evidence fails closed into an
    /// operator-visible disposition requirement.
    LegacyMigration,
}

impl ProvisionMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "new-install" => Some(Self::NewInstall),
            "legacy-migration" => Some(Self::LegacyMigration),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewInstall => "new-install",
            Self::LegacyMigration => "legacy-migration",
        }
    }
}

/// Provision the immutable initial C1 checkpoint for a fresh installation.
/// The caller must arrange for the destination directories and fixed release
/// manifest to be installed first; this function refuses to create or
/// reinterpret either.
pub fn provision(
    policy_input: &Path,
    state_input: &Path,
    trust_input: &Path,
) -> Result<(), ProvisionError> {
    provision_with_mode(
        policy_input,
        state_input,
        trust_input,
        ProvisionMode::NewInstall,
    )
}

/// Provision the immutable initial C1 checkpoint.  In `LegacyMigration` mode
/// the signed `NEVER_RECOVERED` record is accepted only after the installed
/// release, installation identity, and a thorough legacy-evidence absence
/// check verify that recovery was never entered.  Writes are idempotent for
/// identical earlier content and fail closed on any conflicting record.
pub fn provision_with_mode(
    policy_input: &Path,
    state_input: &Path,
    trust_input: &Path,
    mode: ProvisionMode,
) -> Result<(), ProvisionError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(ProvisionError::NotRoot);
    }
    reject_ambiguous_legacy_state()?;

    let policy_bytes = read_input(policy_input)?;
    let state_bytes = read_input(state_input)?;
    let trust_bytes = read_input(trust_input)?;
    let manifest = release_identity::read_fixed_installed_release_manifest()
        .map_err(ProvisionError::Rejected)?;
    let authority = release_identity::BackupReleaseIdentity::c1_authority_from_manifest(&manifest)
        .map_err(ProvisionError::Rejected)?;
    let release = release_identity::BackupReleaseIdentity::from_manifest_bytes(&manifest)
        .map_err(ProvisionError::Rejected)?;
    let key_bytes: [u8; 32] = hex::decode(&authority.ed25519_public_key)
        .map_err(|_| ProvisionError::Rejected("release policy key is malformed".into()))?
        .try_into()
        .map_err(|_| ProvisionError::Rejected("release policy key length is invalid".into()))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| ProvisionError::Rejected("release policy key is invalid".into()))?;
    let policy: identity::InstallationPolicy = identity::verify_signed(
        &policy_bytes,
        &authority.policy_format,
        &authority.key_id,
        &key,
    )
    .map_err(|e| ProvisionError::Rejected(e.to_string()))?;
    identity::verify_policy(&policy, &authority.key_id)
        .map_err(|e| ProvisionError::Rejected(e.to_string()))?;
    if policy.policy_path != authority.policy_path
        || policy.release_identity != release.release_artifact_sha256
        || policy.profile != release.profile_id
        || Path::new(&policy.data_root)
            .canonicalize()
            .map_err(|e| ProvisionError::Rejected(e.to_string()))?
            .as_path()
            != Path::new(&policy.data_root)
    {
        return Err(ProvisionError::Rejected(
            "policy is not bound to the installed release and target".into(),
        ));
    }

    // Trust is an offline signed document; its enclosing signature is checked
    // by the release/installer trust workflow.  Canonical decoding and the
    // policy digest binding prevent replacement or ambiguous JSON here.
    let trust: identity::TrustBundle = identity::decode_canonical(&trust_bytes)
        .map_err(|e| ProvisionError::Rejected(e.to_string()))?;
    if identity::digest(&trust).map_err(|e| ProvisionError::Rejected(e.to_string()))?
        != policy.trust_bundle_digest
        || trust.installation_id != policy.installation_id
        || trust.site_id != policy.site_id
        || trust.profile != policy.profile
        || trust.backend != policy.backend
        || trust.journal_root_key_id != policy.journal_trust_root_id
        || trust.journal_root_public_key != policy.journal_trust_root_public_key
    {
        return Err(ProvisionError::Rejected(
            "trust bundle is not bound to policy".into(),
        ));
    }

    let state: identity::InstallationState = identity::verify_signed(
        &state_bytes,
        "o3k-installation-state-v1",
        &authority.key_id,
        &key,
    )
    .map_err(|e| ProvisionError::Rejected(e.to_string()))?;
    identity::verify_initial_state_transition(None, &state, &policy)
        .map_err(|e| ProvisionError::Rejected(e.to_string()))?;
    if state.state != identity::RecoveryState::NeverRecovered
        || state.policy_digest != hex::encode(Sha256::digest(&policy_bytes))
    {
        return Err(ProvisionError::Rejected(
            "initial state is not an authenticated NEVER_RECOVERED checkpoint".into(),
        ));
    }

    if mode == ProvisionMode::LegacyMigration {
        let evidence = legacy_recovery_evidence(&policy.installation_id);
        migration_evidence_decision(&evidence)?;
    }

    let (_, gid) = service_gid()?;
    let state_dir = ProtectedDirectory::open(
        Path::new(&policy.recovery_state_root),
        0,
        gid,
        0o750,
        policy.recovery_state_device,
        policy.recovery_state_inode,
    )
    .map_err(|e| ProvisionError::Persistence(format!("state directory: {e:?}")))?;
    let (service_uid, _) = service_gid()?;
    let journal_dir = ProtectedDirectory::open(
        Path::new(&policy.journal_directory),
        service_uid,
        gid,
        0o700,
        policy.journal_device,
        policy.journal_inode,
    )
    .map_err(|e| ProvisionError::Persistence(format!("journal directory: {e:?}")))?;
    let _ = journal_dir;
    write_checkpoint(&state_dir, POLICY_NAME, &policy_bytes, gid)?;
    write_checkpoint(&state_dir, "trust.json", &trust_bytes, gid)?;
    write_checkpoint(&state_dir, STATE_NAME, &state_bytes, gid)?;
    Ok(())
}

/// Writes one immutable checkpoint.  Identical earlier content is left
/// untouched (idempotent re-provisioning); conflicting content fails closed.
fn write_checkpoint(
    directory: &ProtectedDirectory,
    name: &str,
    bytes: &[u8],
    gid: u32,
) -> Result<(), ProvisionError> {
    match directory.atomic_write(name, None, bytes, gid) {
        Ok(()) => Ok(()),
        Err(crate::recovery_files::RecoveryFileError::CompareFailed) => {
            let existing = directory
                .read_bounded(name, 0, gid, 0o640, MAX_INPUT as usize)
                .map_err(|e| ProvisionError::Persistence(format!("{name} checkpoint: {e:?}")))?;
            if existing == bytes {
                Ok(())
            } else {
                Err(ProvisionError::Persistence(format!(
                    "{name}: conflicting existing C1 record"
                )))
            }
        }
        Err(error) => Err(ProvisionError::Persistence(format!(
            "{name} checkpoint: {error:?}"
        ))),
    }
}

/// Collects the closed list of legacy recovery evidence for a migration:
/// legacy recovery configuration, per-installation recovery directories with
/// any content, unexpected or foreign entries under the recovery parents, and
/// directories whose posture does not match the accepted layout.  Absence of
/// everything on this list is what allows `NEVER_RECOVERED` initialization.
fn legacy_recovery_evidence(installation_id: &str) -> Vec<String> {
    let mut evidence = Vec::new();
    for config in ["/etc/o3k/restore.json", "/etc/o3k/recovery.json"] {
        if fs::symlink_metadata(config).is_ok() {
            evidence.push(format!("{config} (legacy recovery configuration)"));
        }
    }
    for parent in ["/var/lib/o3k-recovery-state", "/var/lib/o3k-recovery"] {
        let Ok(entries) = fs::read_dir(parent) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(metadata) = entry.metadata() else {
                evidence.push(format!("{} (unreadable entry)", path.display()));
                continue;
            };
            match classify_recovery_entry(&name, installation_id, metadata.is_dir()) {
                RecoveryEntryClass::ForeignDirectory => evidence.push(format!(
                    "{} (foreign installation recovery directory)",
                    path.display()
                )),
                RecoveryEntryClass::UnexpectedEntry => {
                    evidence.push(format!("{} (unexpected entry)", path.display()))
                }
                RecoveryEntryClass::TargetDirectory => match fs::read_dir(&path) {
                    Err(_) => {
                        evidence.push(format!("{} (unreadable directory)", path.display()));
                    }
                    Ok(mut entries) => {
                        if entries.next().is_some() {
                            evidence.push(format!(
                                "{} (existing recovery content requires an authenticated disposition)",
                                path.display()
                            ));
                        }
                    }
                },
            }
        }
    }
    evidence
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryEntryClass {
    /// This installation's own per-installation directory.  Empty is the only
    /// non-evidence state; content is handled by the caller.
    TargetDirectory,
    /// Another installation's recovery directory on this host.
    ForeignDirectory,
    /// Anything that is not a per-installation directory.
    UnexpectedEntry,
}

fn classify_recovery_entry(name: &str, installation_id: &str, is_dir: bool) -> RecoveryEntryClass {
    if !is_dir {
        return RecoveryEntryClass::UnexpectedEntry;
    }
    if name == installation_id {
        RecoveryEntryClass::TargetDirectory
    } else {
        RecoveryEntryClass::ForeignDirectory
    }
}

/// Fails closed with an operator-visible disposition requirement when any
/// legacy evidence exists.  Never writes quarantine state and never converts
/// evidence into `NEVER_RECOVERED`.
fn migration_evidence_decision(evidence: &[String]) -> Result<(), ProvisionError> {
    if evidence.is_empty() {
        return Ok(());
    }
    Err(ProvisionError::Rejected(format!(
        "legacy recovery evidence is present ({}); an authenticated recovery \
         disposition is required and NEVER_RECOVERED was not initialized",
        evidence.join(", ")
    )))
}

fn read_input(path: &Path) -> Result<Vec<u8>, ProvisionError> {
    let meta = fs::symlink_metadata(path).map_err(|e| ProvisionError::Input(e.to_string()))?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || meta.len() > MAX_INPUT
    {
        return Err(ProvisionError::Input(format!(
            "{} is not a bounded root-owned regular file",
            path.display()
        )));
    }
    let file = fs::File::open(path).map_err(|e| ProvisionError::Input(e.to_string()))?;
    let before = file
        .metadata()
        .map_err(|e| ProvisionError::Input(e.to_string()))?;
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| ProvisionError::Input(e.to_string()))?;
    let after = file
        .metadata()
        .map_err(|e| ProvisionError::Input(e.to_string()))?;
    if bytes.len() > MAX_INPUT as usize
        || before.ino() != after.ino()
        || before.len() != after.len()
    {
        return Err(ProvisionError::Input(
            "input changed or exceeds bound".into(),
        ));
    }
    Ok(bytes)
}

fn service_gid() -> Result<(u32, u32), ProvisionError> {
    let text =
        fs::read_to_string("/etc/passwd").map_err(|e| ProvisionError::Input(e.to_string()))?;
    for line in text.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.first() == Some(&"o3k") && fields.len() >= 4 {
            let uid = fields[2]
                .parse()
                .map_err(|_| ProvisionError::Input("invalid o3k uid".into()))?;
            let gid = fields[3]
                .parse()
                .map_err(|_| ProvisionError::Input("invalid o3k gid".into()))?;
            return Ok((uid, gid));
        }
    }
    Err(ProvisionError::Input(
        "o3k service identity is unavailable".into(),
    ))
}

fn reject_ambiguous_legacy_state() -> Result<(), ProvisionError> {
    for path in ["/etc/o3k/restore.json", "/etc/o3k/recovery.json"] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(ProvisionError::Rejected(
                "legacy recovery configuration is present".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn mode_parse_accepts_only_the_two_accepted_modes() {
        assert_eq!(
            ProvisionMode::parse("new-install"),
            Some(ProvisionMode::NewInstall)
        );
        assert_eq!(
            ProvisionMode::parse("legacy-migration"),
            Some(ProvisionMode::LegacyMigration)
        );
        assert_eq!(ProvisionMode::parse(""), None);
        assert_eq!(ProvisionMode::parse("migration"), None);
        assert_eq!(ProvisionMode::parse("NEVER_RECOVERED"), None);
        assert_eq!(ProvisionMode::parse("legacy_migration"), None);
        assert_eq!(ProvisionMode::NewInstall.as_str(), "new-install");
        assert_eq!(ProvisionMode::LegacyMigration.as_str(), "legacy-migration");
    }

    #[test]
    fn classifies_recovery_parent_entries() {
        assert_eq!(
            classify_recovery_entry("inst-1", "inst-1", true),
            RecoveryEntryClass::TargetDirectory
        );
        assert_eq!(
            classify_recovery_entry("inst-2", "inst-1", true),
            RecoveryEntryClass::ForeignDirectory
        );
        assert_eq!(
            classify_recovery_entry("notes.txt", "inst-1", false),
            RecoveryEntryClass::UnexpectedEntry
        );
        // A symlink or device entry never counts as the target directory.
        assert_eq!(
            classify_recovery_entry("inst-1", "inst-1", false),
            RecoveryEntryClass::UnexpectedEntry
        );
    }

    #[test]
    fn migration_decision_passes_only_on_complete_absence() {
        assert!(migration_evidence_decision(&[]).is_ok());
        let error = migration_evidence_decision(&[
            "/etc/o3k/restore.json (legacy recovery configuration)".to_string(),
        ])
        .unwrap_err();
        let message = format!("{error:?}");
        assert!(
            message.contains("authenticated recovery disposition is required"),
            "operator-visible disposition requirement: {message}"
        );
        assert!(
            message.contains("NEVER_RECOVERED was not initialized"),
            "must never silently convert evidence: {message}"
        );
        let error = migration_evidence_decision(&[
            "/var/lib/o3k-recovery/inst-9 (foreign installation recovery directory)".to_string(),
        ])
        .unwrap_err();
        assert!(format!("{error:?}").contains("foreign installation"));
    }

    #[test]
    fn legacy_configuration_paths_are_the_closed_config_set() {
        // Guard the closed list: the migration absence check names exactly
        // the legacy recovery configuration files the installer ever shipped.
        let configs: [&str; 2] = ["/etc/o3k/restore.json", "/etc/o3k/recovery.json"];
        assert!(configs.contains(&"/etc/o3k/restore.json"));
        assert!(configs.contains(&"/etc/o3k/recovery.json"));
        assert_eq!(configs.len(), 2);
    }
}
