//! Root-authorized A10.1 installation-policy migration publication.
//!
//! The verifier remains the authority: this module accepts only externally
//! signed migration inputs and uses the installed v1 verifier before it may
//! acquire D8 or write migration state. It never signs, selects a new trust
//! root, opens the canonical store, or authorizes controller activation.

use std::{
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::{
    recovery_identity as identity,
    recovery_installation::{InstalledRecovery, service_identity},
    recovery_migration_selector as selector,
    upgrade::release_identity::BackupReleaseIdentity,
};

const MAX_INPUT: u64 = 1024 * 1024;
const MAX_CANDIDATE_ARTIFACT: u64 = 2 * 1024 * 1024 * 1024;
const MAX_EXECUTABLE: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub enum MigrationError {
    RootRequired,
    Input(&'static str),
    Rejected(&'static str),
    Persistence(&'static str),
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for MigrationError {}

/// Externally signed inputs required to move a complete C1/C1.1 v1
/// installation to A10.1 v2. `release_manifest` is the exact manifest that
/// the signed migration event names; `candidate_artifact` is independently
/// authenticated and installed only after its archive inventory and
/// executable digests verify.
#[derive(Debug, Clone, Copy)]
pub struct MigrationInputs<'a> {
    pub policy_v2: &'a Path,
    pub migration_event: &'a Path,
    pub release_manifest_v2: &'a Path,
    /// Exact release asset whose SHA-256 is named by the signed event and
    /// release manifest. It is an externally built artifact, never a local
    /// build or caller-selected directory of executables.
    pub candidate_artifact: &'a Path,
    /// Release-level provenance signature inputs for the exact source commit,
    /// bundle manifest, checksums and release artifact.
    pub release_digests: &'a Path,
    pub release_signature: &'a Path,
    /// Raw manifest and release-level provenance for the currently installed
    /// source release. These authenticate the old executable checksum set.
    pub source_manifest: &'a Path,
    pub source_release_digests: &'a Path,
    pub source_release_signature: &'a Path,
}

#[derive(Debug)]
pub struct AuthenticatedMigration {
    pub policy_bytes: Vec<u8>,
    pub event_bytes: Vec<u8>,
    pub manifest_bytes: Vec<u8>,
    pub policy_digest: String,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub release_version: String,
    pub sequence: u64,
    pub candidate_sums: Vec<u8>,
    pub release_digests: Vec<u8>,
    pub release_signature: Vec<u8>,
    pub source_manifest: Vec<u8>,
    pub source_release_digests: Vec<u8>,
    pub source_release_signature: Vec<u8>,
}

struct SourceReleaseProvenance {
    manifest: Vec<u8>,
    digests: Vec<u8>,
    signature: Vec<u8>,
}

struct UpgradeExclusion {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for UpgradeExclusion {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;

        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
            if let Some(parent) = self.path.parent()
                && let Ok(directory) = fs::File::open(parent)
            {
                let _ = directory.sync_all();
            }
        }
    }
}

fn acquire_upgrade_exclusion() -> Result<UpgradeExclusion, MigrationError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut path = crate::upgrade::state::default_state_path().into_os_string();
    path.push(".lock");
    let path = PathBuf::from(path);
    let parent = path
        .parent()
        .ok_or_else(|| reject("upgrade lock path has no parent"))?;
    crate::recovery_files::check_ancestors(&path)
        .map_err(|_| reject("upgrade lock path is unsafe"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|_| reject("upgrade lock directory is unavailable"))?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(reject("upgrade lock directory posture is unsafe"));
    }
    for attempt in 0..2 {
        let mut lock = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(lock) => lock,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let observed = fs::symlink_metadata(&path)
                    .map_err(|_| reject("upgrade exclusion identity is unavailable"))?;
                if !observed.is_file()
                    || observed.uid() != 0
                    || observed.mode() & 0o7777 != 0o600
                    || observed.nlink() != 1
                {
                    return Err(reject("upgrade exclusion posture is unsafe"));
                }
                let holder = fs::read_to_string(&path)
                    .ok()
                    .and_then(|contents| contents.trim().parse::<u32>().ok());
                let stale =
                    holder.is_some_and(|pid| !Path::new("/proc").join(pid.to_string()).exists());
                if !stale || attempt != 0 {
                    return Err(reject("upgrade or rollback is already running"));
                }
                // The upgrade lock is a coordination file, not crash denial.
                // Recheck its inode immediately before reclaiming a dead
                // holder so a concurrent live owner is never unlinked.
                let current = fs::symlink_metadata(&path)
                    .map_err(|_| reject("upgrade exclusion identity changed"))?;
                if current.dev() != observed.dev() || current.ino() != observed.ino() {
                    return Err(reject("upgrade exclusion identity changed"));
                }
                fs::remove_file(&path)
                    .map_err(|_| reject("stale upgrade exclusion cannot be reclaimed"))?;
                fs::File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| {
                        MigrationError::Persistence("stale upgrade lock removal sync failed")
                    })?;
                continue;
            }
            Err(_) => return Err(reject("upgrade or rollback lock cannot be created")),
        };
        use std::io::Write;
        writeln!(lock, "{}", std::process::id())
            .and_then(|()| lock.sync_all())
            .map_err(|_| MigrationError::Persistence("upgrade exclusion sync failed"))?;
        let metadata = lock
            .metadata()
            .map_err(|_| reject("upgrade exclusion identity is unavailable"))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| MigrationError::Persistence("upgrade lock directory sync failed"))?;
        return Ok(UpgradeExclusion {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        });
    }
    Err(reject("upgrade lock raced with another invocation"))
}

/// Unpacks an already authenticated release asset into a new, empty inert
/// directory. The tar parser rejects links, special files, path traversal,
/// duplicate names and oversized expansion before any installed executable
/// is touched. Every regular file must be covered by the bundle SHA256SUMS.
pub fn extract_verified_candidate(
    artifact: &Path,
    authenticated: &AuthenticatedMigration,
    destination: &Path,
) -> Result<PathBuf, MigrationError> {
    use flate2::read::GzDecoder;
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::fs::OpenOptionsExt;

    if digest_root_artifact(artifact)? != authenticated.artifact_digest {
        return Err(reject("candidate artifact changed after authentication"));
    }
    if !destination.is_absolute() || fs::read_dir(destination).is_err() {
        return Err(MigrationError::Input(
            "candidate staging directory is not an existing directory",
        ));
    }
    let status = fs::symlink_metadata(destination)
        .map_err(|_| MigrationError::Input("candidate staging directory is unavailable"))?;
    if !status.is_dir()
        || status.uid() != 0
        || status.mode() & 0o077 != 0
        || fs::read_dir(destination)
            .map_err(|_| MigrationError::Input("candidate staging directory cannot be listed"))?
            .next()
            .is_some()
    {
        return Err(MigrationError::Input(
            "candidate staging directory is not root-only and protected",
        ));
    }
    let mut archive =
        tar::Archive::new(GzDecoder::new(fs::File::open(artifact).map_err(|_| {
            MigrationError::Input("candidate artifact cannot be reopened")
        })?));
    let entries = archive
        .entries()
        .map_err(|_| reject("candidate archive is malformed"))?;
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for entry in entries {
        let mut entry = entry.map_err(|_| reject("candidate archive entry is malformed"))?;
        let entry_type = entry.header().entry_type();
        let path = entry
            .path()
            .map_err(|_| reject("candidate archive path is malformed"))?
            .into_owned();
        if path.components().next()
            != Some(std::path::Component::Normal(
                format!("o3k-{}", authenticated.release_version).as_ref(),
            ))
        {
            return Err(reject("candidate archive has an unexpected bundle root"));
        }
        if path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            || !(entry_type.is_dir() || entry_type.is_file())
            || !seen.insert(path.clone())
        {
            return Err(reject(
                "candidate archive contains an unsafe or duplicate entry",
            ));
        }
        let target = destination.join(&path);
        if entry_type.is_dir() {
            fs::create_dir_all(&target)
                .map_err(|_| MigrationError::Persistence("candidate directory staging failed"))?;
            let metadata = fs::symlink_metadata(&target)
                .map_err(|_| MigrationError::Persistence("candidate directory readback failed"))?;
            if !metadata.is_dir() || metadata.uid() != 0 {
                return Err(reject("candidate directory was substituted"));
            }
            continue;
        }
        let size = entry.size();
        total = total.saturating_add(size);
        if size > MAX_CANDIDATE_ARTIFACT || total > MAX_CANDIDATE_ARTIFACT {
            return Err(reject(
                "candidate archive expands beyond its signed size bound",
            ));
        }
        let parent = target
            .parent()
            .ok_or_else(|| reject("candidate file path has no parent"))?;
        fs::create_dir_all(parent)
            .map_err(|_| MigrationError::Persistence("candidate parent staging failed"))?;
        ensure_root_directories(destination, parent)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .map_err(|_| MigrationError::Persistence("candidate file staging failed"))?;
        std::io::copy(&mut entry, &mut output)
            .map_err(|_| MigrationError::Persistence("candidate file extraction failed"))?;
        output
            .sync_all()
            .map_err(|_| MigrationError::Persistence("candidate file sync failed"))?;
    }
    let bundle_name = format!("o3k-{}", authenticated.release_version);
    let bundle = destination.join(bundle_name);
    if !bundle.is_dir() {
        return Err(reject("candidate archive has no exact release bundle root"));
    }
    let sums = fs::read_to_string(bundle.join("SHA256SUMS"))
        .map_err(|_| reject("candidate archive has no readable SHA256SUMS"))?;
    let mut checksums = BTreeMap::new();
    for line in sums.lines() {
        let mut columns = line.split_whitespace();
        let (Some(hash), Some(name)) = (columns.next(), columns.next()) else {
            return Err(reject("candidate SHA256SUMS entry is malformed"));
        };
        if columns.next().is_some()
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !name.starts_with("./")
            || name.contains("..")
            || checksums.insert(name.to_owned(), hash.to_owned()).is_some()
        {
            return Err(reject(
                "candidate SHA256SUMS has an invalid or duplicate entry",
            ));
        }
    }
    if checksums.is_empty() {
        return Err(reject("candidate SHA256SUMS is empty"));
    }
    for executable in ["o3kd", "o3k", "o3k-compute", "o3k-network"] {
        let entry = format!("./bin/{executable}");
        if !checksums.contains_key(&entry) || !bundle.join("bin").join(executable).is_file() {
            return Err(reject("candidate release omits a required dual verifier"));
        }
    }
    for (name, expected) in &checksums {
        let path = bundle.join(name.trim_start_matches("./"));
        let actual = digest_root_artifact(&path)?;
        if actual != *expected {
            return Err(reject(
                "candidate SHA256SUMS does not match extracted bytes",
            ));
        }
    }
    for path in walk_regular_files(&bundle)? {
        if path == bundle.join("SHA256SUMS") {
            continue;
        }
        let relative = path
            .strip_prefix(&bundle)
            .map_err(|_| reject("candidate bundle path escaped staging"))?;
        let checksum_name = format!("./{}", relative.display());
        if !checksums.contains_key(&checksum_name) {
            return Err(reject("candidate SHA256SUMS does not cover every file"));
        }
    }
    let raw_manifest = fs::read(bundle.join("manifest.json"))
        .map_err(|_| reject("candidate bundle release manifest is unavailable"))?;
    let exact_manifest = crate::upgrade::release_identity::manifest_with_verified_artifact(
        &raw_manifest,
        &authenticated.artifact_digest,
    )
    .map_err(|_| reject("candidate bundle release manifest is invalid"))?;
    if exact_manifest != authenticated.manifest_bytes {
        return Err(reject(
            "candidate bundle manifest differs from the signed target manifest",
        ));
    }
    // Sync each created directory bottom-up so the inert staged tree survives
    // process or host restart before it can be selected.
    let mut directories = walk_directories(&bundle)?;
    directories.reverse();
    for directory in directories {
        fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| MigrationError::Persistence("candidate directory sync failed"))?;
    }
    fs::File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|_| MigrationError::Persistence("candidate staging sync failed"))?;
    Ok(bundle)
}

/// Atomically installs the candidate's complete dual-verifier executable set
/// while the v1 selector is still active. Both the currently installed bytes
/// and candidate bytes must match their exact release SHA256SUMS entries.
pub fn replace_dual_verifiers(
    bundle: &Path,
    old_release_sums: &[u8],
) -> Result<(), MigrationError> {
    const EXECUTABLES: [&str; 4] = ["o3kd", "o3k", "o3k-compute", "o3k-network"];
    let old_hashes = parse_release_sums(old_release_sums)?;
    let candidate_sums = fs::read(bundle.join("SHA256SUMS"))
        .map_err(|_| reject("candidate checksums cannot be read"))?;
    let candidate_hashes = parse_release_sums(&candidate_sums)?;
    let bin_dir =
        crate::recovery_files::ProtectedDirectory::open_root_installer(Path::new("/usr/local/bin"))
            .map_err(|_| reject("installed executable directory is unsafe"))?;
    for name in EXECUTABLES {
        let relative = format!("./bin/{name}");
        let candidate = bundle.join("bin").join(name);
        let candidate_digest = digest_root_artifact(&candidate)?;
        if candidate_hashes.get(&relative) != Some(&candidate_digest) {
            return Err(reject(
                "candidate executable is not authenticated by SHA256SUMS",
            ));
        }
        let installed_path = Path::new("/usr/local/bin").join(name);
        let installed_digest = digest_root_artifact(&installed_path)?;
        let target_digest = candidate_hashes
            .get(&relative)
            .ok_or_else(|| reject("candidate executable checksum is missing"))?;
        if &installed_digest == target_digest {
            // A prior process may have completed replacement but died before
            // publication. Compute must remain blocked from direct execution
            // until the v2 selector and all documents verify.
            if name == "o3k-compute" {
                let metadata = fs::symlink_metadata(&installed_path)
                    .map_err(|_| reject("installed compute executable is unavailable"))?;
                if metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o644 {
                    return Err(reject("candidate compute executable is still admitted"));
                }
            }
            continue;
        }
        if old_hashes.get(&relative) != Some(&installed_digest) {
            return Err(reject(
                "installed executable differs from its release manifest",
            ));
        }
        let old_bytes = read_root_file(&installed_path, MAX_EXECUTABLE)?;
        let new_bytes = read_root_file(&candidate, MAX_EXECUTABLE)?;
        let old_mode = if name == "o3k-compute" { 0o644 } else { 0o755 };
        let new_mode = if name == "o3k-compute" { 0o644 } else { 0o755 };
        bin_dir
            .atomic_replace_installer(name, &old_bytes, &new_bytes, 0, 0, old_mode, new_mode)
            .map_err(|_| MigrationError::Persistence("dual-verifier replacement failed"))?;
    }
    for name in EXECUTABLES {
        let path = Path::new("/usr/local/bin").join(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| reject("installed dual verifier is unavailable"))?;
        let expected_mode = if name == "o3k-compute" { 0o644 } else { 0o755 };
        if metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != expected_mode
            || metadata.nlink() != 1
            || digest_root_artifact(&path)?
                != *candidate_hashes
                    .get(&format!("./bin/{name}"))
                    .ok_or_else(|| reject("candidate executable checksum is missing"))?
        {
            return Err(reject(
                "installed dual-verifier readback differs from candidate",
            ));
        }
    }
    Ok(())
}

/// Saves the exact authenticated predecessor and target inputs under inert
/// protected names, then performs selector-first active publication. The
/// caller must hold the D8 store guard, have quiesced every service, and have
/// installed/readback-verified all candidate executables before calling this.
pub(crate) fn publish_documents_selector_first(
    installed: &InstalledRecovery,
    authenticated: &AuthenticatedMigration,
    candidate_sums: &[u8],
    candidate_artifact: &Path,
) -> Result<(), MigrationError> {
    stage_authority_documents(installed, authenticated, candidate_artifact)?;
    let (_, gid) = service_identity().map_err(|_| reject("o3k service identity is unavailable"))?;
    let (prior_sequence, prior_digest, prior_state, prior_policy, prior_manifest) =
        installed.migration_predecessor();
    let prior_policy_digest = installed.policy_digest.as_str();
    let prior_manifest_digest = hex::encode(Sha256::digest(prior_manifest));
    let state_directory = installed.migration_state_directory();
    let archives = [
        (format!("state-{prior_digest}.json"), prior_state),
        (format!("policy-{prior_policy_digest}.json"), prior_policy),
        (
            format!("release-{prior_manifest_digest}.json"),
            prior_manifest,
        ),
        (
            format!("policy-high-water-{prior_policy_digest}.json"),
            installed.migration_policy_high_water_bytes(),
        ),
    ];
    for (name, bytes) in archives {
        stage_exact(state_directory, &name, bytes, gid)?;
    }
    let inert = [
        (
            format!("migration-v2-event-{}.json", authenticated.sequence),
            authenticated.event_bytes.as_slice(),
        ),
        (
            format!("migration-v2-policy-{}.json", authenticated.policy_digest),
            authenticated.policy_bytes.as_slice(),
        ),
        (
            format!(
                "migration-v2-release-{}.json",
                authenticated.manifest_digest
            ),
            authenticated.manifest_bytes.as_slice(),
        ),
        (
            format!(
                "migration-v2-release-digests-{}.txt",
                authenticated.artifact_digest
            ),
            authenticated.release_digests.as_slice(),
        ),
        (
            format!(
                "migration-v2-release-signature-{}.sig",
                authenticated.artifact_digest
            ),
            authenticated.release_signature.as_slice(),
        ),
        (
            format!(
                "migration-v1-source-manifest-{}.json",
                authenticated.manifest_digest
            ),
            authenticated.source_manifest.as_slice(),
        ),
        (
            format!(
                "migration-v1-source-digests-{}.txt",
                authenticated.artifact_digest
            ),
            authenticated.source_release_digests.as_slice(),
        ),
        (
            format!(
                "migration-v1-source-signature-{}.sig",
                authenticated.artifact_digest
            ),
            authenticated.source_release_signature.as_slice(),
        ),
    ];
    for (name, bytes) in inert {
        stage_exact(state_directory, &name, bytes, gid)?;
    }
    state_directory
        .stage_root_artifact(
            &format!(
                "migration-v2-artifact-{}.tar.gz",
                authenticated.artifact_digest
            ),
            candidate_artifact,
            &authenticated.artifact_digest,
            gid,
            MAX_CANDIDATE_ARTIFACT,
        )
        .map_err(|_| MigrationError::Persistence("candidate artifact staging failed"))?;

    let share_dir = crate::recovery_files::ProtectedDirectory::open_root_installer(Path::new(
        "/usr/local/share/o3k",
    ))
    .map_err(|_| reject("installed release metadata directory is unsafe"))?;

    // The signed migration event changes active authority first. Every later
    // publication is an exact CAS; after this point no v1 rollback is valid.
    state_directory
        .atomic_write(
            "state.json",
            Some(prior_state),
            &authenticated.event_bytes,
            gid,
        )
        .map_err(|_| MigrationError::Persistence("migration selector publication failed"))?;

    let config_dir =
        crate::recovery_files::ProtectedDirectory::open_root_installer(Path::new("/etc/o3k"))
            .map_err(|_| reject("installation policy directory is unsafe"))?;
    config_dir
        .atomic_replace_installer(
            "installation-policy.json",
            prior_policy,
            &authenticated.policy_bytes,
            0,
            gid,
            0o640,
            0o640,
        )
        .map_err(|_| MigrationError::Persistence("v2 policy publication failed"))?;

    let v2_policy: selector::InstallationPolicyV2 =
        identity::decode_canonical(&authenticated.policy_bytes)
            .map_err(|_| reject("authenticated v2 policy cannot be decoded"))?;
    let high_water = identity::canonical(&selector::PolicyHighWaterV2 {
        format_epoch: 2,
        revision: v2_policy.policy_revision,
        digest: authenticated.policy_digest.clone(),
    })
    .map_err(|_| reject("v2 policy high-water cannot be encoded"))?;
    state_directory
        .atomic_write(
            "policy.json",
            Some(installed.migration_policy_high_water_bytes()),
            &high_water,
            gid,
        )
        .map_err(|_| MigrationError::Persistence("v2 policy high-water publication failed"))?;

    let old_release = read_root_input(Path::new("/usr/local/share/o3k/release-manifest.json"))?;
    if old_release != prior_manifest {
        return Err(reject(
            "installed release changed after migration preflight",
        ));
    }
    share_dir
        .atomic_replace_installer(
            "release-manifest.json",
            &old_release,
            &authenticated.manifest_bytes,
            0,
            0,
            0o644,
            0o644,
        )
        .map_err(|_| MigrationError::Persistence("target release publication failed"))?;

    // The active release inventory follows the selector, policy, high-water
    // and exact manifest. It is not a selector or recovery authority.
    let old_sums = read_root_input(Path::new("/usr/local/share/o3k/SHA256SUMS"))?;
    let old_sums_name = format!(
        "release-sums-{}.txt",
        hex::encode(Sha256::digest(prior_manifest))
    );
    let archived_sums = installed
        .migration_state_directory()
        .read_bounded(&old_sums_name, 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| reject("authenticated predecessor checksum inventory is unavailable"))?;
    if old_sums != archived_sums && old_sums != candidate_sums {
        return Err(reject(
            "installed release checksums conflict with both generations",
        ));
    }
    if old_sums != candidate_sums {
        share_dir
            .atomic_replace_installer("SHA256SUMS", &old_sums, candidate_sums, 0, 0, 0o644, 0o644)
            .map_err(|_| MigrationError::Persistence("release checksums publication failed"))?;
    }

    let (backend, preserved) = crate::recovery_installation::verify_v2_selected_generation(
        Path::new("/var/lib/o3k"),
        &authenticated.manifest_bytes,
        &authenticated.policy_bytes,
    )
    .map_err(|_| MigrationError::Persistence("complete v2 generation verification failed"))?;
    if backend != "postgresql" || preserved != installed.preserved_state() {
        return Err(reject(
            "final v2 generation changed installation disposition",
        ));
    }
    let _ = prior_sequence;
    Ok(())
}

fn stage_authority_documents(
    installed: &InstalledRecovery,
    authenticated: &AuthenticatedMigration,
    candidate_artifact: &Path,
) -> Result<(), MigrationError> {
    let (_, gid) = service_identity().map_err(|_| reject("o3k service identity is unavailable"))?;
    let (_, prior_digest, prior_state, prior_policy, prior_manifest) =
        installed.migration_predecessor();
    let prior_policy_digest = installed.policy_digest.as_str();
    let prior_manifest_digest = hex::encode(Sha256::digest(prior_manifest));
    let state_directory = installed.migration_state_directory();
    for (name, bytes) in [
        (format!("state-{prior_digest}.json"), prior_state),
        (format!("policy-{prior_policy_digest}.json"), prior_policy),
        (
            format!("release-{prior_manifest_digest}.json"),
            prior_manifest,
        ),
        (
            format!("policy-high-water-{prior_policy_digest}.json"),
            installed.migration_policy_high_water_bytes(),
        ),
        (
            format!("migration-v2-event-{}.json", authenticated.sequence),
            authenticated.event_bytes.as_slice(),
        ),
        (
            format!("migration-v2-policy-{}.json", authenticated.policy_digest),
            authenticated.policy_bytes.as_slice(),
        ),
        (
            format!(
                "migration-v2-release-{}.json",
                authenticated.manifest_digest
            ),
            authenticated.manifest_bytes.as_slice(),
        ),
    ] {
        stage_exact(state_directory, &name, bytes, gid)?;
    }
    state_directory
        .stage_root_artifact(
            &format!(
                "migration-v2-artifact-{}.tar.gz",
                authenticated.artifact_digest
            ),
            candidate_artifact,
            &authenticated.artifact_digest,
            gid,
            MAX_CANDIDATE_ARTIFACT,
        )
        .map_err(|_| MigrationError::Persistence("candidate artifact staging failed"))
}

/// Preserve the original checksum list before replacing installed programs.
/// A retry with the v1 selector can then distinguish exact old bytes from the
/// authenticated candidate after interruption during per-file replacement.
fn observed_source_release_sums(
    installed: &InstalledRecovery,
) -> Result<(String, Vec<u8>), MigrationError> {
    let (_, gid) = service_identity().map_err(|_| reject("o3k service identity is unavailable"))?;
    let (_, _, _, _, manifest) = installed.migration_predecessor();
    let name = format!("release-sums-{}.txt", hex::encode(Sha256::digest(manifest)));
    let state_directory = installed.migration_state_directory();
    if let Ok(bytes) = state_directory.read_bounded(&name, 0, gid, 0o640, MAX_INPUT as usize) {
        parse_release_sums(&bytes)?;
        return Ok((name, bytes));
    }
    let bytes = read_root_input(Path::new("/usr/local/share/o3k/SHA256SUMS"))?;
    parse_release_sums(&bytes)?;
    parse_release_sums(&bytes)?;
    Ok((name, bytes))
}

fn stage_exact(
    directory: &crate::recovery_files::ProtectedDirectory,
    name: &str,
    bytes: &[u8],
    gid: u32,
) -> Result<(), MigrationError> {
    match directory.read_bounded(name, 0, gid, 0o640, MAX_INPUT as usize) {
        Ok(current) if current == bytes => Ok(()),
        Ok(_) => Err(reject(
            "inert migration input conflicts with authenticated bytes",
        )),
        Err(_) => directory
            .atomic_write(name, None, bytes, gid)
            .map_err(|_| MigrationError::Persistence("inert input staging failed")),
    }
}

fn parse_release_sums(
    bytes: &[u8],
) -> Result<std::collections::BTreeMap<String, String>, MigrationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| reject("release SHA256SUMS is not UTF-8"))?;
    let mut entries = std::collections::BTreeMap::new();
    for line in text.lines() {
        let mut columns = line.split_whitespace();
        let (Some(hash), Some(path)) = (columns.next(), columns.next()) else {
            return Err(reject("release SHA256SUMS entry is malformed"));
        };
        if columns.next().is_some()
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !path.starts_with("./")
            || path.contains("..")
            || entries.insert(path.to_owned(), hash.to_owned()).is_some()
        {
            return Err(reject("release SHA256SUMS contains an unsafe entry"));
        }
    }
    Ok(entries)
}

fn ensure_root_directories(root: &Path, directory: &Path) -> Result<(), MigrationError> {
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| reject("candidate extraction escaped staging"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(reject("candidate extraction path is unsafe"));
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| MigrationError::Persistence("candidate directory is unavailable"))?;
        if !metadata.is_dir() || metadata.uid() != 0 {
            return Err(reject(
                "candidate extraction parent is not a root directory",
            ));
        }
    }
    Ok(())
}

fn walk_regular_files(root: &Path) -> Result<Vec<PathBuf>, MigrationError> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|_| MigrationError::Input("candidate tree cannot be listed"))?
        {
            let entry =
                entry.map_err(|_| MigrationError::Input("candidate entry is unavailable"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| MigrationError::Input("candidate entry metadata is unavailable"))?;
            if metadata.uid() != 0 || metadata.file_type().is_symlink() {
                return Err(reject("candidate tree contains a substituted entry"));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() && metadata.nlink() == 1 {
                files.push(entry.path());
            } else {
                return Err(reject("candidate tree contains a special file"));
            }
        }
    }
    Ok(files)
}

fn walk_directories(root: &Path) -> Result<Vec<PathBuf>, MigrationError> {
    let mut directories = vec![root.to_path_buf()];
    for entry in
        fs::read_dir(root).map_err(|_| MigrationError::Input("candidate tree cannot be listed"))?
    {
        let entry = entry.map_err(|_| MigrationError::Input("candidate entry is unavailable"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| MigrationError::Input("candidate entry metadata is unavailable"))?;
        if metadata.is_dir() && metadata.uid() == 0 {
            directories.extend(walk_directories(&entry.path())?);
        }
    }
    Ok(directories)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationPosition {
    /// No migration selector committed. The original v1 generation is exact.
    V1Intact,
    /// The event is authoritative and one or more exact target files remain
    /// to be published. Consumers must deny operation until completion.
    V2ExactForward,
    /// The signed selector and every target document are byte-exact.
    V2Complete,
    /// Conflicting, missing, or equivocal bytes; mutation is forbidden.
    Deny,
}

#[derive(Debug, Clone, Copy)]
struct ServicePosture {
    unit: &'static str,
    was_active: bool,
    was_masked: bool,
}

/// Classifies a restart observation without guessing at a syscall's outcome.
/// `state.json` is the selector: an exact migration event makes v2
/// authoritative even if the prior process did not observe directory fsync.
/// Once selected, each other active document must be either the exact v1
/// predecessor or exact signed target bytes.
#[allow(clippy::too_many_arguments)]
pub fn classify_publication(
    active_state: Option<&[u8]>,
    active_policy: Option<&[u8]>,
    active_high_water: Option<&[u8]>,
    active_manifest: Option<&[u8]>,
    old_state: &[u8],
    old_policy: &[u8],
    old_high_water: &[u8],
    old_manifest: &[u8],
    target_event: &[u8],
    target_policy: &[u8],
    target_high_water: &[u8],
    target_manifest: &[u8],
) -> PublicationPosition {
    let (Some(state), Some(policy), Some(high_water), Some(manifest)) = (
        active_state,
        active_policy,
        active_high_water,
        active_manifest,
    ) else {
        return PublicationPosition::Deny;
    };
    if state == old_state
        && policy == old_policy
        && high_water == old_high_water
        && manifest == old_manifest
    {
        return PublicationPosition::V1Intact;
    }
    if state != target_event
        || ![old_policy, target_policy].contains(&policy)
        || ![old_high_water, target_high_water].contains(&high_water)
        || ![old_manifest, target_manifest].contains(&manifest)
    {
        return PublicationPosition::Deny;
    }
    if policy == target_policy && high_water == target_high_water && manifest == target_manifest {
        PublicationPosition::V2Complete
    } else {
        PublicationPosition::V2ExactForward
    }
}

fn reject(reason: &'static str) -> MigrationError {
    MigrationError::Rejected(reason)
}

fn read_root_input(path: &Path) -> Result<Vec<u8>, MigrationError> {
    read_root_file(path, MAX_INPUT)
}

fn read_root_file(path: &Path, maximum: u64) -> Result<Vec<u8>, MigrationError> {
    use rustix::fs::{Mode, OFlags, fstat, open};

    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(MigrationError::Input("signed input path is not absolute"));
    }
    crate::recovery_files::check_ancestors(path)
        .map_err(|_| MigrationError::Input("signed input ancestor path is unsafe"))?;
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| MigrationError::Input("signed input cannot be opened safely"))?;
    let before = fstat(&descriptor)
        .map_err(|_| MigrationError::Input("signed input metadata is unavailable"))?;
    if before.st_mode & 0o170000 != 0o100000
        || before.st_nlink != 1
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_size < 0
        || before.st_size as u64 > maximum
    {
        return Err(MigrationError::Input(
            "signed input is not a bounded root-owned regular file",
        ));
    }
    let file = fs::File::from(descriptor);
    let mut bytes = Vec::new();
    (&file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| MigrationError::Input("signed input read failed"))?;
    let after = file
        .metadata()
        .map_err(|_| MigrationError::Input("signed input readback failed"))?;
    if bytes.len() as u64 > maximum
        || before.st_dev != after.dev()
        || before.st_ino != after.ino()
        || before.st_size as u64 != after.len()
        || after.mtime() < 0
        || after.ctime() < 0
        || before.st_mtime != after.mtime() as u64
        || before.st_ctime != after.ctime() as u64
    {
        return Err(MigrationError::Input("signed input changed during read"));
    }
    Ok(bytes)
}

/// Hashes a bounded root-owned artifact through a no-follow descriptor. The
/// path and opened inode are checked before and after the read so replacing a
/// pathname cannot substitute a different candidate during authentication.
fn digest_root_artifact(path: &Path) -> Result<String, MigrationError> {
    use rustix::fs::{Mode, OFlags, fstat, open};

    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(MigrationError::Input(
            "candidate artifact path is not absolute",
        ));
    }
    crate::recovery_files::check_ancestors(path)
        .map_err(|_| MigrationError::Input("candidate artifact ancestor path is unsafe"))?;
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| MigrationError::Input("candidate artifact cannot be opened safely"))?;
    let before = fstat(&descriptor)
        .map_err(|_| MigrationError::Input("candidate artifact metadata is unavailable"))?;
    if before.st_mode & 0o170000 != 0o100000
        || before.st_nlink != 1
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_size <= 0
        || before.st_size as u64 > MAX_CANDIDATE_ARTIFACT
    {
        return Err(MigrationError::Input(
            "candidate artifact is not a bounded root-owned regular file",
        ));
    }
    let file = fs::File::from(descriptor);
    let mut hash = Sha256::new();
    let mut reader = (&file).take(MAX_CANDIDATE_ARTIFACT + 1);
    let mut buffer = [0; 64 * 1024];
    let mut size = 0u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| MigrationError::Input("candidate artifact read failed"))?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > MAX_CANDIDATE_ARTIFACT {
            return Err(MigrationError::Input("candidate artifact is too large"));
        }
        hash.update(&buffer[..count]);
    }
    let after = file
        .metadata()
        .map_err(|_| MigrationError::Input("candidate artifact readback failed"))?;
    if before.st_dev != after.dev()
        || before.st_ino != after.ino()
        || before.st_size as u64 != size
        || after.mtime() < 0
        || after.ctime() < 0
        || before.st_mtime != after.mtime() as u64
        || before.st_ctime != after.ctime() as u64
    {
        return Err(MigrationError::Input(
            "candidate artifact changed during read",
        ));
    }
    Ok(hex::encode(hash.finalize()))
}

fn policy_key(public_key: &str) -> Result<VerifyingKey, MigrationError> {
    let bytes: [u8; 32] = hex::decode(public_key)
        .map_err(|_| reject("installation-policy signer key is malformed"))?
        .try_into()
        .map_err(|_| reject("installation-policy signer key has the wrong length"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| reject("installation-policy signer key is invalid"))
}

/// Verifies the release operator's detached Ed25519 provenance signature with
/// the public key pinned in this source tree, then binds the exact candidate
/// archive, bundle manifest and checksum inventory to that signed statement.
/// The policy signer alone cannot substitute a different release artifact.
fn verify_target_release_provenance(
    inputs: &MigrationInputs<'_>,
    release: &BackupReleaseIdentity,
    installed_manifest: &[u8],
    artifact_digest: &str,
) -> Result<Vec<u8>, MigrationError> {
    use flate2::read::GzDecoder;
    use std::collections::BTreeMap;

    let digests = read_root_input(inputs.release_digests)?;
    let signature = read_root_input(inputs.release_signature)?;
    verify_release_signature(
        &digests,
        &signature,
        include_bytes!("../../../packaging/release-verify.pub"),
    )?;

    let mut signed_assets = BTreeMap::new();
    for line in std::str::from_utf8(&digests)
        .map_err(|_| reject("release digest statement is not UTF-8"))?
        .lines()
    {
        let mut columns = line.split_whitespace();
        let (Some(digest), Some(path)) = (columns.next(), columns.next()) else {
            return Err(reject("release digest statement is malformed"));
        };
        if columns.next().is_some()
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || signed_assets
                .insert(path.to_owned(), digest.to_owned())
                .is_some()
        {
            return Err(reject("release digest statement has invalid entries"));
        }
    }
    let version = release
        .o3k_version
        .strip_prefix('v')
        .unwrap_or(&release.o3k_version);
    let bundle = format!("o3k-{version}");
    let archive_name = format!("{bundle}-linux-x86_64.tar.gz");
    let required = [
        "install.sh".to_owned(),
        archive_name.clone(),
        format!("{archive_name}.sha256"),
        format!("{bundle}/manifest.json"),
        format!("{bundle}/SHA256SUMS"),
        format!("{bundle}/sbom.spdx.json"),
    ];
    if signed_assets.len() != required.len()
        || required
            .iter()
            .any(|name| !signed_assets.contains_key(name))
    {
        return Err(reject(
            "release digest statement has an unexpected asset set",
        ));
    }
    let signed_archive_digest = signed_assets
        .get(&archive_name)
        .ok_or_else(|| reject("release provenance omits the candidate archive"))?;
    if signed_archive_digest != artifact_digest {
        return Err(reject(
            "signed release digest differs from candidate artifact",
        ));
    }

    let mut archive = tar::Archive::new(GzDecoder::new(
        fs::File::open(inputs.candidate_artifact)
            .map_err(|_| MigrationError::Input("candidate artifact cannot be reopened"))?,
    ));
    let mut raw_manifest = None;
    let mut candidate_sums = None;
    for entry in archive
        .entries()
        .map_err(|_| reject("signed release archive is malformed"))?
    {
        let entry = entry.map_err(|_| reject("signed release archive entry is malformed"))?;
        let name = entry
            .path()
            .map_err(|_| reject("signed release archive path is malformed"))?
            .to_string_lossy()
            .into_owned();
        if name == format!("{bundle}/manifest.json") {
            let mut bytes = Vec::new();
            entry
                .take(MAX_INPUT + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| reject("signed release manifest cannot be read"))?;
            if bytes.len() as u64 > MAX_INPUT || raw_manifest.replace(bytes).is_some() {
                return Err(reject("signed release manifest is oversized or duplicated"));
            }
        } else if name == format!("{bundle}/SHA256SUMS") {
            let mut bytes = Vec::new();
            entry
                .take(MAX_INPUT + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| reject("signed release checksums cannot be read"))?;
            if bytes.len() as u64 > MAX_INPUT || candidate_sums.replace(bytes).is_some() {
                return Err(reject(
                    "signed release checksums are oversized or duplicated",
                ));
            }
        }
    }
    let raw_manifest = raw_manifest.ok_or_else(|| reject("signed bundle manifest is absent"))?;
    let candidate_sums = candidate_sums.ok_or_else(|| reject("signed checksums are absent"))?;
    for (path, bytes) in [
        (format!("{bundle}/manifest.json"), raw_manifest.as_slice()),
        (format!("{bundle}/SHA256SUMS"), candidate_sums.as_slice()),
    ] {
        let expected = signed_assets
            .get(&path)
            .ok_or_else(|| reject("release provenance omits a required bundle file"))?;
        if hex::encode(Sha256::digest(bytes)) != *expected {
            return Err(reject(
                "release provenance does not authenticate bundle bytes",
            ));
        }
    }
    let augmented = crate::upgrade::release_identity::manifest_with_verified_artifact(
        &raw_manifest,
        artifact_digest,
    )
    .map_err(|_| reject("release-signed manifest is invalid"))?;
    if augmented != installed_manifest {
        return Err(reject(
            "target manifest is not the exact installed form of the signed bundle manifest",
        ));
    }
    Ok(candidate_sums)
}

fn verify_source_release_provenance(
    inputs: &MigrationInputs<'_>,
    release: &BackupReleaseIdentity,
    installed_manifest: &[u8],
    installed_sums: &[u8],
) -> Result<SourceReleaseProvenance, MigrationError> {
    use std::collections::BTreeMap;

    let raw_manifest = read_root_input(inputs.source_manifest)?;
    let digests = read_root_input(inputs.source_release_digests)?;
    let signature = read_root_input(inputs.source_release_signature)?;
    verify_release_signature(
        &digests,
        &signature,
        include_bytes!("../../../packaging/release-verify.pub"),
    )?;
    let mut signed_assets = BTreeMap::new();
    for line in std::str::from_utf8(&digests)
        .map_err(|_| reject("source release digest statement is not UTF-8"))?
        .lines()
    {
        let mut columns = line.split_whitespace();
        let (Some(digest), Some(path)) = (columns.next(), columns.next()) else {
            return Err(reject("source release digest statement is malformed"));
        };
        if columns.next().is_some()
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || signed_assets
                .insert(path.to_owned(), digest.to_owned())
                .is_some()
        {
            return Err(reject(
                "source release digest statement has invalid entries",
            ));
        }
    }
    let version = release
        .o3k_version
        .strip_prefix('v')
        .unwrap_or(&release.o3k_version);
    let bundle = format!("o3k-{version}");
    let archive_name = format!("{bundle}-linux-x86_64.tar.gz");
    let required = [
        "install.sh".to_owned(),
        archive_name.clone(),
        format!("{archive_name}.sha256"),
        format!("{bundle}/manifest.json"),
        format!("{bundle}/SHA256SUMS"),
        format!("{bundle}/sbom.spdx.json"),
    ];
    if signed_assets.len() != required.len()
        || required
            .iter()
            .any(|name| !signed_assets.contains_key(name))
    {
        return Err(reject("source release has an unexpected signed asset set"));
    }
    let artifact_digest = &release.release_artifact_sha256;
    if signed_assets.get(&archive_name) != Some(artifact_digest)
        || signed_assets.get(&format!("{bundle}/SHA256SUMS"))
            != Some(&hex::encode(Sha256::digest(installed_sums)))
        || signed_assets.get(&format!("{bundle}/manifest.json"))
            != Some(&hex::encode(Sha256::digest(&raw_manifest)))
    {
        return Err(reject(
            "source release provenance does not authenticate installed release metadata",
        ));
    }
    let augmented = crate::upgrade::release_identity::manifest_with_verified_artifact(
        &raw_manifest,
        artifact_digest,
    )
    .map_err(|_| reject("source release-signed manifest is invalid"))?;
    if augmented != installed_manifest {
        return Err(reject(
            "installed source manifest differs from signed release bytes",
        ));
    }
    Ok(SourceReleaseProvenance {
        manifest: raw_manifest,
        digests,
        signature,
    })
}

fn verify_release_signature(
    digests: &[u8],
    signature: &[u8],
    public_key_pem: &[u8],
) -> Result<(), MigrationError> {
    use openssl::{pkey::PKey, sign::Verifier};

    let public_key = PKey::public_key_from_pem(public_key_pem)
        .map_err(|_| reject("pinned release verification key is invalid"))?;
    let mut verifier = Verifier::new_without_digest(&public_key)
        .map_err(|_| reject("release signature verifier is unavailable"))?;
    if verifier
        .verify_oneshot(signature, digests)
        .map_err(|_| reject("release signature verification failed"))?
    {
        Ok(())
    } else {
        Err(reject("release provenance signature is invalid"))
    }
}

/// Authenticates a candidate migration entirely before mutation. `load`
/// authenticates the full installed v1 state chain, trust/high-water, release,
/// and C1.1 checkpoint where required. A v2 journal cannot be admitted by the
/// v1 predecessor verifier and therefore cannot be rotated here.
pub fn authenticate_inputs(
    data_dir: &Path,
    inputs: &MigrationInputs<'_>,
) -> Result<AuthenticatedMigration, MigrationError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(MigrationError::RootRequired);
    }
    if data_dir != Path::new("/var/lib/o3k") {
        return Err(reject("publisher requires the fixed installed data root"));
    }

    let installed = InstalledRecovery::load(data_dir)
        .map_err(|_| reject("complete authenticated v1 installation is unavailable"))?;
    let (prior_sequence, prior_tip_digest, _prior_tip, prior_policy_bytes, prior_manifest_bytes) =
        installed.migration_predecessor();
    if installed.policy.format != "o3k-installation-policy-v1"
        || installed.policy.policy_revision == u64::MAX
    {
        return Err(reject("source policy is not a migratable v1 generation"));
    }

    let prior_authority = BackupReleaseIdentity::c1_authority_from_manifest(prior_manifest_bytes)
        .map_err(|_| reject("source release policy authority is invalid"))?;
    let prior_release = BackupReleaseIdentity::from_manifest_bytes(prior_manifest_bytes)
        .map_err(|_| reject("source release identity is invalid"))?;
    let source_sums = read_root_input(Path::new("/usr/local/share/o3k/SHA256SUMS"))?;
    parse_release_sums(&source_sums)?;
    let source_provenance = verify_source_release_provenance(
        inputs,
        &prior_release,
        prior_manifest_bytes,
        &source_sums,
    )?;
    let policy_bytes = read_root_input(inputs.policy_v2)?;
    let event_bytes = read_root_input(inputs.migration_event)?;
    let manifest_bytes = read_root_input(inputs.release_manifest_v2)?;
    let artifact_digest = digest_root_artifact(inputs.candidate_artifact)?;
    let prior_manifest_digest = hex::encode(Sha256::digest(prior_manifest_bytes));
    let manifest_digest = hex::encode(Sha256::digest(&manifest_bytes));
    let new_authority = BackupReleaseIdentity::c1_authority_from_manifest(&manifest_bytes)
        .map_err(|_| reject("target release v1 authority is missing"))?;
    let new_v2_authority = BackupReleaseIdentity::c1_v2_authority_from_manifest(&manifest_bytes)
        .map_err(|_| reject("target release v2 authority is missing"))?;
    let release = BackupReleaseIdentity::from_manifest_bytes(&manifest_bytes)
        .map_err(|_| reject("target release identity is invalid"))?;
    let candidate_sums = verify_target_release_provenance(
        inputs,
        &release,
        &manifest_bytes,
        artifact_digest.as_str(),
    )?;
    if prior_authority.key_id != new_authority.key_id
        || prior_authority.ed25519_public_key != new_authority.ed25519_public_key
        || new_authority.key_id != new_v2_authority.key_id
        || new_authority.ed25519_public_key != new_v2_authority.ed25519_public_key
        || new_authority.policy_path != new_v2_authority.policy_path
    {
        return Err(reject(
            "policy signer or fixed path changed during migration",
        ));
    }
    let key = policy_key(&new_v2_authority.ed25519_public_key)?;
    if release.release_artifact_sha256 != artifact_digest {
        return Err(reject(
            "candidate artifact digest does not match the authenticated release",
        ));
    }
    let policy = selector::verify_v2_policy(
        &policy_bytes,
        &new_v2_authority.key_id,
        &key,
        &manifest_digest,
        &release.release_artifact_sha256,
        &release.o3k_version,
        &release.source_sha,
    )
    .map_err(|_| reject("target v2 policy signature or binding is invalid"))?;
    let policy_digest = hex::encode(Sha256::digest(&policy_bytes));
    let trust: identity::TrustBundle =
        identity::decode_canonical(installed.migration_trust_bundle_bytes())
            .map_err(|_| reject("source trust bundle is malformed"))?;
    let trust_digest = identity::digest(&trust)
        .map_err(|_| reject("source trust bundle digest cannot be computed"))?;
    if policy.installation_id != installed.policy.installation_id
        || policy.site_id != installed.policy.site_id
        || policy.profile != installed.policy.profile
        || policy.backend != installed.policy.backend
        || policy.data_root != installed.policy.data_root
        || policy.target_device != installed.policy.target_device
        || policy.target_inode != installed.policy.target_inode
        || policy.policy_path != installed.policy.policy_path
        || policy.trust_bundle_path != installed.policy.trust_bundle_path
        || policy.trust_bundle_digest != installed.policy.trust_bundle_digest
        || policy.recovery_state_root != installed.policy.recovery_state_root
        || policy.recovery_state_device != installed.policy.recovery_state_device
        || policy.recovery_state_inode != installed.policy.recovery_state_inode
        || policy.journal_directory != installed.policy.journal_directory
        || policy.journal_device != installed.policy.journal_device
        || policy.journal_inode != installed.policy.journal_inode
        || policy.journal_trust_root_id != installed.policy.journal_trust_root_id
        || policy.journal_trust_root_public_key != installed.policy.journal_trust_root_public_key
        || policy.evidence_trust_root_id != installed.policy.evidence_trust_root_id
        || policy.evidence_trust_root_public_key != installed.policy.evidence_trust_root_public_key
        || policy.signer_key_id != installed.policy.signer_key_id
        || policy.prior_policy_digest != installed.policy_digest
        || policy.policy_revision != installed.policy.policy_revision + 1
        || installed.policy.trust_bundle_digest != trust_digest
    {
        return Err(reject(
            "target policy changes a protected installation binding",
        ));
    }

    let migration = selector::verify_migration(
        &event_bytes,
        &new_v2_authority.key_id,
        &key,
        &selector::MigrationBindings {
            prior_sequence,
            prior_tip_digest,
            prior_policy_digest: &installed.policy_digest,
            prior_policy_revision: installed.policy.policy_revision,
            new_policy_digest: &policy_digest,
            prior_manifest_digest: &prior_manifest_digest,
            new_manifest_digest: &manifest_digest,
            target_device: installed.policy.target_device,
            target_inode: installed.policy.target_inode,
            trust_digest: &installed.policy.trust_bundle_digest,
        },
    )
    .map_err(|_| reject("migration event signature or predecessor binding is invalid"))?;
    selector::verify_migration_identity(
        &migration,
        &installed.policy.installation_id,
        &installed.policy.site_id,
        installed.preserved_state(),
    )
    .map_err(|_| reject("migration event changes installation or recovery state"))?;
    let prior_identity = selector::ReleaseIdentity {
        version: prior_release.o3k_version,
        source_commit: prior_release.source_sha,
        release_artifact_sha256: prior_release.release_artifact_sha256,
        profile_id: prior_release.profile_id,
        schema_version: prior_release.schema_version,
    };
    let target_identity = selector::ReleaseIdentity {
        version: release.o3k_version.clone(),
        source_commit: release.source_sha,
        release_artifact_sha256: release.release_artifact_sha256,
        profile_id: release.profile_id,
        schema_version: release.schema_version,
    };
    if migration.prior_release_identity != prior_identity
        || migration.new_release_identity != target_identity
    {
        return Err(reject(
            "migration event release identities do not match manifests",
        ));
    }
    let expected_checkpoint = installed.migration_checkpoint_digest();
    if migration.checkpoint_digest != expected_checkpoint {
        return Err(reject(
            "migration event does not bind the authenticated C1.1 checkpoint",
        ));
    }
    // Touch the exact source policy bytes so the compiler and future code
    // changes keep the authenticated predecessor explicit at this boundary.
    if hex::encode(Sha256::digest(prior_policy_bytes)) != installed.policy_digest {
        return Err(reject(
            "authenticated source policy changed during preflight",
        ));
    }
    let _ = service_identity().map_err(|_| reject("o3k service identity is unavailable"))?;
    Ok(AuthenticatedMigration {
        policy_bytes,
        event_bytes,
        manifest_bytes,
        policy_digest,
        manifest_digest,
        artifact_digest,
        release_version: release.o3k_version,
        sequence: migration.sequence,
        candidate_sums,
        release_digests: read_root_input(inputs.release_digests)?,
        release_signature: read_root_input(inputs.release_signature)?,
        source_manifest: source_provenance.manifest,
        source_release_digests: source_provenance.digests,
        source_release_signature: source_provenance.signature,
    })
}

/// Executes the root-authorized migration from a complete installed v1
/// generation. All signature, release, predecessor, trust and artifact
/// checks run before compute or service state changes. A failed or interrupted
/// attempt leaves compute denied and all affected units masked.
pub fn publish_v2(inputs: &MigrationInputs<'_>) -> Result<PublicationPosition, MigrationError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(MigrationError::RootRequired);
    }
    let data_dir = Path::new("/var/lib/o3k");
    if let Some(position) = resume_selected_v2(inputs)? {
        return Ok(position);
    }
    let installed = match InstalledRecovery::load(data_dir) {
        Ok(installed) => installed,
        Err(_) => {
            return Err(reject(
                "complete authenticated v1 installation is unavailable",
            ));
        }
    };
    let authenticated = authenticate_inputs(data_dir, inputs)?;
    if installed.policy.profile != "o3k-small-edge-v1"
        || installed.policy.backend != "postgresql"
        || !matches!(
            installed.preserved_state(),
            identity::RecoveryState::NeverRecovered
                | identity::RecoveryState::RecoveryDesignated
                | identity::RecoveryState::Released
        )
    {
        return Err(reject(
            "source installation is outside accepted A10.1 profiles",
        ));
    }
    let (old_sums_name, old_sums) = observed_source_release_sums(&installed)?;
    if read_root_input(Path::new("/usr/local/share/o3k/SHA256SUMS"))? != old_sums {
        return Err(reject(
            "active source checksum inventory differs from authenticated predecessor",
        ));
    }
    verify_prepublication_executables(&old_sums, &authenticated.candidate_sums)?;
    let _upgrade_guard = acquire_upgrade_exclusion()?;
    let service_posture = snapshot_service_posture()?;
    let executable_inodes = installed_executable_inodes()?;
    let compute_identity = disable_compute_executable()?;
    if !executable_inodes.contains(&compute_identity) {
        return Err(reject(
            "compute executable identity changed during preparation",
        ));
    }
    mask_and_quiesce_services()?;
    // SPEC-0050 D8-A10-15 requires refusing D8 acquisition if an installed
    // executable still has a process; repeat under the guard to close the
    // direct-start race between this observation and lock acquisition.
    verify_process_quiescence(&executable_inodes)?;

    // This is the same process-held data-directory guard used by o3kd and
    // backup/upgrade operations. Protected state and journal directory locks
    // below exclude root maintenance/signing writers which do not open the
    // canonical store. The selector remains the reboot-persistent authority.
    let store_guard = o3k_store::StoreAccessLock::acquire_read_only(data_dir)
        .map_err(|_| reject("D8 store exclusion could not be acquired"))?;
    installed
        .migration_state_directory()
        .lock()
        .map_err(|_| reject("protected installation-state exclusion is busy"))?;
    installed
        .migration_lock_journal_directory()
        .map_err(|_| reject("recovery-journal exclusion is busy"))?;
    let (uid, gid) =
        service_identity().map_err(|_| reject("o3k service identity is unavailable"))?;
    installed
        .strict_pending_signing_request_exclusion(uid, gid)
        .map_err(|_| reject("pending signing request or reservation blocks migration"))?;
    verify_process_quiescence(&executable_inodes)?;
    let (_, gid) = service_identity().map_err(|_| reject("o3k service identity is unavailable"))?;
    stage_exact(
        installed.migration_state_directory(),
        &old_sums_name,
        &old_sums,
        gid,
    )?;

    let stage_name = format!(
        ".a10-candidate-{}-{}-{}",
        authenticated.artifact_digest,
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let stage_root = installed
        .migration_state_directory()
        .path()
        .join(&stage_name);
    let mut builder = fs::DirBuilder::new();
    use std::os::unix::fs::DirBuilderExt;
    builder.mode(0o700);
    builder
        .create(&stage_root)
        .map_err(|_| MigrationError::Persistence("candidate staging directory creation failed"))?;
    fs::File::open(installed.migration_state_directory().path())
        .and_then(|directory| directory.sync_all())
        .map_err(|_| MigrationError::Persistence("candidate staging parent sync failed"))?;
    let bundle =
        extract_verified_candidate(inputs.candidate_artifact, &authenticated, &stage_root)?;
    let candidate_sums = fs::read(bundle.join("SHA256SUMS"))
        .map_err(|_| reject("candidate SHA256SUMS is unavailable"))?;
    if candidate_sums != authenticated.candidate_sums {
        return Err(reject(
            "candidate checksums differ from signed release provenance",
        ));
    }

    stage_authority_documents(&installed, &authenticated, inputs.candidate_artifact)?;
    replace_dual_verifiers(&bundle, &old_sums)?;
    verify_dual_verifiers(&bundle, false)?;
    publish_documents_selector_first(
        &installed,
        &authenticated,
        &candidate_sums,
        inputs.candidate_artifact,
    )?;
    verify_dual_verifiers(&bundle, false)?;
    if installed.preserved_state() != identity::RecoveryState::NeverRecovered {
        // C1 disposition is still denial authority. Leave all affected units
        // masked and compute non-executable even though migration itself
        // authenticated successfully.
        drop(store_guard);
        return Ok(PublicationPosition::V2Complete);
    }

    // Services are restored only after complete-generation readback. The
    // D8 guard is released before any service can attempt store access.
    drop(installed);
    drop(store_guard);
    enable_compute_executable()?;
    verify_dual_verifiers(&bundle, true)?;
    run_systemctl(&["daemon-reload"])?;
    restore_service_posture(&service_posture)?;
    Ok(PublicationPosition::V2Complete)
}

/// Resume only from the exact event and target bytes durably staged before the
/// selector rename. Caller-supplied retry paths are deliberately ignored once
/// the v2 selector is active.
fn resume_selected_v2(
    inputs: &MigrationInputs<'_>,
) -> Result<Option<PublicationPosition>, MigrationError> {
    use crate::recovery_files::ProtectedDirectory;

    let data_dir = Path::new("/var/lib/o3k");
    let active_policy_bytes = read_root_input(Path::new("/etc/o3k/installation-policy.json"))?;
    let active_signed: identity::Signed<serde_json::Value> =
        identity::decode_canonical(&active_policy_bytes)
            .map_err(|_| reject("active installation policy is malformed"))?;
    let payload = active_signed.payload;
    let state_root = payload
        .get("recovery_state_root")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| reject("active installation policy has no protected state path"))?;
    let state_device = payload
        .get("recovery_state_device")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| reject("active installation policy has no protected state device"))?;
    let state_inode = payload
        .get("recovery_state_inode")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| reject("active installation policy has no protected state inode"))?;
    let (_, gid) = service_identity().map_err(|_| reject("o3k service identity is unavailable"))?;
    let state_directory = ProtectedDirectory::open(
        Path::new(state_root),
        0,
        gid,
        0o750,
        state_device,
        state_inode,
    )
    .map_err(|_| reject("active protected selector directory is unavailable"))?;
    let selector_bytes = state_directory
        .read_bounded("state.json", 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| reject("active installation selector is unavailable"))?;
    let selector_value: identity::Signed<serde_json::Value> =
        identity::decode_canonical(&selector_bytes)
            .map_err(|_| reject("active installation selector is malformed"))?;
    if selector_value
        .payload
        .get("format")
        .and_then(serde_json::Value::as_str)
        != Some(selector::MIGRATION_FORMAT)
    {
        return Ok(None);
    }
    if read_root_input(inputs.migration_event)? != selector_bytes {
        return Err(reject("retry migration event differs from active selector"));
    }
    let migration: identity::Signed<selector::InstallationPolicyMigrationV1> =
        identity::decode_canonical(&selector_bytes)
            .map_err(|_| reject("active migration selector is malformed"))?;
    let migration = migration.payload;
    let target_manifest_name = format!(
        "migration-v2-release-{}.json",
        migration.new_release_manifest_sha256
    );
    let target_manifest = state_directory
        .read_bounded(&target_manifest_name, 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| reject("exact staged target manifest is unavailable"))?;
    if hex::encode(Sha256::digest(&target_manifest)) != migration.new_release_manifest_sha256 {
        return Err(reject("staged target manifest digest changed"));
    }
    let target_authority = BackupReleaseIdentity::c1_v2_authority_from_manifest(&target_manifest)
        .map_err(|_| reject("staged target policy authority is invalid"))?;
    let target_key = policy_key(&target_authority.ed25519_public_key)?;
    let migration = selector::verify_migration(
        &selector_bytes,
        &target_authority.key_id,
        &target_key,
        &selector::MigrationBindings {
            prior_sequence: migration.sequence.saturating_sub(1),
            prior_tip_digest: &migration.prior_record_digest,
            prior_policy_digest: &migration.prior_policy_digest,
            prior_policy_revision: migration.prior_policy_revision,
            new_policy_digest: &migration.new_policy_digest,
            prior_manifest_digest: &migration.prior_release_manifest_sha256,
            new_manifest_digest: &migration.new_release_manifest_sha256,
            target_device: migration.target_device,
            target_inode: migration.target_inode,
            trust_digest: &migration.trust_bundle_digest,
        },
    )
    .map_err(|_| reject("active migration selector signature or binding is invalid"))?;
    let target_policy_name = format!("migration-v2-policy-{}.json", migration.new_policy_digest);
    let target_policy = state_directory
        .read_bounded(&target_policy_name, 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| reject("exact staged target policy is unavailable"))?;
    if hex::encode(Sha256::digest(&target_policy)) != migration.new_policy_digest {
        return Err(reject("staged target policy digest changed"));
    }
    if read_root_input(inputs.policy_v2)? != target_policy {
        return Err(reject("retry v2 policy differs from staged signed bytes"));
    }
    if read_root_input(inputs.release_manifest_v2)? != target_manifest {
        return Err(reject(
            "retry release manifest differs from staged signed bytes",
        ));
    }
    let policy = selector::verify_v2_policy(
        &target_policy,
        &target_authority.key_id,
        &target_key,
        &hex::encode(Sha256::digest(&target_manifest)),
        &BackupReleaseIdentity::from_manifest_bytes(&target_manifest)
            .map_err(|_| reject("staged target release identity is invalid"))?
            .release_artifact_sha256,
        &migration.new_release_identity.version,
        &migration.new_release_identity.source_commit,
    )
    .map_err(|_| reject("staged target policy signature or binding is invalid"))?;
    if migration.installation_id != policy.installation_id
        || migration.site_id != policy.site_id
        || migration.target_device != policy.target_device
        || migration.target_inode != policy.target_inode
    {
        return Err(reject("staged migration changes installation authority"));
    }
    let artifact_name = format!(
        "migration-v2-artifact-{}.tar.gz",
        migration.new_release_identity.release_artifact_sha256
    );
    let artifact = state_directory.path().join(artifact_name);
    let artifact_digest = digest_root_artifact(&artifact)?;
    if artifact_digest != migration.new_release_identity.release_artifact_sha256 {
        return Err(reject("staged candidate artifact digest changed"));
    }
    if digest_root_artifact(inputs.candidate_artifact)? != artifact_digest {
        return Err(reject(
            "retry candidate differs from staged authenticated artifact",
        ));
    }
    crate::recovery_installation::verify_v2_migration_predecessor(
        data_dir,
        &target_manifest,
        &target_policy,
    )
    .map_err(|_| reject("authenticated migration predecessor chain is invalid"))?;

    // Re-establish reboot-persistent and direct-execution denial before any
    // exact-forward writes. This path never replaces executable bytes.
    let _upgrade_guard = acquire_upgrade_exclusion()?;
    let executable_inodes = installed_executable_inodes()?;
    let compute_identity = disable_compute_executable()?;
    if !executable_inodes.contains(&compute_identity) {
        return Err(reject(
            "compute executable identity changed during preparation",
        ));
    }
    mask_and_quiesce_services()?;
    verify_process_quiescence(&executable_inodes)?;
    let store_guard = o3k_store::StoreAccessLock::acquire_read_only(data_dir)
        .map_err(|_| reject("D8 store exclusion could not be acquired"))?;
    state_directory
        .lock()
        .map_err(|_| reject("protected installation-state exclusion is busy"))?;
    let (service_uid, _) =
        service_identity().map_err(|_| reject("o3k service identity is unavailable"))?;
    let journal_directory = ProtectedDirectory::open(
        Path::new(&policy.journal_directory),
        service_uid,
        gid,
        0o700,
        policy.journal_device,
        policy.journal_inode,
    )
    .map_err(|_| reject("protected journal directory is unavailable"))?;
    journal_directory
        .lock()
        .map_err(|_| reject("recovery-journal exclusion is busy"))?;
    ensure_no_pending_signing(&journal_directory, service_uid, gid)?;
    verify_process_quiescence(&executable_inodes)?;

    let old_state_name = format!("state-{}.json", migration.prior_record_digest);
    let old_policy_name = format!("policy-{}.json", migration.prior_policy_digest);
    let old_release_name = format!("release-{}.json", migration.prior_release_manifest_sha256);
    let old_state = state_directory
        .read_bounded(&old_state_name, 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| reject("authenticated predecessor state archive is unavailable"))?;
    let old_policy = state_directory
        .read_bounded(&old_policy_name, 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| reject("authenticated predecessor policy archive is unavailable"))?;
    let old_release = state_directory
        .read_bounded(&old_release_name, 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| reject("authenticated predecessor release archive is unavailable"))?;
    let old_release_identity = BackupReleaseIdentity::from_manifest_bytes(&old_release)
        .map_err(|_| reject("authenticated predecessor release identity is invalid"))?;
    let old_sums_name = format!(
        "release-sums-{}.txt",
        migration.prior_release_manifest_sha256
    );
    let old_sums = state_directory
        .read_bounded(&old_sums_name, 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| reject("authenticated predecessor checksum inventory is unavailable"))?;
    verify_source_release_provenance(inputs, &old_release_identity, &old_release, &old_sums)?;
    let old_high_water_name = format!("policy-high-water-{}.json", migration.prior_policy_digest);
    let old_high_water = state_directory
        .read_bounded(&old_high_water_name, 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| reject("authenticated predecessor policy high-water is unavailable"))?;
    let high_water = identity::canonical(&selector::PolicyHighWaterV2 {
        format_epoch: 2,
        revision: policy.policy_revision,
        digest: migration.new_policy_digest.clone(),
    })
    .map_err(|_| reject("target v2 high-water cannot be encoded"))?;
    let active_state = state_directory
        .read_bounded("state.json", 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| reject("active migration selector is unavailable"))?;
    let active_policy = read_root_input(Path::new("/etc/o3k/installation-policy.json"))?;
    let active_high_water = state_directory
        .read_bounded("policy.json", 0, gid, 0o640, MAX_INPUT as usize)
        .ok();
    let active_manifest = read_root_input(Path::new("/usr/local/share/o3k/release-manifest.json"))?;
    let position = classify_publication(
        Some(&active_state),
        Some(&active_policy),
        active_high_water.as_deref(),
        Some(&active_manifest),
        &old_state,
        &old_policy,
        &old_high_water,
        &old_release,
        &selector_bytes,
        &target_policy,
        &high_water,
        &target_manifest,
    );
    if !matches!(
        position,
        PublicationPosition::V2ExactForward | PublicationPosition::V2Complete
    ) {
        return Err(reject(
            "active generation conflicts with exact-forward migration",
        ));
    }
    // The previous process may have died after renaming state.json but before
    // syncing its directory. Authenticate the observed selector above, then
    // make it durable again before publishing any later active document.
    fs::File::open(state_directory.path())
        .and_then(|directory| directory.sync_all())
        .map_err(|_| MigrationError::Persistence("migration selector directory sync failed"))?;
    let staged_root = state_directory.path().join(format!(
        ".a10-resume-{}-{}-{}",
        migration.new_policy_digest,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&staged_root)
        .map_err(|_| MigrationError::Persistence("exact-forward staging directory failed"))?;
    let release_digests = state_directory
        .read_bounded(
            &format!("migration-v2-release-digests-{artifact_digest}.txt"),
            0,
            gid,
            0o640,
            MAX_INPUT as usize,
        )
        .map_err(|_| reject("exact release provenance is not staged"))?;
    let release_signature = state_directory
        .read_bounded(
            &format!("migration-v2-release-signature-{artifact_digest}.sig"),
            0,
            gid,
            0o640,
            MAX_INPUT as usize,
        )
        .map_err(|_| reject("exact release signature is not staged"))?;
    if read_root_input(inputs.release_digests)? != release_digests
        || read_root_input(inputs.release_signature)? != release_signature
    {
        return Err(reject("retry release provenance differs from staged bytes"));
    }
    let source_manifest = state_directory
        .read_bounded(
            &format!(
                "migration-v1-source-manifest-{}.json",
                migration.new_release_manifest_sha256
            ),
            0,
            gid,
            0o640,
            MAX_INPUT as usize,
        )
        .map_err(|_| reject("exact source release manifest is not staged"))?;
    let source_release_digests = state_directory
        .read_bounded(
            &format!("migration-v1-source-digests-{artifact_digest}.txt"),
            0,
            gid,
            0o640,
            MAX_INPUT as usize,
        )
        .map_err(|_| reject("exact source release provenance is not staged"))?;
    let source_release_signature = state_directory
        .read_bounded(
            &format!("migration-v1-source-signature-{artifact_digest}.sig"),
            0,
            gid,
            0o640,
            MAX_INPUT as usize,
        )
        .map_err(|_| reject("exact source release signature is not staged"))?;
    if read_root_input(inputs.source_manifest)? != source_manifest
        || read_root_input(inputs.source_release_digests)? != source_release_digests
        || read_root_input(inputs.source_release_signature)? != source_release_signature
    {
        return Err(reject(
            "retry source release provenance differs from staged bytes",
        ));
    }
    let release_identity = BackupReleaseIdentity::from_manifest_bytes(&target_manifest)
        .map_err(|_| reject("staged target release identity is invalid"))?;
    let candidate_sums = verify_target_release_provenance(
        inputs,
        &release_identity,
        &target_manifest,
        &artifact_digest,
    )?;
    let authenticated = AuthenticatedMigration {
        policy_bytes: target_policy.clone(),
        event_bytes: selector_bytes.clone(),
        manifest_bytes: target_manifest.clone(),
        policy_digest: migration.new_policy_digest.clone(),
        manifest_digest: migration.new_release_manifest_sha256.clone(),
        artifact_digest,
        release_version: migration.new_release_identity.version.clone(),
        sequence: migration.sequence,
        candidate_sums: candidate_sums.clone(),
        release_digests,
        release_signature,
        source_manifest,
        source_release_digests,
        source_release_signature,
    };
    let bundle = extract_verified_candidate(&artifact, &authenticated, &staged_root)?;
    verify_dual_verifiers(&bundle, false)?;
    let extracted_sums = fs::read(bundle.join("SHA256SUMS"))
        .map_err(|_| reject("target release checksums are unavailable"))?;
    if extracted_sums != authenticated.candidate_sums {
        return Err(reject(
            "candidate checksum inventory differs from signed provenance",
        ));
    }
    let active_sums = read_root_input(Path::new("/usr/local/share/o3k/SHA256SUMS"))?;
    let old_sums_name = format!(
        "release-sums-{}.txt",
        migration.prior_release_manifest_sha256
    );
    let old_sums = state_directory
        .read_bounded(&old_sums_name, 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| reject("authenticated predecessor checksum inventory is unavailable"))?;
    if active_sums != old_sums && active_sums != extracted_sums {
        return Err(reject(
            "installed release checksums conflict with both generations",
        ));
    }
    let config = ProtectedDirectory::open_root_installer(Path::new("/etc/o3k"))
        .map_err(|_| reject("installation policy directory is unsafe"))?;
    if active_policy != target_policy {
        config
            .atomic_replace_installer(
                "installation-policy.json",
                &old_policy,
                &target_policy,
                0,
                gid,
                0o640,
                0o640,
            )
            .map_err(|_| MigrationError::Persistence("exact-forward policy publication failed"))?;
    }
    if active_high_water.as_deref() != Some(high_water.as_slice()) {
        state_directory
            .atomic_write(
                "policy.json",
                active_high_water.as_deref(),
                &high_water,
                gid,
            )
            .map_err(|_| {
                MigrationError::Persistence("exact-forward high-water publication failed")
            })?;
    }
    if active_manifest != target_manifest {
        let share = ProtectedDirectory::open_root_installer(Path::new("/usr/local/share/o3k"))
            .map_err(|_| reject("installed release metadata directory is unsafe"))?;
        share
            .atomic_replace_installer(
                "release-manifest.json",
                &old_release,
                &target_manifest,
                0,
                0,
                0o644,
                0o644,
            )
            .map_err(|_| MigrationError::Persistence("exact-forward release publication failed"))?;
    }
    if active_sums != extracted_sums {
        let share = ProtectedDirectory::open_root_installer(Path::new("/usr/local/share/o3k"))
            .map_err(|_| reject("installed release metadata directory is unsafe"))?;
        share
            .atomic_replace_installer(
                "SHA256SUMS",
                &active_sums,
                &extracted_sums,
                0,
                0,
                0o644,
                0o644,
            )
            .map_err(|_| {
                MigrationError::Persistence("exact-forward checksum publication failed")
            })?;
    }
    crate::recovery_installation::verify_v2_selected_generation(
        data_dir,
        &target_manifest,
        &target_policy,
    )
    .map_err(|_| MigrationError::Persistence("exact-forward generation verification failed"))?;
    verify_dual_verifiers(&bundle, false)?;
    // A process restart loses the pre-migration service snapshot. Keep
    // services masked and compute non-executable rather than infer that
    // controller startup was previously permitted.
    drop(store_guard);
    Ok(Some(PublicationPosition::V2Complete))
}

fn ensure_no_pending_signing(
    journal: &crate::recovery_files::ProtectedDirectory,
    uid: u32,
    gid: u32,
) -> Result<(), MigrationError> {
    if journal
        .read_bounded(
            crate::recovery_reanchor::PENDING_REQUEST_NAME,
            uid,
            gid,
            0o600,
            MAX_INPUT as usize,
        )
        .is_ok()
    {
        return Err(reject("pending offline signing request blocks migration"));
    }
    for name in journal
        .list_names()
        .map_err(|_| reject("protected journal directory cannot be inspected"))?
    {
        if name == crate::recovery_reanchor::PENDING_REQUEST_NAME {
            return Err(reject("pending offline signing request blocks migration"));
        }
        if name.starts_with("restore-reservation-") && name.ends_with(".lock") {
            return Err(reject("held signing reservation blocks migration"));
        }
    }
    let lock_path = journal.path().join("restore-signing-request.lock");
    if let Ok(file) = fs::File::open(&lock_path)
        && rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err()
    {
        return Err(reject("offline signing operation holds its lock"));
    }
    Ok(())
}

fn verify_dual_verifiers(bundle: &Path, compute_admitted: bool) -> Result<(), MigrationError> {
    let sums = fs::read(bundle.join("SHA256SUMS"))
        .map_err(|_| reject("candidate SHA256SUMS is unavailable"))?;
    let hashes = parse_release_sums(&sums)?;
    for name in ["o3kd", "o3k", "o3k-compute", "o3k-network"] {
        let path = Path::new("/usr/local/bin").join(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| reject("installed dual verifier is unavailable"))?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777
                != if name == "o3k-compute" {
                    if compute_admitted { 0o755 } else { 0o644 }
                } else {
                    0o755
                }
            || metadata.nlink() != 1
        {
            return Err(reject("installed dual verifier posture is invalid"));
        }
        let digest = digest_root_artifact(&path)?;
        if hashes.get(&format!("./bin/{name}")) != Some(&digest) {
            return Err(reject(
                "installed dual verifier differs from candidate release",
            ));
        }
    }
    Ok(())
}

fn verify_prepublication_executables(
    old_sums: &[u8],
    candidate_sums: &[u8],
) -> Result<(), MigrationError> {
    let old = parse_release_sums(old_sums)?;
    let candidate = parse_release_sums(candidate_sums)?;
    for name in ["o3kd", "o3k", "o3k-compute", "o3k-network"] {
        let path = Path::new("/usr/local/bin").join(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| reject("installed executable is unavailable"))?;
        let digest = digest_root_artifact(&path)?;
        let relative = format!("./bin/{name}");
        let recognized =
            old.get(&relative) == Some(&digest) || candidate.get(&relative) == Some(&digest);
        let mode = metadata.mode() & 0o7777;
        let mode_valid = if name == "o3k-compute" {
            matches!(mode, 0o644 | 0o755)
        } else {
            mode == 0o755
        };
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || !mode_valid
            || !recognized
        {
            return Err(reject(
                "installed executable identity or posture is not authenticated",
            ));
        }
    }
    Ok(())
}

fn installed_executable_inodes() -> Result<Vec<(u64, u64)>, MigrationError> {
    use std::os::unix::fs::MetadataExt;

    ["o3kd", "o3k", "o3k-compute", "o3k-network"]
        .into_iter()
        .map(|name| {
            let path = Path::new("/usr/local/bin").join(name);
            crate::recovery_files::check_ancestors(&path)
                .map_err(|_| reject("installed executable path is unsafe"))?;
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| reject("installed executable is unavailable"))?;
            if !metadata.is_file() || metadata.uid() != 0 || metadata.nlink() != 1 {
                return Err(reject("installed executable identity is unsafe"));
            }
            Ok((metadata.dev(), metadata.ino()))
        })
        .collect()
}

fn verify_process_quiescence(inodes: &[(u64, u64)]) -> Result<(), MigrationError> {
    for (device, inode) in inodes {
        if process_uses_inode(*device, *inode)? {
            return Err(reject(
                "an installed O3K executable still has a running process",
            ));
        }
    }
    Ok(())
}

fn disable_compute_executable() -> Result<(u64, u64), MigrationError> {
    use rustix::fs::{Mode, OFlags, fchmod, fstat, open};

    let path = Path::new("/usr/local/bin/o3k-compute");
    crate::recovery_files::check_ancestors(path)
        .map_err(|_| reject("compute executable path is unsafe"))?;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| reject("installed compute executable is unavailable"))?;
    let before = fstat(&fd).map_err(|_| reject("compute executable identity is unavailable"))?;
    if before.st_mode & 0o170000 != 0o100000
        || before.st_uid != 0
        || before.st_nlink != 1
        || !matches!(before.st_mode & 0o7777, 0o755 | 0o644)
    {
        return Err(reject("compute executable posture is unexpected"));
    }
    fchmod(&fd, Mode::from_raw_mode(0o644))
        .map_err(|_| MigrationError::Persistence("compute execution denial failed"))?;
    fs::File::from(fd)
        .sync_all()
        .map_err(|_| MigrationError::Persistence("compute execution denial sync failed"))?;
    fs::File::open("/usr/local/bin")
        .and_then(|directory| directory.sync_all())
        .map_err(|_| MigrationError::Persistence("compute directory sync failed"))?;
    let after = fs::symlink_metadata(path)
        .map_err(|_| reject("compute executable readback is unavailable"))?;
    if after.dev() != before.st_dev
        || after.ino() != before.st_ino
        || after.mode() & 0o7777 != 0o644
    {
        return Err(reject(
            "compute executable denial readback changed identity or mode",
        ));
    }
    Ok((before.st_dev, before.st_ino))
}

fn enable_compute_executable() -> Result<(), MigrationError> {
    use rustix::fs::{Mode, OFlags, fchmod, fstat, open};

    let path = Path::new("/usr/local/bin/o3k-compute");
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| reject("verified compute executable is unavailable"))?;
    let before = fstat(&fd).map_err(|_| reject("verified compute identity is unavailable"))?;
    if before.st_mode & 0o170000 != 0o100000 || before.st_uid != 0 || before.st_nlink != 1 {
        return Err(reject("verified compute executable posture changed"));
    }
    fchmod(&fd, Mode::from_raw_mode(0o755))
        .map_err(|_| MigrationError::Persistence("compute admission restore failed"))?;
    fs::File::from(fd)
        .sync_all()
        .map_err(|_| MigrationError::Persistence("compute admission sync failed"))?;
    fs::File::open("/usr/local/bin")
        .and_then(|directory| directory.sync_all())
        .map_err(|_| MigrationError::Persistence("compute admission directory sync failed"))?;
    let after = fs::symlink_metadata(path)
        .map_err(|_| reject("compute admission readback is unavailable"))?;
    if after.dev() != before.st_dev
        || after.ino() != before.st_ino
        || after.mode() & 0o7777 != 0o755
    {
        return Err(reject(
            "compute admission readback changed identity or mode",
        ));
    }
    Ok(())
}

fn process_uses_inode(device: u64, inode: u64) -> Result<bool, MigrationError> {
    use std::os::unix::fs::MetadataExt;

    for entry in fs::read_dir("/proc").map_err(|_| reject("process table cannot be inspected"))? {
        let entry = entry.map_err(|_| reject("process table entry cannot be inspected"))?;
        let name = entry.file_name();
        if !name
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let executable = entry.path().join("exe");
        match fs::metadata(executable) {
            Ok(metadata) if metadata.dev() == device && metadata.ino() == inode => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(reject("process executable identity cannot be verified")),
        }
    }
    Ok(false)
}

fn run_systemctl(args: &[&str]) -> Result<String, MigrationError> {
    use std::{process::Command, time::Duration};

    let mut command = Command::new("systemctl");
    command.args(args);
    let outcome = crate::sys::run_bounded_with_timeout(&mut command, Duration::from_secs(120))
        .map_err(|_| reject("systemctl could not be started"))?;
    if !outcome.completed || !outcome.output.status.success() {
        return Err(MigrationError::Persistence("systemd operation failed"));
    }
    Ok(String::from_utf8_lossy(&outcome.output.stdout)
        .trim()
        .to_owned())
}

fn snapshot_service_posture() -> Result<[ServicePosture; 3], MigrationError> {
    let units = ["o3kd.service", "o3k-network.service", "o3k-compute.service"];
    let mut posture = Vec::with_capacity(units.len());
    for unit in units {
        let active = run_systemctl(&["show", "--property=ActiveState", "--value", unit])?;
        let unit_file = run_systemctl(&["show", "--property=UnitFileState", "--value", unit])?;
        posture.push(ServicePosture {
            unit,
            was_active: active == "active" || active == "activating",
            was_masked: unit_file == "masked" || unit_file == "masked-runtime",
        });
    }
    posture
        .try_into()
        .map_err(|_| reject("systemd service snapshot is incomplete"))
}

fn restore_service_posture(posture: &[ServicePosture; 3]) -> Result<(), MigrationError> {
    for service in posture {
        if service.was_masked {
            continue;
        }
        run_systemctl(&["unmask", service.unit])?;
    }
    run_systemctl(&["daemon-reload"])?;
    for service in posture {
        if service.was_active && !service.was_masked {
            run_systemctl(&["start", service.unit])?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn operationally_admissible(position: PublicationPosition) -> bool {
    matches!(
        position,
        PublicationPosition::V1Intact | PublicationPosition::V2Complete
    )
}

fn mask_and_quiesce_services() -> Result<(), MigrationError> {
    for unit in ["o3kd.service", "o3k-network.service", "o3k-compute.service"] {
        run_systemctl(&["stop", unit])?;
        run_systemctl(&["mask", "--now", unit])?;
    }
    fs::File::open("/etc/systemd/system")
        .and_then(|directory| directory.sync_all())
        .map_err(|_| MigrationError::Persistence("systemd mask directory sync failed"))?;
    run_systemctl(&["daemon-reload"])?;
    for unit in ["o3kd.service", "o3k-network.service", "o3k-compute.service"] {
        let target = PathBuf::from("/etc/systemd/system").join(unit);
        if fs::read_link(&target).ok().as_deref() != Some(Path::new("/dev/null")) {
            return Err(reject("systemd service mask does not resolve to /dev/null"));
        }
        let state = run_systemctl(&["show", "--property=ActiveState", "--value", unit])?;
        if state != "inactive" && state != "failed" {
            return Err(reject("affected systemd service remains active"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use openssl::{pkey::PKey, sign::Signer};

    const OLD_STATE: &[u8] = b"signed-v1-state";
    const OLD_POLICY: &[u8] = b"signed-v1-policy";
    const OLD_HIGH_WATER: &[u8] = b"v1-high-water";
    const OLD_MANIFEST: &[u8] = b"authenticated-v1-manifest";
    const EVENT: &[u8] = b"signed-v2-migration-event";
    const POLICY: &[u8] = b"signed-v2-policy";
    const HIGH_WATER: &[u8] = b"v2-high-water";
    const MANIFEST: &[u8] = b"authenticated-v2-manifest";

    fn classify(
        state: Option<&[u8]>,
        policy: Option<&[u8]>,
        high_water: Option<&[u8]>,
        manifest: Option<&[u8]>,
    ) -> PublicationPosition {
        classify_publication(
            state,
            policy,
            high_water,
            manifest,
            OLD_STATE,
            OLD_POLICY,
            OLD_HIGH_WATER,
            OLD_MANIFEST,
            EVENT,
            POLICY,
            HIGH_WATER,
            MANIFEST,
        )
    }

    #[test]
    fn release_provenance_signature_rejects_tampering_and_unpinned_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = PKey::generate_ed25519()?;
        let public = key.public_key_to_pem()?;
        let message = b"signed release digest inventory\n";
        let mut signer = Signer::new_without_digest(&key)?;
        let signature = signer.sign_oneshot_to_vec(message)?;
        assert!(verify_release_signature(message, &signature, &public).is_ok());
        assert!(verify_release_signature(b"tampered", &signature, &public).is_err());
        assert!(verify_release_signature(message, b"wrong signature", &public).is_err());
        Ok(())
    }

    #[test]
    fn exact_v1_is_the_only_pre_selector_resumable_generation() {
        assert_eq!(
            classify(
                Some(OLD_STATE),
                Some(OLD_POLICY),
                Some(OLD_HIGH_WATER),
                Some(OLD_MANIFEST),
            ),
            PublicationPosition::V1Intact
        );
        assert_eq!(
            classify(
                Some(OLD_STATE),
                Some(POLICY),
                Some(OLD_HIGH_WATER),
                Some(OLD_MANIFEST),
            ),
            PublicationPosition::Deny
        );
    }

    #[test]
    fn selector_is_authoritative_and_partial_bytes_only_allow_exact_forward() {
        assert_eq!(
            classify(
                Some(EVENT),
                Some(OLD_POLICY),
                Some(OLD_HIGH_WATER),
                Some(OLD_MANIFEST),
            ),
            PublicationPosition::V2ExactForward
        );
        assert_eq!(
            classify(Some(EVENT), Some(POLICY), Some(HIGH_WATER), Some(MANIFEST),),
            PublicationPosition::V2Complete
        );
    }

    #[test]
    fn selector_never_permits_conflicting_retry_or_downgrade() {
        assert_eq!(
            classify(
                Some(OLD_STATE),
                Some(OLD_POLICY),
                Some(OLD_HIGH_WATER),
                Some(MANIFEST),
            ),
            PublicationPosition::Deny
        );
        assert_eq!(
            classify(
                Some(b"different-event"),
                Some(OLD_POLICY),
                Some(OLD_HIGH_WATER),
                Some(OLD_MANIFEST),
            ),
            PublicationPosition::Deny
        );
        assert_eq!(
            classify(
                Some(EVENT),
                Some(b"equivocated-policy"),
                Some(HIGH_WATER),
                Some(MANIFEST)
            ),
            PublicationPosition::Deny
        );
        assert_eq!(
            classify(Some(EVENT), None, Some(HIGH_WATER), Some(MANIFEST)),
            PublicationPosition::Deny
        );
    }

    #[test]
    fn d8_a10_01_and_02_inactive_bytes_never_select_v2() {
        // A selector temp or complete policy under an inert name is not an
        // active generation document.
        assert_eq!(
            classify(
                Some(OLD_STATE),
                Some(OLD_POLICY),
                Some(OLD_HIGH_WATER),
                Some(OLD_MANIFEST)
            ),
            PublicationPosition::V1Intact
        );
    }

    #[test]
    fn d8_a10_03_active_v2_policy_without_event_is_denied() {
        assert_eq!(
            classify(
                Some(OLD_STATE),
                Some(POLICY),
                Some(OLD_HIGH_WATER),
                Some(OLD_MANIFEST)
            ),
            PublicationPosition::Deny
        );
    }

    #[test]
    fn d8_a10_04_to_07_selector_first_partial_generations_are_not_operational() {
        for (policy, high_water, manifest) in [
            (OLD_POLICY, OLD_HIGH_WATER, OLD_MANIFEST),
            (POLICY, OLD_HIGH_WATER, OLD_MANIFEST),
            (POLICY, HIGH_WATER, OLD_MANIFEST),
        ] {
            assert_eq!(
                classify(Some(EVENT), Some(policy), Some(high_water), Some(manifest)),
                PublicationPosition::V2ExactForward
            );
        }
        assert_eq!(
            classify(Some(EVENT), None, Some(OLD_HIGH_WATER), Some(OLD_MANIFEST)),
            PublicationPosition::Deny
        );
    }

    #[test]
    fn d8_a10_08_to_10_reject_old_verifier_downgrade_and_equivocation() {
        assert_eq!(
            classify(Some(EVENT), Some(POLICY), Some(HIGH_WATER), Some(MANIFEST)),
            PublicationPosition::V2Complete
        );
        assert_eq!(
            classify(
                Some(OLD_STATE),
                Some(OLD_POLICY),
                Some(OLD_HIGH_WATER),
                Some(OLD_MANIFEST)
            ),
            PublicationPosition::V1Intact
        );
        assert_eq!(
            classify(
                Some(b"rewritten-or-regressed-event"),
                Some(POLICY),
                Some(HIGH_WATER),
                Some(MANIFEST)
            ),
            PublicationPosition::Deny
        );
        // An altered retry event is not an exact-forward replay.
        assert_eq!(
            classify(
                Some(b"event-with-one-byte-changed"),
                Some(OLD_POLICY),
                Some(OLD_HIGH_WATER),
                Some(OLD_MANIFEST)
            ),
            PublicationPosition::Deny
        );
    }

    #[test]
    fn d8_a10_07_policy_and_high_water_before_manifest_are_exact_forward_only() {
        // This is a specified publication boundary. It is a valid exact-forward
        // observation for the publisher, never operational admission.
        assert_eq!(
            classify(
                Some(EVENT),
                Some(POLICY),
                Some(HIGH_WATER),
                Some(OLD_MANIFEST)
            ),
            PublicationPosition::V2ExactForward
        );
        assert!(!operationally_admissible(
            PublicationPosition::V2ExactForward
        ));
    }

    #[test]
    fn missing_active_generation_bytes_are_denied_not_repaired_by_classifier() {
        for incomplete in [
            (Some(EVENT), Some(POLICY), Some(HIGH_WATER), None),
            (Some(EVENT), Some(POLICY), None, Some(MANIFEST)),
        ] {
            assert_eq!(
                classify(incomplete.0, incomplete.1, incomplete.2, incomplete.3),
                PublicationPosition::Deny
            );
        }
    }
}
