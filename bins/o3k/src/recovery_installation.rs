//! Installed C1 recovery discovery. No configuration or prefix environment
//! variable participates in this trust path. Metadata never grants activation.
use std::{fs, path::Path};

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::{
    recovery_files::{DirectoryPosture, ProtectedDirectory},
    recovery_identity::{self as identity, InstallationPolicy, InstallationState, RecoveryState},
    recovery_reanchor as reanchor,
    recovery_reanchor::{GenerationView, ReanchorError, RotationArea, RotationStore},
    upgrade::release_identity::{self, BackupReleaseIdentity},
};

const MAX_DOCUMENT: usize = 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

/// An authenticated policy and its protected state directory. The data and
/// journal descriptors are retained so callers can recheck identities around
/// durable transitions. This value is not a store-access reservation.
pub struct InstalledRecovery {
    pub policy: InstallationPolicy,
    pub policy_digest: String,
    /// The current state-chain tip when it is a C1 disposition record. For a
    /// rotated installation (tip is the re-anchor record R) this holds the
    /// era-1 base disposition record instead.
    pub state: InstallationState,
    pub state_digest: String,
    /// The preserved recovery-state value: the tip's own state for a
    /// disposition tip, or the preserved state carried by the re-anchor tip.
    preserved_state: RecoveryState,
    /// The sequence of the state-chain tip itself (for a re-anchor tip this
    /// differs from the base disposition record's sequence).
    tip_sequence: u64,
    /// The full authenticated generation bytes retained for the C1.1
    /// rotation driver and final observation.
    manifest_bytes: Vec<u8>,
    policy_bytes: Vec<u8>,
    fixed_bundle_bytes: Vec<u8>,
    trust_high_water_bytes: Vec<u8>,
    state_tip_bytes: Vec<u8>,
    journal_bytes: Option<Vec<u8>>,
    checkpoint_bytes: Option<Vec<u8>>,
    consumption_record_bytes: Option<Vec<u8>>,
    /// The durable policy high-water and the inert staged prior-generation
    /// bytes, observed by the partial load for the C1.1 rotation driver's
    /// exact-forward resume (SPEC-0050 §7.3.9).
    policy_high_water_bytes: Option<Vec<u8>>,
    pending_reanchor_bytes: Option<Vec<u8>>,
    staged_prior_policy_bytes: Option<Vec<u8>>,
    staged_prior_trust_bytes: Option<Vec<u8>>,
    tip_is_reanchor: bool,
    state_directory: ProtectedDirectory,
    _data_directory: ProtectedDirectory,
    journal_directory: Option<ProtectedDirectory>,
}

fn key(value: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(value)
        .map_err(|_| "recovery authority key is malformed")?
        .try_into()
        .map_err(|_| "recovery authority key is malformed")?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "recovery authority key is invalid")
}

/// Enforces C1 for every operational store opener. Missing installed identity
/// is a provisioning failure, including when the caller selects another path.
pub fn deny_operational_access(data_dir: &Path) -> Result<()> {
    deny_operational_access_for_backend(data_dir, None)
}

pub fn deny_operational_access_for_backend(
    data_dir: &Path,
    expected_backend: Option<&str>,
) -> Result<()> {
    // A source-built TestLab process uses a non-default data directory and
    // has no installed release manifest. It is not an installed O3K
    // installation: leave its existing startup lifecycle unchanged. The
    // packaged data directory always requires installed C1 identity, and any
    // release manifest that authenticates a C1 policy also requires it, so an
    // installed host cannot use another data path to bypass designation.
    if data_dir != Path::new("/var/lib/o3k")
        && !fs::canonicalize(data_dir).is_ok_and(|path| path == Path::new("/var/lib/o3k"))
    {
        let legacy_fixture = match release_identity::read_fixed_installed_release_manifest() {
            Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes).is_ok_and(|value| {
                value.get("installation_policy_format").is_none()
                    && value.get("installation_policy_path").is_none()
                    && value.get("installation_policy_authority").is_none()
            }),
            Err(_) => fs::symlink_metadata(release_identity::FIXED_RELEASE_MANIFEST_PATH)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        };
        if legacy_fixture {
            return Ok(());
        }
    }
    let installed = InstalledRecovery::load(data_dir)?;
    if expected_backend.is_some_and(|expected| installed.policy.backend != expected) {
        return Err("installation policy backend does not match configured backend");
    }
    if installed.preserved_state() != RecoveryState::NeverRecovered {
        return Err("authenticated recovery designation denies operational access");
    }
    Ok(())
}

impl InstalledRecovery {
    /// Loads without authenticating the generation chain: the rotation
    /// driver's plan builder performs the clean-or-resume observation, and a
    /// partial generation after a crash must remain openable for the
    /// exact-forward resume (§7.3.9). All filesystem, posture, and signature
    /// checks on the individual records still run.
    pub fn load_partial(data_dir: &Path) -> Result<Self> {
        Self::load_impl(data_dir, false)
    }

    pub fn load(data_dir: &Path) -> Result<Self> {
        Self::load_impl(data_dir, true)
    }

    fn load_impl(data_dir: &Path, authenticate: bool) -> Result<Self> {
        let release_bytes = release_identity::read_fixed_installed_release_manifest()
            .map_err(|_| "installed recovery release is unsafe or unavailable")?;
        let authority = BackupReleaseIdentity::c1_authority_from_manifest(&release_bytes)
            .map_err(|_| "installed release requires authenticated C1 migration")?;
        let release = BackupReleaseIdentity::from_manifest_bytes(&release_bytes)
            .map_err(|_| "installed recovery release identity is incomplete")?;
        let (uid, gid) = service_identity()?;
        let policy_bytes = read_protected_config(Path::new(&authority.policy_path), gid)?;
        let policy_key = key(&authority.ed25519_public_key)?;
        let policy: InstallationPolicy = identity::verify_signed(
            &policy_bytes,
            "o3k-installation-policy-v1",
            &authority.key_id,
            &policy_key,
        )
        .map_err(|_| "installation policy signature is invalid")?;
        identity::verify_policy(&policy, &authority.key_id)
            .map_err(|_| "installation policy binding is invalid")?;
        if policy.release_identity != release.release_artifact_sha256
            || policy.profile != release.profile_id
            || Path::new(&policy.data_root) != data_dir
            || fs::canonicalize(data_dir).map_err(|_| "recovery target is unavailable")? != data_dir
        {
            return Err("installation policy release or target identity changed");
        }
        let (installation, site) = o3k_store::identity_tokens(data_dir)
            .map_err(|_| "installation identity cannot be resolved")?;
        if policy.installation_id != hex::encode(installation)
            || policy.site_id != hex::encode(site)
        {
            return Err("installation policy does not match canonical identity");
        }
        if policy.recovery_state_root
            != format!("/var/lib/o3k-recovery-state/{}", policy.installation_id)
            || policy.journal_directory
                != format!("/var/lib/o3k-recovery/{}", policy.installation_id)
            || policy.trust_bundle_path != "/etc/o3k/recovery-trust.json"
            || policy.policy_path != authority.policy_path
        {
            return Err("installation recovery discovery paths are substituted");
        }
        let state_directory = ProtectedDirectory::open(
            Path::new(&policy.recovery_state_root),
            0,
            gid,
            0o750,
            policy.recovery_state_device,
            policy.recovery_state_inode,
        )
        .map_err(|_| "protected recovery state directory is unsafe")?;
        let journal_directory = match fs::symlink_metadata(&policy.journal_directory) {
            Ok(_) => Some(
                ProtectedDirectory::open(
                    Path::new(&policy.journal_directory),
                    uid,
                    gid,
                    0o700,
                    policy.journal_device,
                    policy.journal_inode,
                )
                .map_err(|_| "recovery journal identity or protection changed")?,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err("recovery journal identity cannot be observed"),
        };
        let data_directory = open_data_root(data_dir, uid, gid, &policy)
            .map_err(|_| "recovery target identity or protection changed")?;
        let policy_digest = hex::encode(Sha256::digest(&policy_bytes));
        // Checkpoint is the exact signed policy, not an unsigned permission
        // marker. Only the root-authorized installer may advance it. A
        // partial load (crash resume) tolerates a not-yet-advanced high-water.
        let checkpoint = state_directory
            .read_bounded("policy.json", 0, gid, 0o640, MAX_DOCUMENT)
            .map_err(|_| "installation policy high-water state is unavailable")?;
        if authenticate && checkpoint != policy_bytes {
            return Err("installation policy rollback or equivocation detected");
        }
        let state_tip_bytes = state_directory
            .read_bounded("state.json", 0, gid, 0o640, MAX_DOCUMENT)
            .map_err(|_| "protected installation state is unavailable")?;
        let state_digest = hex::encode(Sha256::digest(&state_tip_bytes));
        let tip_envelope: identity::Signed<serde_json::Value> =
            identity::decode_canonical(&state_tip_bytes)
                .map_err(|_| "installation state is malformed")?;
        let tip_format = tip_envelope
            .payload
            .get("format")
            .and_then(serde_json::Value::as_str)
            .ok_or("installation state is malformed")?;
        if !authenticate {
            // Rotation-driver context: the plan builder authenticates the
            // generation (clean or exact-forward resume). The byte fields the
            // pipeline needs are gathered here without the chain checks.
            let state: InstallationState = if tip_format == reanchor::REANCHOR_FORMAT {
                // A re-anchor tip: expose the preserved bindings in the base
                // disposition shape (rotation never reads this field).
                let signed: identity::Signed<serde_json::Value> =
                    identity::decode_canonical(&state_tip_bytes)
                        .map_err(|_| "installation state is malformed")?;
                let payload = &signed.payload;
                let get = |key: &str| {
                    payload
                        .get(key)
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                };
                InstallationState {
                    format: "o3k-installation-state-v1".to_string(),
                    installation_id: get("installation_id").unwrap_or_default(),
                    site_id: get("site_id").unwrap_or_default(),
                    profile: get("profile").unwrap_or_default(),
                    backend: get("backend").unwrap_or_default(),
                    policy_revision: get("new_policy_revision")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(policy.policy_revision),
                    policy_digest: get("new_policy_digest").unwrap_or_default(),
                    target_device: get("target_device")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(policy.target_device),
                    target_inode: get("target_inode")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(policy.target_inode),
                    sequence: get("sequence")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or_default(),
                    prior_record_digest: get("prior_record_digest").unwrap_or_default(),
                    state: get("preserved_state")
                        .and_then(|v| match v.as_str() {
                            "NEVER_RECOVERED" => Some(RecoveryState::NeverRecovered),
                            "RECOVERY_DESIGNATED" => Some(RecoveryState::RecoveryDesignated),
                            "RELEASED" => Some(RecoveryState::Released),
                            _ => None,
                        })
                        .ok_or("installation state is malformed")?,
                    operation_id: get("operation_id"),
                    artifact_sha256: get("artifact_sha256"),
                    recovery_directory_digest: get("recovery_directory_digest"),
                    trust_bundle_digest: Some(policy.trust_bundle_digest.clone()),
                    terminal_journal_digest: get("terminal_journal_digest"),
                    evidence_digest: get("terminal_evidence_digest"),
                }
            } else {
                identity::decode_canonical::<identity::Signed<InstallationState>>(&state_tip_bytes)
                    .map_err(|_| "installation state is malformed")
                    .map(|signed| signed.payload)?
            };
            let (
                fixed_bundle_bytes,
                trust_high_water_bytes,
                journal_bytes,
                checkpoint_bytes,
                consumption_record_bytes,
            ) = (
                read_protected_config(Path::new(&policy.trust_bundle_path), gid)
                    .map_err(|_| "installed recovery trust is unsafe or unavailable")?,
                state_directory
                    .read_bounded("trust.json", 0, gid, 0o640, MAX_DOCUMENT)
                    .map_err(|_| "durable recovery trust high-water state is unavailable")?,
                journal_directory.as_ref().and_then(|directory| {
                    directory
                        .read_bounded("restore-journal.json", uid, gid, 0o600, 64 * 1024 * 1024)
                        .ok()
                }),
                journal_directory.as_ref().and_then(|directory| {
                    directory
                        .read_bounded(reanchor::CHECKPOINT_NAME, uid, gid, 0o600, MAX_DOCUMENT)
                        .ok()
                }),
                state_directory
                    .read_bounded(reanchor::CONSUMPTION_NAME, 0, gid, 0o640, MAX_DOCUMENT)
                    .ok(),
            );
            return Ok(Self {
                state: state.clone(),
                policy,
                policy_digest,
                state_digest,
                preserved_state: state.state,
                tip_sequence: state.sequence,
                manifest_bytes: release_bytes,
                policy_bytes,
                fixed_bundle_bytes,
                trust_high_water_bytes,
                state_tip_bytes,
                journal_bytes,
                checkpoint_bytes,
                consumption_record_bytes,
                policy_high_water_bytes: Some(checkpoint),
                pending_reanchor_bytes: state_directory
                    .read_bounded(reanchor::STAGED_REANCHOR_NAME, 0, gid, 0o640, MAX_DOCUMENT)
                    .ok(),
                staged_prior_policy_bytes: state_directory
                    .read_bounded(
                        reanchor::STAGED_PRIOR_POLICY_NAME,
                        0,
                        gid,
                        0o640,
                        MAX_DOCUMENT,
                    )
                    .ok(),
                staged_prior_trust_bytes: state_directory
                    .read_bounded(
                        reanchor::STAGED_PRIOR_TRUST_NAME,
                        0,
                        gid,
                        0o640,
                        MAX_DOCUMENT,
                    )
                    .ok(),
                tip_is_reanchor: tip_format == reanchor::REANCHOR_FORMAT,
                state_directory,
                _data_directory: data_directory,
                journal_directory,
            });
        }

        let manifest_bytes = release_bytes.clone();
        let mut fixed_bundle_bytes = Vec::new();
        let mut trust_high_water_bytes = Vec::new();
        let mut journal_bytes = None;
        let mut checkpoint_bytes = None;
        let mut consumption_record_bytes = None;
        let mut tip_is_reanchor = false;
        let (state, preserved_state, tip_sequence, journal_directory) = match tip_format {
            "o3k-installation-state-v1" => {
                let unverified: identity::Signed<InstallationState> =
                    identity::decode_canonical(&state_tip_bytes)
                        .map_err(|_| "installation state is malformed")?;
                let (state, journal_directory) = if unverified.payload.state
                    == RecoveryState::NeverRecovered
                {
                    let initial = identity::verify_signed(
                        &state_tip_bytes,
                        "o3k-installation-state-v1",
                        &authority.key_id,
                        &policy_key,
                    )
                    .map_err(|_| "installation state signature is invalid")?;
                    identity::verify_initial_state_transition(None, &initial, &policy)
                        .map_err(|_| "installation state predecessor is invalid")?;
                    // The provisioned journal directory stays observed on a
                    // NEVER_RECOVERED tip: designation (and the C1.1 rotation
                    // driver) require it, and its identity is policy-bound.
                    (initial, journal_directory)
                } else {
                    let journal_directory = journal_directory
                        .ok_or("recovery journal identity or protection changed")?;
                    let trust = load_trust(&policy, &state_directory, gid)?;
                    let signer = &unverified.envelope.signer_key_id;
                    let signer_key = trust
                        .journal_key(signer)
                        .ok_or("installation state signer is unknown or revoked")?;
                    let current: InstallationState = identity::verify_signed(
                        &state_tip_bytes,
                        "o3k-installation-state-v1",
                        signer,
                        signer_key,
                    )
                    .map_err(|_| "installation state signature is invalid")?;
                    // C1 supports designation now. RELEASED requires independently
                    // verified activation evidence; A10 completion never qualifies.
                    startup_state_check(&current)?;
                    let previous_bytes = state_directory
                        .read_bounded(
                            &format!("state-{}.json", current.prior_record_digest),
                            0,
                            gid,
                            0o640,
                            MAX_DOCUMENT,
                        )
                        .map_err(|_| "installation state predecessor is missing")?;
                    if hex::encode(Sha256::digest(&previous_bytes)) != current.prior_record_digest {
                        return Err("installation state predecessor digest changed");
                    }
                    let previous_envelope: identity::Signed<serde_json::Value> =
                        identity::decode_canonical(&previous_bytes)
                            .map_err(|_| "installation state predecessor is malformed")?;
                    let previous_format = previous_envelope
                        .payload
                        .get("format")
                        .and_then(serde_json::Value::as_str)
                        .ok_or("installation state predecessor is malformed")?;
                    match previous_format {
                        // A designation after rotation transitions from the
                        // preserved value of the re-anchor tip; the re-anchor
                        // link is authenticated by its policy-authority
                        // signature and its binding of the installed policy.
                        reanchor::REANCHOR_FORMAT => {
                            let record =
                                reanchor::verify_reanchor_record(&previous_bytes, &release_bytes)
                                    .map_err(|_| "re-anchor predecessor is invalid")?;
                            if record.new_policy_digest != policy_digest {
                                return Err(
                                    "re-anchor predecessor does not bind the installed policy",
                                );
                            }
                            let record_view = identity::StateTipView {
                                sequence: record.sequence,
                                state: record.preserved_state,
                                policy_digest: record.new_policy_digest.as_str(),
                                operation_id: record.operation_id.as_deref(),
                                artifact_sha256: record.artifact_sha256.as_deref(),
                                trust_bundle_digest: None,
                                recovery_directory_digest: record
                                    .recovery_directory_digest
                                    .as_deref(),
                            };
                            identity::verify_tip_transition(
                                Some(record_view),
                                Some(current.prior_record_digest.as_str()),
                                &current,
                                &policy,
                            )
                            .map_err(|_| "installation designation predecessor is invalid")?;
                        }
                        "o3k-installation-state-v1" => {
                            let previous: InstallationState = identity::verify_signed(
                                &previous_bytes,
                                "o3k-installation-state-v1",
                                &authority.key_id,
                                &policy_key,
                            )
                            .map_err(|_| "installation initial state signature is invalid")?;
                            identity::verify_initial_state_transition(None, &previous, &policy)
                                .map_err(|_| "installation initial predecessor is invalid")?;
                            identity::verify_state_transition_with_previous_digest(
                                Some(&previous),
                                Some(&current.prior_record_digest),
                                &current,
                                &policy,
                            )
                            .map_err(|_| "installation designation predecessor is invalid")?;
                        }
                        _ => return Err("installation state predecessor kind is unknown"),
                    }
                    if !designation_binding_valid(&current, &policy, &policy_digest) {
                        return Err("installation designation trust or directory binding changed");
                    }
                    (current, Some(journal_directory))
                };
                if state.policy_digest != policy_digest {
                    return Err("installation state policy digest changed");
                }
                let preserved = state.state;
                let tip_sequence = state.sequence;
                (state, preserved, tip_sequence, journal_directory)
            }
            reanchor::REANCHOR_FORMAT => {
                tip_is_reanchor = true;
                let journal_directory =
                    journal_directory.ok_or("recovery journal identity or protection changed")?;
                fixed_bundle_bytes =
                    read_protected_config(Path::new(&policy.trust_bundle_path), gid)
                        .map_err(|_| "installed recovery trust is unsafe or unavailable")?;
                trust_high_water_bytes = state_directory
                    .read_bounded("trust.json", 0, gid, 0o640, MAX_DOCUMENT)
                    .map_err(|_| "durable recovery trust high-water state is unavailable")?;
                journal_bytes = journal_directory
                    .read_bounded("restore-journal.json", uid, gid, 0o600, 64 * 1024 * 1024)
                    .ok();
                checkpoint_bytes = journal_directory
                    .read_bounded(reanchor::CHECKPOINT_NAME, uid, gid, 0o600, MAX_DOCUMENT)
                    .ok();
                consumption_record_bytes = state_directory
                    .read_bounded(reanchor::CONSUMPTION_NAME, 0, gid, 0o640, MAX_DOCUMENT)
                    .ok();
                let archives = ProtectedArchives {
                    state_directory: &state_directory,
                    journal_directory: Some(&journal_directory),
                    uid,
                    gid,
                };
                let staged_prior_policy_bytes = state_directory
                    .read_bounded(
                        reanchor::STAGED_PRIOR_POLICY_NAME,
                        0,
                        gid,
                        0o640,
                        MAX_DOCUMENT,
                    )
                    .ok();
                let staged_prior_trust_bytes = state_directory
                    .read_bounded(
                        reanchor::STAGED_PRIOR_TRUST_NAME,
                        0,
                        gid,
                        0o640,
                        MAX_DOCUMENT,
                    )
                    .ok();
                let policy_high_water_bytes = state_directory
                    .read_bounded(
                        reanchor::POLICY_HIGH_WATER_NAME,
                        0,
                        gid,
                        0o640,
                        MAX_DOCUMENT,
                    )
                    .ok();
                let view = GenerationView {
                    manifest_bytes: &manifest_bytes,
                    policy_bytes: &policy_bytes,
                    policy_high_water_bytes: policy_high_water_bytes.as_deref(),
                    fixed_bundle_bytes: &fixed_bundle_bytes,
                    trust_high_water_bytes: &trust_high_water_bytes,
                    pending_reanchor_bytes: None,
                    staged_prior_policy_bytes: staged_prior_policy_bytes.as_deref(),
                    staged_prior_trust_bytes: staged_prior_trust_bytes.as_deref(),
                    state_tip_bytes: &state_tip_bytes,
                    journal_bytes: journal_bytes.as_deref(),
                    checkpoint_bytes: checkpoint_bytes.as_deref(),
                    consumption_record_bytes: consumption_record_bytes.as_deref(),
                    pending_signing_request_present: false,
                    now: chrono::Utc::now().timestamp(),
                };
                let observed = reanchor::authenticate_rotated_generation(&view, &archives)
                    .map_err(rotated_denial_reason)?;
                match observed.preserved_state {
                    RecoveryState::NeverRecovered => {}
                    RecoveryState::RecoveryDesignated => {
                        let base = observed.base_disposition.as_ref().ok_or(
                            "authenticated recovery designation denies operational access",
                        )?;
                        // The base designation may sit at any sequence >= 1:
                        // designation after a re-anchor rotation chains
                        // through the re-anchor tip.
                        if base.sequence < 1 {
                            return Err("recovery release requires accepted activation evidence");
                        }
                    }
                    RecoveryState::Released => {
                        return Err(
                            "installation state RELEASED is a recovery disposition, not a startup authority",
                        );
                    }
                }
                let base = observed
                    .base_disposition
                    .clone()
                    .ok_or("protected installation state is unavailable")?;
                (
                    base,
                    observed.preserved_state,
                    observed.tip_sequence,
                    Some(journal_directory),
                )
            }
            _ => return Err("installation state is malformed"),
        };
        let installed = Self {
            policy,
            policy_digest,
            state,
            state_digest,
            preserved_state,
            tip_sequence,
            manifest_bytes,
            policy_bytes,
            fixed_bundle_bytes,
            trust_high_water_bytes,
            state_tip_bytes,
            journal_bytes,
            checkpoint_bytes,
            consumption_record_bytes,
            policy_high_water_bytes: None,
            pending_reanchor_bytes: None,
            staged_prior_policy_bytes: None,
            staged_prior_trust_bytes: None,
            tip_is_reanchor,
            state_directory,
            _data_directory: data_directory,
            journal_directory,
        };
        if installed.preserved_state != RecoveryState::NeverRecovered && !installed.tip_is_reanchor
        {
            let (_, gid) = service_identity()?;
            let trust = load_trust(&installed.policy, &installed.state_directory, gid)?;
            installed.authenticate_journal_for(&installed.state, &trust)?;
        }
        Ok(installed)
    }

    /// Persists an offline-authorized designation before any target mutation.
    /// This root helper never opens a canonical database.
    pub fn persist_designation(&self, signed_state: &[u8]) -> Result<()> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err("recovery designation requires root-authorized persistence");
        }
        if self.preserved_state() != RecoveryState::NeverRecovered {
            return Err("recovery designation has an invalid predecessor");
        }
        if self.journal_directory.is_none() {
            return Err("recovery journal must be provisioned before designation");
        }
        self._data_directory
            .lock()
            .map_err(|_| "recovery target is busy")?;
        self.revalidate_state()?;
        let (_, gid) = service_identity()?;
        let trust = load_trust(&self.policy, &self.state_directory, gid)?;
        let next = verify_designation_record(
            &self.state_tip_view(),
            &self.state_digest,
            &self.policy,
            &self.policy_digest,
            &trust,
            signed_state,
        )?;
        self.authenticate_journal_for(&next, &trust)?;
        let previous = self
            .state_directory
            .read_bounded("state.json", 0, gid, 0o640, MAX_DOCUMENT)
            .map_err(|_| "recovery designation predecessor cannot be observed")?;
        let archive = format!("state-{}.json", self.state_digest);
        match self
            .state_directory
            .read_bounded(&archive, 0, gid, 0o640, MAX_DOCUMENT)
        {
            Ok(bytes) if bytes == previous => {}
            Ok(_) => return Err("recovery designation predecessor conflicts"),
            Err(_) => self
                .state_directory
                .atomic_write(&archive, None, &previous, gid)
                .map_err(|_| "recovery designation predecessor persistence is uncertain")?,
        }
        self.state_directory
            .atomic_write("state.json", Some(&previous), signed_state, gid)
            .map_err(|_| "recovery designation write outcome requires authenticated observation")?;
        let observed = Self::load(Path::new(&self.policy.data_root))?;
        if observed.state_digest != hex::encode(Sha256::digest(signed_state)) {
            return Err("recovery designation outcome is conflicting");
        }
        Ok(())
    }

    /// Persists an offline-signed `RELEASED` disposition.  Every structural
    /// check runs first: the record must be signed by an installed,
    /// non-revoked journal authority, must bind the exact observed
    /// designation as its predecessor, and the journal must still
    /// authenticate for the same operation and artifact after a target
    /// identity recheck.  The terminal-evidence gate then fails closed:
    /// journal v1 is limited to `PREFLIGHTED` and no accepted terminal
    /// activation evidence (`COMMITTED` under D7, or the A10
    /// `INACTIVE_VERIFIED` branch, which by itself never permits RELEASED or
    /// startup) is implemented.  Nothing here fabricates the missing
    /// evidence and no caller can bypass the gate.
    pub fn persist_release(&self, signed_state: &[u8]) -> Result<()> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err("recovery release requires root-authorized persistence");
        }
        if self.preserved_state() != RecoveryState::RecoveryDesignated || self.state.sequence != 1 {
            return Err("recovery release requires a durable recovery designation");
        }
        if self.journal_directory.is_none() {
            return Err("recovery journal must be provisioned before release");
        }
        // Target identity recheck before any recovery-state mutation.
        self._data_directory
            .lock()
            .map_err(|_| "recovery target is busy")?;
        self.revalidate_state()?;
        let (_, gid) = service_identity()?;
        let trust = load_trust(&self.policy, &self.state_directory, gid)?;
        let next = verify_release_record(
            &self.state_tip_view(),
            &self.state_digest,
            &self.policy,
            &self.policy_digest,
            &trust,
            signed_state,
        )?;
        let journal = self.authenticate_journal(&next, &trust)?;
        verify_release_terminal_evidence(journal.phase())?;
        // Unreachable today: persistence lands here only after an accepted
        // terminal-evidence verifier exists, and must mirror
        // `persist_designation` (archive predecessor, atomic rename,
        // authenticated observation) before startup may proceed.  The future
        // gate must also prove `next.terminal_journal_digest` equals the
        // actual authenticated terminal chain hash (the `AuthenticatedJournal`
        // signed hash) and that `next.evidence_digest` equals the digest of
        // the authenticated verification evidence for this exact operation;
        // a signed RELEASED record whose terminal digest does not match the
        // authenticated chain must never be written.
        Err(
            "recovery release persistence requires an accepted terminal activation evidence verifier",
        )
    }

    fn authenticate_journal(
        &self,
        state: &InstallationState,
        trust: &crate::recovery_trust::VerifiedTrust,
    ) -> Result<crate::restore_journal::AuthenticatedJournal> {
        let (uid, gid) = service_identity()?;
        let journal = self
            .journal_directory
            .as_ref()
            .ok_or("recovery journal is unavailable")?
            .read_bounded("restore-journal.json", uid, gid, 0o600, 64 * 1024 * 1024)
            .map_err(|_| "recovery journal is unsafe or unavailable")?;
        let operation_id = state
            .operation_id
            .as_deref()
            .ok_or("recovery operation is missing")?
            .parse()
            .map_err(|_| "recovery operation is invalid")?;
        let artifact = state
            .artifact_sha256
            .as_deref()
            .ok_or("recovery artifact is missing")?;
        crate::restore_journal::authenticate_installed_chain(
            &journal,
            &self.policy,
            trust,
            operation_id,
            artifact,
        )
        .map_err(|_| "recovery journal is unauthenticated or conflicts with designation")
    }

    fn authenticate_journal_for(
        &self,
        state: &InstallationState,
        trust: &crate::recovery_trust::VerifiedTrust,
    ) -> Result<()> {
        self.authenticate_journal(state, trust).map(|_| ())
    }

    /// Re-observes the protected signed record. Consumers cannot assume an
    /// uncertain persistence result succeeded or retain an obsolete snapshot.
    pub fn revalidate_state(&self) -> Result<()> {
        let (_, gid) = service_identity()?;
        let bytes = self
            .state_directory
            .read_bounded("state.json", 0, gid, 0o640, MAX_DOCUMENT)
            .map_err(|_| "protected installation state cannot be observed")?;
        if hex::encode(Sha256::digest(bytes)) != self.state_digest {
            return Err("installation state changed during operation");
        }
        Ok(())
    }

    /// The preserved recovery-state value of the authenticated tip.
    pub fn preserved_state(&self) -> RecoveryState {
        self.preserved_state
    }

    /// Whether the state-chain tip is a C1.1 re-anchor record.
    pub fn tip_is_reanchor(&self) -> bool {
        self.tip_is_reanchor
    }

    fn state_tip_view(&self) -> identity::StateTipView<'_> {
        if self.tip_is_reanchor {
            identity::StateTipView {
                sequence: self.tip_sequence,
                state: self.preserved_state,
                policy_digest: &self.policy_digest,
                operation_id: self.state.operation_id.as_deref(),
                artifact_sha256: self.state.artifact_sha256.as_deref(),
                trust_bundle_digest: self.state.trust_bundle_digest.as_deref(),
                recovery_directory_digest: self.state.recovery_directory_digest.as_deref(),
            }
        } else {
            identity::state_tip_view(&self.state)
        }
    }

    /// Exclusive data-directory quiescence for rotation: the same flock the
    /// designation path holds, plus the policy-bound identity recheck.
    pub(crate) fn quiesce_data_directory(&self) -> std::result::Result<(), ReanchorError> {
        self._data_directory
            .lock()
            .map_err(|_| ReanchorError::Quiescence("recovery target is busy"))?;
        let (device, inode) = self._data_directory.identity();
        if device != self.policy.target_device || inode != self.policy.target_inode {
            return Err(ReanchorError::Quiescence(
                "recovery target identity changed",
            ));
        }
        Ok(())
    }

    /// Strict pending-signing-request exclusion: no unsigned or in-flight
    /// journal signing request may exist before the tips are observed.
    pub(crate) fn strict_pending_signing_request_exclusion(
        &self,
        uid: u32,
        gid: u32,
    ) -> std::result::Result<(), ReanchorError> {
        let journal = self
            .journal_directory
            .as_ref()
            .ok_or(ReanchorError::Quiescence(
                "recovery journal directory is unavailable",
            ))?;
        if journal
            .read_bounded(
                reanchor::PENDING_REQUEST_NAME,
                uid,
                gid,
                0o600,
                MAX_DOCUMENT,
            )
            .is_ok()
        {
            return Err(ReanchorError::Quiescence(
                "an unsigned journal signing request is pending; rotation is denied",
            ));
        }
        for name in journal.list_names().map_err(|_| {
            ReanchorError::Quiescence("recovery journal directory cannot be inspected")
        })? {
            if name.starts_with("restore-reservation-") && name.ends_with(".lock") {
                return Err(ReanchorError::Quiescence(
                    "an in-flight journal reservation exists; rotation is denied",
                ));
            }
        }
        let lock_path = journal.path().join("restore-signing-request.lock");
        if let Ok(file) = fs::File::open(&lock_path)
            && rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .is_err()
        {
            return Err(ReanchorError::Quiescence(
                "a journal signing request is in flight; rotation is denied",
            ));
        }
        Ok(())
    }

    /// Byte-level view of the authenticated generation for the C1.1
    /// rotation pipeline.
    pub(crate) fn generation_view(
        &self,
        uid: u32,
        _gid: u32,
    ) -> std::result::Result<GenerationView<'_>, ReanchorError> {
        let pending_signing_request_present = match self.journal_directory.as_ref() {
            Some(journal) => journal
                .list_names()
                .map_err(|_| {
                    ReanchorError::Quiescence("recovery journal directory cannot be inspected")
                })?
                .iter()
                .any(|name| {
                    name == reanchor::PENDING_REQUEST_NAME
                        || (name.starts_with("restore-reservation-") && name.ends_with(".lock"))
                }),
            None => false,
        };
        let _ = uid;
        Ok(GenerationView {
            manifest_bytes: &self.manifest_bytes,
            policy_bytes: &self.policy_bytes,
            policy_high_water_bytes: self.policy_high_water_bytes.as_deref(),
            fixed_bundle_bytes: &self.fixed_bundle_bytes,
            trust_high_water_bytes: &self.trust_high_water_bytes,
            pending_reanchor_bytes: self.pending_reanchor_bytes.as_deref(),
            staged_prior_policy_bytes: self.staged_prior_policy_bytes.as_deref(),
            staged_prior_trust_bytes: self.staged_prior_trust_bytes.as_deref(),
            state_tip_bytes: &self.state_tip_bytes,
            journal_bytes: self.journal_bytes.as_deref(),
            checkpoint_bytes: self.checkpoint_bytes.as_deref(),
            consumption_record_bytes: self.consumption_record_bytes.as_deref(),
            pending_signing_request_present,
            now: chrono::Utc::now().timestamp(),
        })
    }

    pub(crate) fn archive_lookup(&self, uid: u32, gid: u32) -> ProtectedArchives<'_> {
        ProtectedArchives {
            state_directory: &self.state_directory,
            journal_directory: self.journal_directory.as_ref(),
            uid,
            gid,
        }
    }

    pub(crate) fn rotation_store(
        &self,
        uid: u32,
        gid: u32,
    ) -> std::result::Result<ProtectedRotationStore<'_>, ReanchorError> {
        Ok(ProtectedRotationStore {
            state_directory: &self.state_directory,
            journal_directory: self
                .journal_directory
                .as_ref()
                .ok_or(ReanchorError::Quiescence(
                    "rotation requires the provisioned journal directory",
                ))?,
            fixed_config: open_fixed_config_directory()?,
            uid,
            gid,
        })
    }
}

pub(crate) fn read_protected_config(path: &Path, gid: u32) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    // Parent identity is discovered only after opening the protected path;
    // ProtectedDirectory performs the authoritative no-follow walk.
    let parent = path.parent().ok_or("installation policy path is invalid")?;
    let metadata =
        fs::symlink_metadata(parent).map_err(|_| "installation policy is unavailable")?;
    let directory = ProtectedDirectory::open(
        parent,
        0,
        metadata.gid(),
        metadata.mode() & 0o7777,
        metadata.dev(),
        metadata.ino(),
    )
    .map_err(|_| "installation policy directory is unsafe")?;
    directory
        .read_bounded(
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or("invalid recovery configuration path")?,
            0,
            gid,
            0o640,
            MAX_DOCUMENT,
        )
        .map_err(|_| "installation policy is unsafe or unavailable")
}

pub(crate) fn service_identity() -> Result<(u32, u32)> {
    let passwd =
        fs::read_to_string("/etc/passwd").map_err(|_| "o3k service identity is unavailable")?;
    for line in passwd.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.first() == Some(&"o3k") && fields.len() >= 4 {
            return Ok((
                fields[2]
                    .parse()
                    .map_err(|_| "o3k service uid is invalid")?,
                fields[3]
                    .parse()
                    .map_err(|_| "o3k service gid is invalid")?,
            ));
        }
    }
    Err("o3k service identity is unavailable")
}

fn journal_identity_digest(policy: &InstallationPolicy) -> Result<String> {
    identity::digest(&(
        policy.journal_directory.as_str(),
        policy.journal_device,
        policy.journal_inode,
    ))
    .map_err(|_| "recovery directory identity cannot be canonicalized")
}

/// Opens the canonical data root.  SPEC-0050 §7.2.1 binds the device/inode
/// and verified ext4 filesystem, not one exact owner/mode tuple.  The
/// accepted postures are:
///
/// - routine/TestLab: `o3k:o3k` `0700` (owner-only); and
/// - packaged libvirt: `o3k:o3k-compute` `0711`, so the QEMU process (primary
///   group `kvm`) can traverse the data root to reach compute overlays while
///   durable files stay `0600` and group/other write is never granted.
///
/// Replacement and posture drift still fail closed: the signed policy binds
/// the device/inode, the walk is no-follow with root-owned, non-writable
/// ancestors, and every later use revalidates the exact observed identity.
fn open_data_root(
    data_dir: &Path,
    uid: u32,
    gid: u32,
    policy: &InstallationPolicy,
) -> std::result::Result<ProtectedDirectory, crate::recovery_files::RecoveryFileError> {
    ProtectedDirectory::open_accepted(
        data_dir,
        &data_root_postures(uid, gid, compute_group_gid().ok()),
        policy.target_device,
        policy.target_inode,
    )
}

/// The closed set of accepted data-root postures.  Without a resolvable
/// `o3k-compute` group the packaged QEMU-traversal posture cannot be
/// described, so only the routine owner-only posture is offered.
pub(crate) fn data_root_postures(
    uid: u32,
    gid: u32,
    compute_gid: Option<u32>,
) -> Vec<DirectoryPosture> {
    let mut postures = vec![DirectoryPosture {
        uid,
        gid,
        mode: 0o700,
    }];
    if let Some(compute_gid) = compute_gid {
        postures.push(DirectoryPosture {
            uid,
            gid: compute_gid,
            mode: 0o711,
        });
    }
    postures
}

pub(crate) fn compute_group_gid() -> Result<u32> {
    let groups =
        fs::read_to_string("/etc/group").map_err(|_| "o3k compute group is unavailable")?;
    for line in groups.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.first() == Some(&"o3k-compute") && fields.len() >= 3 {
            return fields[2]
                .parse()
                .map_err(|_| "o3k compute group gid is invalid");
        }
    }
    Err("o3k compute group is unavailable")
}

/// The only authenticated post-initial record that may describe an
/// installation at startup.  `RELEASED` is a recovery disposition, never a
/// startup authority: startup with a RELEASED (or otherwise unexpected)
/// record fails closed because release requires the separately accepted
/// terminal activation evidence, which C1 does not implement.
fn startup_state_check(state: &InstallationState) -> Result<()> {
    match state.state {
        // A designation at any sequence >= 1 authenticates: after a C1.1
        // re-anchor rotation the designation transitions from the re-anchor
        // tip and therefore sits at sequence two or later.
        RecoveryState::RecoveryDesignated if state.sequence >= 1 => Ok(()),
        RecoveryState::Released => {
            Err("installation state RELEASED is a recovery disposition, not a startup authority")
        }
        _ => Err("recovery release requires accepted activation evidence"),
    }
}

/// Designation binding shared by startup load and designation persistence:
/// the record must carry the exact signed policy digest and the policy-bound
/// trust-bundle and recovery-directory identities.
fn designation_binding_valid(
    record: &InstallationState,
    policy: &InstallationPolicy,
    policy_digest: &str,
) -> bool {
    record.policy_digest == policy_digest
        && record.trust_bundle_digest.as_deref() == Some(policy.trust_bundle_digest.as_str())
        && journal_identity_digest(policy).ok().as_deref()
            == record.recovery_directory_digest.as_deref()
}

/// Verifies an offline-signed `RECOVERY_DESIGNATED` candidate against the
/// observed state tip (a disposition or a re-anchor record): canonical
/// encoding, installed journal-authority signature (unknown or revoked
/// signers fail), exact predecessor digest chain, and installation binding.
fn verify_designation_record(
    previous: &identity::StateTipView<'_>,
    previous_digest: &str,
    policy: &InstallationPolicy,
    policy_digest: &str,
    trust: &crate::recovery_trust::VerifiedTrust,
    signed_state: &[u8],
) -> Result<InstallationState> {
    let envelope: identity::Signed<InstallationState> = identity::decode_canonical(signed_state)
        .map_err(|_| "recovery designation is malformed")?;
    let signer = &envelope.envelope.signer_key_id;
    let verifier = trust
        .journal_key(signer)
        .ok_or("recovery designation signer is unknown or revoked")?;
    let next: InstallationState =
        identity::verify_signed(signed_state, "o3k-installation-state-v1", signer, verifier)
            .map_err(|_| "recovery designation signature is invalid")?;
    identity::verify_tip_transition(Some(*previous), Some(previous_digest), &next, policy)
        .map_err(|_| "recovery designation predecessor is invalid")?;
    if next.state != RecoveryState::RecoveryDesignated
        || !designation_binding_valid(&next, policy, policy_digest)
    {
        return Err("recovery designation is not bound to this installation");
    }
    Ok(next)
}

/// Verifies an offline-signed `RELEASED` candidate against the observed
/// designation: canonical encoding, installed journal-authority signature,
/// exact predecessor chain, and continuity of the designation binding.
fn verify_release_record(
    previous: &identity::StateTipView<'_>,
    previous_digest: &str,
    policy: &InstallationPolicy,
    policy_digest: &str,
    trust: &crate::recovery_trust::VerifiedTrust,
    signed_state: &[u8],
) -> Result<InstallationState> {
    let envelope: identity::Signed<InstallationState> =
        identity::decode_canonical(signed_state).map_err(|_| "recovery release is malformed")?;
    let signer = &envelope.envelope.signer_key_id;
    let verifier = trust
        .journal_key(signer)
        .ok_or("recovery release signer is unknown or revoked")?;
    let next: InstallationState =
        identity::verify_signed(signed_state, "o3k-installation-state-v1", signer, verifier)
            .map_err(|_| "recovery release signature is invalid")?;
    identity::verify_tip_transition(Some(*previous), Some(previous_digest), &next, policy)
        .map_err(|_| "recovery release predecessor is invalid")?;
    if next.state != RecoveryState::Released
        || next.policy_digest != policy_digest
        || next.trust_bundle_digest.as_deref() != previous.trust_bundle_digest
        || next.recovery_directory_digest.as_deref() != previous.recovery_directory_digest
    {
        return Err("recovery release is not bound to the designated operation");
    }
    Ok(next)
}

/// RELEASED is accepted only after the exact operation reached an accepted
/// terminal state and the required verification evidence authenticated.
/// This gate fails closed today: journal v1 cannot advance past `PREFLIGHTED`
/// (its chain authentication rejects every later phase, so an A10
/// `INACTIVE_VERIFIED` record is not even representable in v1), and the
/// accepted terminal-evidence verifiers (D7 activation `COMMITTED`; the A10
/// inactive branch, which by itself never permits RELEASED or startup) are
/// not implemented.  Evidence is never inferred or fabricated.
fn verify_release_terminal_evidence(phase: crate::restore_journal::RestorePhase) -> Result<()> {
    match phase {
        crate::restore_journal::RestorePhase::Committed => Err(
            "recovery release requires authenticated D7 activation evidence; the D7 evidence verifier is not implemented",
        ),
        _ => Err(
            "recovery release requires accepted terminal activation evidence; journal v1 is limited to PREFLIGHTED and no accepted terminal state is implemented",
        ),
    }
}

fn load_trust(
    policy: &InstallationPolicy,
    state_directory: &ProtectedDirectory,
    gid: u32,
) -> Result<crate::recovery_trust::VerifiedTrust> {
    let bytes = read_protected_config(Path::new(&policy.trust_bundle_path), gid)
        .map_err(|_| "installed recovery trust is unsafe or unavailable")?;
    let initial_digest = hex::encode(Sha256::digest(&bytes));
    if initial_digest != policy.trust_bundle_digest {
        return Err("installed recovery trust digest changed");
    }
    let initial: identity::TrustBundle =
        identity::decode_canonical(&bytes).map_err(|_| "installed recovery trust is malformed")?;
    let current_bytes = state_directory
        .read_bounded("trust.json", 0, gid, 0o640, MAX_DOCUMENT)
        .map_err(|_| "durable recovery trust high-water state is unavailable")?;
    let bundle: identity::TrustBundle = identity::decode_canonical(&current_bytes)
        .map_err(|_| "durable recovery trust state is malformed")?;
    // The durable document is deliberately NOT compared against
    // `policy.trust_bundle_digest`: an accepted revocation refresh advances
    // it past the initial digest.  Its integrity and monotonicity are
    // enforced by the scope/certificate comparison below and by
    // `verify_trust_bundle` against the initial sequence/digest anchors.
    if bundle.installation_id != policy.installation_id
        || bundle.site_id != policy.site_id
        || bundle.profile != policy.profile
        || bundle.backend != policy.backend
        || bundle.journal_root_key_id != policy.journal_trust_root_id
        || bundle.journal_root_public_key != policy.journal_trust_root_public_key
        || bundle.evidence_root_key_id != policy.evidence_trust_root_id
        || bundle.evidence_root_public_key != policy.evidence_trust_root_public_key
        || bundle.journal_certificate != initial.journal_certificate
        || bundle.evidence_certificate != initial.evidence_certificate
    {
        return Err("installed recovery trust scope is invalid");
    }
    let now = chrono::Utc::now().timestamp();
    crate::recovery_trust::verify_trust_bundle(
        bundle,
        &key(&policy.journal_trust_root_public_key)?,
        &key(&policy.evidence_trust_root_public_key)?,
        now,
        Some((
            initial.journal_revocations.payload.sequence,
            &initial.journal_revocation_digest,
        )),
        Some((
            initial.evidence_revocations.payload.sequence,
            &initial.evidence_revocation_digest,
        )),
    )
    .map_err(|_| "installed recovery authority is stale, expired, revoked or conflicting")
}

/// Archive lookup over the protected recovery directories. Only the
/// content-named archive shapes are readable; anything else is ignored.
pub(crate) struct ProtectedArchives<'a> {
    state_directory: &'a ProtectedDirectory,
    journal_directory: Option<&'a ProtectedDirectory>,
    uid: u32,
    gid: u32,
}

impl reanchor::ArchiveLookup for ProtectedArchives<'_> {
    fn read_archive(&self, name: &str) -> Option<Vec<u8>> {
        let (area, digest) = parse_archive_name(name)?;
        let max = MAX_DOCUMENT;
        match area {
            ArchiveArea::StateRoot => self
                .state_directory
                .read_bounded(name, 0, self.gid, 0o640, max)
                .ok()
                .filter(|bytes| hex::encode(Sha256::digest(bytes)) == digest),
            ArchiveArea::JournalDir => self.journal_directory.as_ref().and_then(|directory| {
                directory
                    .read_bounded(name, self.uid, self.gid, 0o600, max)
                    .ok()
                    .filter(|bytes| hex::encode(Sha256::digest(bytes)) == digest)
            }),
        }
    }
}

enum ArchiveArea {
    StateRoot,
    JournalDir,
}

fn parse_archive_name(name: &str) -> Option<(ArchiveArea, String)> {
    let (prefix, rest) = name.split_once('-')?;
    let digest = rest.strip_suffix(".json")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let area = match prefix {
        "state" | "policy" | "trust" => ArchiveArea::StateRoot,
        "checkpoint" => ArchiveArea::JournalDir,
        _ => return None,
    };
    Some((area, digest.to_string()))
}

/// Descriptor-anchored rotation store over the protected installer
/// directories. Fixed-config files land root-owned service-readable (0640),
/// state-root files likewise, and journal files service-owned 0600.
pub(crate) struct ProtectedRotationStore<'a> {
    state_directory: &'a ProtectedDirectory,
    journal_directory: &'a ProtectedDirectory,
    fixed_config: ProtectedDirectory,
    uid: u32,
    gid: u32,
}

fn open_fixed_config_directory() -> std::result::Result<ProtectedDirectory, ReanchorError> {
    use std::os::unix::fs::MetadataExt;
    let path = Path::new("/etc/o3k");
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ReanchorError::Persistence("fixed configuration directory is unavailable"))?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || !metadata.is_dir() {
        return Err(ReanchorError::Persistence(
            "fixed configuration directory posture is invalid",
        ));
    }
    ProtectedDirectory::open(
        path,
        0,
        metadata.gid(),
        metadata.mode() & 0o7777,
        metadata.dev(),
        metadata.ino(),
    )
    .map_err(|_| ReanchorError::Persistence("fixed configuration directory is unsafe"))
}

impl RotationStore for ProtectedRotationStore<'_> {
    fn read(
        &self,
        area: RotationArea,
        name: &str,
    ) -> std::result::Result<Option<Vec<u8>>, ReanchorError> {
        let bytes = match area {
            RotationArea::StateRoot => self
                .state_directory
                .read_bounded(name, 0, self.gid, 0o640, MAX_DOCUMENT)
                .ok(),
            RotationArea::JournalDir => self
                .journal_directory
                .read_bounded(name, self.uid, self.gid, 0o600, MAX_DOCUMENT)
                .ok(),
            RotationArea::FixedConfig => self
                .fixed_config
                .read_bounded(name, 0, self.gid, 0o640, MAX_DOCUMENT)
                .ok(),
        };
        Ok(bytes)
    }

    fn publish(
        &mut self,
        area: RotationArea,
        name: &str,
        bytes: &[u8],
    ) -> std::result::Result<(), ReanchorError> {
        let result = match area {
            RotationArea::StateRoot => self
                .state_directory
                .atomic_publish_installer(name, bytes, 0, self.gid, 0o640),
            RotationArea::JournalDir => self
                .journal_directory
                .atomic_publish_installer(name, bytes, self.uid, self.gid, 0o600),
            RotationArea::FixedConfig => self
                .fixed_config
                .atomic_publish_installer(name, bytes, 0, self.gid, 0o640),
        };
        result.map_err(|_| ReanchorError::Persistence("protected publication failed"))
    }

    fn list(&self, area: RotationArea) -> std::result::Result<Vec<String>, ReanchorError> {
        let directory = match area {
            RotationArea::StateRoot => self.state_directory,
            RotationArea::JournalDir => self.journal_directory,
            RotationArea::FixedConfig => &self.fixed_config,
        };
        directory
            .list_names()
            .map_err(|_| ReanchorError::Persistence("protected directory cannot be listed"))
    }
}

/// Maps a rotated-generation authentication failure to the startup denial
/// reason. The messages stay within the established recovery-denial wording.
fn rotated_denial_reason(error: ReanchorError) -> &'static str {
    match error {
        ReanchorError::Trust(reason) => {
            let _ = reason;
            "installed recovery authority is stale, expired, revoked or conflicting"
        }
        ReanchorError::Signature(reason) => {
            let _ = reason;
            "installation state signature is invalid"
        }
        ReanchorError::Quiescence(reason) => {
            let _ = reason;
            "recovery journal identity cannot be observed"
        }
        ReanchorError::Persistence(reason) => {
            let _ = reason;
            "protected installation state is unavailable"
        }
        ReanchorError::Sequence(reason)
        | ReanchorError::Malformed(reason)
        | ReanchorError::Binding(reason)
        | ReanchorError::Evidence(reason)
        | ReanchorError::Equivocation(reason)
        | ReanchorError::Conflicting(reason) => reason,
        ReanchorError::NotRoot | ReanchorError::InjectedCrash(_) => {
            "authenticated recovery designation denies operational access"
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::recovery_identity::{
        CertificateScope, RevocationDocument, SignatureEnvelope, Signed, TrustBundle,
        TrustCertificate, canonical, digest,
    };
    use crate::restore_journal::RestorePhase;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Serialize;

    const NOW: i64 = 1_800_000_000;
    const JOURNAL_ROOT_ID: &str = "journal-root-1";
    const EVIDENCE_ROOT_ID: &str = "evidence-root-1";
    const JOURNAL_SIGNER_ID: &str = "journal-signer-1";
    const EVIDENCE_SIGNER_ID: &str = "evidence-signer-1";
    const POLICY_DIGEST: &str = "policy-digest";

    fn keypair(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn key_hex(key: &ed25519_dalek::VerifyingKey) -> String {
        hex::encode(key.as_bytes())
    }

    fn sign<T: Serialize + Clone>(
        payload: &T,
        signing: &SigningKey,
        signer_key_id: &str,
    ) -> Signed<T> {
        let canonical_payload = canonical(payload).expect("canonical payload");
        Signed {
            payload: payload.clone(),
            envelope: SignatureEnvelope {
                algorithm: "Ed25519".to_string(),
                signer_key_id: signer_key_id.to_string(),
                signature: hex::encode(signing.sign(&canonical_payload).to_bytes()),
            },
        }
    }

    fn sign_bytes<T: Serialize + Clone>(
        payload: &T,
        signing: &SigningKey,
        signer_key_id: &str,
    ) -> Vec<u8> {
        canonical(&sign(payload, signing, signer_key_id)).expect("canonical signed document")
    }

    struct Fixture {
        journal_root: SigningKey,
        evidence_root: SigningKey,
        journal_signer: SigningKey,
        policy: InstallationPolicy,
        trust: crate::recovery_trust::VerifiedTrust,
        initial: InstallationState,
        initial_digest: String,
        designated: InstallationState,
        designated_digest: String,
        released: InstallationState,
    }

    fn certificate(
        purpose: &str,
        key_id: &str,
        public_key: &str,
        issuer: &str,
    ) -> TrustCertificate {
        let format = match purpose {
            "restore_journal" => "o3k-journal-authority-v1",
            "recovery_evidence" => "o3k-evidence-authority-v1",
            _ => "unknown-purpose",
        };
        TrustCertificate {
            format: format.to_string(),
            key_id: key_id.to_string(),
            public_key: public_key.to_string(),
            purpose: purpose.to_string(),
            site_id: "site-1".to_string(),
            installation_id: "inst-1".to_string(),
            profile: "o3k-demo-v1".to_string(),
            backend: "sqlite".to_string(),
            serial: format!("serial-{key_id}"),
            not_before: NOW - 1000,
            not_after: NOW + 1000,
            issuer: issuer.to_string(),
        }
    }

    fn revocations() -> RevocationDocument {
        RevocationDocument {
            format: "o3k-recovery-revocations-v1".to_string(),
            site_id: "site-1".to_string(),
            profile: "o3k-demo-v1".to_string(),
            sequence: 1,
            issued_at: NOW - 100,
            next_update: NOW + 100,
            revoked_serials: vec![],
            revoked_key_ids: vec![],
        }
    }

    fn fixture() -> Fixture {
        let journal_root = keypair(1);
        let evidence_root = keypair(2);
        let journal_signer = keypair(3);
        let evidence_signer = keypair(4);
        let journal_certificate = sign(
            &certificate(
                "restore_journal",
                JOURNAL_SIGNER_ID,
                &key_hex(&journal_signer.verifying_key()),
                JOURNAL_ROOT_ID,
            ),
            &journal_root,
            JOURNAL_ROOT_ID,
        );
        let evidence_certificate = sign(
            &certificate(
                "recovery_evidence",
                EVIDENCE_SIGNER_ID,
                &key_hex(&evidence_signer.verifying_key()),
                EVIDENCE_ROOT_ID,
            ),
            &evidence_root,
            EVIDENCE_ROOT_ID,
        );
        let journal_revocations = sign(&revocations(), &journal_root, JOURNAL_ROOT_ID);
        let evidence_revocations = sign(&revocations(), &evidence_root, EVIDENCE_ROOT_ID);
        let bundle = TrustBundle {
            format: "o3k-recovery-trust-v1".to_string(),
            site_id: "site-1".to_string(),
            profile: "o3k-demo-v1".to_string(),
            installation_id: "inst-1".to_string(),
            backend: "sqlite".to_string(),
            journal_root_key_id: JOURNAL_ROOT_ID.to_string(),
            journal_root_public_key: key_hex(&journal_root.verifying_key()),
            evidence_root_key_id: EVIDENCE_ROOT_ID.to_string(),
            evidence_root_public_key: key_hex(&evidence_root.verifying_key()),
            journal_revocation_sequence: journal_revocations.payload.sequence,
            journal_revocation_digest: digest(&journal_revocations).expect("digest"),
            evidence_revocation_sequence: evidence_revocations.payload.sequence,
            evidence_revocation_digest: digest(&evidence_revocations).expect("digest"),
            journal_certificate,
            evidence_certificate,
            journal_revocations,
            evidence_revocations,
        };
        let trust_bundle_digest = digest(&bundle).expect("digest");
        let policy = InstallationPolicy {
            format: "o3k-installation-policy-v1".to_string(),
            installation_id: "inst-1".to_string(),
            site_id: "site-1".to_string(),
            profile: "o3k-demo-v1".to_string(),
            backend: "sqlite".to_string(),
            release_identity: hex::encode([9; 32]),
            data_root: "/var/lib/o3k".to_string(),
            target_device: 2049,
            target_inode: 12_345,
            policy_revision: 1,
            prior_policy_digest: hex::encode([8; 32]),
            policy_path: "/etc/o3k/installation-policy.json".to_string(),
            trust_bundle_path: "/etc/o3k/recovery-trust.json".to_string(),
            trust_bundle_digest,
            recovery_state_root: "/var/lib/o3k-recovery-state/inst-1".to_string(),
            recovery_state_device: 2049,
            recovery_state_inode: 45_678,
            journal_directory: "/var/lib/o3k-recovery/inst-1".to_string(),
            journal_device: 2049,
            journal_inode: 78_901,
            journal_trust_root_id: JOURNAL_ROOT_ID.to_string(),
            journal_trust_root_public_key: key_hex(&journal_root.verifying_key()),
            evidence_trust_root_id: EVIDENCE_ROOT_ID.to_string(),
            evidence_trust_root_public_key: key_hex(&evidence_root.verifying_key()),
            signer_key_id: "policy-signer-1".to_string(),
        };
        let trust = crate::recovery_trust::verify_trust_bundle(
            bundle,
            &journal_root.verifying_key(),
            &evidence_root.verifying_key(),
            NOW,
            None,
            None,
        )
        .expect("fixture trust verifies");
        let initial = InstallationState {
            format: "o3k-installation-state-v1".to_string(),
            installation_id: policy.installation_id.clone(),
            site_id: policy.site_id.clone(),
            profile: policy.profile.clone(),
            backend: policy.backend.clone(),
            policy_revision: policy.policy_revision,
            policy_digest: POLICY_DIGEST.to_string(),
            target_device: policy.target_device,
            target_inode: policy.target_inode,
            sequence: 0,
            prior_record_digest: String::new(),
            state: RecoveryState::NeverRecovered,
            operation_id: None,
            artifact_sha256: None,
            recovery_directory_digest: None,
            trust_bundle_digest: None,
            terminal_journal_digest: None,
            evidence_digest: None,
        };
        let initial_digest = digest(&initial).expect("digest");
        let designated = InstallationState {
            sequence: 1,
            prior_record_digest: initial_digest.clone(),
            state: RecoveryState::RecoveryDesignated,
            operation_id: Some(uuid::Uuid::now_v7().to_string()),
            artifact_sha256: Some(hex::encode([4; 32])),
            recovery_directory_digest: Some(journal_identity_digest(&policy).expect("digest")),
            trust_bundle_digest: Some(policy.trust_bundle_digest.clone()),
            terminal_journal_digest: None,
            evidence_digest: None,
            ..initial.clone()
        };
        let designated_digest = digest(&designated).expect("digest");
        let released = InstallationState {
            sequence: 2,
            prior_record_digest: designated_digest.clone(),
            state: RecoveryState::Released,
            terminal_journal_digest: Some(hex::encode([6; 32])),
            evidence_digest: Some(hex::encode([11; 32])),
            ..designated.clone()
        };
        Fixture {
            journal_root,
            evidence_root,
            journal_signer,
            policy,
            trust,
            initial,
            initial_digest,
            designated,
            designated_digest,
            released,
        }
    }

    #[test]
    fn startup_accepts_designated_sequence_at_least_one() {
        let fixture = fixture();
        assert_eq!(startup_state_check(&fixture.designated), Ok(()));
        assert_eq!(
            startup_state_check(&fixture.released),
            Err("installation state RELEASED is a recovery disposition, not a startup authority")
        );
        // A designation after a C1.1 re-anchor rotation sits at sequence >= 2:
        // the disposition transitions from the re-anchor tip, so any real
        // designation (sequence >= 1) authenticates at startup.
        let mut later = fixture.designated.clone();
        later.sequence = 2;
        assert_eq!(startup_state_check(&later), Ok(()));
        assert_eq!(
            startup_state_check(&fixture.initial),
            Err("recovery release requires accepted activation evidence")
        );
    }

    #[test]
    fn release_terminal_evidence_gate_never_passes() {
        for phase in [
            RestorePhase::Preflighted,
            RestorePhase::SourceFenced,
            RestorePhase::TargetReserved,
            RestorePhase::Staging,
            RestorePhase::DatabaseRestored,
            RestorePhase::FilesRestored,
            RestorePhase::TargetFenced,
            RestorePhase::Started,
            RestorePhase::Reconciled,
            RestorePhase::Committed,
            RestorePhase::Aborted,
            RestorePhase::FailedRecoverable,
            RestorePhase::Quarantined,
            RestorePhase::Discarded,
        ] {
            let result = verify_release_terminal_evidence(phase);
            assert!(
                result.is_err(),
                "phase {phase:?} must not authorize RELEASED persistence"
            );
            let message = result.unwrap_err();
            assert!(
                message.contains("activation evidence"),
                "fail-closed error must name the missing evidence: {message}"
            );
        }
        // The v1 chain authenticator rejects every post-PREFLIGHTED phase, so
        // an A10 INACTIVE_VERIFIED record is not even representable here; the
        // gate remains the explicit backstop.
        assert!(
            verify_release_terminal_evidence(RestorePhase::Preflighted)
                .unwrap_err()
                .contains("journal v1 is limited to PREFLIGHTED")
        );
        assert!(
            verify_release_terminal_evidence(RestorePhase::Committed)
                .unwrap_err()
                .contains("D7 activation evidence")
        );
    }

    #[test]
    fn data_root_postures_cover_packaged_and_routine_layouts() {
        let with_compute = data_root_postures(100, 100, Some(120));
        assert!(with_compute.contains(&DirectoryPosture {
            uid: 100,
            gid: 100,
            mode: 0o700
        }));
        assert!(with_compute.contains(&DirectoryPosture {
            uid: 100,
            gid: 120,
            mode: 0o711
        }));
        // Group/world-writable postures are never offered.
        assert!(with_compute.iter().all(|p| p.mode & 0o022 == 0));
        // Without the compute group the packaged posture cannot be described
        // and is not offered.
        let without_compute = data_root_postures(100, 100, None);
        assert_eq!(without_compute.len(), 1);
        assert_eq!(without_compute[0].mode, 0o700);
    }

    #[test]
    fn journal_identity_digest_binds_directory_device_and_inode() {
        let fixture = fixture();
        let expected = journal_identity_digest(&fixture.policy).expect("digest");
        assert_eq!(expected.len(), 64);
        let mut changed = fixture.policy.clone();
        changed.journal_inode += 1;
        assert_ne!(journal_identity_digest(&changed).expect("digest"), expected);
        let mut changed = fixture.policy.clone();
        changed.journal_directory = "/var/lib/o3k-recovery/other".to_string();
        assert_ne!(journal_identity_digest(&changed).expect("digest"), expected);
    }

    #[test]
    fn designation_record_verifies_against_observed_predecessor() {
        let fixture = fixture();
        let signed = sign_bytes(
            &fixture.designated,
            &fixture.journal_signer,
            JOURNAL_SIGNER_ID,
        );
        let verified = verify_designation_record(
            &identity::state_tip_view(&fixture.initial),
            &fixture.initial_digest,
            &fixture.policy,
            POLICY_DIGEST,
            &fixture.trust,
            &signed,
        )
        .expect("valid designation verifies");
        assert_eq!(verified, fixture.designated);
    }

    #[test]
    fn designation_record_rejects_unknown_revoked_and_wrong_purpose_signers() {
        let fixture = fixture();
        // Unknown signer key ID.
        let unknown = keypair(50);
        let signed = sign_bytes(&fixture.designated, &unknown, "unknown-signer");
        assert_eq!(
            verify_designation_record(
                &identity::state_tip_view(&fixture.initial),
                &fixture.initial_digest,
                &fixture.policy,
                POLICY_DIGEST,
                &fixture.trust,
                &signed
            ),
            Err("recovery designation signer is unknown or revoked")
        );
        // Evidence signer is installed but never a journal authority.
        let signed = sign_bytes(&fixture.designated, &keypair(4), EVIDENCE_SIGNER_ID);
        assert_eq!(
            verify_designation_record(
                &identity::state_tip_view(&fixture.initial),
                &fixture.initial_digest,
                &fixture.policy,
                POLICY_DIGEST,
                &fixture.trust,
                &signed
            ),
            Err("recovery designation signer is unknown or revoked")
        );
        // A revoked or rotated journal signer is no longer installed, so the
        // bundle installs a replacement certificate and the old signer key ID
        // no longer resolves.
        let mut rotated_fixture = fixture;
        let replacement_signer = keypair(60);
        let mut bundle = rotated_fixture.trust.bundle.clone();
        bundle.journal_certificate = sign(
            &certificate(
                "restore_journal",
                "journal-signer-2",
                &key_hex(&replacement_signer.verifying_key()),
                JOURNAL_ROOT_ID,
            ),
            &rotated_fixture.journal_root,
            JOURNAL_ROOT_ID,
        );
        rotated_fixture.trust = crate::recovery_trust::verify_trust_bundle(
            bundle,
            &rotated_fixture.journal_root.verifying_key(),
            &rotated_fixture.evidence_root.verifying_key(),
            NOW,
            None,
            None,
        )
        .expect("rotated bundle verifies");
        let signed = sign_bytes(
            &rotated_fixture.designated,
            &rotated_fixture.journal_signer,
            JOURNAL_SIGNER_ID,
        );
        assert_eq!(
            verify_designation_record(
                &identity::state_tip_view(&rotated_fixture.initial),
                &rotated_fixture.initial_digest,
                &rotated_fixture.policy,
                POLICY_DIGEST,
                &rotated_fixture.trust,
                &signed
            ),
            Err("recovery designation signer is unknown or revoked")
        );
    }

    #[test]
    fn designation_record_rejects_tampered_binding_and_wrong_state() {
        let fixture = fixture();
        // Wrong predecessor digest: anti-rollback.
        let signed = sign_bytes(
            &fixture.designated,
            &fixture.journal_signer,
            JOURNAL_SIGNER_ID,
        );
        assert_eq!(
            verify_designation_record(
                &identity::state_tip_view(&fixture.initial),
                &hex::encode([0xde; 32]),
                &fixture.policy,
                POLICY_DIGEST,
                &fixture.trust,
                &signed
            ),
            Err("recovery designation predecessor is invalid")
        );
        // Trust-bundle binding differs from the signed policy.
        let mut tampered = fixture.designated.clone();
        tampered.trust_bundle_digest = Some(hex::encode([0xad; 32]));
        let signed = sign_bytes(&tampered, &fixture.journal_signer, JOURNAL_SIGNER_ID);
        assert_eq!(
            verify_designation_record(
                &identity::state_tip_view(&fixture.initial),
                &fixture.initial_digest,
                &fixture.policy,
                POLICY_DIGEST,
                &fixture.trust,
                &signed
            ),
            Err("recovery designation is not bound to this installation")
        );
        // Recovery-directory identity differs from the policy binding.
        let mut tampered = fixture.designated.clone();
        tampered.recovery_directory_digest = Some(hex::encode([0xbe; 32]));
        let signed = sign_bytes(&tampered, &fixture.journal_signer, JOURNAL_SIGNER_ID);
        assert_eq!(
            verify_designation_record(
                &identity::state_tip_view(&fixture.initial),
                &fixture.initial_digest,
                &fixture.policy,
                POLICY_DIGEST,
                &fixture.trust,
                &signed
            ),
            Err("recovery designation is not bound to this installation")
        );
        // A RELEASED record is never a designation, even with a structurally
        // valid predecessor chain.
        let signed = sign_bytes(
            &fixture.released,
            &fixture.journal_signer,
            JOURNAL_SIGNER_ID,
        );
        assert_eq!(
            verify_designation_record(
                &identity::state_tip_view(&fixture.designated),
                &fixture.designated_digest,
                &fixture.policy,
                POLICY_DIGEST,
                &fixture.trust,
                &signed
            ),
            Err("recovery designation is not bound to this installation")
        );
        // Non-canonical bytes are rejected before any signature math.
        assert_eq!(
            verify_designation_record(
                &identity::state_tip_view(&fixture.initial),
                &fixture.initial_digest,
                &fixture.policy,
                POLICY_DIGEST,
                &fixture.trust,
                b"not canonical"
            ),
            Err("recovery designation is malformed")
        );
    }

    #[test]
    fn release_record_verifies_but_terminal_gate_keeps_release_unavailable() {
        let fixture = fixture();
        let signed = sign_bytes(
            &fixture.released,
            &fixture.journal_signer,
            JOURNAL_SIGNER_ID,
        );
        // Every structural check passes: the only remaining barrier is the
        // fail-closed terminal-evidence gate.
        let verified = verify_release_record(
            &identity::state_tip_view(&fixture.designated),
            &fixture.designated_digest,
            &fixture.policy,
            POLICY_DIGEST,
            &fixture.trust,
            &signed,
        )
        .expect("valid RELEASED record passes structural checks");
        assert_eq!(verified, fixture.released);
        assert_eq!(
            verify_release_terminal_evidence(RestorePhase::Preflighted),
            Err(
                "recovery release requires accepted terminal activation evidence; journal v1 is limited to PREFLIGHTED and no accepted terminal state is implemented"
            )
        );
    }

    #[test]
    fn release_record_rejects_wrong_predecessor_state_and_binding_drift() {
        let fixture = fixture();
        let signed = sign_bytes(
            &fixture.released,
            &fixture.journal_signer,
            JOURNAL_SIGNER_ID,
        );
        // RELEASED from NEVER_RECOVERED skips designation.
        assert_eq!(
            verify_release_record(
                &identity::state_tip_view(&fixture.initial),
                &fixture.initial_digest,
                &fixture.policy,
                POLICY_DIGEST,
                &fixture.trust,
                &signed
            ),
            Err("recovery release predecessor is invalid")
        );
        // Designation binding drift after designation.
        let mut drifted = fixture.released.clone();
        drifted.trust_bundle_digest = Some(hex::encode([0xc1; 32]));
        let signed = sign_bytes(&drifted, &fixture.journal_signer, JOURNAL_SIGNER_ID);
        assert_eq!(
            verify_release_record(
                &identity::state_tip_view(&fixture.designated),
                &fixture.designated_digest,
                &fixture.policy,
                POLICY_DIGEST,
                &fixture.trust,
                &signed
            ),
            Err("recovery release is not bound to the designated operation")
        );
        // Operation continuity broken: the artifact changed after designation.
        let mut drifted = fixture.released.clone();
        drifted.artifact_sha256 = Some(hex::encode([0xc2; 32]));
        let signed = sign_bytes(&drifted, &fixture.journal_signer, JOURNAL_SIGNER_ID);
        assert_eq!(
            verify_release_record(
                &identity::state_tip_view(&fixture.designated),
                &fixture.designated_digest,
                &fixture.policy,
                POLICY_DIGEST,
                &fixture.trust,
                &signed
            ),
            Err("recovery release predecessor is invalid")
        );
        // A designation record presented as a release disposition.
        let signed = sign_bytes(
            &fixture.designated,
            &fixture.journal_signer,
            JOURNAL_SIGNER_ID,
        );
        assert_eq!(
            verify_release_record(
                &identity::state_tip_view(&fixture.initial),
                &fixture.initial_digest,
                &fixture.policy,
                POLICY_DIGEST,
                &fixture.trust,
                &signed
            ),
            Err("recovery release is not bound to the designated operation")
        );
    }

    #[test]
    fn certificate_scope_fixture_matches_trust_verifier_shape() {
        // Guard the fixture against scope drift: the trust verifier binds the
        // certificate scope exactly as the installation policy does.
        let fixture = fixture();
        let scope = CertificateScope {
            purpose: "restore_journal",
            site: &fixture.policy.site_id,
            installation: &fixture.policy.installation_id,
            profile: &fixture.policy.profile,
            backend: &fixture.policy.backend,
            issuer: JOURNAL_ROOT_ID,
            now: NOW,
        };
        identity::verify_certificate_binding(
            &fixture.trust.bundle.journal_certificate.payload,
            scope,
        )
        .expect("fixture certificate binds to the policy scope");
    }
}
