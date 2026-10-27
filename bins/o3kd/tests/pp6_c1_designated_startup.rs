//! Real-process C1 startup-denial evidence for an authenticated
//! RECOVERY_DESIGNATED installation (issue #1086).
//!
//! The fixture is signed with clearly test-only ed25519 keys by this test
//! itself; it is implementation evidence, not production qualification, an
//! authenticated installed-release acceptance gate, or a signing-tool
//! substitute.  Every scenario runs the real `o3kd` daemon (or the real
//! store-opening `o3k` maintenance commands) in a private mount namespace and
//! asserts denial before any API listener or canonical store access.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{
    fs,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use ed25519_dalek::{Signer, SigningKey};
use o3k::recovery_identity as identity;
use o3k::restore_journal;
use serde_json::json;
use sha2::Digest;

const O3K_UID: u32 = 900;
const O3K_GID: u32 = 900;
const RELEASE_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const BACKUP_ARTIFACT_SHA256: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";

// ---- test-only fixture keys (fixed seeds; never real material) ----

struct Keys {
    policy: SigningKey,
    journal_root: SigningKey,
    evidence_root: SigningKey,
    journal_signer: SigningKey,
    evidence_signer: SigningKey,
}

impl Keys {
    fn test_only() -> Self {
        Self {
            policy: SigningKey::from_bytes(&[0xA1; 32]),
            journal_root: SigningKey::from_bytes(&[0xB2; 32]),
            evidence_root: SigningKey::from_bytes(&[0xC3; 32]),
            journal_signer: SigningKey::from_bytes(&[0xD4; 32]),
            evidence_signer: SigningKey::from_bytes(&[0xE5; 32]),
        }
    }

    fn policy_id(&self) -> String {
        "test-policy-signer-1".to_string()
    }
    fn journal_root_id(&self) -> String {
        "test-journal-root-1".to_string()
    }
    fn evidence_root_id(&self) -> String {
        "test-evidence-root-1".to_string()
    }
    fn journal_signer_id(&self) -> String {
        "test-journal-signer-1".to_string()
    }
    fn evidence_signer_id(&self) -> String {
        "test-evidence-signer-1".to_string()
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn key_hex(key: &ed25519_dalek::VerifyingKey) -> String {
    to_hex(key.as_bytes())
}

fn signed_envelope<T: serde::Serialize + Clone>(
    payload: &T,
    signing: &SigningKey,
    signer_key_id: &str,
) -> identity::Signed<T> {
    let canonical_payload = identity::canonical(payload).expect("canonical payload");
    identity::Signed {
        payload: payload.clone(),
        envelope: identity::SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            signer_key_id: signer_key_id.to_string(),
            signature: to_hex(&signing.sign(&canonical_payload).to_bytes()),
        },
    }
}

fn sign<T: serde::Serialize + Clone>(
    payload: &T,
    signing: &SigningKey,
    signer_key_id: &str,
) -> Vec<u8> {
    identity::canonical(&signed_envelope(payload, signing, signer_key_id))
        .expect("canonical signed document")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    Control,
    RevokedSigner,
    StaleCertificate,
}

/// One authenticated RECOVERY_DESIGNATED installation fixture rooted under
/// `/var/lib` so the namespace bind of `var` onto `/var/lib` presents the
/// canonical layout, and so every identity is derived from real inodes.
struct DesignatedFixture {
    root: PathBuf,
    data_dir_host: PathBuf,
    journal_dir_host: PathBuf,
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
        .map_err(|e| format!("chown {}: {e}", path.display()))
}

fn posture(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

fn write_root_o3k(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    chown(path, 0, O3K_GID)?;
    posture(path, 0o640)
}

fn finish_fixture(
    root: &Path,
    data: PathBuf,
    journal_dir: PathBuf,
) -> Result<DesignatedFixture, String> {
    Ok(DesignatedFixture {
        root: root.to_path_buf(),
        data_dir_host: data,
        journal_dir_host: journal_dir,
    })
}

fn build(root: &Path, variant: Variant) -> Result<DesignatedFixture, String> {
    let keys = Keys::test_only();
    let now = chrono::Utc::now().timestamp();

    let var = root.join("var");
    let etc = var.join("etc-fixture");
    let etc_o3k = etc.join("o3k");
    let share = var.join("share-fixture");
    for dir in [&var, &etc, &etc_o3k, &share] {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        chown(dir, 0, 0)?;
        posture(dir, 0o755)?;
    }
    fs::write(
        etc.join("passwd"),
        b"root:x:0:0:root:/root:/bin/sh\no3k:x:900:900::/var/lib/o3k:/usr/sbin/nologin\n",
    )
    .map_err(|e| format!("write passwd: {e}"))?;
    fs::write(
        etc.join("group"),
        b"root:x:0:\no3k:x:900:\no3k-compute:x:901:\n",
    )
    .map_err(|e| format!("write group: {e}"))?;

    // Data root in the routine accepted posture.
    let data = var.join("o3k");
    fs::create_dir(&data).map_err(|e| format!("mkdir data: {e}"))?;
    chown(&data, O3K_UID, O3K_GID)?;
    posture(&data, 0o700)?;
    let data_meta = fs::metadata(&data).map_err(|e| e.to_string())?;

    // Identity tokens derive from the canonical path string, so they must be
    // computed from the literal in-namespace data-root path (the fixture
    // directory is bind-mounted at /var/lib inside the namespace).
    let (installation_token, site_token) = o3k_store::identity_tokens(Path::new("/var/lib/o3k"))
        .map_err(|e| format!("identity tokens: {e}"))?;
    let installation_id = to_hex(&installation_token);
    let site_id = to_hex(&site_token);

    let state_dir = var.join("o3k-recovery-state").join(&installation_id);
    let journal_dir = var.join("o3k-recovery").join(&installation_id);
    for (dir, uid, gid, mode) in [
        (var.join("o3k-recovery-state"), 0, 0, 0o755),
        (var.join("o3k-recovery"), 0, 0, 0o755),
        (state_dir.clone(), 0, O3K_GID, 0o750),
        (journal_dir.clone(), O3K_UID, O3K_GID, 0o700),
    ] {
        fs::create_dir(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        chown(&dir, uid, gid)?;
        posture(&dir, mode)?;
    }
    let state_meta = fs::metadata(&state_dir).map_err(|e| e.to_string())?;
    let journal_meta = fs::metadata(&journal_dir).map_err(|e| e.to_string())?;

    // Installed trust bundle: test-only offline roots sign purpose-bound
    // certificates and the initial revocation documents.
    let certificate =
        |purpose: &str, key_id: &str, public_key: &str, issuer: &str| identity::TrustCertificate {
            format: match purpose {
                "restore_journal" => "o3k-journal-authority-v1",
                "recovery_evidence" => "o3k-evidence-authority-v1",
                _ => "unknown",
            }
            .to_string(),
            key_id: key_id.to_string(),
            public_key: public_key.to_string(),
            purpose: purpose.to_string(),
            site_id: site_id.clone(),
            installation_id: installation_id.clone(),
            profile: "o3k-demo-v1".to_string(),
            backend: "sqlite".to_string(),
            serial: format!("serial-{key_id}"),
            not_before: now - 1000,
            not_after: match variant {
                Variant::StaleCertificate => now - 100,
                _ => now + 86_000,
            },
            issuer: issuer.to_string(),
        };
    let (journal_nb, journal_na) = (now - 100, now + 86_300);
    let journal_revocations = identity::RevocationDocument {
        format: "o3k-recovery-revocations-v1".to_string(),
        site_id: site_id.clone(),
        profile: "o3k-demo-v1".to_string(),
        sequence: 1,
        issued_at: journal_nb,
        next_update: journal_na,
        revoked_serials: vec![],
        revoked_key_ids: match variant {
            Variant::RevokedSigner => vec![keys.journal_signer_id()],
            _ => vec![],
        },
    };
    let evidence_revocations = identity::RevocationDocument {
        issued_at: now - 100,
        next_update: now + 86_300,
        ..journal_revocations.clone()
    };
    let journal_certificate = signed_envelope(
        &certificate(
            "restore_journal",
            &keys.journal_signer_id(),
            &key_hex(&keys.journal_signer.verifying_key()),
            &keys.journal_root_id(),
        ),
        &keys.journal_root,
        &keys.journal_root_id(),
    );
    let evidence_certificate = signed_envelope(
        &certificate(
            "recovery_evidence",
            &keys.evidence_signer_id(),
            &key_hex(&keys.evidence_signer.verifying_key()),
            &keys.evidence_root_id(),
        ),
        &keys.evidence_root,
        &keys.evidence_root_id(),
    );
    let journal_revocations = signed_envelope(
        &journal_revocations,
        &keys.journal_root,
        &keys.journal_root_id(),
    );
    let evidence_revocations = signed_envelope(
        &evidence_revocations,
        &keys.evidence_root,
        &keys.evidence_root_id(),
    );
    let bundle = identity::TrustBundle {
        format: "o3k-recovery-trust-v1".to_string(),
        site_id: site_id.clone(),
        profile: "o3k-demo-v1".to_string(),
        installation_id: installation_id.clone(),
        backend: "sqlite".to_string(),
        journal_root_key_id: keys.journal_root_id(),
        journal_root_public_key: key_hex(&keys.journal_root.verifying_key()),
        evidence_root_key_id: keys.evidence_root_id(),
        evidence_root_public_key: key_hex(&keys.evidence_root.verifying_key()),
        journal_revocation_sequence: journal_revocations.payload.sequence,
        journal_revocation_digest: identity::digest(&journal_revocations)
            .map_err(|e| format!("digest: {e:?}"))?,
        evidence_revocation_sequence: evidence_revocations.payload.sequence,
        evidence_revocation_digest: identity::digest(&evidence_revocations)
            .map_err(|e| format!("digest: {e:?}"))?,
        journal_certificate,
        evidence_certificate,
        journal_revocations,
        evidence_revocations,
    };
    let trust_bytes = identity::canonical(&bundle).map_err(|e| format!("canonical: {e:?}"))?;

    // Release manifest authenticates the test-only policy verification key.
    let manifest = json!({
        "version": "v0.4.0-rc.5",
        "profile": "libvirt",
        "profile_id": "o3k-demo-v1",
        "source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "workflow": "test-fixture",
        "installer_sha256": to_hex(&[0u8; 32]),
        "release_artifact_sha256": RELEASE_SHA256,
        "schema_version": "1",
        "installation_policy_format": "o3k-installation-policy-v1",
        "installation_policy_path": "/etc/o3k/installation-policy.json",
        "installation_policy_authority": {
            "key_id": keys.policy_id(),
            "ed25519_public_key": key_hex(&keys.policy.verifying_key()),
        },
    });
    fs::write(
        share.join("release-manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .map_err(|e| format!("write manifest: {e}"))?;

    let policy = identity::InstallationPolicy {
        format: "o3k-installation-policy-v1".to_string(),
        installation_id: installation_id.clone(),
        site_id: site_id.clone(),
        profile: "o3k-demo-v1".to_string(),
        backend: "sqlite".to_string(),
        release_identity: RELEASE_SHA256.to_string(),
        data_root: "/var/lib/o3k".to_string(),
        target_device: data_meta.dev(),
        target_inode: data_meta.ino(),
        policy_revision: 1,
        prior_policy_digest: to_hex(&[8u8; 32]),
        policy_path: "/etc/o3k/installation-policy.json".to_string(),
        trust_bundle_path: "/etc/o3k/recovery-trust.json".to_string(),
        trust_bundle_digest: to_hex(&sha2::Sha256::digest(&trust_bytes)),
        recovery_state_root: format!("/var/lib/o3k-recovery-state/{installation_id}"),
        recovery_state_device: state_meta.dev(),
        recovery_state_inode: state_meta.ino(),
        journal_directory: format!("/var/lib/o3k-recovery/{installation_id}"),
        journal_device: journal_meta.dev(),
        journal_inode: journal_meta.ino(),
        journal_trust_root_id: keys.journal_root_id(),
        journal_trust_root_public_key: key_hex(&keys.journal_root.verifying_key()),
        evidence_trust_root_id: keys.evidence_root_id(),
        evidence_trust_root_public_key: key_hex(&keys.evidence_root.verifying_key()),
        signer_key_id: keys.policy_id(),
    };
    identity::verify_policy(&policy, &keys.policy_id())
        .map_err(|e| format!("policy invalid: {e:?}"))?;
    let policy_bytes = sign(&policy, &keys.policy, &keys.policy_id());

    let initial = identity::InstallationState {
        format: "o3k-installation-state-v1".to_string(),
        installation_id: installation_id.clone(),
        site_id: site_id.clone(),
        profile: "o3k-demo-v1".to_string(),
        backend: "sqlite".to_string(),
        policy_revision: 1,
        policy_digest: to_hex(&sha2::Sha256::digest(&policy_bytes)),
        target_device: data_meta.dev(),
        target_inode: data_meta.ino(),
        sequence: 0,
        prior_record_digest: String::new(),
        state: identity::RecoveryState::NeverRecovered,
        operation_id: None,
        artifact_sha256: None,
        recovery_directory_digest: None,
        trust_bundle_digest: None,
        terminal_journal_digest: None,
        evidence_digest: None,
    };
    let initial_bytes = sign(&initial, &keys.policy, &keys.policy_id());
    let initial_digest = to_hex(&sha2::Sha256::digest(&initial_bytes));

    let operation_id = uuid::Uuid::now_v7();
    let journal_identity_digest = identity::digest(&(
        policy.journal_directory.as_str(),
        policy.journal_device,
        policy.journal_inode,
    ))
    .map_err(|e| format!("journal identity digest: {e:?}"))?;
    let designated = identity::InstallationState {
        sequence: 1,
        prior_record_digest: initial_digest.clone(),
        state: identity::RecoveryState::RecoveryDesignated,
        operation_id: Some(operation_id.to_string()),
        artifact_sha256: Some(BACKUP_ARTIFACT_SHA256.to_string()),
        recovery_directory_digest: Some(journal_identity_digest),
        trust_bundle_digest: Some(policy.trust_bundle_digest.clone()),
        terminal_journal_digest: None,
        evidence_digest: None,
        ..initial.clone()
    };
    identity::verify_state_transition_with_previous_digest(
        Some(&initial),
        Some(&initial_digest),
        &designated,
        &policy,
    )
    .map_err(|e| format!("designated transition invalid: {e:?}"))?;
    let designated_bytes = sign(&designated, &keys.journal_signer, &keys.journal_signer_id());

    // Journal v1 PREFLIGHTED record bound to the designation.  A10
    // INACTIVE_VERIFIED is a journal-v2 phase and is intentionally not
    // representable here; journal v1 cannot advance past PREFLIGHTED.
    let binding = restore_journal::RequestBinding {
        operation_id,
        site_id: site_id.clone(),
        artifact_sha256: BACKUP_ARTIFACT_SHA256.to_string(),
        target_installation_id: installation_id.clone(),
        target_device: data_meta.dev(),
        target_inode: data_meta.ino(),
        target_database_identity: "sqlite-fixture-v1".to_string(),
        source_installation_id: to_hex(&[7u8; 16]),
        journal_authority_id: keys.journal_signer_id(),
        sequence: 1,
        previous_signed_hash: String::new(),
        intended_transition: restore_journal::RestorePhase::Preflighted,
    };
    let request = restore_journal::initial_preflight_request(&binding)
        .map_err(|e| format!("journal request: {e:?}"))?;
    let request_bytes = restore_journal::canonical_request(&request)
        .map_err(|e| format!("canonical request: {e:?}"))?;
    let response = restore_journal::SigningResponse {
        format: restore_journal::RESPONSE_FORMAT.to_string(),
        request_sha256: to_hex(&sha2::Sha256::digest(&request_bytes)),
        key_id: keys.journal_signer_id(),
        signature: to_hex(&keys.journal_signer.sign(&request_bytes).to_bytes()),
    };
    let transition = restore_journal::verify_response(
        &request,
        &response,
        &keys.journal_signer_id(),
        &keys.journal_signer.verifying_key(),
    )
    .map_err(|e| format!("journal response: {e:?}"))?;
    let envelope = json!({
        "format": restore_journal::JOURNAL_FORMAT,
        "transitions": [serde_json::to_value(&transition).unwrap()],
    });
    let journal_bytes =
        identity::canonical(&envelope).map_err(|e| format!("journal jcs: {e:?}"))?;

    // Authenticated-journal self-check with the same public verifier the
    // daemon uses; a fixture bug fails here, not as a misleading deny.
    let trust_check = o3k::recovery_trust::verify_trust_bundle(
        bundle,
        &keys.journal_root.verifying_key(),
        &keys.evidence_root.verifying_key(),
        now,
        None,
        None,
    );
    let trust: Option<o3k::recovery_trust::VerifiedTrust> = match variant {
        Variant::Control => {
            Some(trust_check.map_err(|e| format!("control fixture trust does not verify: {e:?}"))?)
        }
        Variant::RevokedSigner | Variant::StaleCertificate => {
            // The variant fixtures intentionally carry revoked or expired
            // authority: startup denial is the expected outcome, proven by
            // the process scenarios below.
            assert!(
                trust_check.is_err(),
                "revoked/stale fixture trust unexpectedly verified"
            );
            // The revoked/stale variants are written below exactly like the
            // control fixture; the daemon reaches trust verification and
            // denies there.  The journal self-check is control-only.
            assert!(trust_check.is_err());
            None
        }
    };
    if let Some(trust) = &trust {
        restore_journal::authenticate_installed_chain(
            &journal_bytes,
            &policy,
            trust,
            operation_id,
            BACKUP_ARTIFACT_SHA256,
        )
        .map_err(|e| format!("fixture journal does not authenticate: {e:?}"))?;
    }

    write_root_o3k(&etc_o3k.join("installation-policy.json"), &policy_bytes)?;
    write_root_o3k(&etc_o3k.join("recovery-trust.json"), &trust_bytes)?;
    write_root_o3k(&state_dir.join("policy.json"), &policy_bytes)?;
    write_root_o3k(&state_dir.join("trust.json"), &trust_bytes)?;
    write_root_o3k(&state_dir.join("state.json"), &designated_bytes)?;
    write_root_o3k(
        &state_dir.join(format!("state-{initial_digest}.json")),
        &initial_bytes,
    )?;
    fs::write(journal_dir.join("restore-journal.json"), &journal_bytes)
        .map_err(|e| format!("write journal: {e}"))?;
    chown(&journal_dir.join("restore-journal.json"), O3K_UID, O3K_GID)?;
    posture(&journal_dir.join("restore-journal.json"), 0o600)?;

    finish_fixture(root, data, journal_dir)
}

impl DesignatedFixture {
    fn install_legacy_restore_config(&self) -> Result<(), String> {
        let etc_o3k = self.root.join("var/etc-fixture/o3k");
        let value = serde_json::json!({
            "format": "o3k-restore-preflight-v1",
            "backend": "sqlite",
            "target_directory": "/var/lib/o3k",
            "recovery_directory": "/var/lib/legacy-recovery",
        });
        write_root_o3k(
            &etc_o3k.join("restore.json"),
            &serde_json::to_vec(&value).unwrap(),
        )
    }
}

impl Drop for DesignatedFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fixture_root() -> Option<PathBuf> {
    if rustix::process::geteuid().as_raw() != 0 {
        return None;
    }
    let path = PathBuf::from(format!(
        "/var/lib/o3k-c1-designated-{}",
        uuid::Uuid::now_v7()
    ));
    fs::create_dir(&path).ok()?;
    Some(path)
}

fn run_namespaced(fixture: &DesignatedFixture, inner: &str, stderr_name: &str) -> (String, bool) {
    let o3k_bin = Path::new(env!("CARGO_BIN_EXE_o3kd")).with_file_name("o3k");
    let script = format!(
        "set -u; mount --make-rprivate /; \
         mount --bind {0} /var/lib; \
         mount --bind /var/lib/etc-fixture /etc; \
         mount --bind /var/lib/share-fixture /usr/local/share/o3k; \
         test -d /var/lib/o3k; echo C1_DESIGNATED_NAMESPACE_READY >&2; {1}",
        fixture.root.join("var").display(),
        inner
            .replace("{o3kd}", env!("CARGO_BIN_EXE_o3kd"))
            .replace("{o3k}", &o3k_bin.display().to_string())
            .replace("{stderr}", &format!("/var/lib/{stderr_name}"))
    );
    let output = Command::new("unshare")
        .args(["--mount", "--fork", "--", "sh", "-c", &script])
        .output()
        .expect("unshare");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        stderr.contains("C1_DESIGNATED_NAMESPACE_READY"),
        "namespace mounts failed: {stderr}"
    );
    let captured = fs::read_to_string(fixture.root.join("var").join(stderr_name))
        .unwrap_or_else(|_| String::new());
    (captured, output.status.success())
}

fn unused_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
}

fn assert_denied(
    case: &str,
    stderr: &str,
    succeeded: bool,
    fixture: &DesignatedFixture,
    address: Option<SocketAddr>,
) -> Result<(), String> {
    if succeeded {
        return Err(format!(
            "{case}: daemon/command unexpectedly succeeded: {stderr}"
        ));
    }
    if stderr.trim().is_empty() {
        return Err(format!("{case}: no denial output captured"));
    }
    // Guard acquired before denial, canonical store untouched.
    if !fixture.data_dir_host.join(".o3k-store.lock").exists() {
        return Err(format!(
            "{case}: store-access guard lock absent before denial"
        ));
    }
    if fixture.data_dir_host.join("o3k.sqlite").exists() {
        return Err(format!(
            "{case}: canonical SQLite store was created or opened"
        ));
    }
    if let Some(address) = address
        && TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok()
    {
        return Err(format!(
            "{case}: API listener unexpectedly accepting connections"
        ));
    }
    Ok(())
}

const DESIGNATION: &str = "authenticated recovery designation denies operational access";

fn scenario(
    case: &str,
    variant: Variant,
    extra_env: &str,
    expected: &[&str],
    mutate: impl FnOnce(&DesignatedFixture) -> Result<(), String>,
) -> Result<(), String> {
    let Some(root) = fixture_root() else {
        return Err("requires root".to_string());
    };
    let fixture = build(&root, variant)?;
    mutate(&fixture)?;
    let address = unused_address();
    let inner = format!(
        "setpriv --reuid={O3K_UID} --regid={O3K_GID} --clear-groups \
         env -i PATH=/usr/bin:/bin O3K_LISTEN_ADDR={address} O3K_PROVIDER=fake {extra_env} \
         {{o3kd}} --data-dir /var/lib/o3k --log-filter warn 2>{{stderr}}"
    );
    let (stderr, ok) = run_namespaced(&fixture, &inner, "daemon-stderr.log");
    assert_denied(case, &stderr, ok, &fixture, Some(address))?;
    if !expected.iter().any(|fragment| stderr.contains(fragment)) {
        return Err(format!(
            "{case}: denial reason {:?} did not contain any of {expected:?}",
            stderr.trim()
        ));
    }
    eprintln!("{case}: denied as expected: {}", stderr.trim());
    Ok(())
}

#[test]
#[ignore = "requires root, unshare(1), local ext4, and the sibling o3k binary; run explicitly with --ignored"]
fn designated_installation_denies_o3kd_startup_before_listener_or_store() {
    let mut failures: Vec<String> = Vec::new();

    // Control: the fully authenticated designation itself denies startup.
    if let Err(e) = scenario(
        "designated_control",
        Variant::Control,
        "",
        &[DESIGNATION],
        |_| Ok(()),
    ) {
        failures.push(e);
    }

    // Legacy restore configuration present: C1 designation still denies
    // first, before the legacy D8 guard would even inspect it.
    if let Err(e) = scenario(
        "legacy_restore_json_present",
        Variant::Control,
        "",
        &[DESIGNATION],
        |fixture| fixture.install_legacy_restore_config(),
    ) {
        failures.push(e);
    }

    // Prefix-env redirect: even with a bogus prefix whose legacy
    // configuration would allow startup, the fixed-path C1 designation
    // denies (prefix env never redirects installed C1 identity).
    if let Err(e) = scenario(
        "prefix_env_redirect",
        Variant::Control,
        "O3K_INSTALL_PREFIX=/var/lib/bogus-prefix",
        &[DESIGNATION],
        |fixture| {
            // A bogus prefix whose legacy configuration would allow startup
            // if the prefix env redirected installed C1 identity; it must not.
            let bogus = fixture.root.join("var/bogus-prefix/etc/o3k");
            fs::create_dir_all(&bogus).map_err(|e| e.to_string())?;
            chown(&bogus, 0, 0)?;
            posture(&bogus, 0o755)?;
            let value = serde_json::json!({
                "format": "o3k-restore-preflight-v1",
                "backend": "sqlite",
                "target_directory": "/var/lib/o3k",
                "recovery_directory": "/var/lib/legacy-recovery",
            });
            write_root_o3k(
                &bogus.join("restore.json"),
                &serde_json::to_vec(&value).unwrap(),
            )
        },
    ) {
        failures.push(e);
    }

    if let Err(e) = scenario(
        "recovery_directory_renamed",
        Variant::Control,
        "",
        &["recovery journal identity or protection changed"],
        |fixture| {
            fs::rename(
                &fixture.journal_dir_host,
                fixture.journal_dir_host.with_extension("moved"),
            )
            .map_err(|e| e.to_string())
        },
    ) {
        failures.push(e);
    }

    if let Err(e) = scenario(
        "journal_corrupted",
        Variant::Control,
        "",
        &["recovery journal is unauthenticated or conflicts with designation"],
        |fixture| {
            fs::write(
                fixture.journal_dir_host.join("restore-journal.json"),
                b"corrupted",
            )
            .map_err(|e| e.to_string())?;
            chown(
                &fixture.journal_dir_host.join("restore-journal.json"),
                O3K_UID,
                O3K_GID,
            )
            .map_err(|e| e.to_string())?;
            posture(
                &fixture.journal_dir_host.join("restore-journal.json"),
                0o600,
            )
        },
    ) {
        failures.push(e);
    }

    if let Err(e) = scenario(
        "trust_material_missing",
        Variant::Control,
        "",
        &["installed recovery trust is unsafe or unavailable"],
        |fixture| {
            fs::remove_file(fixture.root.join("var/etc-fixture/o3k/recovery-trust.json"))
                .map_err(|e| e.to_string())
        },
    ) {
        failures.push(e);
    }

    if let Err(e) = scenario(
        "signer_revoked",
        Variant::RevokedSigner,
        "",
        &["stale, expired, revoked or conflicting"],
        |_| Ok(()),
    ) {
        failures.push(e);
    }

    if let Err(e) = scenario(
        "signer_stale",
        Variant::StaleCertificate,
        "",
        &["stale, expired, revoked or conflicting"],
        |_| Ok(()),
    ) {
        failures.push(e);
    }

    assert!(
        failures.is_empty(),
        "designated startup denial failures:\n{}",
        failures.join("\n")
    );
}

#[test]
#[ignore = "requires root, unshare(1), and local ext4; run explicitly with --ignored"]
fn designated_installation_denies_across_process_restart() {
    let Some(root) = fixture_root() else {
        eprintln!("NOT_RUN designated restart: requires root");
        return;
    };
    let fixture = build(&root, Variant::Control).expect("fixture builds");
    for round in 1..=2 {
        let inner = format!(
            "setpriv --reuid={O3K_UID} --regid={O3K_GID} --clear-groups \
             env -i PATH=/usr/bin:/bin O3K_LISTEN_ADDR={} O3K_PROVIDER=fake \
             {{o3kd}} --data-dir /var/lib/o3k --log-filter warn 2>{{stderr}}",
            unused_address()
        );
        let (stderr, ok) = run_namespaced(&fixture, &inner, &format!("restart-{round}.log"));
        assert_denied(
            &format!("restart round {round}"),
            &stderr,
            ok,
            &fixture,
            None,
        )
        .expect("restart round denies");
    }
}

#[test]
#[ignore = "requires root, unshare(1), local ext4, and the sibling o3k binary; run explicitly with --ignored"]
fn designated_installation_denies_integrated_maintenance_paths() {
    let Some(root) = fixture_root() else {
        eprintln!("NOT_RUN maintenance: requires root");
        return;
    };
    let fixture = build(&root, Variant::Control).expect("fixture builds");

    // `o3k doctor --json`: deny before canonical database checks.
    let (output, ok) = run_namespaced(&fixture, "{o3k} doctor --json >{stderr} 2>&1", "doctor.log");
    assert!(!ok, "doctor unexpectedly succeeded: {output}");
    assert!(
        output.contains("canonical store access denied") && output.contains("recovery"),
        "doctor denial output unexpected: {output}"
    );
    assert!(
        !fixture.data_dir_host.join("o3k.sqlite").exists(),
        "doctor created or opened the canonical store"
    );

    // `o3k backup create`: deny before capture; destination stays empty.
    let destination = fixture.root.join("var/backup-destination");
    fs::create_dir(&destination).unwrap();
    let (output, ok) = run_namespaced(
        &fixture,
        &format!(
            "{{o3k}} backup create --destination /var/lib/backup-destination \
             --operation-id {} >{{stderr}} 2>&1",
            uuid::Uuid::now_v7()
        ),
        "backup.log",
    );
    assert!(!ok, "backup create unexpectedly succeeded: {output}");
    assert!(
        ["quarantine", "recovery", "restore"]
            .iter()
            .any(|word| output.contains(word)),
        "backup denial output unexpected: {output}"
    );
    assert!(
        fs::read_dir(&destination).unwrap().next().is_none(),
        "backup destination mutated despite denial"
    );
    assert!(
        !fixture.data_dir_host.join("o3k.sqlite").exists(),
        "backup created or opened the canonical store"
    );

    // `o3k rollback`: deny at the real rollback mutation entry before
    // snapshot, destination, or store mutation and before any service start.
    let (output, ok) = run_namespaced(&fixture, "{o3k} rollback >{stderr} 2>&1", "rollback.log");
    assert!(!ok, "rollback unexpectedly succeeded: {output}");
    assert!(
        ["quarantine", "recovery", "restore"]
            .iter()
            .any(|word| output.contains(word)),
        "rollback denial output unexpected: {output}"
    );
    assert!(
        !fixture.data_dir_host.join("o3k.sqlite").exists(),
        "rollback created or opened the canonical store"
    );
    assert!(
        fs::read_dir(&fixture.data_dir_host)
            .unwrap()
            .find(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|entry| entry.file_name() == "o3k.sqlite.backup")
            })
            .is_none(),
        "rollback left a database snapshot in the data directory"
    );

    // `o3k upgrade --check`: deny before the store phase lock.
    let (output, ok) = run_namespaced(
        &fixture,
        "{o3k} upgrade --check >{stderr} 2>&1",
        "upgrade.log",
    );
    assert!(!ok, "upgrade --check unexpectedly succeeded: {output}");
    assert!(
        ["quarantine", "recovery", "restore"]
            .iter()
            .any(|word| output.contains(word)),
        "upgrade denial output unexpected: {output}"
    );
    assert!(
        !fixture.data_dir_host.join("o3k.sqlite").exists(),
        "upgrade created or opened the canonical store"
    );
}

#[test]
#[ignore = "requires a systemd manager; run explicitly with --ignored"]
fn designated_installation_denies_under_systemd_restart() {
    let available = std::fs::read_to_string("/proc/1/comm")
        .map(|comm| comm.trim() == "systemd")
        .unwrap_or(false)
        && Command::new("systemctl")
            .arg("is-system-running")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
    if !available {
        eprintln!(
            "NOT_RUN systemd restart denial: no systemd manager available in this environment; \
             repeated direct exec is not systemd evidence"
        );
        return;
    }
    let Some(root) = fixture_root() else {
        eprintln!("NOT_RUN systemd restart denial: requires root");
        return;
    };
    let fixture = build(&root, Variant::Control).expect("fixture builds");
    let _ = fixture;
    panic!(
        "systemd manager present but the namespace-scoped systemd unit path is not implemented; \
         add the unit-based denial here rather than relabeling direct exec as systemd evidence"
    );
}
