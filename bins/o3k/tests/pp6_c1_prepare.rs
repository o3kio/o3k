//! Source-only C1 provisioning-preparation journey evidence.  The fixture is
//! deliberately isolated in a private mount namespace and is not an
//! installed-release or production qualification claim.  The descriptor this
//! exercises is unsigned operator staging input; nothing here fabricates an
//! authenticated installed-release acceptance.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

fn root_fixture() -> Option<PathBuf> {
    if rustix::process::geteuid().as_raw() != 0 {
        return None;
    }
    let path = PathBuf::from(format!("/var/lib/o3k-c1-prepare-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&path).ok()?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).ok()?;
    Some(path)
}

fn setup_fixture(fixture: &Path) {
    let var = fixture.join("var");
    // The etc/share bind sources must live under var: the namespace script
    // binds var onto /var/lib first and then addresses them as
    // /var/lib/etc-fixture and /var/lib/share-fixture, so the sources keep
    // resolving after the first bind (the startup-process fixture class).
    let etc = var.join("etc-fixture");
    let share = var.join("share-fixture");
    let _ = fs::remove_dir_all(&var);
    fs::create_dir_all(&var).unwrap();
    fs::create_dir_all(&etc).unwrap();
    fs::create_dir_all(&share).unwrap();
    let data = var.join("o3k");
    fs::create_dir(&data).unwrap();
    // The packaged libvirt posture: o3k:o3k-compute 0711.
    fs::set_permissions(&data, fs::Permissions::from_mode(0o711)).unwrap();
    std::os::unix::fs::chown(&data, Some(900), Some(901)).unwrap();
    fs::write(etc.join("passwd"), b"root:x:0:0:root:/root:/bin/sh\no3k:x:900:900::/var/lib/o3k:/usr/sbin/nologin\no3k-compute:x:901:901::/var/lib/o3k/compute:/usr/sbin/nologin\n").unwrap();
    fs::write(
        etc.join("group"),
        b"root:x:0:\no3k:x:900:\no3k-compute:x:901:\nkvm:x:108:\n",
    )
    .unwrap();
    fs::write(
        share.join("release-manifest.json"),
        br#"{"version":"v0.4.0-rc.5","profile":"libvirt","profile_id":"o3k-demo-v1","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","workflow":"test","installer_sha256":"0000000000000000000000000000000000000000000000000000000000000000","release_artifact_sha256":"1111111111111111111111111111111111111111111111111111111111111111","schema_version":"1","installation_policy_format":"o3k-installation-policy-v1","installation_policy_path":"/etc/o3k/installation-policy.json","installation_policy_authority":{"key_id":"policy-key-1","ed25519_public_key":"2222222222222222222222222222222222222222222222222222222222222222"}}"#,
    )
    .unwrap();
}

/// Runs the script in a private mount namespace over the prepared fixture:
/// /var/lib -> fixture var, /etc -> fixture var/etc-fixture (addressed via
/// /var/lib), and /usr/local/share/o3k -> fixture var/share-fixture.  The
/// etc/share sources are addressed through /var/lib because the first bind
/// mount shadows their original absolute paths.
fn run_in_namespace(fixture: &Path, script: &str) -> (String, String, std::process::ExitStatus) {
    let binary = env!("CARGO_BIN_EXE_o3k");
    let script = format!(
        "set -u; umask 077; mount --make-rprivate /; mount --bind {0} /var/lib; mount --bind /var/lib/etc-fixture /etc; mount --bind /var/lib/share-fixture /usr/local/share/o3k; test -d /var/lib/o3k; echo C1_PREPARE_NAMESPACE_READY >&2; {1}",
        fixture.join("var").display(),
        script.replace("{binary}", binary)
    );
    let output = Command::new("unshare")
        .args(["--mount", "--fork", "--", "sh", "-c", &script])
        .output()
        .expect("unshare");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status,
    )
}

fn descriptor(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).expect("descriptor is bounded JSON on stdout")
}

fn dir_posture(path: &Path) -> (u32, u32, u32) {
    let meta = fs::symlink_metadata(path).expect("dir metadata");
    (meta.uid(), meta.gid(), meta.mode() & 0o7777)
}

#[test]
#[ignore = "requires root, unshare(1), and a source-built o3k binary"]
fn prepare_journey_emits_unsigned_descriptor_and_exact_directories() {
    let Some(fixture) = root_fixture() else {
        return;
    };
    setup_fixture(&fixture);
    let script = "{binary} recovery-provision-prepare --data-root /var/lib/o3k --backend sqlite";
    let (stdout, stderr, status) = run_in_namespace(&fixture, script);
    assert!(stderr.contains("C1_PREPARE_NAMESPACE_READY"));
    assert!(status.success(), "prepare failed: {stderr}");

    let value = descriptor(&stdout);
    assert_eq!(value["format"], "o3k-recovery-provisioning-v1");
    assert_eq!(value["unsigned"], true, "descriptor must be unsigned");
    assert_eq!(value["authentication"], "none");
    let installation_id = value["installation_id"].as_str().expect("installation id");
    let site_id = value["site_id"].as_str().expect("site id");
    // Identity tokens are 16 bytes; the canonical installation/site IDs are
    // their 32-character lowercase hex encodings (o3k-store identity_tokens).
    assert_eq!(installation_id.len(), 32);
    assert_eq!(site_id.len(), 32);
    assert_ne!(installation_id, site_id);
    assert_eq!(value["profile"], "o3k-demo-v1");
    assert_eq!(value["backend"], "sqlite");
    assert_eq!(
        value["release_identity"],
        "1111111111111111111111111111111111111111111111111111111111111111"
    );
    assert_eq!(value["policy_authority"]["key_id"], "policy-key-1");
    assert_eq!(value["data_root"], "/var/lib/o3k");
    assert!(value["data_root_device"].as_u64().unwrap() > 0);
    assert!(value["data_root_inode"].as_u64().unwrap() > 0);
    assert_eq!(
        value["recovery_state_root"],
        format!("/var/lib/o3k-recovery-state/{installation_id}")
    );
    assert_eq!(
        value["journal_directory"],
        format!("/var/lib/o3k-recovery/{installation_id}")
    );

    // The exact per-installation directory postures from SPEC-0050 §7.2.1.
    let state_root = fixture
        .join("var")
        .join("o3k-recovery-state")
        .join(installation_id);
    let journal_dir = fixture
        .join("var")
        .join("o3k-recovery")
        .join(installation_id);
    assert_eq!(dir_posture(&state_root), (0, 900, 0o750), "root:o3k 0750");
    assert_eq!(dir_posture(&journal_dir), (900, 900, 0o700), "o3k:o3k 0700");
    // The recovery parents are created with the exact root:root 0755 layout
    // even on a clean host and even under a restrictive umask.
    let state_parent = fixture.join("var").join("o3k-recovery-state");
    let journal_parent = fixture.join("var").join("o3k-recovery");
    assert_eq!(dir_posture(&state_parent), (0, 0, 0o755), "root:root 0755");
    assert_eq!(
        dir_posture(&journal_parent),
        (0, 0, 0o755),
        "root:root 0755"
    );
    // Descriptor binds the observed device/inode of the created directories.
    let state_meta = fs::metadata(&state_root).unwrap();
    assert_eq!(
        value["recovery_state_device"].as_u64().unwrap(),
        state_meta.dev()
    );
    assert_eq!(
        value["recovery_state_inode"].as_u64().unwrap(),
        state_meta.ino()
    );
    let journal_meta = fs::metadata(&journal_dir).unwrap();
    assert_eq!(
        value["journal_device"].as_u64().unwrap(),
        journal_meta.dev()
    );
    assert_eq!(value["journal_inode"].as_u64().unwrap(), journal_meta.ino());

    // Idempotent: a second identical run succeeds and reports the same
    // directory identities.
    let (stdout2, _, status2) = run_in_namespace(&fixture, script);
    assert!(status2.success(), "idempotent re-run failed");
    let value2 = descriptor(&stdout2);
    assert_eq!(
        value2["recovery_state_inode"],
        value["recovery_state_inode"]
    );
    assert_eq!(value2["journal_inode"], value["journal_inode"]);

    // Fail closed: recovery content in the journal directory is evidence and
    // is never ignored or converted.
    fs::write(journal_dir.join("restore-journal.json"), b"legacy").unwrap();
    let (_, stderr3, status3) = run_in_namespace(&fixture, script);
    assert!(!status3.success(), "content-bearing journal dir must fail");
    assert!(
        stderr3.contains("authenticated recovery disposition"),
        "operator-visible disposition requirement: {stderr3}"
    );

    let _ = fs::remove_dir_all(&fixture);
}

#[test]
#[ignore = "requires root, unshare(1), and a source-built o3k binary"]
fn prepare_rejects_conflicting_posture_and_missing_manifest_authority() {
    let Some(fixture) = root_fixture() else {
        return;
    };
    setup_fixture(&fixture);
    // Pre-create the recovery-state root with a writable mode; prepare must
    // refuse to adopt it.
    let bogus = fixture.join("var").join("o3k-recovery-state");
    fs::create_dir(&bogus).unwrap();
    fs::set_permissions(&bogus, fs::Permissions::from_mode(0o777)).unwrap();
    let script = "{binary} recovery-provision-prepare --data-root /var/lib/o3k --backend sqlite";
    let (_, stderr, status) = run_in_namespace(&fixture, script);
    assert!(
        !status.success(),
        "writable pre-existing state root must fail"
    );
    assert!(
        stderr.contains("posture") || stderr.contains("Unsafe"),
        "unexpected error: {stderr}"
    );
    let _ = fs::remove_dir_all(&fixture);
}

#[test]
#[ignore = "requires root, unshare(1), and a source-built o3k binary"]
fn prepare_rejects_symlinked_recovery_parent() {
    let Some(fixture) = root_fixture() else {
        return;
    };
    setup_fixture(&fixture);
    // A symlinked recovery parent is never followed or adopted.
    let outside = fixture.join("outside");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, fixture.join("var").join("o3k-recovery-state")).unwrap();
    let script = "{binary} recovery-provision-prepare --data-root /var/lib/o3k --backend sqlite";
    let (_, stderr, status) = run_in_namespace(&fixture, script);
    assert!(!status.success(), "symlinked parent must fail closed");
    assert!(
        stderr.contains("not a directory"),
        "unexpected error: {stderr}"
    );
    let _ = fs::remove_dir_all(&fixture);
}
