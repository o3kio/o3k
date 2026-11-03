//! Qualification-only signed journal-v2 publication/restart checks.
//!
//! These tests exercise the D8 protected ext4 publisher, not a PostgreSQL
//! restore executor. Run explicitly as root on a disposable local ext4 host:
//! `cargo test -p o3k --all-features restore_journal_v2::realfs_tests
//! -- --ignored --nocapture`.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use super::*;
use crate::{recovery_files::ProtectedDirectory, restore_journal_v2};
use ed25519_dalek::{Signer, SigningKey};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;
const KEY_ID: &str = "qualification-journal-key";
const JOURNAL: &str = "restore-journal-v2.json";
const DISPOSABLE_HOST_ACK: &str = "I_AUTHORIZE_PP6_EXT4_JOURNAL_TEST_ON_THIS_DISPOSABLE_HOST";
const TEST_ROOT_ENV: &str = "O3K_PP6_JOURNAL_TEST_ROOT";
const HOST_ACK_ENV: &str = "O3K_PP6_DISPOSABLE_HOST_ACK";

struct Fixture {
    root: PathBuf,
    path: Option<PathBuf>,
    device: u64,
    inode: u64,
}

impl Fixture {
    fn new() -> Result<Self, String> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err("root is required for the disposable ext4 fixture".into());
        }
        let root = qualification_root()?;
        let path = root.join(format!("journal-test-{}", Uuid::now_v7()));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&path)
            .map_err(|error| format!("create fixture directory: {error}"))?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                let cleanup = fs::remove_dir(&path);
                return Err(format!(
                    "inspect fixture directory: {error}; empty-directory cleanup: {cleanup:?}"
                ));
            }
        };
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o700
        {
            let cleanup = fs::remove_dir(&path);
            return Err(format!(
                "new fixture directory has unsafe identity or mode; empty-directory cleanup: {cleanup:?}"
            ));
        }
        let fixture = Self {
            root,
            path: Some(path),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let setup = (|| -> io::Result<()> {
            fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))?;
            fs::write(fixture.path().join("restore-signing-request.lock"), b"")?;
            fs::set_permissions(
                fixture.path().join("restore-signing-request.lock"),
                fs::Permissions::from_mode(0o600),
            )?;
            Ok(())
        })();
        if let Err(error) = setup {
            let cleanup = fixture.cleanup();
            return Err(match cleanup {
                Ok(()) => format!("initialize fixture: {error}"),
                Err(cleanup_error) => {
                    format!("initialize fixture: {error}; cleanup also failed: {cleanup_error}")
                }
            });
        }
        Ok(fixture)
    }

    fn open(&self) -> ProtectedDirectory {
        let metadata = fs::symlink_metadata(self.path()).expect("fixture metadata");
        ProtectedDirectory::open(self.path(), 0, 0, 0o700, metadata.dev(), metadata.ino())
            .expect("protected ext4 fixture")
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("fixture path is present")
    }

    fn cleanup(mut self) -> Result<(), String> {
        let Some(path) = self.path.take() else {
            return Ok(());
        };
        remove_fixture(&path, self.device, self.inode)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(path) = self.path.take()
            && let Err(error) = remove_fixture(&path, self.device, self.inode)
        {
            eprintln!(
                "failed to remove qualification fixture {}: {error}",
                path.display()
            );
        }
    }
}

fn qualification_root() -> Result<PathBuf, String> {
    if std::env::var(HOST_ACK_ENV).ok().as_deref() != Some(DISPOSABLE_HOST_ACK) {
        return Err(format!(
            "set {HOST_ACK_ENV} only after dedicated-host preflight and authorization"
        ));
    }
    let raw = std::env::var_os(TEST_ROOT_ENV).ok_or_else(|| {
        format!("{TEST_ROOT_ENV} must name the pre-provisioned journal ext4 mount")
    })?;
    let requested = PathBuf::from(raw);
    if !requested.is_absolute() {
        return Err("journal test root must be an absolute path".into());
    }
    let canonical = fs::canonicalize(&requested)
        .map_err(|error| format!("canonicalize journal test root: {error}"))?;
    if canonical != requested {
        return Err("journal test root must not contain symlink components".into());
    }
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("inspect journal test root: {error}"))?;
    let root_metadata = fs::metadata("/").map_err(|error| format!("inspect host root: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o700
        || metadata.dev() == root_metadata.dev()
    {
        return Err(
            "journal test root must be root-owned mode 0700 on a separate filesystem".into(),
        );
    }
    ProtectedDirectory::open(&canonical, 0, 0, 0o700, metadata.dev(), metadata.ino())
        .map_err(|_| "journal test root must be a verified ext4 filesystem".to_owned())?;
    Ok(canonical)
}

fn remove_fixture(path: &Path, device: u64, inode: u64) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect fixture before cleanup: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.dev() != device
        || metadata.ino() != inode
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err("fixture directory identity changed; refusing recursive cleanup".into());
    }
    for entry in
        fs::read_dir(path).map_err(|error| format!("read fixture before cleanup: {error}"))?
    {
        let entry = entry.map_err(|error| format!("read fixture entry: {error}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("inspect fixture entry: {error}"))?;
        let allowed_name = name == "restore-signing-request.lock"
            || name == JOURNAL
            || (name.starts_with(".restore-journal-v2.json.tmp-") && {
                let pid = &name[".restore-journal-v2.json.tmp-".len()..];
                !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit())
            });
        if !allowed_name
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.dev() != device
            || metadata.uid() != 0
        {
            return Err(format!(
                "unexpected fixture entry; refusing cleanup: {}",
                entry.path().display()
            ));
        }
        fs::remove_file(entry.path()).map_err(|error| format!("remove fixture file: {error}"))?;
    }
    fs::remove_dir(path).map_err(|error| format!("remove fixture directory: {error}"))
}

fn open_child_fixture() -> (PathBuf, ProtectedDirectory) {
    let root = qualification_root().expect("authorized journal test root");
    let raw = std::env::var_os("O3K_JOURNAL_V2_FIXTURE")
        .expect("fixture path supplied by the parent test");
    let requested = PathBuf::from(raw);
    let fixture = fs::canonicalize(&requested).expect("canonical fixture path");
    assert_eq!(fixture, requested, "fixture path must not contain symlinks");
    assert_eq!(
        fixture.parent(),
        Some(root.as_path()),
        "fixture must be a direct child of test root"
    );
    let metadata = fs::symlink_metadata(&fixture).expect("fixture metadata");
    let root_metadata = fs::metadata(&root).expect("test root metadata");
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.gid(), 0);
    assert_eq!(metadata.mode() & 0o7777, 0o700);
    assert_eq!(metadata.dev(), root_metadata.dev());
    let protected = ProtectedDirectory::open(&fixture, 0, 0, 0o700, metadata.dev(), metadata.ino())
        .expect("protected ext4 fixture");
    (fixture, protected)
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

fn authority(key: &SigningKey) -> JournalAuthority<'_> {
    let verifying_key = Box::leak(Box::new(key.verifying_key()));
    JournalAuthority {
        key_id: KEY_ID,
        purpose: restore_journal_v2::SIGNING_PURPOSE,
        site_id: "qualification-site",
        installation_id: "target-installation",
        profile: restore_journal_v2::PROFILE,
        backend: restore_journal_v2::BACKEND,
        backend_version: "16",
        deployment: restore_journal_v2::DEPLOYMENT,
        release_identity: "qualification-release",
        policy_sha256: Box::leak("b".repeat(64).into_boxed_str()),
        not_before: NOW - 10,
        not_after: NOW + 10,
        revoked: false,
        verifying_key,
    }
}

fn signed(request: SigningRequest, key: &SigningKey) -> SignedRecord {
    let request_bytes = restore_journal_v2::canonical_request(&request).expect("canonical request");
    SignedRecord {
        format: restore_journal_v2::JOURNAL_FORMAT.to_owned(),
        request,
        response: SigningResponse {
            format: restore_journal_v2::RESPONSE_FORMAT.to_owned(),
            request_sha256: restore_journal_v2::digest(&request_bytes),
            key_id: KEY_ID.to_owned(),
            signature: hex::encode(key.sign(&request_bytes).to_bytes()),
        },
    }
}

fn chain(target_inode: u64, phases: &[InactivePhase], key: &SigningKey) -> Vec<u8> {
    let mut records: Vec<SignedRecord> = Vec::new();
    for (index, phase) in phases.iter().enumerate() {
        let previous = records
            .last()
            .map(|record| {
                restore_journal_v2::digest(
                    &restore_journal_v2::canonical(record).expect("canonical signed record"),
                )
            })
            .unwrap_or_default();
        let sequence = index as u64 + 1;
        records.push(signed(
            SigningRequest {
                format: restore_journal_v2::REQUEST_FORMAT.to_owned(),
                branch: restore_journal_v2::BRANCH_INACTIVE.to_owned(),
                request_id: Uuid::from_u128(u128::from(sequence + 10)),
                request_nonce: format!("{sequence:064x}"),
                operation_id: Uuid::from_u128(900),
                artifact_sha256: "a".repeat(64),
                site_id: "qualification-site".to_owned(),
                source_installation_id: "source-installation".to_owned(),
                target_installation_id: "target-installation".to_owned(),
                target_device: 8,
                target_inode,
                target_database_identity: "o3k_restore_900".to_owned(),
                profile: restore_journal_v2::PROFILE.to_owned(),
                backend: restore_journal_v2::BACKEND.to_owned(),
                backend_version: "16".to_owned(),
                deployment: restore_journal_v2::DEPLOYMENT.to_owned(),
                release_identity: "qualification-release".to_owned(),
                installation_policy_sha256: "b".repeat(64),
                sequence,
                previous_signed_record_sha256: previous,
                intended_transition: *phase,
                verification: None,
            },
            key,
        ));
    }
    restore_journal_v2::canonical(&Journal {
        format: restore_journal_v2::JOURNAL_FORMAT.to_owned(),
        branch: restore_journal_v2::BRANCH_INACTIVE.to_owned(),
        records,
    })
    .expect("canonical journal")
}

fn run_crash_child(point: &str, fixture: &Fixture) -> Option<i32> {
    Command::new(std::env::current_exe().expect("test executable"))
        .arg(concat!(module_path!(), "::publish_crash_child"))
        .arg("--exact")
        .arg("--nocapture")
        .env("O3K_RECOVERY_FILES_CRASH_AT", point)
        .env(HOST_ACK_ENV, DISPOSABLE_HOST_ACK)
        .env(TEST_ROOT_ENV, &fixture.root)
        .env("O3K_JOURNAL_V2_FIXTURE", fixture.path())
        .status()
        .expect("spawn journal publisher")
        .code()
}

#[test]
fn publish_crash_child() {
    if std::env::var_os("O3K_JOURNAL_V2_FIXTURE").is_none() {
        return;
    }
    let (fixture, protected) = open_child_fixture();
    let key = signing_key();
    let candidate = chain(
        9,
        &[
            InactivePhase::Preflighted,
            InactivePhase::TargetReservedInactive,
        ],
        &key,
    );
    let first = chain(9, &[InactivePhase::Preflighted], &key);
    let prior = if fs::symlink_metadata(fixture.join(JOURNAL)).is_ok() {
        Some(first.as_slice())
    } else {
        None
    };
    let _ = restore_journal_v2::publish_chain(
        &protected,
        JOURNAL,
        prior,
        &candidate,
        &authority(&key),
        NOW,
        0,
        0,
    );
}

#[test]
#[ignore = "requires root and an isolated local ext4 qualification host"]
fn signed_journal_publication_is_old_or_new_and_restart_requires_observation() {
    let fixture = Fixture::new().expect("authorized root/ext4 fixture");
    let key = signing_key();
    let authority = authority(&key);
    let preflighted = chain(9, &[InactivePhase::Preflighted], &key);
    let appended = chain(
        9,
        &[
            InactivePhase::Preflighted,
            InactivePhase::TargetReservedInactive,
        ],
        &key,
    );

    // The first two boundaries must preserve the already-published prior
    // journal. Retry only after a fresh process has observed and authenticated
    // those exact old bytes.
    for point in ["before-file-fsync", "after-file-fsync"] {
        let protected = fixture.open();
        restore_journal_v2::publish_chain(
            &protected,
            JOURNAL,
            None,
            &preflighted,
            &authority,
            NOW,
            0,
            0,
        )
        .expect("seed prior journal");
        let status = run_crash_child(point, &fixture);
        assert_eq!(status, Some(86), "injection at {point}");
        let observed = fixture
            .open()
            .read_bounded(JOURNAL, 0, 0, 0o600, restore_journal_v2::MAX_JOURNAL_BYTES)
            .expect("prior journal remains after restart");
        assert_eq!(observed, preflighted, "old bytes after {point}");
        assert_eq!(
            restore_journal_v2::authenticate_chain(&observed, &authority, NOW)
                .expect("old journal authenticates after restart")
                .phase,
            InactivePhase::Preflighted
        );
        let restarted = fixture.open();
        let published = restore_journal_v2::publish_chain(
            &restarted,
            JOURNAL,
            Some(&observed),
            &appended,
            &authority,
            NOW,
            0,
            0,
        )
        .expect("retry after observing prior journal");
        assert_eq!(published, appended);
        assert_eq!(
            restore_journal_v2::authenticate_chain(&published, &authority, NOW)
                .expect("authenticated after restart")
                .phase,
            InactivePhase::TargetReservedInactive
        );
        fs::remove_file(fixture.path().join(JOURNAL)).expect("reset disposable journal");
    }

    // Seed a prior signed record and prove that a validly signed alternate
    // prefix cannot replace it, even when the proposed append also verifies.
    let protected = fixture.open();
    let seeded = restore_journal_v2::publish_chain(
        &protected,
        JOURNAL,
        None,
        &preflighted,
        &authority,
        NOW,
        0,
        0,
    )
    .expect("seed signed prior chain");
    let fork = chain(
        10,
        &[
            InactivePhase::Preflighted,
            InactivePhase::TargetReservedInactive,
        ],
        &key,
    );
    assert_eq!(
        restore_journal_v2::publish_chain(
            &protected,
            JOURNAL,
            Some(&seeded),
            &fork,
            &authority,
            NOW,
            0,
            0,
        ),
        Err(restore_journal_v2::JournalError::ReplayOrFork)
    );
    assert_eq!(
        protected
            .read_bounded(JOURNAL, 0, 0, 0o600, restore_journal_v2::MAX_JOURNAL_BYTES)
            .expect("prior remains intact"),
        seeded
    );

    // A crash after rename may have published the complete next journal even
    // though the writer never returned. Reopen and authenticate before any
    // retry; do not blindly append or repeat target work.
    for point in ["after-rename", "after-directory-fsync"] {
        let path = fixture.path().join(JOURNAL);
        if path.exists() {
            fs::remove_file(&path).expect("remove previous journal before reseed");
        }
        let protected = fixture.open();
        restore_journal_v2::publish_chain(
            &protected,
            JOURNAL,
            None,
            &preflighted,
            &authority,
            NOW,
            0,
            0,
        )
        .expect("seed prior journal for post-rename boundary");
        let status = run_crash_child(point, &fixture);
        assert_eq!(status, Some(86), "injection at {point}");
        let restarted = fixture.open();
        let bytes = restarted
            .read_bounded(JOURNAL, 0, 0, 0o600, restore_journal_v2::MAX_JOURNAL_BYTES)
            .expect("journal observed after restart");
        assert_eq!(bytes, appended, "complete candidate after {point}");
        let authenticated = restore_journal_v2::authenticate_chain(&bytes, &authority, NOW)
            .expect("candidate authenticates after restart");
        assert_eq!(authenticated.phase, InactivePhase::TargetReservedInactive);
        assert!(authenticated.phase.denies_runtime());
    }
    fixture
        .cleanup()
        .expect("clean successful test fixture teardown");
}
