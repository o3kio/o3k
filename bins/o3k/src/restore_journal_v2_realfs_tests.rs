//! Qualification-only signed journal-v2 publication/restart checks.
//!
//! These tests exercise the D8 protected ext4 publisher, not a PostgreSQL
//! restore executor. Run explicitly as root on a disposable local ext4 host:
//! `cargo test -p o3k --all-features restore_journal_v2::realfs_tests
//! -- --ignored --nocapture`.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
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

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Option<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return None;
        }
        let path = PathBuf::from(format!("/var/lib/o3k-journal-v2-{}", Uuid::now_v7()));
        fs::create_dir(&path).ok()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).ok()?;
        fs::write(path.join("restore-signing-request.lock"), b"").ok()?;
        fs::set_permissions(
            path.join("restore-signing-request.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .ok()?;
        Some(Self(path))
    }

    fn open(&self) -> ProtectedDirectory {
        let metadata = fs::metadata(&self.0).expect("fixture metadata");
        ProtectedDirectory::open(&self.0, 0, 0, 0o700, metadata.dev(), metadata.ino())
            .expect("protected ext4 fixture")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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

fn run_crash_child(point: &str, fixture: &Path) -> Option<i32> {
    Command::new(std::env::current_exe().expect("test executable"))
        .arg(concat!(module_path!(), "::publish_crash_child"))
        .arg("--exact")
        .arg("--nocapture")
        .env("O3K_RECOVERY_FILES_CRASH_AT", point)
        .env("O3K_JOURNAL_V2_FIXTURE", fixture)
        .status()
        .expect("spawn journal publisher")
        .code()
}

#[test]
fn publish_crash_child() {
    let Ok(raw) = std::env::var("O3K_JOURNAL_V2_FIXTURE") else {
        return;
    };
    let fixture = PathBuf::from(raw);
    let metadata = fs::metadata(&fixture).expect("fixture metadata");
    let protected = ProtectedDirectory::open(&fixture, 0, 0, 0o700, metadata.dev(), metadata.ino())
        .expect("protected ext4 fixture");
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
    let fixture = Fixture::new().expect("root fixture");
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

    // The first two boundaries leave no published journal. A later process
    // may retry only after observing that the journal is absent.
    for point in ["before-file-fsync", "after-file-fsync"] {
        let status = run_crash_child(point, &fixture.0);
        assert_eq!(status, Some(86), "injection at {point}");
        assert!(fs::symlink_metadata(fixture.0.join(JOURNAL)).is_err());
        let restarted = fixture.open();
        let published = restore_journal_v2::publish_chain(
            &restarted,
            JOURNAL,
            None,
            &preflighted,
            &authority,
            NOW,
            0,
            0,
        )
        .expect("retry after observing absent journal");
        assert_eq!(published, preflighted);
        assert_eq!(
            restore_journal_v2::authenticate_chain(&published, &authority, NOW)
                .expect("authenticated after restart")
                .phase,
            InactivePhase::Preflighted
        );
        fs::remove_file(fixture.0.join(JOURNAL)).expect("reset disposable journal");
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
        fs::write(fixture.0.join(JOURNAL), &preflighted).expect("restore known prior bytes");
        fs::set_permissions(fixture.0.join(JOURNAL), fs::Permissions::from_mode(0o600))
            .expect("journal mode");
        let status = run_crash_child(point, &fixture.0);
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
}
