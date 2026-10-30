//! Explicit C1 protected-file process evidence.  These tests are ignored by
//! default because they require root and a local ext4 mount.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use o3k::recovery_files::{DirectoryPosture, ProtectedDirectory, RecoveryFileError};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Option<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return None;
        }
        let path = PathBuf::from(format!("/var/lib/o3k-c1-test-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).ok()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).ok()?;
        Some(Self(path))
    }
    fn open(&self) -> ProtectedDirectory {
        let meta = fs::metadata(&self.0).unwrap();
        ProtectedDirectory::open(
            &self.0,
            meta.uid() as u32,
            meta.gid() as u32,
            0o750,
            meta.dev(),
            meta.ino(),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_dir_all(self.0.with_extension("replacement"));
    }
}

fn child_crash(point: &str, fixture: &Path) -> Option<i32> {
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("crash_child")
        .arg("--exact")
        .arg("--nocapture")
        .env("O3K_RECOVERY_FILES_CRASH_AT", point)
        .env("O3K_RECOVERY_FILES_FIXTURE", fixture)
        .status()
        .unwrap();
    status.code()
}

#[test]
fn crash_child() {
    let Ok(raw) = std::env::var("O3K_RECOVERY_FILES_FIXTURE") else {
        return;
    };
    let path = PathBuf::from(raw);
    let meta = fs::metadata(&path).unwrap();
    let dir = ProtectedDirectory::open(
        &path,
        meta.uid() as u32,
        meta.gid() as u32,
        0o750,
        meta.dev(),
        meta.ino(),
    )
    .unwrap();
    let _ = dir.atomic_write("state", Some(b"old"), b"new", meta.gid() as u32);
}

#[test]
#[ignore = "requires root and local ext4"]
fn crash_boundaries_preserve_only_old_or_new_bytes() {
    let fixture = Fixture::new().expect("root/local fixture");
    let dir = fixture.open();
    fs::write(fixture.0.join("state"), b"old").unwrap();
    fs::set_permissions(fixture.0.join("state"), fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(child_crash("before-file-fsync", &fixture.0), Some(86));
    assert_eq!(dir.read_bounded("state", 0, 0, 0o640, 32).unwrap(), b"old");
}

#[test]
#[ignore = "requires root and local ext4"]
fn accepts_packaged_posture_and_rejects_writable_posture_and_stale_identity() {
    let fixture = Fixture::new().expect("root/local fixture");
    // The packaged data-root posture is owner o3k, group o3k-compute, mode
    // 0711 (QEMU traversal).  The fixture runs as root, so owner/group are
    // root:root; the accepted-posture set mirrors the installed one.
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o711)).unwrap();
    let meta = fs::metadata(&fixture.0).unwrap();
    let packaged = [DirectoryPosture {
        uid: meta.uid() as u32,
        gid: meta.gid() as u32,
        mode: 0o711,
    }];
    let dir = ProtectedDirectory::open_accepted(&fixture.0, &packaged, meta.dev(), meta.ino())
        .expect("packaged posture opens");
    assert_eq!(dir.identity(), (meta.dev(), meta.ino()));
    // A group-writable variant of the same directory is not an accepted
    // posture and fails closed.
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o731)).unwrap();
    assert!(matches!(
        ProtectedDirectory::open_accepted(&fixture.0, &packaged, meta.dev(), meta.ino()),
        Err(RecoveryFileError::Unsafe("directory identity"))
    ));
    // A stale device/inode binding (target replaced underneath the policy)
    // fails closed even with the exact packaged posture.
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o711)).unwrap();
    assert!(matches!(
        ProtectedDirectory::open_accepted(&fixture.0, &packaged, meta.dev(), meta.ino() + 1),
        Err(RecoveryFileError::Unsafe("directory identity"))
    ));
}

#[test]
#[ignore = "requires root and local ext4"]
fn named_lock_is_no_follow_and_remains_exclusive_while_held() {
    let fixture = Fixture::new().expect("root/local fixture");
    let directory = fixture.open();
    let path = fixture.0.join("restore-signing-request.lock");
    fs::write(&path, b"").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let held = directory
        .try_lock_existing_file("restore-signing-request.lock", 0, 0, 0o600)
        .unwrap()
        .expect("existing lock file");
    assert!(
        directory
            .try_lock_existing_file("restore-signing-request.lock", 0, 0, 0o600)
            .is_err()
    );
    drop(held);
    assert!(
        directory
            .try_lock_existing_file("restore-signing-request.lock", 0, 0, 0o600)
            .unwrap()
            .is_some()
    );

    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("missing-lock-target", &path).unwrap();
    assert!(
        directory
            .try_lock_existing_file("restore-signing-request.lock", 0, 0, 0o600)
            .is_err()
    );
}

#[test]
#[ignore = "requires root and local ext4"]
fn rejects_symlink_and_stale_cas_and_detects_path_replacement() {
    let fixture = Fixture::new().expect("root/local fixture");
    let dir = fixture.open();
    std::os::unix::fs::symlink("/etc/passwd", fixture.0.join("link")).unwrap();
    assert!(matches!(
        dir.read_bounded("link", 0, 0, 0o640, 32),
        Err(RecoveryFileError::Io(_)) | Err(RecoveryFileError::Unsafe(_))
    ));
    fs::write(fixture.0.join("state"), b"one").unwrap();
    fs::set_permissions(fixture.0.join("state"), fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        dir.atomic_write("state", Some(b"two"), b"three", 0),
        Err(RecoveryFileError::CompareFailed)
    ));
    let replacement = fixture.0.with_extension("replacement");
    fs::rename(&fixture.0, &replacement).unwrap();
    fs::create_dir(&fixture.0).unwrap();
    fs::write(fixture.0.join("state"), b"replacement").unwrap();
    fs::set_permissions(fixture.0.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        dir.read_bounded("state", 0, 0, 0o640, 32),
        Err(RecoveryFileError::Unsafe(_))
    ));
    fs::set_permissions(fixture.0.join("state"), fs::Permissions::from_mode(0o640)).unwrap();
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(fixture.0.join("state"), fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(dir.lock(), Err(RecoveryFileError::Unsafe(_))));
    fs::remove_file(fixture.0.join("state")).unwrap();
    fs::remove_dir(&fixture.0).unwrap();
    fs::rename(replacement, fixture.0.clone()).unwrap();
    let meta = fs::metadata(&fixture.0).unwrap();
    let contender = ProtectedDirectory::open(
        &fixture.0,
        meta.uid() as u32,
        meta.gid() as u32,
        0o750,
        meta.dev(),
        meta.ino(),
    )
    .unwrap();
    dir.lock().unwrap();
    assert!(matches!(contender.lock(), Err(RecoveryFileError::Io(_))));
}
