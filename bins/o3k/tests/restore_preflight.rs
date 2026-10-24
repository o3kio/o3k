//! D12 process regressions: preflight must reject before opening any database.
#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]
use std::{fs, process::Command};
use uuid::Uuid;

fn reject(artifact: &str, target: &str, reason: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_o3k"))
        .args([
            "restore",
            "preflight",
            "--artifact",
            artifact,
            "--target",
            target,
        ])
        .output()
        .expect("run preflight");
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("bounded JSON");
    assert_eq!(value["reason"], reason);
    assert!(output.stdout.len() < 4096);
    assert!(!String::from_utf8_lossy(&output.stderr).contains(artifact));
}

#[test]
fn rejects_relative_artifact_with_redacted_json() {
    reject("secret-artifact.o3k", "/no-target", "artifact-path-invalid");
}

#[test]
fn rejects_relative_target_with_redacted_json() {
    reject("/no-artifact", "foreign-target", "target-path-invalid");
}

#[test]
fn rejects_nonempty_target_without_changing_it() {
    let root = std::env::temp_dir().join(format!("o3k-preflight-{}", Uuid::now_v7()));
    fs::create_dir(&root).expect("target");
    let sentinel = root.join("foreign-state");
    fs::write(&sentinel, b"must survive").expect("sentinel");
    reject(
        "/no-artifact",
        root.to_str().expect("path"),
        "target-not-empty",
    );
    assert_eq!(fs::read(&sentinel).expect("unchanged"), b"must survive");
    assert_eq!(fs::read_dir(&root).expect("read target").count(), 1);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn rejects_symlinked_target_component_without_changing_foreign_state() {
    let root = std::env::temp_dir().join(format!("o3k-preflight-{}", Uuid::now_v7()));
    fs::create_dir(&root).expect("root");
    let target = root.join("target");
    fs::create_dir(&target).expect("target");
    let link = root.join("link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    reject(
        "/no-artifact",
        link.to_str().expect("path"),
        "target-path-unsafe",
    );
    assert_eq!(fs::read_dir(&target).expect("read target").count(), 0);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn rejects_traversal_before_access() {
    reject("/tmp/../foreign.o3k", "/no-target", "artifact-path-invalid");
    reject("/tmp/./foreign.o3k", "/no-target", "artifact-path-invalid");
}

#[test]
fn directory_startup_lock_excludes_preflight_without_creating_a_second_lock() {
    use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
    let target = std::env::temp_dir().join(format!("o3k-preflight-{}", Uuid::now_v7()));
    fs::create_dir(&target).expect("target");
    let directory =
        open(&target, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).expect("directory");
    flock(&directory, FlockOperation::NonBlockingLockExclusive).expect("startup exclusion");
    reject(
        "/no-artifact",
        target.to_str().expect("path"),
        "controller-or-restore-active",
    );
    assert_eq!(fs::read_dir(&target).expect("read directory").count(), 0);
    fs::remove_dir(target).expect("cleanup");
}
