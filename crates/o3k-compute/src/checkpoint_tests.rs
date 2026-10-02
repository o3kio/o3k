//! Test-only process-boundary regression for the targeted checkpoint seam.

#![cfg(unix)]

use super::*;
use std::path::{Path, PathBuf};
use std::process::Command;

#[allow(clippy::expect_used, clippy::unwrap_used)]
fn checkpoint_test_config(
    checkpoint_path: &Path,
    release_path: &Path,
    server_id: Uuid,
    run_id: &str,
    timeout_ms: &str,
) -> TestFaultCheckpointConfig {
    test_fault_checkpoint_config_from_values(
        Some(checkpoint_path.as_os_str()),
        Some(&server_id.to_string()),
        Some("endpoint-1"),
        Some(run_id),
        Some(run_id),
        Some(release_path.as_os_str()),
        Some(timeout_ms),
    )
    .expect("valid checkpoint test configuration")
    .expect("checkpoint seam should be active")
}

#[test]
#[allow(clippy::expect_used, clippy::unwrap_used)]
fn targeted_checkpoint_unprivileged_boundary_publishes_and_releases() {
    const CHILD_ENV: &str = "O3K_CHECKPOINT_BOUNDARY_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        let mode = std::env::var("O3K_CHECKPOINT_BOUNDARY_MODE").expect("boundary mode");
        let checkpoint =
            PathBuf::from(std::env::var("O3K_CHECKPOINT_BOUNDARY_CHECKPOINT").expect("checkpoint"));
        let release =
            PathBuf::from(std::env::var("O3K_CHECKPOINT_BOUNDARY_RELEASE").expect("release"));
        let server =
            Uuid::parse_str(&std::env::var("O3K_CHECKPOINT_BOUNDARY_SERVER").expect("server"))
                .expect("server uuid");
        let config = checkpoint_test_config(&checkpoint, &release, server, "run-1", "5000");
        if mode == "original" {
            let error = test_fault_checkpoint_publish(&config, server, "endpoint-1", Some("bound"))
                .expect_err("root-owned original layout must reject publication");
            assert_eq!(error.failure_step(), "temporary_create");
            assert_eq!(error.failure_kind(), "permission_denied");
            assert!(error.failure_errno().is_some());
        } else {
            test_fault_checkpoint_publish(&config, server, "endpoint-1", Some("bound"))
                .expect("daemon-owned layout must publish");
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("runtime")
                .block_on(test_fault_checkpoint_wait_for_release(&config))
                .expect("release marker must unblock publisher");
        }
        return;
    }

    let uid = String::from_utf8(
        Command::new("id")
            .args(["-u"])
            .output()
            .expect("current uid")
            .stdout,
    )
    .expect("uid")
    .trim()
    .parse::<u32>()
    .expect("numeric uid");
    let gid = String::from_utf8(
        Command::new("id")
            .args(["-g"])
            .output()
            .expect("current gid")
            .stdout,
    )
    .expect("gid")
    .trim()
    .parse::<u32>()
    .expect("numeric gid");
    let daemon = if uid == 0 {
        let output = Command::new("id")
            .args(["-u", "o3k"])
            .output()
            .expect("id o3k");
        if !output.status.success() {
            eprintln!("skipping boundary regression: o3k account is unavailable");
            return;
        }
        String::from_utf8(output.stdout)
            .expect("uid")
            .trim()
            .parse::<u32>()
            .expect("numeric uid")
    } else {
        uid
    };
    let daemon_gid = if uid == 0 {
        let output = Command::new("id")
            .args(["-g", "o3k"])
            .output()
            .expect("id o3k group");
        String::from_utf8(output.stdout)
            .expect("gid")
            .trim()
            .parse::<u32>()
            .expect("numeric gid")
    } else {
        gid
    };
    let owns_root = std::env::var_os("O3K_CHECKPOINT_BOUNDARY_ROOT").is_none();
    let root = std::env::var_os("O3K_CHECKPOINT_BOUNDARY_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("o3k-checkpoint-boundary-{}", Uuid::new_v4()))
        });
    let original = root.join("original");
    let corrected = root.join("corrected");
    std::fs::create_dir_all(&original).expect("original directory");
    std::fs::create_dir_all(&corrected).expect("corrected directory");
    // The protected runner creates the legacy directory as root:root 0755.
    // When this unit test itself is not root, model the same daemon boundary
    // with an existing 0555 directory owned by the test user.
    let original_mode = if uid == 0 { 0o755 } else { 0o555 };
    std::fs::set_permissions(
        &original,
        std::os::unix::fs::PermissionsExt::from_mode(original_mode),
    )
    .expect("original mode");
    std::fs::set_permissions(
        &corrected,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("corrected mode");
    if uid == 0 {
        let owner = format!("{daemon}:{daemon_gid}");
        assert!(
            Command::new("chown")
                .args([&owner, corrected.to_str().unwrap()])
                .status()
                .expect("chown")
                .success()
        );
    }
    let server = Uuid::new_v4();
    let exe = std::env::current_exe().expect("test executable");
    let run_child = |mode: &str, directory: &Path| {
        let checkpoint = directory.join("checkpoint.json");
        let release = directory.join("release");
        let mut command = Command::new(&exe);
        command
            .args([
                "--exact",
                "checkpoint_tests::targeted_checkpoint_unprivileged_boundary_publishes_and_releases",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .env("O3K_CHECKPOINT_BOUNDARY_MODE", mode)
            .env("O3K_CHECKPOINT_BOUNDARY_CHECKPOINT", &checkpoint)
            .env("O3K_CHECKPOINT_BOUNDARY_RELEASE", &release)
            .env("O3K_CHECKPOINT_BOUNDARY_SERVER", server.to_string());
        if uid == 0 {
            use std::os::unix::process::CommandExt;
            command.uid(daemon).gid(daemon_gid);
        }
        (command, checkpoint, release)
    };
    let (mut original_child, original_checkpoint, original_release) =
        run_child("original", &original);
    assert!(original_child.status().expect("original child").success());
    let (mut corrected_child, corrected_checkpoint, corrected_release) =
        run_child("corrected", &corrected);
    let mut child = corrected_child.spawn().expect("corrected child");
    for _ in 0..100 {
        if corrected_checkpoint.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        corrected_checkpoint.exists(),
        "checkpoint was not published"
    );
    std::fs::write(&corrected_release, b"release\n").expect("release marker");
    assert!(child.wait().expect("corrected child wait").success());
    let checkpoint = std::fs::read_to_string(&corrected_checkpoint).expect("checkpoint contents");
    assert!(checkpoint.contains("\"server_id\""));
    assert!(checkpoint.contains("\"endpoint_id\":\"endpoint-1\""));
    assert!(!original_checkpoint.exists());
    assert!(!original_release.exists());
    if let Some(evidence_path) = std::env::var_os("O3K_CHECKPOINT_BOUNDARY_EVIDENCE") {
        let evidence = serde_json::json!({
            "original_layout": "permission_denied",
            "corrected_layout": "published_and_released",
            "original_checkpoint": original_checkpoint,
            "corrected_checkpoint": corrected_checkpoint,
        });
        std::fs::write(
            evidence_path,
            serde_json::to_vec_pretty(&evidence).expect("evidence json"),
        )
        .expect("evidence artifact");
    }
    if owns_root {
        let _ = std::fs::remove_dir_all(root);
    }
}
