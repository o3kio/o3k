//! Source-only C1 startup boundary evidence.  The fixture is deliberately
//! isolated in a private mount namespace and is not an installed-release or
//! production qualification claim.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

fn root_fixture() -> Option<PathBuf> {
    if rustix::process::geteuid().as_raw() != 0 {
        return None;
    }
    let path = PathBuf::from(format!("/var/lib/o3k-c1-startup-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&path).ok()?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).ok()?;
    Some(path)
}

#[test]
#[ignore = "requires root, unshare(1), and a source-built o3k binary"]
fn missing_fixed_release_metadata_denies_before_store() {
    let fixture = root_fixture().expect("root fixture");
    let var = fixture.join("var");
    let etc = var.join("etc-o3k");
    let share = var.join("share-o3k");
    fs::create_dir_all(&var).unwrap();
    fs::create_dir_all(&etc).unwrap();
    fs::create_dir_all(&share).unwrap();
    fs::copy("/etc/passwd", etc.join("passwd")).unwrap();
    fs::copy("/etc/group", etc.join("group")).unwrap();
    let data = var.join("o3k");
    fs::create_dir(&data).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    let binary = env!("CARGO_BIN_EXE_o3k");
    let script = format!(
        "set -eu; mount --make-rprivate /; mount --bind {0} /var/lib; mount -t tmpfs tmpfs /etc; mkdir /etc/o3k; mount --bind {1} /etc/o3k; mount -t tmpfs tmpfs /usr/local; mkdir -p /usr/local/share/o3k; mount --bind {2} /usr/local/share/o3k; test -d /var/lib/o3k; test -d /etc/o3k; test -d /usr/local/share/o3k; echo C1_NAMESPACE_READY >&2; exec {3} doctor --json",
        var.display(),
        "/var/lib/etc-o3k",
        "/var/lib/share-o3k",
        binary
    );
    let output = Command::new("unshare")
        .args(["--mount", "--fork", "--", "sh", "-c", &script])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stderr).contains("C1_NAMESPACE_READY"));
    assert!(
        !output.status.success(),
        "missing fixed installation policy unexpectedly allowed startup"
    );
    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_ascii_lowercase();
    assert!(
        output_text.contains("installed recovery release"),
        "unexpected startup denial: {output_text}"
    );
    assert!(
        !data.join("o3k.db").exists(),
        "startup reached canonical store"
    );
    let _ = fs::remove_dir_all(fixture);
}
