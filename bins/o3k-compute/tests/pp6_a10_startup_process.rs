//! Direct-executable installed-path denial coverage for A10.1.
#![allow(clippy::expect_used)]

use std::{env, fs, path::PathBuf, process::Command};

fn fixture_root() -> PathBuf {
    let root = env::temp_dir().join(format!("o3k-a10-compute-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create fixture");
    root
}

#[test]
#[ignore = "requires root, unshare(1), and mount namespace capability"]
fn direct_executable_denies_invalid_fixed_installed_selector_before_side_effects() {
    let uid = Command::new("id").args(["-u"]).output().expect("query uid");
    if String::from_utf8_lossy(&uid.stdout).trim() != "0" {
        eprintln!("skipping root-only mount namespace test");
        return;
    }
    let root = fixture_root();
    let manifest = root.join("release-manifest.json");
    let policy = root.join("installation-policy.json");
    let data = root.join("data");
    let network = root.join("network");
    let tls = root.join("tls");
    for path in [&data, &network, &tls] {
        fs::create_dir(path).expect("create side-effect sentinel");
    }
    fs::write(&manifest, br#"{"version":"old","source_commit":"wrong"}"#)
        .expect("write invalid release manifest");
    fs::write(&policy, b"invalid-selector\n").expect("write invalid selector");
    let binary = env::var("CARGO_BIN_EXE_o3k-compute").expect("Cargo-provided compute binary");
    let script = r#"
set -eu
mkdir -p /usr/local/share/o3k /etc/o3k /var/lib/o3k
: > /usr/local/share/o3k/release-manifest.json
: > /etc/o3k/installation-policy.json
mount --bind "$MANIFEST" /usr/local/share/o3k/release-manifest.json
mount --bind "$POLICY" /etc/o3k/installation-policy.json
mount --bind "$DATA" /var/lib/o3k
exec "$BIN"
"#;
    let status = Command::new("unshare")
        .args([
            "--mount",
            "--fork",
            "--propagation",
            "private",
            "sh",
            "-c",
            script,
        ])
        .env("BIN", binary)
        .env("MANIFEST", &manifest)
        .env("POLICY", &policy)
        .env("DATA", &data)
        .env("O3K_COMPUTE_DATA_DIR", &data)
        .env("O3K_COMPUTE_NETWORK_ROOT", &network)
        .env("O3K_COMPUTE_TLS_DIR", &tls)
        .env("O3K_COMPUTE_CONTROL_ENDPOINT", "https://127.0.0.1:1")
        .env("O3K_COMPUTE_HEALTH_ADDR", "127.0.0.1:1")
        .env("RUST_LOG", "off")
        .output()
        .expect("invoke unshare");
    assert!(
        !status.status.success(),
        "invalid selector must deny startup"
    );
    assert!(
        fs::read_dir(&data)
            .expect("inspect data sentinel")
            .next()
            .is_none()
    );
    assert!(
        fs::read_dir(&network)
            .expect("inspect network sentinel")
            .next()
            .is_none()
    );
    assert!(
        fs::read_dir(&tls)
            .expect("inspect TLS sentinel")
            .next()
            .is_none()
    );
    let _ = fs::remove_dir_all(root);
}
