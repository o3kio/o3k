//! A10.1 startup-denial process checks.
//!
//! These tests deliberately use disposable filesystems and never create or
//! restore a PostgreSQL target.  They are ignored by default because the
//! protected release paths require root, mount namespaces, and a local
//! filesystem.  The executable is invoked directly so the test covers the
//! same guard used by systemd and by an operator starting `o3kd` manually.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{
    fs,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    time::Duration,
};

struct Fixture {
    root: PathBuf,
    data: PathBuf,
    share: PathBuf,
    etc_o3k: PathBuf,
}

impl Fixture {
    fn new() -> std::io::Result<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "A10.1 process fixture requires root",
            ));
        }
        let root = PathBuf::from(format!(
            "/tmp/o3k-a10-startup-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        let data = root.join("var/o3k");
        let share = root.join("share/o3k");
        let etc_o3k = root.join("etc/o3k");
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&share)?;
        fs::create_dir_all(&etc_o3k)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            root,
            data,
            share,
            etc_o3k,
        })
    }

    fn install_manifest(&self, bytes: &[u8]) -> std::io::Result<()> {
        fs::write(self.share.join("release-manifest.json"), bytes)
    }

    fn install_policy(&self, bytes: &[u8]) -> std::io::Result<()> {
        fs::write(self.etc_o3k.join("installation-policy.json"), bytes)
    }

    fn run(&self, state: &str) -> std::io::Result<(std::process::ExitStatus, String, SocketAddr)> {
        let address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        let script = format!(
            "set -eu; mount --make-rprivate /; mkdir -p /var/lib /usr/local/share/o3k /etc/o3k; mount --bind {0} /var/lib; mount --bind {1} /usr/local/share/o3k; mount --bind {2} /etc/o3k; {3}",
            self.root.join("var").display(),
            self.root.join("share/o3k").display(),
            self.root.join("etc/o3k").display(),
            state
                .replace("{o3kd}", env!("CARGO_BIN_EXE_o3kd"))
                .replace("{data}", "/var/lib/o3k")
                .replace("{addr}", &address.to_string())
        );
        let output = Command::new("unshare")
            .args(["--mount", "--fork", "--", "sh", "-c", &script])
            .output()?;
        Ok((
            output.status,
            String::from_utf8_lossy(&output.stderr).into_owned(),
            address,
        ))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_denied(fixture: &Fixture, command: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (status, stderr, address) = fixture.run(command)?;
    assert!(
        !status.success(),
        "A10.1-denied daemon unexpectedly succeeded: {stderr}"
    );
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err(),
        "denied daemon bound its API listener"
    );
    assert!(
        !fixture.data.join("o3k.sqlite").exists(),
        "denied daemon opened the canonical SQLite store"
    );
    Ok(())
}

#[test]
#[ignore = "requires root, unshare(1), protected release paths, and local storage"]
fn missing_selector_denies_before_listener_or_store() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fixture.install_manifest(br#"{"version":"test","source_commit":"0000000000000000000000000000000000000000","release_artifact_sha256":"0000000000000000000000000000000000000000000000000000000000000000","profile_id":"o3k-small-edge-v1","schema_version":1,"installation_policy_format":"o3k-installation-policy-v1","installation_policy_path":"/etc/o3k/installation-policy.json","installation_policy_authority":{"key_id":"test-policy","ed25519_public_key":"0000000000000000000000000000000000000000000000000000000000000000","policy_format":"o3k-installation-policy-v1","policy_path":"/etc/o3k/installation-policy.json"}}"#)?;
    assert_denied(
        &fixture,
        "{o3kd} --data-dir {data} --listen-addr {addr} --provider fake",
    )
}

#[test]
#[ignore = "requires root, unshare(1), protected release paths, and local storage"]
fn invalid_manifest_or_selector_denies_before_listener_or_store()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fixture.install_manifest(b"{not-json")?;
    fixture.install_policy(br#"not-json"#)?;
    assert_denied(
        &fixture,
        "{o3kd} --data-dir {data} --listen-addr {addr} --provider fake",
    )
}

#[test]
#[ignore = "requires root, unshare(1), protected release paths, and local storage"]
fn partial_generation_denies_before_listener_or_store() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fixture.install_manifest(br#"{"version":"test","source_commit":"0000000000000000000000000000000000000000","release_artifact_sha256":"0000000000000000000000000000000000000000000000000000000000000000","profile_id":"o3k-small-edge-v1","schema_version":1,"installation_policy_format":"o3k-installation-policy-v1","installation_policy_path":"/etc/o3k/installation-policy.json","installation_policy_authority":{"key_id":"test","ed25519_public_key":"0000000000000000000000000000000000000000000000000000000000000000","policy_format":"o3k-installation-policy-v1","policy_path":"/etc/o3k/installation-policy.json"}}"#)?;
    fs::write(
        fixture.data.join("state.json"),
        br#"{"format":"o3k-installation-policy-migration-v1"}"#,
    )?;
    fixture.install_policy(br#"{"format":"o3k-installation-policy-v1"}"#)?;
    assert_denied(
        &fixture,
        "{o3kd} --data-dir {data} --listen-addr {addr} --provider fake",
    )
}
