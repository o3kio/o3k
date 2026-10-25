//! PP.6 maintenance-entry quarantine evidence for the real `o3k` CLI.

#![allow(clippy::expect_used, clippy::panic)]

use std::{
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::PathBuf,
    process::Command,
};

struct RootFixture(PathBuf);

impl RootFixture {
    fn new() -> std::io::Result<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "requires root to provision the installed recovery posture",
            ));
        }
        let path = PathBuf::from(format!(
            "/var/lib/o3k-pp6-verify-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        Ok(Self(path))
    }

    fn data_dir(&self) -> PathBuf {
        self.0.join("data")
    }

    fn prefix(&self) -> PathBuf {
        self.0.join("prefix")
    }

    fn chown(path: &std::path::Path, uid: u32, gid: u32) -> std::io::Result<()> {
        let status = Command::new("chown")
            .arg(format!("{uid}:{gid}"))
            .arg(path)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other("could not set fixture owner"))
        }
    }
}

fn o3k_identity() -> std::io::Result<(u32, u32)> {
    let passwd = fs::read_to_string("/etc/passwd")?;
    for line in passwd.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.first() == Some(&"o3k") && fields.len() >= 4 {
            let uid = fields[2]
                .parse()
                .map_err(|_| std::io::Error::other("invalid o3k uid"))?;
            let gid = fields[3]
                .parse()
                .map_err(|_| std::io::Error::other("invalid o3k gid"))?;
            return Ok((uid, gid));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "o3k service account is unavailable",
    ))
}

impl Drop for RootFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires root and a local ext4 recovery fixture; run explicitly with --ignored"]
fn backup_verify_quarantines_before_acquiring_store_access()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RootFixture::new()?;
    let (uid, gid) = o3k_identity()?;
    let data_dir = fixture.data_dir();
    let etc = fixture.prefix().join("etc/o3k");
    let recovery = fixture.0.join("recovery");
    fs::create_dir_all(&data_dir)?;
    fs::create_dir_all(&etc)?;
    fs::create_dir(&recovery)?;
    RootFixture::chown(&data_dir, uid, gid)?;
    RootFixture::chown(&recovery, uid, gid)?;
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(fixture.prefix(), fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(
        fixture.prefix().join("etc"),
        fs::Permissions::from_mode(0o755),
    )?;
    fs::set_permissions(&etc, fs::Permissions::from_mode(0o755))?;

    let journal = recovery.join("restore-journal.json");
    let restore_config = etc.join("restore.json");
    fs::write(
        &restore_config,
        serde_json::to_vec(&serde_json::json!({
            "format": "o3k-restore-preflight-v1",
            "backend": "sqlite",
            "target_directory": data_dir,
            "recovery_directory": recovery,
        }))?,
    )?;
    RootFixture::chown(&restore_config, 0, gid)?;
    // The policy remains root-owned and non-writable, while the daemon/service
    // group can read it. This makes the test exercise journal discovery rather
    // than an unreadable-config fail-closed path.
    fs::set_permissions(&restore_config, fs::Permissions::from_mode(0o640))?;

    let artifact = fixture.0.join("inert-artifact.o3k");
    fs::write(&artifact, b"inert")?;
    RootFixture::chown(&artifact, uid, gid)?;
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600))?;

    let run_verify = || -> std::io::Result<std::process::Output> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_o3k"));
        command
            .args(["backup", "verify", "--artifact"])
            .arg(&artifact)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("O3K_DATA_DIR", &data_dir)
            .env("O3K_INSTALL_PREFIX", fixture.prefix());
        command.uid(uid).gid(gid);
        command.output()
    };

    // With the same readable, valid config but an empty recovery directory,
    // verification gets past the quarantine guard and acquires the store lock.
    let control = run_verify()?;
    assert!(!String::from_utf8_lossy(&control.stdout).contains("restore-recovery-state-present"));
    let store_lock = data_dir.join(".o3k-store.lock");
    assert!(
        store_lock.exists(),
        "control run did not reach store access"
    );
    fs::remove_file(&store_lock)?;

    fs::write(&journal, b"quarantine-evidence")?;
    RootFixture::chown(&journal, uid, gid)?;
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))?;
    let output = run_verify()?;
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("restore-recovery-state-present"),
        "unexpected backup verify result: {stdout}"
    );
    assert!(
        !data_dir.join(".o3k-store.lock").exists(),
        "backup verify acquired store access before quarantine"
    );
    Ok(())
}
