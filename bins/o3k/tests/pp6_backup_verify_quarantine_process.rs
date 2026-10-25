//! PP.6 maintenance-entry quarantine evidence for the real `o3k` CLI.

#![allow(clippy::expect_used, clippy::panic)]

use std::{
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::PathBuf,
    process::Command,
};

const O3K_UID: u32 = 994;
const O3K_GID: u32 = 985;

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

    fn chown_to_o3k(path: &std::path::Path) -> std::io::Result<()> {
        let status = Command::new("chown")
            .arg(format!("{O3K_UID}:{O3K_GID}"))
            .arg(path)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other("could not set fixture owner"))
        }
    }
}

impl Drop for RootFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires root and a local ext4 recovery fixture; run in the installed-host gate"]
fn backup_verify_quarantines_before_acquiring_store_access()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RootFixture::new()?;
    let data_dir = fixture.data_dir();
    let etc = fixture.prefix().join("etc/o3k");
    let recovery = fixture.0.join("recovery");
    fs::create_dir_all(&data_dir)?;
    fs::create_dir_all(&etc)?;
    fs::create_dir(&recovery)?;
    RootFixture::chown_to_o3k(&data_dir)?;
    RootFixture::chown_to_o3k(&recovery)?;
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(fixture.prefix(), fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(
        fixture.prefix().join("etc"),
        fs::Permissions::from_mode(0o755),
    )?;
    fs::set_permissions(&etc, fs::Permissions::from_mode(0o755))?;

    let journal = recovery.join("restore-journal.json");
    fs::write(&journal, b"quarantine-evidence")?;
    RootFixture::chown_to_o3k(&journal)?;
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))?;
    let restore_config = etc.join("restore.json");
    fs::write(
        &restore_config,
        serde_json::to_vec(&serde_json::json!({
            "format": "o3k-restore-preflight-v1",
            "backend": "postgresql",
            "target_directory": data_dir,
            "recovery_directory": recovery,
        }))?,
    )?;
    fs::set_permissions(&restore_config, fs::Permissions::from_mode(0o600))?;

    let artifact = fixture.0.join("inert-artifact.o3k");
    fs::write(&artifact, b"inert")?;
    RootFixture::chown_to_o3k(&artifact)?;
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600))?;

    let mut command = Command::new(env!("CARGO_BIN_EXE_o3k"));
    command
        .args(["backup", "verify", "--artifact"])
        .arg(&artifact)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("O3K_DATA_DIR", &data_dir)
        .env("O3K_INSTALL_PREFIX", fixture.prefix());
    command.uid(O3K_UID).gid(O3K_GID);
    let output = command.output()?;
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
