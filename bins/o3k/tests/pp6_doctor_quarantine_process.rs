//! PP.6 maintenance-entry quarantine evidence for `o3k doctor`.

#![allow(clippy::expect_used, clippy::panic)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

struct RootFixture(PathBuf);

impl RootFixture {
    fn new() -> std::io::Result<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "requires root to provision the protected recovery fixture",
            ));
        }
        let path = PathBuf::from(format!(
            "/var/lib/o3k-pp6-doctor-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        Ok(Self(path))
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

impl Drop for RootFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
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
            if uid == 0 || gid == 0 {
                return Err(std::io::Error::other("o3k must be an unprivileged account"));
            }
            return Ok((uid, gid));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "o3k service account is unavailable",
    ))
}

#[test]
#[ignore = "requires root and a local ext4 recovery fixture; run explicitly with --ignored"]
fn doctor_quarantines_before_canonical_database_checks() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RootFixture::new()?;
    let (uid, gid) = o3k_identity()?;
    let data_dir = fixture.0.join("data");
    let config_dir = fixture.0.join("config");
    let prefix_config = fixture.0.join("prefix/etc/o3k");
    let recovery_dir = fixture.0.join("recovery");
    fs::create_dir(&data_dir)?;
    fs::create_dir(&config_dir)?;
    fs::create_dir_all(&prefix_config)?;
    fs::create_dir(&recovery_dir)?;
    RootFixture::chown(&data_dir, uid, gid)?;
    RootFixture::chown(&recovery_dir, uid, gid)?;
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&recovery_dir, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(fixture.0.join("prefix"), fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(
        fixture.0.join("prefix/etc"),
        fs::Permissions::from_mode(0o755),
    )?;
    fs::set_permissions(&prefix_config, fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o755))?;

    let restore_config = prefix_config.join("restore.json");
    fs::write(
        &restore_config,
        serde_json::to_vec(&serde_json::json!({
            "format": "o3k-restore-preflight-v1",
            "backend": "postgres",
            "target_directory": data_dir,
            "recovery_directory": recovery_dir,
        }))?,
    )?;
    RootFixture::chown(&restore_config, 0, gid)?;
    fs::set_permissions(&restore_config, fs::Permissions::from_mode(0o640))?;

    let journal = recovery_dir.join("restore-journal.json");
    fs::write(&journal, b"quarantine-evidence")?;
    RootFixture::chown(&journal, uid, gid)?;
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))?;

    let mut command = Command::new("/usr/bin/setpriv");
    command.args([
        "--reuid",
        &uid.to_string(),
        "--regid",
        &gid.to_string(),
        "--clear-groups",
        "--",
        env!("CARGO_BIN_EXE_o3k"),
    ]);
    command
        .args(["doctor", "--json"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("O3K_DATA_DIR", &data_dir)
        .env("O3K_DATABASE_BACKEND", "postgres")
        .env("O3K_DATABASE_URL", "postgres://o3k@127.0.0.1:1/o3k")
        .env("O3K_DOCTOR_DATA_DIR", &data_dir)
        .env("O3K_DOCTOR_CONFIG_DIR", &config_dir)
        .env("O3K_INSTALL_PREFIX", fixture.0.join("prefix"));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    assert_denied(run_bounded(&mut command)?, "recovery quarantine")?;

    // Empty recovery metadata cannot bypass an absent or busy lifetime guard.
    fs::remove_file(&journal)?;
    assert_denied(run_bounded(&mut command)?, "store-access lock unavailable")?;
    let lock_path = data_dir.join(".o3k-store.lock");
    assert!(
        !lock_path.exists(),
        "doctor created missing installation state"
    );
    fs::write(&lock_path, b"")?;
    RootFixture::chown(&lock_path, uid, gid)?;
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))?;
    let directory = rustix::fs::open(
        &data_dir,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    rustix::fs::flock(
        &directory,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )?;
    assert_denied(run_bounded(&mut command)?, "store-access lock unavailable")?;
    rustix::fs::flock(&directory, rustix::fs::FlockOperation::Unlock)?;

    // A running diagnostic owns the guard until process termination.
    let mut child = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let observation = (|| -> std::io::Result<bool> {
        loop {
            match rustix::fs::flock(
                &directory,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            ) {
                Err(rustix::io::Errno::WOULDBLOCK) => return Ok(true),
                Err(error) => return Err(error.into()),
                Ok(()) => rustix::fs::flock(&directory, rustix::fs::FlockOperation::Unlock)?,
            }
            if child.try_wait()?.is_some() || Instant::now() >= deadline {
                return Ok(false);
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    let _ = child.kill();
    child.wait_with_output()?;
    let observed_lock = observation?;
    assert!(
        observed_lock,
        "doctor did not retain its store-access guard"
    );
    rustix::fs::flock(
        &directory,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )?;
    Ok(())
}

fn run_bounded(command: &mut Command) -> std::io::Result<Output> {
    let mut child = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output(),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "doctor did not fail closed promptly",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_denied(output: Output, reason: &str) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["overall_status"], "unhealthy");
    let checks = report["checks"].as_array().expect("checks array");
    assert_eq!(checks.len(), 1, "doctor ran checks despite quarantine");
    assert_eq!(checks[0]["id"], "database.accessible");
    assert_eq!(checks[0]["status"], "FAIL");
    assert!(
        checks[0]["summary"]
            .as_str()
            .expect("summary")
            .contains(reason)
    );
    Ok(())
}
