//! Real-daemon PP.6 startup-boundary evidence. These cases need root because
//! production recovery paths require root-protected ancestors on local ext4.

#![allow(clippy::expect_used, clippy::panic)]

use std::{
    fs,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const O3K_UID: u32 = 994;
const O3K_GID: u32 = 985;

struct RootFixture(PathBuf);

impl RootFixture {
    fn new() -> std::io::Result<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "requires root for installed recovery path posture",
            ));
        }
        let path = PathBuf::from(format!(
            "/var/lib/o3k-pp6-startup-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }

    fn data_dir(&self) -> PathBuf {
        self.0.join("data")
    }

    fn prefix(&self) -> PathBuf {
        self.0.join("prefix")
    }

    fn prepare_layout(&self) -> std::io::Result<()> {
        fs::create_dir(self.data_dir())?;
        fs::set_permissions(self.data_dir(), fs::Permissions::from_mode(0o700))?;
        for path in [self.prefix().join("etc"), self.prefix().join("etc/o3k")] {
            fs::create_dir_all(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        }
        Ok(())
    }

    fn install_restore_config(&self, recovery_dir: &Path) -> std::io::Result<()> {
        let value = serde_json::json!({
            "format": "o3k-restore-preflight-v1",
            "backend": "postgresql",
            "target_directory": self.data_dir(),
            "recovery_directory": recovery_dir,
        });
        fs::write(
            self.prefix().join("etc/o3k/restore.json"),
            serde_json::to_vec(&value)?,
        )?;
        fs::set_permissions(
            self.prefix().join("etc/o3k/restore.json"),
            fs::Permissions::from_mode(0o600),
        )
    }

    fn daemon(&self, address: SocketAddr) -> std::io::Result<Child> {
        Command::new(env!("CARGO_BIN_EXE_o3kd"))
            .arg("--data-dir")
            .arg(self.data_dir())
            .arg("--log-filter")
            .arg("warn")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("O3K_INSTALL_PREFIX", self.prefix())
            .env("O3K_LISTEN_ADDR", address.to_string())
            .env("O3K_PROVIDER", "fake")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
    }
}

impl Drop for RootFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn unused_address() -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr()
}

fn chown_to_o3k(path: &Path) -> std::io::Result<()> {
    let status = Command::new("chown")
        .arg(format!("{O3K_UID}:{O3K_GID}"))
        .arg(path)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "could not set recovery fixture owner",
        ))
    }
}

fn assert_no_listener(address: SocketAddr) {
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err(),
        "quarantined daemon unexpectedly accepted a connection"
    );
}

fn wait_for_exit(child: &mut Child) -> std::io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "o3kd did not exit after startup quarantine",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
#[ignore = "requires root and a local ext4 recovery fixture; run in the installed-host gate"]
fn real_o3kd_quarantines_before_listener_or_store_open() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RootFixture::new()?;
    fixture.prepare_layout()?;
    let recovery = fixture.0.join("recovery");
    fs::create_dir(&recovery)?;
    chown_to_o3k(&recovery)?;
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700))?;
    fs::write(
        recovery.join("restore-journal.json"),
        b"quarantine-evidence",
    )?;
    chown_to_o3k(&recovery.join("restore-journal.json"))?;
    fs::set_permissions(
        recovery.join("restore-journal.json"),
        fs::Permissions::from_mode(0o600),
    )?;
    fixture.install_restore_config(&recovery)?;

    let address = unused_address()?;
    let mut child = fixture.daemon(address)?;
    let status = wait_for_exit(&mut child)?;
    assert!(!status.success(), "quarantined daemon exited successfully");
    assert_no_listener(address);
    assert!(
        !fixture.data_dir().join("o3k.sqlite").exists(),
        "quarantined daemon opened or created the canonical SQLite store"
    );
    Ok(())
}

#[test]
#[ignore = "requires root; run in the installed-host gate"]
fn real_o3kd_lock_contention_denies_before_listener_or_store_open()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RootFixture::new()?;
    fixture.prepare_layout()?;
    let _lock = o3k_store::StoreAccessLock::acquire(fixture.data_dir())?;
    let address = unused_address()?;
    let mut child = fixture.daemon(address)?;
    let status = wait_for_exit(&mut child)?;
    assert!(
        !status.success(),
        "second daemon succeeded while lock was held"
    );
    assert_no_listener(address);
    assert!(
        !fixture.data_dir().join("o3k.sqlite").exists(),
        "lock-contention daemon opened or created the canonical SQLite store"
    );
    Ok(())
}
