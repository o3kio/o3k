//! Real-daemon PP.6 startup-boundary evidence. These cases need root because
//! production recovery paths require root-protected ancestors on local ext4.

#![allow(clippy::expect_used, clippy::panic)]

use std::{
    fs,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct RootFixture(PathBuf);

impl RootFixture {
    fn new() -> std::io::Result<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "requires root for protected recovery-path fixture",
            ));
        }
        let path = PathBuf::from(format!(
            "/var/lib/o3k-pp6-startup-{}-{}",
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

    fn prepare_layout(&self) -> std::io::Result<()> {
        fs::create_dir(self.data_dir())?;
        let (uid, gid) = o3k_identity()?;
        chown(&self.data_dir(), uid, gid)?;
        fs::set_permissions(self.data_dir(), fs::Permissions::from_mode(0o700))?;
        for path in [self.prefix().join("etc"), self.prefix().join("etc/o3k")] {
            fs::create_dir_all(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        }
        Ok(())
    }

    fn install_restore_config(&self, recovery_dir: &Path) -> std::io::Result<()> {
        let (_, gid) = o3k_identity()?;
        let value = serde_json::json!({
            "format": "o3k-restore-preflight-v1",
            "backend": "sqlite",
            "target_directory": self.data_dir(),
            "recovery_directory": recovery_dir,
        });
        fs::write(
            self.prefix().join("etc/o3k/restore.json"),
            serde_json::to_vec(&value)?,
        )?;
        chown(&self.prefix().join("etc/o3k/restore.json"), 0, gid)?;
        fs::set_permissions(
            self.prefix().join("etc/o3k/restore.json"),
            fs::Permissions::from_mode(0o640),
        )
    }

    fn daemon(&self, address: SocketAddr) -> std::io::Result<Child> {
        let (uid, gid) = o3k_identity()?;
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
            .uid(uid)
            .gid(gid)
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

fn chown(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    let status = Command::new("chown")
        .arg(format!("{uid}:{gid}"))
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

struct ProcessLockHolder(Child);

impl ProcessLockHolder {
    fn start(data_dir: &Path, ready_path: &Path, uid: u32, gid: u32) -> std::io::Result<Self> {
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", "lock_holder_helper", "--nocapture"])
            .env("O3K_PP6_LOCK_HOLDER_DATA_DIR", data_dir)
            .env("O3K_PP6_LOCK_HOLDER_READY_PATH", ready_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .uid(uid)
            .gid(gid)
            .spawn()?;
        Self::wait_until_ready(child, ready_path, Duration::from_secs(5))
    }

    fn wait_until_ready(
        mut child: Child,
        ready_path: &Path,
        timeout: Duration,
    ) -> std::io::Result<Self> {
        let deadline = Instant::now() + timeout;
        while !ready_path.exists() && Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !ready_path.exists() {
            // Stop the helper before reading its pipe to EOF: a live helper can
            // keep stderr open indefinitely after the readiness deadline.
            let _ = child.kill();
            let _ = child.wait();
            let mut stderr = String::new();
            if let Some(mut stream) = child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut stream, &mut stderr);
            }
            return Err(std::io::Error::other(format!(
                "service-user store-lock helper did not acquire the lock; stderr={stderr:?}"
            )));
        }
        Ok(Self(child))
    }

    fn release(mut self) -> std::io::Result<std::process::ExitStatus> {
        self.0.stdin.take();
        self.0.wait()
    }
}

impl Drop for ProcessLockHolder {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn stalled_lock_helper() {
    if std::env::var_os("O3K_PP6_STALLED_HELPER").is_some() {
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
    }
}

#[test]
fn lock_holder_readiness_timeout_stops_child_before_reading_stderr()
-> Result<(), Box<dyn std::error::Error>> {
    let ready_path = std::env::temp_dir().join(format!("o3k-never-ready-{}", uuid::Uuid::new_v4()));
    let child = Command::new(std::env::current_exe()?)
        .args(["--exact", "stalled_lock_helper", "--nocapture"])
        .env("O3K_PP6_STALLED_HELPER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    let result =
        ProcessLockHolder::wait_until_ready(child, &ready_path, Duration::from_millis(100));
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    Ok(())
}

#[test]
fn lock_holder_helper() {
    let Ok(data_dir) = std::env::var("O3K_PP6_LOCK_HOLDER_DATA_DIR") else {
        return;
    };
    let lock = o3k_store::StoreAccessLock::acquire(data_dir)
        .expect("service-user lock helper must acquire the store lock");
    let ready_path =
        std::env::var("O3K_PP6_LOCK_HOLDER_READY_PATH").expect("lock-ready path must be provided");
    fs::write(ready_path, b"ready").expect("write lock-ready marker");
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    drop(lock);
}

fn assert_no_listener(address: SocketAddr) {
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err(),
        "quarantined daemon unexpectedly accepted a connection"
    );
}

fn assert_stderr_contains(child: &mut Child, expected: &str) -> std::io::Result<()> {
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        std::io::Read::read_to_string(&mut stream, &mut stderr)?;
    }
    assert!(
        stderr.contains(expected),
        "expected startup rejection {expected:?}; stderr={stderr:?}"
    );
    Ok(())
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
#[ignore = "requires root and a local ext4 recovery fixture; run explicitly with --ignored"]
fn real_o3kd_quarantines_before_listener_or_store_open() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RootFixture::new()?;
    fixture.prepare_layout()?;
    let recovery = fixture.0.join("recovery");
    fs::create_dir(&recovery)?;
    let (uid, gid) = o3k_identity()?;
    chown(&recovery, uid, gid)?;
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700))?;
    fs::write(
        recovery.join("restore-journal.json"),
        b"quarantine-evidence",
    )?;
    chown(&recovery.join("restore-journal.json"), uid, gid)?;
    fs::set_permissions(
        recovery.join("restore-journal.json"),
        fs::Permissions::from_mode(0o600),
    )?;
    fixture.install_restore_config(&recovery)?;

    let address = unused_address()?;
    let mut child = fixture.daemon(address)?;
    let status = wait_for_exit(&mut child)?;
    assert!(!status.success(), "quarantined daemon exited successfully");
    assert_stderr_contains(
        &mut child,
        "restore recovery state is present; daemon startup is quarantined",
    )?;
    assert!(fixture.data_dir().join(".o3k-store.lock").exists());
    assert_no_listener(address);
    assert!(
        !fixture.data_dir().join("o3k.sqlite").exists(),
        "quarantined daemon opened or created the canonical SQLite store"
    );
    Ok(())
}

#[test]
#[ignore = "requires root; run explicitly with --ignored"]
fn real_o3k_rollback_denies_under_restore_quarantine() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = RootFixture::new()?;
    fixture.prepare_layout()?;
    let (uid, gid) = o3k_identity()?;
    let recovery = fixture.0.join("recovery");
    fs::create_dir(&recovery)?;
    chown(&recovery, uid, gid)?;
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700))?;
    fs::write(
        recovery.join("restore-journal.json"),
        b"quarantine-evidence",
    )?;
    chown(&recovery.join("restore-journal.json"), uid, gid)?;
    fs::set_permissions(
        recovery.join("restore-journal.json"),
        fs::Permissions::from_mode(0o600),
    )?;
    fixture.install_restore_config(&recovery)?;

    // The real rollback mutation entry must inherit the legacy restore-state
    // deny through deny_startup_if_restore_state: denial before any snapshot,
    // store, or service mutation.
    let o3k_binary = Path::new(env!("CARGO_BIN_EXE_o3kd")).with_file_name("o3k");
    let output = Command::new(o3k_binary)
        .arg("rollback")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("O3K_INSTALL_PREFIX", fixture.prefix())
        .env("O3K_UPGRADE_PREFIX", fixture.prefix())
        .output()?;
    assert!(
        !output.status.success(),
        "rollback succeeded under restore quarantine"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("restore quarantine"),
        "unexpected rollback output: {text}"
    );
    assert!(
        !fixture.data_dir().join("o3k.sqlite").exists(),
        "rollback created or opened the canonical SQLite store"
    );
    Ok(())
}

#[test]
#[ignore = "requires root; run explicitly with --ignored"]
fn real_o3kd_lock_contention_denies_before_listener_or_store_open()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RootFixture::new()?;
    fixture.prepare_layout()?;
    let (uid, gid) = o3k_identity()?;
    let ready_path = fixture.data_dir().join(".lock-holder-ready");
    let lock_holder = ProcessLockHolder::start(&fixture.data_dir(), &ready_path, uid, gid)?;
    let address = unused_address()?;
    let mut child = fixture.daemon(address)?;
    let status = wait_for_exit(&mut child)?;
    assert!(
        !status.success(),
        "second daemon succeeded while lock was held"
    );
    assert_stderr_contains(
        &mut child,
        "failed to acquire O3K data-directory lifetime lock",
    )?;
    assert_no_listener(address);
    assert!(
        !fixture.data_dir().join("o3k.sqlite").exists(),
        "lock-contention daemon opened or created the canonical SQLite store"
    );
    assert!(
        lock_holder.release()?.success(),
        "service-user lock holder exited unsuccessfully"
    );
    Ok(())
}
