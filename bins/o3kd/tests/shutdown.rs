#![cfg(unix)]

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct TestDataDir(std::path::PathBuf);

impl TestDataDir {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "o3kd-store-lock-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
}

impl Drop for TestDataDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_address() -> io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr()
}

fn daemon_command(address: std::net::SocketAddr, data_dir: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_o3kd"));
    command
        .args([
            "--listen-addr",
            &address.to_string(),
            "--data-dir",
            data_dir.to_str().unwrap_or_default(),
            "--log-filter",
            "off",
        ])
        .env(
            "O3K_NATIVE_CURSOR_HMAC_KEY",
            "test-native-cursor-key-0123456789abcdef",
        )
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

fn wait_until_ready(child: &mut Child, address: std::net::SocketAddr) -> io::Result<()> {
    let startup_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < startup_deadline {
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!(
                "o3kd exited before readiness: {status}"
            )));
        }
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            stream.set_read_timeout(Some(Duration::from_millis(200)))?;
            stream.write_all(
                b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            let mut response = Vec::new();
            if stream.read_to_end(&mut response).is_ok() && response.starts_with(b"HTTP/1.1 200 OK")
            {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "o3kd did not become ready",
    ))
}

fn stop_daemon(child: &mut Child) -> io::Result<()> {
    let status = Command::new("kill")
        .args(["-TERM".to_owned(), child.id().to_string()])
        .status()?;
    if !status.success() {
        return Err(io::Error::other("failed to send SIGTERM to o3kd"));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("o3kd shutdown failed: {status}")))
            };
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "o3kd did not shut down",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn assert_signal_shutdown(signal: &str) -> Result<(), Box<dyn std::error::Error>> {
    let probe = TcpListener::bind("127.0.0.1:0")?;
    let address = probe.local_addr()?;
    drop(probe);

    let mut child = Command::new(env!("CARGO_BIN_EXE_o3kd"))
        .args([
            "--listen-addr",
            &address.to_string(),
            "--data-dir",
            &format!("/tmp/o3kd-test-{}-{signal}", std::process::id()),
            "--log-filter",
            "off",
        ])
        .env(
            "O3K_NATIVE_CURSOR_HMAC_KEY",
            "test-native-cursor-key-0123456789abcdef",
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let startup_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < startup_deadline {
        if TcpStream::connect(address).is_ok() {
            break;
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!("o3kd exited during startup: {status}")).into());
        }
        thread::sleep(Duration::from_millis(25));
    }
    if TcpStream::connect(address).is_err() {
        let _ = child.kill();
        return Err(io::Error::new(io::ErrorKind::TimedOut, "o3kd did not start").into());
    }
    let mut readiness = TcpStream::connect(address)?;
    readiness.set_read_timeout(Some(Duration::from_secs(2)))?;
    readiness.write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = Vec::new();
    readiness.read_to_end(&mut response)?;
    let response = String::from_utf8_lossy(&response);
    if !response.starts_with("HTTP/1.1 200 OK") {
        let _ = child.kill();
        return Err(io::Error::other(format!("daemon is not ready: {response}")).into());
    }

    let signal_status = Command::new("kill")
        .args([format!("-{signal}"), child.id().to_string()])
        .status()?;
    if !signal_status.success() {
        let _ = child.kill();
        return Err(io::Error::other("failed to send shutdown signal").into());
    }

    let shutdown_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(io::Error::other(format!("o3kd shutdown failed: {status}")).into());
            }
            break;
        }
        if Instant::now() >= shutdown_deadline {
            let _ = child.kill();
            return Err(io::Error::new(io::ErrorKind::TimedOut, "o3kd did not shut down").into());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}

#[test]
fn sigterm_shuts_down_cleanly() -> Result<(), Box<dyn std::error::Error>> {
    assert_signal_shutdown("TERM")
}

#[test]
fn sigint_shuts_down_cleanly() -> Result<(), Box<dyn std::error::Error>> {
    assert_signal_shutdown("INT")
}

#[test]
fn second_daemon_with_same_data_directory_fails_before_store_startup()
-> Result<(), Box<dyn std::error::Error>> {
    let data_dir = TestDataDir::new()?;
    let first_probe = TcpListener::bind("127.0.0.1:0")?;
    let second_probe = TcpListener::bind("127.0.0.1:0")?;
    let first_address = first_probe.local_addr()?;
    let second_address = second_probe.local_addr()?;
    drop((first_probe, second_probe));
    let mut first = ChildGuard(daemon_command(first_address, &data_dir.0).spawn()?);
    wait_until_ready(&mut first.0, first_address)?;

    let second = daemon_command(second_address, &data_dir.0).output()?;
    assert!(
        !second.status.success(),
        "second daemon unexpectedly started"
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("O3K data-directory lifetime lock"),
        "second daemon did not fail at the store lock boundary: {stderr}"
    );
    assert!(TcpStream::connect_timeout(&second_address, Duration::from_millis(100)).is_err());

    stop_daemon(&mut first.0)?;
    Ok(())
}

#[test]
fn startup_failure_after_lock_acquisition_releases_store_lock()
-> Result<(), Box<dyn std::error::Error>> {
    let data_dir = TestDataDir::new()?;
    // A directory at SQLite's database filename forces store opening to fail
    // after the process-lifetime lock has been acquired.
    std::fs::create_dir(data_dir.0.join("o3k.sqlite"))?;
    let address = free_address()?;
    let failed_start = daemon_command(address, &data_dir.0).output()?;
    assert!(
        !failed_start.status.success(),
        "daemon unexpectedly opened a directory as SQLite DB"
    );
    let stderr = String::from_utf8_lossy(&failed_start.stderr);
    assert!(
        !stderr.contains("O3K data-directory lifetime lock"),
        "startup failed before reaching store open: {stderr}"
    );
    o3k_store::StoreAccessLock::acquire(&data_dir.0)?;
    Ok(())
}
