#![cfg(target_os = "linux")]
//! In-process wiring test for the daemon-side backup control channel: the
//! dedicated accept thread authenticates the expected executor, forwards the
//! accepted request, and fires the same graceful-shutdown notify as SIGTERM.
//! The full cross-process handoff (daemon drain + descriptor transfer against
//! the real `o3k` executor) is Slice D evidence and intentionally not
//! attempted here.

use std::{
    io,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use o3kd::composition::{backup, expected_backup_executor_from, shutdown_signal_with_backup};

const HELPER_TEST_NAME: &str = "backup_control_client_helper";
const OPERATION_ID: [u8; 16] = [0xA5; 16];

struct TestDirs {
    bin_dir: PathBuf,
    data_dir: PathBuf,
}

impl TestDirs {
    fn new() -> io::Result<Self> {
        let unique = format!("{}-{}", std::process::id(), uuid::Uuid::now_v7());
        let root = std::env::temp_dir().join(format!("o3kd-backup-control-test-{unique}"));
        let bin_dir = root.join("bin");
        let data_dir = root.join("data");
        std::fs::create_dir_all(&bin_dir)?;
        std::fs::create_dir(&data_dir)?;
        set_private(&root)?;
        set_private(&bin_dir)?;
        set_private(&data_dir)?;
        Ok(Self { bin_dir, data_dir })
    }
}

impl Drop for TestDirs {
    fn drop(&mut self) {
        if let Some(root) = self.data_dir.parent() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

fn set_private(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn kill(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
        }
    }

    fn wait_with_output(&mut self) -> io::Result<std::process::Output> {
        match self.0.take() {
            Some(child) => child.wait_with_output(),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "child process already taken",
            )),
        }
    }

    fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        match self.0.take() {
            Some(mut child) => child.wait(),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "child process already taken",
            )),
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Runs in the copied `o3k` binary: speaks the executor side of the control
/// protocol against the in-process listener, then stays alive on the accepted
/// connection until the parent drops it.
#[test]
#[ignore = "subprocess helper for authenticated_backup_request_triggers_shutdown"]
fn backup_control_client_helper() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(std::env::var("O3K_BACKUP_CLIENT_DATA_DIR")?);
    let (installation, site) = o3k_store::identity_tokens(&data_dir)?;
    let request = o3k_store::BackupHandoffRequest {
        operation_id: uuid::Uuid::from_bytes(OPERATION_ID),
        installation,
        site,
    };
    let mut stream = o3k_store::connect_and_request(&data_dir, &request, Duration::from_secs(10))?;
    // The parent revalidates this live peer; stay connected until it drops
    // the accepted request, which surfaces here as EOF.
    let mut sink = [0_u8; 8];
    loop {
        use std::io::Read;
        match stream.read(&mut sink) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

#[tokio::test]
async fn authenticated_backup_request_triggers_shutdown() -> Result<(), Box<dyn std::error::Error>>
{
    let dirs = TestDirs::new()?;
    // The peer must authenticate as the sibling `o3k` of the daemon exe: copy
    // this test binary to that name so /proc/<pid>/exe matches the expected
    // canonical path and device/inode.
    let sibling = dirs.bin_dir.join("o3k");
    std::fs::copy(std::env::current_exe()?, &sibling)?;
    set_private(&sibling)?;
    let expected = expected_backup_executor_from(&dirs.bin_dir.join("o3kd"), &dirs.data_dir)
        .ok_or("expected executor should resolve against the copied sibling")?;
    let mut control = backup::start_backup_control(&expected, &dirs.data_dir)
        .ok_or("backup control should start")?;

    let mut child = ChildGuard(Some(
        Command::new(&sibling)
            .args(["--exact", HELPER_TEST_NAME, "--ignored", "--nocapture"])
            .env("O3K_BACKUP_CLIENT_DATA_DIR", &dirs.data_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    ));

    // Poll for the accepted request: `take_accepted` returns instantly while
    // no backup was requested, and the accept thread sets `requested` only
    // after queuing the request, so this does not consume the shutdown
    // notify's permit the way waiting on the Notify would. This mirrors
    // production, where main only looks for a request after the serve ended.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let request = loop {
        if let Some(request) = control.take_accepted().await {
            break request;
        }
        if std::time::Instant::now() >= deadline {
            child.kill();
            let output = child.wait_with_output()?;
            return Err(io::Error::other(format!(
                "accepted backup request did not arrive; helper status {:?}, stdout: {}, \
                 stderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(request.operation_id, OPERATION_ID);
    assert_eq!(request.peer.uid, rustix::process::geteuid().as_raw());
    request
        .revalidate_peer()
        .map_err(|error| io::Error::other(error.to_string()))?;

    // The accept thread notified before forwarding, so the graceful-shutdown
    // future must already be resolvable: the backup path ends the axum serve
    // exactly like SIGTERM.
    tokio::time::timeout(
        Duration::from_secs(5),
        shutdown_signal_with_backup(o3k_api::AppState::new(), control.shutdown_notify()),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "backup notify did not end the serve",
        )
    })?;

    drop(request);
    drop(control);
    let status = child.wait()?;
    assert!(status.success(), "backup client helper failed: {status}");
    Ok(())
}
