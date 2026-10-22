//! Crash-injection tests for the `o3k backup create` test hooks (feature
//! `backup-test-hooks`, PP.6 concurrency campaign).
//!
//! These tests spawn the real `o3k` binary against a fake in-process
//! controller and assert the hard-exit codes:
//!
//! - `O3K_BACKUP_TEST_EXIT_BEFORE_RECEIVE=1` exits 95 after the authenticated
//!   accept frame but before the store-lock descriptors are received;
//! - `O3K_BACKUP_TEST_EXIT_AFTER_RECEIVE=1` exits 94 immediately after
//!   `receive_handoff` completes;
//! - `O3K_BACKUP_TEST_SKIP_MARKER_CLEANUP=1` completes with exit 0 but leaves
//!   the denial-only interrupted-backup marker in place.
#![cfg(all(feature = "backup-test-hooks", target_os = "linux"))]

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, SystemTime},
};

use o3k_store::{BackupControlListener, ExpectedExecutor, StoreAccessLock, identity_tokens};
use rustix::process::geteuid;
use serde_json::Value;
use uuid::Uuid;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(tag: &str) -> io::Result<Self> {
        let unique = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "o3k-backup-hooks-{tag}-{}-{unique}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }

    fn private_dir(&self, name: &str) -> io::Result<PathBuf> {
        let path = self.0.join(name);
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn o3k_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_o3k"))
}

fn run_backup_create(data_dir: &Path, dest: &Path, operation_id: Uuid) -> Command {
    let mut command = Command::new(o3k_bin());
    command
        .arg("backup")
        .arg("create")
        .arg("--destination")
        .arg(dest)
        .arg("--operation-id")
        .arg(operation_id.to_string())
        .env("O3K_DATA_DIR", data_dir);
    command
}

fn read_request_frame(stream: &mut UnixStream) -> io::Result<()> {
    let mut frame = [0_u8; 64];
    stream.read_exact(&mut frame)
}

/// Binds a raw fake controller socket that authenticates nothing and always
/// answers the acceptance frame. Binding happens in the test body so the
/// socket exists before the child process starts.
fn fake_controller(data_dir: &Path) -> io::Result<std::os::unix::net::UnixListener> {
    let control = data_dir.join(o3k_store::BACKUP_CONTROL_DIR);
    fs::create_dir(&control)?;
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700))?;
    std::os::unix::net::UnixListener::bind(control.join(o3k_store::BACKUP_CONTROL_SOCKET))
}

/// Spawns the authenticated "daemon" side: acquires the store-access lock,
/// accepts the child request, and hands the lock descriptors over.
fn spawn_handoff_server(
    data_dir: PathBuf,
    listener: BackupControlListener,
) -> thread::JoinHandle<io::Result<()>> {
    thread::spawn(move || -> io::Result<()> {
        let lock = StoreAccessLock::acquire(&data_dir)?;
        let mut accepted = listener
            .accept_authenticated(&expected_executor(&data_dir)?, Duration::from_secs(10))
            .map_err(io::Error::other)?;
        accepted.send_accept()?;
        lock.handoff(&mut accepted.stream, Duration::from_secs(10))
            .map_err(|(_, error)| error)
    })
}

fn expected_executor(data_dir: &Path) -> io::Result<ExpectedExecutor> {
    let (installation, site) = identity_tokens(data_dir)?;
    Ok(ExpectedExecutor {
        exe: fs::canonicalize(o3k_bin())?,
        uid: geteuid().as_raw(),
        installation,
        site,
    })
}

fn create_migrated_store(data_dir: &Path) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime
        .block_on(o3k_store::testkit::open_file(&data_dir.join("o3k.sqlite")))
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

#[test]
fn crash_before_receive_exits_95() -> io::Result<()> {
    let root = TempRoot::new("before-receive")?;
    let data_dir = root.private_dir("data")?;
    let dest = root.private_dir("dest")?;
    let listener = fake_controller(&data_dir)?;
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        read_request_frame(&mut stream)?;
        stream.write_all(b"O3KBKAC\0")?;
        thread::sleep(Duration::from_secs(2));
        Ok(())
    });
    let output = run_backup_create(&data_dir, &dest, Uuid::new_v4())
        .env("O3K_BACKUP_TEST_EXIT_BEFORE_RECEIVE", "1")
        .output()?;
    server
        .join()
        .map_err(|_| io::Error::other("fake controller thread panicked"))??;
    assert_eq!(
        output.status.code(),
        Some(95),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn crash_after_receive_exits_94() -> io::Result<()> {
    let root = TempRoot::new("after-receive")?;
    let data_dir = root.private_dir("data")?;
    let dest = root.private_dir("dest")?;
    let listener = fake_controller(&data_dir)?;
    let server_data_dir = data_dir.clone();
    let server = thread::spawn(move || -> io::Result<()> {
        let lock = StoreAccessLock::acquire(&server_data_dir)?;
        let (mut stream, _) = listener.accept()?;
        read_request_frame(&mut stream)?;
        stream.write_all(b"O3KBKAC\0")?;
        lock.handoff(&mut stream, Duration::from_secs(10))
            .map_err(|(_, error)| error)
    });
    let operation_id = Uuid::new_v4();
    let output = run_backup_create(&data_dir, &dest, operation_id)
        .env("O3K_BACKUP_TEST_EXIT_AFTER_RECEIVE", "1")
        .output()?;
    server
        .join()
        .map_err(|_| io::Error::other("handoff server thread panicked"))??;
    assert_eq!(
        output.status.code(),
        Some(94),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The crash happens before the interrupted-backup marker is written.
    assert!(
        !data_dir
            .join(format!(".o3k-backup-in-progress-{operation_id}"))
            .exists()
    );
    Ok(())
}

#[test]
fn skip_marker_cleanup_keeps_marker_on_success() -> io::Result<()> {
    let root = TempRoot::new("skip-marker")?;
    let data_dir = root.private_dir("data")?;
    let dest = root.private_dir("dest")?;
    let operation_id = Uuid::new_v4();
    create_migrated_store(&data_dir)?;

    let listener = BackupControlListener::bind(&data_dir)?;
    let server = spawn_handoff_server(data_dir.clone(), listener);
    let output = run_backup_create(&data_dir, &dest, operation_id)
        .env("O3K_BACKUP_TEST_SKIP_MARKER_CLEANUP", "1")
        .output()?;
    server
        .join()
        .map_err(|_| io::Error::other("handoff server thread panicked"))??;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(stdout.trim())?;
    assert_eq!(parsed["status"], "provisional-capture-complete");
    assert!(
        dest.join(format!("provisional-backup-{operation_id}"))
            .is_dir()
    );
    assert!(
        data_dir
            .join(format!(".o3k-backup-in-progress-{operation_id}"))
            .is_file()
    );
    Ok(())
}
