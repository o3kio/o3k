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
//! - `O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE=1` exits 91 inside the signing
//!   wait (store lock and denial marker held), leaving the exact
//!   crash-during-wait state a killed process would leave;
//! - `O3K_BACKUP_TEST_STOP_AFTER_STAGING=1` stages the artifact and reports
//!   `signing-required` (exit 3) without waiting; combined with
//!   `O3K_BACKUP_TEST_SKIP_MARKER_CLEANUP=1` the marker is kept.
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

use ed25519_dalek::SigningKey;
use hpke::{Kem, Serializable, kem::X25519HkdfSha256};
use o3k_store::{BackupControlListener, ExpectedExecutor, StoreAccessLock, identity_tokens};
use rustix::process::geteuid;
use serde_json::Value;
use sha2::{Digest, Sha256};
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
    let test_executable =
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/nonexistent-test-executable"));
    let mut command = Command::new(o3k_bin());
    command
        .arg("backup")
        .arg("create")
        .arg("--destination")
        .arg(dest)
        .arg("--operation-id")
        .arg(operation_id.to_string())
        .env("O3K_DATA_DIR", data_dir)
        // The fake controller runs in this test process; tell the executor
        // which executable answered the handoff (feature-gated hook).
        .env("O3K_BACKUP_TEST_DAEMON_EXE", test_executable);
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
    create_migrated_store(&data_dir)?;
    let fixture = trust_fixture(&root, &data_dir)?;
    let listener = fake_controller(&data_dir)?;
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        read_request_frame(&mut stream)?;
        stream.write_all(b"O3KBKAC\0")?;
        thread::sleep(Duration::from_secs(2));
        Ok(())
    });
    let output = run_backup_create(&data_dir, &dest, Uuid::new_v4())
        .env("O3K_BACKUP_TRUST_CONFIG", &fixture.trust_config)
        .env("O3K_INSTALL_PREFIX", &fixture.install_prefix)
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
    create_migrated_store(&data_dir)?;
    let fixture = trust_fixture(&root, &data_dir)?;
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
        .env("O3K_BACKUP_TRUST_CONFIG", &fixture.trust_config)
        .env("O3K_INSTALL_PREFIX", &fixture.install_prefix)
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

/// Root-owned trust document and installed release manifest for the real
/// binary. The trust document binds the canonical identity of `data_dir`, so
/// the executor accepts it for this installation only.
struct TrustFixture {
    trust_config: PathBuf,
    install_prefix: PathBuf,
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn latest_sqlite_schema_version() -> io::Result<u64> {
    let directory = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/o3k-store/migrations"
    ));
    let entries = fs::read_dir(directory)?;
    let version = entries
        .filter_map(|entry| {
            let name = entry.ok()?.file_name();
            name.to_str()?.split('_').next()?.parse::<u64>().ok()
        })
        .max();
    version.ok_or_else(|| io::Error::other("no sqlite migration found"))
}

fn trust_fixture(root: &TempRoot, data_dir: &Path) -> io::Result<TrustFixture> {
    let signing = SigningKey::from_bytes(&[17_u8; 32]);
    let (recipient, _public) = X25519HkdfSha256::gen_keypair();
    let recipient_key = root.0.join("recipient.key");
    write_private(&recipient_key, &recipient.to_bytes())?;
    let (installation, site) = identity_tokens(data_dir)?;
    let public_key = signing.verifying_key().to_bytes();
    let trust_config = root.0.join("backup-trust.json");
    let document = serde_json::json!({
        "format": "o3k-backup-trust-v1",
        "site_id": hex::encode(site),
        "installation_id": hex::encode(installation),
        "profile_id": "o3k-demo-v1",
        "artifact_signing": {
            "key_id": "signing-1",
            "ed25519_public_key": hex::encode(public_key),
        },
        "recipient": {
            "key_id": "recovery-1",
            "x25519_private_key_file": recipient_key.display().to_string(),
        },
        "revoked_key_ids": [],
        "custody": {
            "record_id": "custody-1",
            "purpose": "artifact-signing",
            "key_fingerprint": hex::encode(Sha256::digest(public_key)),
            "threshold": "2-of-3",
            "custodians": ["principal-a", "principal-b", "principal-c"],
            "storage_class": "offline-safe",
            "expires_at": "2035-01-01T00:00:00Z",
        },
    });
    write_private(&trust_config, &serde_json::to_vec_pretty(&document)?)?;
    let install_prefix = root.0.join("install");
    let share = install_prefix.join("share/o3k");
    fs::create_dir_all(&share)?;
    for directory in [
        install_prefix.clone(),
        install_prefix.join("share"),
        share.clone(),
    ] {
        // 0755 like a production install; the ambient umask must not make the
        // release-manifest parent group-writable.
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
    }
    let manifest = serde_json::json!({
        "version": "0.4.0",
        "profile": "demo",
        "profile_id": "o3k-demo-v1",
        "source_commit": "0123456789abcdef0123456789abcdef01234567",
        "release_artifact_sha256": "a".repeat(64),
        "schema_version": latest_sqlite_schema_version()?.to_string(),
    });
    write_private(
        &share.join("release-manifest.json"),
        &serde_json::to_vec(&manifest)?,
    )?;
    Ok(TrustFixture {
        trust_config,
        install_prefix,
    })
}

#[test]
fn crash_during_the_signing_wait_keeps_the_marker_and_staged_request() -> io::Result<()> {
    let root = TempRoot::new("awaiting-signature")?;
    let data_dir = root.private_dir("data")?;
    let dest = root.private_dir("dest")?;
    let operation_id = Uuid::new_v4();
    create_migrated_store(&data_dir)?;
    let fixture = trust_fixture(&root, &data_dir)?;

    let listener = BackupControlListener::bind(&data_dir)?;
    let server = spawn_handoff_server(data_dir.clone(), listener);
    let output = run_backup_create(&data_dir, &dest, operation_id)
        .env("O3K_BACKUP_TRUST_CONFIG", &fixture.trust_config)
        .env("O3K_INSTALL_PREFIX", &fixture.install_prefix)
        .env("O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE", "1")
        .output()?;
    server
        .join()
        .map_err(|_| io::Error::other("handoff server thread panicked"))??;
    assert_eq!(
        output.status.code(),
        Some(91),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The wait announced itself on stderr with one stable line naming the
    // operation id (SPEC-0050 §8) and no filesystem path.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "o3k backup create: awaiting-signature {operation_id}"
        )),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("signing-request.json"),
        "the awaiting-signature line must not emit the staging path: {stderr}"
    );
    // The crash leaves exactly the documented state: request staged, journal
    // `staged`, denial marker present, nothing published.
    let staging = dest.join(format!(".o3k-backup-artifact-{operation_id}"));
    assert!(staging.join("signing-request.json").is_file());
    assert!(!dest.join(format!("backup-{operation_id}.o3k")).exists());
    assert!(
        data_dir
            .join(format!(".o3k-backup-in-progress-{operation_id}"))
            .is_file(),
        "the denial marker must outlive a crash during the signing wait"
    );
    let journal: Value = serde_json::from_slice(&fs::read(
        data_dir
            .join("backup-operations")
            .join(format!("{operation_id}.json")),
    )?)?;
    assert_eq!(journal["phase"], "staged", "{journal}");
    Ok(())
}
