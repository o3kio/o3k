//! PP.6 #1089: malformed configuration input fails closed at process level.
//!
//! Each case starts the real `o3kd` binary with bad input and asserts that it
//! exits unsuccessfully before serving, that its error output does not echo a
//! sentinel secret, and that a pre-existing data directory is left byte-for-
//! byte unchanged.
#![cfg(unix)]

use serde_json::json;
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SENTINEL: &str = "pp6-config-sentinel-secret";

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "o3kd-pp6-config-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7().simple()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runs `o3kd` with the given arguments and environment and returns its exit
/// status and stderr. A process still running after the deadline is killed
/// and reported as an error: bad configuration must never reach serving.
fn run_o3kd(
    args: &[String],
    envs: &[(&str, &str)],
) -> Result<(ExitStatus, String, String), Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_o3kd"));
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn()?;
    // Drain stderr while the child runs, so a large error output cannot
    // fill the pipe and block it.
    let mut pipe = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr was not captured"))?;
    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout was not captured"))?;
    let reader = thread::spawn(move || {
        let mut stderr = String::new();
        io::Read::read_to_string(&mut pipe, &mut stderr).map(|_| stderr)
    });
    let stdout_reader = thread::spawn(move || {
        let mut stdout = String::new();
        io::Read::read_to_string(&mut stdout_pipe, &mut stdout).map(|_| stdout)
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("o3kd kept running with invalid configuration").into());
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stderr = reader
        .join()
        .map_err(|_| io::Error::other("stderr reader panicked"))??;
    let stdout = stdout_reader
        .join()
        .map_err(|_| io::Error::other("stdout reader panicked"))??;
    Ok((status, stderr, stdout))
}

/// Every file under `root` with its contents, for before/after comparison.
fn snapshot(root: &Path) -> io::Result<BTreeMap<PathBuf, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                files.insert(path.clone(), Vec::new());
                pending.push(path);
            } else {
                files.insert(path.clone(), fs::read(&path)?);
            }
        }
    }
    Ok(files)
}

/// A data directory that already holds state, so the test can show bad
/// configuration leaves it untouched.
fn populated_data_dir(label: &str) -> io::Result<TempDir> {
    let dir = TempDir::new(label)?;
    fs::write(dir.0.join("o3k.db"), b"pre-existing canonical state")?;
    fs::create_dir_all(dir.0.join("compute"))?;
    fs::write(dir.0.join("compute").join("marker"), b"untouched")?;
    Ok(dir)
}

fn assert_fails_closed(
    label: &str,
    args: impl FnOnce(&Path) -> Vec<String>,
    envs: &[(&str, &str)],
    expected_error: &str,
) -> TestResult {
    let data = populated_data_dir(label)?;
    let before = snapshot(&data.0)?;
    let (status, stderr, stdout) = run_o3kd(&args(&data.0), envs)?;
    assert!(!status.success(), "{label}: o3kd must exit unsuccessfully");
    assert!(
        stderr.contains(expected_error),
        "{label}: expected configuration error classification was absent"
    );
    assert!(
        !stderr.contains(SENTINEL),
        "{label}: stderr echoed the sentinel secret"
    );
    assert!(
        !stdout.contains(SENTINEL),
        "{label}: stdout echoed the sentinel secret"
    );
    assert_eq!(
        snapshot(&data.0)?,
        before,
        "{label}: data directory changed"
    );
    write_evidence(label, &data.0, &stderr, &stdout)?;
    Ok(())
}

fn write_evidence(label: &str, data: &Path, stderr: &str, stdout: &str) -> io::Result<()> {
    let Ok(directory) = std::env::var("O3K_PP6_CONFIG_EVIDENCE_DIR") else {
        return Ok(());
    };
    fs::create_dir_all(&directory)?;
    let binary = env!("CARGO_BIN_EXE_o3kd");
    let digest_output = Command::new("sha256sum").arg(binary).output()?;
    if !digest_output.status.success() {
        return Err(io::Error::other("o3kd binary digest command failed"));
    }
    let digest = digest_output.stdout;
    let binary_sha256 = String::from_utf8_lossy(&digest)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    if binary_sha256.len() != 64 || !binary_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::other("o3kd binary digest unavailable"));
    }
    let source = std::env::var("O3K_PP6_SOURCE_HEAD_SHA")
        .map_err(|_| io::Error::other("O3K_PP6_SOURCE_HEAD_SHA is required"))?;
    let tree = std::env::var("O3K_PP6_SOURCE_TREE_SHA")
        .map_err(|_| io::Error::other("O3K_PP6_SOURCE_TREE_SHA is required"))?;
    let execution_head = std::env::var("O3K_PP6_EXECUTION_HEAD_SHA")
        .map_err(|_| io::Error::other("O3K_PP6_EXECUTION_HEAD_SHA is required"))?;
    let execution_tree = std::env::var("O3K_PP6_EXECUTION_TREE_SHA")
        .map_err(|_| io::Error::other("O3K_PP6_EXECUTION_TREE_SHA is required"))?;
    let artifact = json!({
        "schema": "o3k.pp6.config-process.v1",
        "case": label,
        "disposition": "PASS",
        "source_head": source,
        "source_tree": tree,
        "execution_head": execution_head,
        "execution_tree": execution_tree,
        "harness": "pp6_config_input_process",
        "profile": "o3k-small-edge-v1",
        "backend_observation": "not_exercised",
        "binary": {"path": "o3kd", "sha256": binary_sha256},
        "fixture": {"data_directory": data.file_name().and_then(|name| name.to_str()).unwrap_or("unknown")},
        "observations": {"exited_before_serving": true, "data_directory_unchanged": true, "secret_scan": "passed", "redaction_scope": "stdout_and_stderr", "stderr_bytes": stderr.len(), "stdout_bytes": stdout.len()},
        "foreign_state": {"status": "not_exercised", "reason": "configuration validation exits before provider access"}
    });
    let path = Path::new(&directory).join(format!("{label}.json"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, &artifact).map_err(io::Error::other)
}

fn data_dir_args(data: &Path, extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        "--data-dir".to_owned(),
        data.display().to_string(),
        "--log-filter".to_owned(),
        "off".to_owned(),
    ];
    args.extend(extra.iter().map(|value| (*value).to_owned()));
    args
}

#[test]
fn positional_secret_fragment_is_not_echoed() -> TestResult {
    // An unquoted password containing a space splits into two arguments; the
    // second half arrives as a positional argument.
    let fragment = format!("part2-{SENTINEL}");
    assert_fails_closed(
        "positional",
        |data| data_dir_args(data, &["--bootstrap-password=part1", &fragment]),
        &[],
        "UnexpectedArgument",
    )
}

#[test]
fn dash_prefixed_secret_fragment_is_not_echoed() -> TestResult {
    // The tail of an unquoted password may also start with a dash.
    let fragment = format!("-X{SENTINEL}");
    assert_fails_closed(
        "dash-prefixed",
        |data| data_dir_args(data, &["--bootstrap-password=part1", &fragment]),
        &[],
        "UnexpectedArgument",
    )
}

#[test]
fn malformed_config_file_is_rejected_without_echoing_contents() -> TestResult {
    let config = TempDir::new("file")?;
    let path = config.0.join("o3kd.toml");
    fs::write(
        &path,
        format!("token_signing_key = \"{SENTINEL}\nlisten_addr = [\n"),
    )?;
    let config_path = path.display().to_string();
    assert_fails_closed(
        "config-file",
        |data| data_dir_args(data, &["--config", &config_path]),
        &[],
        "ParseFile",
    )
}

#[test]
fn invalid_listen_address_is_rejected() -> TestResult {
    assert_fails_closed(
        "listen-address",
        |data| data_dir_args(data, &["--listen-addr", "not-an-address"]),
        &[],
        "InvalidListenAddress",
    )
}

#[test]
fn postgres_backend_without_url_is_rejected() -> TestResult {
    assert_fails_closed(
        "postgres-url",
        |data| data_dir_args(data, &[]),
        &[
            ("O3K_DATABASE_BACKEND", "postgres"),
            ("O3K_BOOTSTRAP_SECRET", SENTINEL),
        ],
        "MissingDatabaseUrl",
    )
}

#[test]
fn weak_token_signing_key_is_rejected_without_echoing_it() -> TestResult {
    assert_fails_closed(
        "signing-key",
        |data| data_dir_args(data, &[]),
        &[
            ("O3K_BOOTSTRAP_PASSWORD", SENTINEL),
            ("O3K_TOKEN_SIGNING_KEY", "short"),
        ],
        "WeakTokenSigningKey",
    )
}
