//! PP.6 #1089: malformed configuration input fails closed at process level.
//!
//! Each case starts the real `o3kd` binary with bad input and asserts that it
//! exits unsuccessfully before serving, that its error output does not echo a
//! sentinel secret, and that a pre-existing data directory is left byte-for-
//! byte unchanged.
#![cfg(unix)]

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
) -> Result<(ExitStatus, String), Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_o3kd"));
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn()?;
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
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        io::Read::read_to_string(&mut pipe, &mut stderr)?;
    }
    Ok((status, stderr))
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
    let (status, stderr) = run_o3kd(&args(&data.0), envs)?;
    assert!(!status.success(), "{label}: o3kd must exit unsuccessfully");
    assert!(
        stderr.contains(expected_error),
        "{label}: expected `{expected_error}` in stderr, got: {stderr}"
    );
    assert!(
        !stderr.contains(SENTINEL),
        "{label}: stderr echoed the sentinel secret: {stderr}"
    );
    assert_eq!(
        snapshot(&data.0)?,
        before,
        "{label}: data directory changed"
    );
    Ok(())
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
