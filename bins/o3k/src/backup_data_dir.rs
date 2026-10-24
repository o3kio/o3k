//! Data-directory resolution shared by `o3k backup create` and `o3k backup
//! verify` (SPEC-0050 §8).
//!
//! The packaged daemon is started with `--data-dir /var/lib/o3k` through
//! `/etc/o3k/o3kd.env`, while a portable/TestLab CLI run defaults to `./data`.
//! A backup command must therefore resolve the *same* directory the installed
//! controller uses, because both sides derive the installation/site identity
//! tokens from the canonical path and the control socket lives inside it.
//!
//! Resolution order:
//!
//! * **root** (`euid == 0`) ignores the environment and uses the packaged
//!   `/var/lib/o3k` ([`ROOT_DATA_DIR`]), matching `packaging/o3kd.service` and
//!   `o3k-config`'s default. A caller must not be able to redirect the canonical
//!   data directory (and therefore the identity the trust document is checked
//!   against).
//! * **non-root** uses a non-empty `O3K_DATA_DIR`, else `O3K_DATA_DIR=` from
//!   `/etc/o3k/o3kd.env`, else `./data` ([`LOCAL_DATA_DIR`]).
//!
//! The environment file is parsed as a bounded `KEY=VALUE` list, never sourced
//! or shell-evaluated: only the single literal `O3K_DATA_DIR=` assignment is
//! read, surrounding quotes are stripped, and every other line is ignored.
//! Anything that is not a bounded absolute-or-relative path is rejected.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use rustix::fs::{Mode, OFlags, open};

/// Data directory used by the packaged root daemon.
pub const ROOT_DATA_DIR: &str = "/var/lib/o3k";
/// Portable/TestLab default when nothing is configured.
pub const LOCAL_DATA_DIR: &str = "./data";
/// Root-owned environment file of the packaged daemon.
pub const ENV_FILE: &str = "/etc/o3k/o3kd.env";
/// Upper bound for the environment file (it holds a handful of assignments).
const MAX_ENV_FILE_BYTES: u64 = 64 * 1024;
/// Upper bound for one path value.
const MAX_PATH_BYTES: usize = 4096;
const REASON_ENV_FILE_UNSAFE: &str = "data-dir-env-unsafe";

/// Resolves the canonical data directory for the current process.
///
/// # Errors
///
/// Returns a stable reason code when the resolved directory does not exist or
/// cannot be canonicalized (`data-dir-unavailable`), or when the packaged
/// environment file has an untrusted posture (`data-dir-env-unsafe`).
pub fn resolve_data_dir() -> Result<PathBuf, &'static str> {
    // Root must not be redirectable through the environment: the identity the
    // trust document is checked against derives from this path.
    if is_root() {
        return resolve_data_dir_from(Some(ROOT_DATA_DIR));
    }
    let configured = match std::env::var("O3K_DATA_DIR") {
        Ok(value) => non_empty(Some(value.as_str())),
        Err(_) => env_file_data_dir(Path::new(ENV_FILE))?,
    };
    resolve_data_dir_from(configured.as_deref())
}

/// [`resolve_data_dir`] with the configured value supplied by the caller, so
/// the precedence is testable without mutating the process environment.
///
/// # Errors
///
/// `data-dir-unavailable` when the directory cannot be canonicalized.
pub fn resolve_data_dir_from(configured: Option<&str>) -> Result<PathBuf, &'static str> {
    fs::canonicalize(data_dir_from(configured)).map_err(|_| "data-dir-unavailable")
}

/// Chooses the configured data directory: non-empty trimmed value, else the
/// portable `./data` default (mirroring `o3k-config`).
#[must_use]
pub fn data_dir_from(configured: Option<&str>) -> PathBuf {
    non_empty(configured)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(LOCAL_DATA_DIR))
}

/// The packaged root daemon's data directory.
#[must_use]
pub fn root_data_dir() -> PathBuf {
    PathBuf::from(ROOT_DATA_DIR)
}

fn is_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Reads `O3K_DATA_DIR=` from a root-owned `KEY=VALUE` environment file.
///
/// A missing file is not an error (the portable default applies). A present
/// file must be a root-or-effective-uid-owned, non-group/other-writable regular
/// file opened `O_NOFOLLOW`; every other posture fails closed.
fn env_file_data_dir(path: &Path) -> Result<Option<String>, &'static str> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(REASON_ENV_FILE_UNSAFE),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(REASON_ENV_FILE_UNSAFE);
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| REASON_ENV_FILE_UNSAFE)?;
    let mut bytes = Vec::new();
    fs::File::from(descriptor)
        .take(MAX_ENV_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REASON_ENV_FILE_UNSAFE)?;
    if bytes.len() as u64 > MAX_ENV_FILE_BYTES {
        return Err(REASON_ENV_FILE_UNSAFE);
    }
    let contents = String::from_utf8(bytes).map_err(|_| REASON_ENV_FILE_UNSAFE)?;
    parse_env_file(&contents).map_err(|_| REASON_ENV_FILE_UNSAFE)
}

/// Parses the single `O3K_DATA_DIR=` assignment out of an environment file.
///
/// This is a bounded reader, not a shell: comments, blank lines and every other
/// assignment are ignored, `export ` prefixes are tolerated, and only a
/// single-line value is accepted. A duplicated assignment with a different
/// value is ambiguous and rejected.
///
/// # Errors
///
/// Returns `data-dir-env-unsafe` for a duplicated/ambiguous assignment, a
/// multi-line value, or a value that is empty, contains control characters or
/// exceeds the path bound.
pub fn parse_env_file(contents: &str) -> Result<Option<String>, &'static str> {
    let mut found: Option<String> = None;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some(value) = line.strip_prefix("O3K_DATA_DIR=") else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|rest| rest.strip_suffix('\''))
            })
            .unwrap_or(value);
        if value.is_empty()
            || value.len() > MAX_PATH_BYTES
            || value.chars().any(char::is_control)
            || value.contains('$')
            || value.contains('`')
            || value.contains('\\')
        {
            return Err(REASON_ENV_FILE_UNSAFE);
        }
        if let Some(previous) = &found
            && previous != value
        {
            return Err(REASON_ENV_FILE_UNSAFE);
        }
        found = Some(value.to_owned());
    }
    Ok(found)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_single_assignment_and_ignores_everything_else() {
        let contents = "# o3k daemon configuration\n\
            O3K_LOG=info\n\
            O3K_DATA_DIR=/var/lib/o3k\n\
            O3K_LISTEN_ADDR=127.0.0.1:8080\n";
        assert_eq!(
            parse_env_file(contents),
            Ok(Some("/var/lib/o3k".to_owned()))
        );
        assert_eq!(parse_env_file("O3K_LOG=info\n"), Ok(None));
        assert_eq!(parse_env_file(""), Ok(None));
        assert_eq!(
            parse_env_file("  export O3K_DATA_DIR=/srv/o3k-data  \n"),
            Ok(Some("/srv/o3k-data".to_owned()))
        );
        assert_eq!(
            parse_env_file("O3K_DATA_DIR=\"/srv/spaced data\"\n"),
            Ok(Some("/srv/spaced data".to_owned()))
        );
        assert_eq!(
            parse_env_file("O3K_DATA_DIR='/srv/quoted'\n"),
            Ok(Some("/srv/quoted".to_owned()))
        );
        // The same value twice is unambiguous.
        assert_eq!(
            parse_env_file("O3K_DATA_DIR=/srv/a\nO3K_DATA_DIR=/srv/a\n"),
            Ok(Some("/srv/a".to_owned()))
        );
        // A comment or a different variable never shadows the assignment.
        assert_eq!(
            parse_env_file("# O3K_DATA_DIR=/wrong\nO3K_DATA_DIR=/right\n"),
            Ok(Some("/right".to_owned()))
        );
        // Assignment-looking text inside a value is not evaluated.
        assert_eq!(parse_env_file("O3K_LOG=O3K_DATA_DIR=/nope\n"), Ok(None));
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_values() {
        for contents in [
            "O3K_DATA_DIR=/srv/a\nO3K_DATA_DIR=/srv/b\n",
            "O3K_DATA_DIR=\n",
            "O3K_DATA_DIR=\r\n",
            "O3K_DATA_DIR=/srv/$(id)\n",
            "O3K_DATA_DIR=/srv/`id`\n",
            "O3K_DATA_DIR=/srv/a\\ b\n",
            "O3K_DATA_DIR=/srv/\u{7f}\n",
        ] {
            assert_eq!(
                parse_env_file(contents),
                Err(REASON_ENV_FILE_UNSAFE),
                "{contents:?}"
            );
        }
        let oversized = format!("O3K_DATA_DIR={}\n", "a".repeat(MAX_PATH_BYTES + 1));
        assert_eq!(parse_env_file(&oversized), Err(REASON_ENV_FILE_UNSAFE));
    }

    #[test]
    fn precedence_matches_the_documented_rule() {
        assert_eq!(data_dir_from(None), PathBuf::from(LOCAL_DATA_DIR));
        assert_eq!(
            data_dir_from(Some("  /var/lib/o3k  ")),
            PathBuf::from("/var/lib/o3k")
        );
        assert_eq!(data_dir_from(Some("   ")), PathBuf::from(LOCAL_DATA_DIR));
        assert_eq!(root_data_dir(), PathBuf::from(ROOT_DATA_DIR));
        assert_eq!(
            resolve_data_dir_from(Some("/definitely/absent-o3k-data")),
            Err("data-dir-unavailable")
        );
    }

    #[test]
    fn installed_environment_file_parses_when_present() {
        // The real file only exists on an installed host; when present it must
        // resolve to the packaged root data directory.
        if let Ok(contents) = fs::read_to_string(ENV_FILE) {
            let parsed = parse_env_file(&contents).expect("installed environment file is valid");
            if let Some(value) = parsed {
                assert!(value.starts_with('/'), "{value}");
            }
        }
    }
}
