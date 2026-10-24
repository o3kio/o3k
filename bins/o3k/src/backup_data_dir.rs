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
//!   `/etc/o3k/o3kd.env`, else the packaged `/var/lib/o3k` when it exists and
//!   is owned by the effective uid (the installed `o3k:o3k` posture), else
//!   `./data` ([`LOCAL_DATA_DIR`]).
//!
//! The packaged environment file is `root:root 0600`, so the installed service
//! user cannot read it even though the daemon it describes runs from the same
//! directory. A present-but-unreadable environment file (or one without an
//! `O3K_DATA_DIR=` assignment) therefore falls through to the packaged data
//! directory instead of failing the command or silently using `./data`. An
//! *unsafe* file (symlink, non-regular, untrusted owner, group/other-writable)
//! still fails closed.
//!
//! The environment file is parsed as a bounded `KEY=VALUE` list, never sourced
//! or shell-evaluated: only the single literal `O3K_DATA_DIR=` assignment is
//! read, surrounding quotes are stripped, and every other line is ignored.
//! Anything that is not a bounded absolute-or-relative path is rejected.

use std::{
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use rustix::fs::{FileType, Mode, OFlags, fstat, open};

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
    resolve_non_root_data_dir(
        std::env::var("O3K_DATA_DIR").ok().as_deref(),
        Path::new(ENV_FILE),
        Path::new(ROOT_DATA_DIR),
        current_euid(),
    )
}

/// The non-root resolution rule shared by `o3k backup create` and `o3k backup
/// verify`, with every input (environment value, environment file, packaged
/// directory, effective uid) supplied by the caller so each branch is testable
/// against temporary fixtures.
///
/// Precedence: non-empty `O3K_DATA_DIR`, else `O3K_DATA_DIR=` from the
/// environment file, else the packaged data directory when it exists and is
/// owned by `effective_uid`, else [`LOCAL_DATA_DIR`].
///
/// # Errors
///
/// `data-dir-env-unsafe` for an unsafe environment-file posture;
/// `data-dir-unavailable` when the chosen directory cannot be canonicalized.
pub fn resolve_non_root_data_dir(
    environment: Option<&str>,
    env_file: &Path,
    packaged_dir: &Path,
    effective_uid: u32,
) -> Result<PathBuf, &'static str> {
    let configured = match non_empty(environment) {
        Some(value) => Some(PathBuf::from(value)),
        None => match env_file_data_dir(env_file, effective_uid)? {
            Some(value) => Some(PathBuf::from(value)),
            None => packaged_data_dir(packaged_dir, effective_uid),
        },
    };
    let chosen = configured.unwrap_or_else(|| PathBuf::from(LOCAL_DATA_DIR));
    fs::canonicalize(&chosen).map_err(|_| "data-dir-unavailable")
}

/// The packaged data directory when it is usable for `effective_uid`.
///
/// The installed `o3k:o3k` posture creates `/var/lib/o3k` owned by the service
/// user, so a backup command running as that user resolves the same directory
/// the daemon uses even though it cannot read the root-owned environment file.
/// A missing entry, a non-directory, or a directory owned by anyone else yields
/// `None`, so the portable default applies instead of a directory the caller
/// does not own.
#[must_use]
pub fn packaged_data_dir(packaged_dir: &Path, effective_uid: u32) -> Option<PathBuf> {
    let metadata = fs::metadata(packaged_dir).ok()?;
    if !metadata.file_type().is_dir() || metadata.uid() != effective_uid {
        return None;
    }
    Some(packaged_dir.to_path_buf())
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
    current_euid() == 0
}

fn current_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Reads `O3K_DATA_DIR=` from a root-owned `KEY=VALUE` environment file.
///
/// A missing file is not an error (the portable default applies), and an
/// existing file this process may not read yields no value: the packaged file
/// is `root:root 0600`, so the installed service user must fall through to the
/// packaged data directory rather than fail the command. A present, readable
/// file must be a root-or-effective-uid-owned, non-group/other-writable regular
/// file whose descriptor was opened `O_NOFOLLOW`; every other posture fails
/// closed with `data-dir-env-unsafe`.
fn env_file_data_dir(path: &Path, effective_uid: u32) -> Result<Option<String>, &'static str> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // An untraversable parent directory is the same "cannot read it" case.
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
        Err(_) => return Err(REASON_ENV_FILE_UNSAFE),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(REASON_ENV_FILE_UNSAFE);
    }
    let descriptor = match open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::ACCESS | rustix::io::Errno::PERM) => return Ok(None),
        Err(_) => return Err(REASON_ENV_FILE_UNSAFE),
    };
    // The posture is checked on the descriptor that is actually read, so a
    // replacement between `lstat` and `open` cannot relax it.
    let stat = fstat(&descriptor).map_err(|_| REASON_ENV_FILE_UNSAFE)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || (stat.st_uid != 0 && stat.st_uid != effective_uid)
        || stat.st_mode & 0o022 != 0
    {
        return Err(REASON_ENV_FILE_UNSAFE);
    }
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
    use std::os::unix::fs::PermissionsExt;

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

    struct TempRoot(PathBuf);

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl TempRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "o3k-backup-data-dir-{label}-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
            fs::create_dir(&path).expect("create private fixture root");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("restrict fixture root");
            Self(path)
        }

        fn dir(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir(&path).expect("create fixture directory");
            path
        }
    }

    fn write_env_file(path: &Path, contents: &str, mode: u32) {
        fs::write(path, contents).expect("write environment file");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode environment file");
    }

    #[test]
    fn readable_environment_file_wins_over_the_packaged_directory() {
        let root = TempRoot::new("env-wins");
        let configured = root.dir("configured");
        let packaged = root.dir("packaged");
        let env_file = root.0.join("o3kd.env");
        write_env_file(
            &env_file,
            &format!("O3K_LOG=info\nO3K_DATA_DIR={}\n", configured.display()),
            0o600,
        );
        assert_eq!(
            resolve_non_root_data_dir(None, &env_file, &packaged, current_euid()),
            Ok(fs::canonicalize(&configured).expect("canonical configured directory"))
        );
        // A non-empty O3K_DATA_DIR still outranks the file.
        let explicit = root.dir("explicit");
        assert_eq!(
            resolve_non_root_data_dir(
                Some(explicit.to_str().expect("utf-8 path")),
                &env_file,
                &packaged,
                current_euid(),
            ),
            Ok(fs::canonicalize(&explicit).expect("canonical explicit directory"))
        );
    }

    #[test]
    fn packaged_directory_is_used_when_the_environment_file_yields_nothing() {
        let root = TempRoot::new("packaged-fallback");
        let packaged = root.dir("var-lib-o3k");
        let euid = current_euid();
        let canonical = fs::canonicalize(&packaged).expect("canonical packaged directory");

        // Missing environment file (installed host without o3kd.env).
        let missing = root.0.join("absent.env");
        assert_eq!(
            resolve_non_root_data_dir(None, &missing, &packaged, euid),
            Ok(canonical.clone())
        );

        // Present but without the assignment.
        let without_value = root.0.join("without-value.env");
        write_env_file(&without_value, "O3K_LOG=info\n", 0o600);
        assert_eq!(
            resolve_non_root_data_dir(None, &without_value, &packaged, euid),
            Ok(canonical.clone())
        );

        // Present, root-owned 0600 and unreadable for the service user: the
        // packaged posture the fallback exists for. A process that can still
        // read the file (euid 0) only exercises the readable branch, so skip.
        if euid != 0 {
            let unreadable = root.0.join("unreadable.env");
            write_env_file(&unreadable, "O3K_DATA_DIR=/elsewhere\n", 0o000);
            assert_eq!(env_file_data_dir(&unreadable, euid), Ok(None));
            assert_eq!(
                resolve_non_root_data_dir(None, &unreadable, &packaged, euid),
                Ok(canonical)
            );
        }
    }

    #[test]
    fn packaged_directory_is_not_used_when_it_is_not_owned_by_the_caller() {
        let root = TempRoot::new("packaged-not-owned");
        let packaged = root.dir("var-lib-o3k");
        let missing = root.0.join("absent.env");
        let foreign_uid = current_euid() + 1;
        assert!(packaged_data_dir(&packaged, foreign_uid).is_none());
        assert!(packaged_data_dir(&packaged, current_euid()).is_some());
        assert!(
            resolve_non_root_data_dir(None, &missing, &packaged, foreign_uid)
                != Ok(fs::canonicalize(&packaged).expect("canonical packaged directory"))
        );
        // A missing packaged directory never becomes the default either.
        assert!(packaged_data_dir(&root.0.join("absent-dir"), current_euid()).is_none());
    }

    #[test]
    fn environment_file_posture_requires_a_trusted_owner_and_no_group_write() {
        let root = TempRoot::new("env-posture");
        let target = root.dir("target");
        let contents = format!("O3K_DATA_DIR={}\n", target.display());
        let euid = current_euid();

        let accepted = root.0.join("accepted.env");
        write_env_file(&accepted, &contents, 0o600);
        assert_eq!(
            env_file_data_dir(&accepted, euid),
            Ok(Some(target.display().to_string()))
        );

        for mode in [0o660, 0o620, 0o602, 0o666] {
            let path = root.0.join(format!("mode-{mode:o}.env"));
            write_env_file(&path, &contents, mode);
            assert_eq!(
                env_file_data_dir(&path, euid),
                Err(REASON_ENV_FILE_UNSAFE),
                "mode {mode:o}"
            );
        }

        // Owned by neither root nor the effective uid.
        let foreign = root.0.join("foreign.env");
        write_env_file(&foreign, &contents, 0o600);
        assert_eq!(
            env_file_data_dir(&foreign, euid + 1),
            Err(REASON_ENV_FILE_UNSAFE)
        );

        // A symlink is an unsafe posture, not an unreadable file.
        let link = root.0.join("link.env");
        std::os::unix::fs::symlink(&accepted, &link).expect("environment file symlink");
        assert_eq!(env_file_data_dir(&link, euid), Err(REASON_ENV_FILE_UNSAFE));
    }
}
