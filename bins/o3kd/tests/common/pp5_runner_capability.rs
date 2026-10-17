use std::{collections::BTreeMap, fs, io, process::Command};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub(crate) fn require_runner_capability(lane: &str) -> Result<(), io::Error> {
    let reject =
        |detail: &str| io::Error::other(format!("PP.5 runner capability rejected: {detail}"));
    let path = std::env::var_os("O3K_PP5_1035_CAPABILITY_FILE")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| reject("capability file is missing"))?;
    let root = std::env::var_os("O3K_PP5_1035_CAPABILITY_ROOT")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| reject("capability root is missing"))?;
    let token = std::env::var("O3K_PP5_1035_CAPABILITY_TOKEN")
        .map_err(|_| reject("capability token is missing"))?;
    let run_id =
        std::env::var("O3K_PP5_1035_RUN_ID").map_err(|_| reject("run identity is missing"))?;
    let source_sha = std::env::var("O3K_PP5_1035_SOURCE_SHA")
        .map_err(|_| reject("source identity is missing"))?;

    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(reject("capability token is malformed"));
    }
    if source_sha.len() != 40 || !source_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(reject("source identity is malformed"));
    }
    if run_id.is_empty()
        || run_id.len() > 128
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return Err(reject("run identity is malformed"));
    }

    if !path.is_absolute() || !root.is_absolute() {
        return Err(reject("capability paths must be absolute"));
    }
    let root_metadata =
        fs::symlink_metadata(&root).map_err(|_| reject("capability root is unavailable"))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(reject("capability root is not a directory"));
    }
    #[cfg(unix)]
    if root_metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(reject("capability root permissions are not 0700"));
    }
    let canonical_root =
        fs::canonicalize(&root).map_err(|_| reject("capability root is unavailable"))?;
    let canonical_parent = path
        .parent()
        .ok_or_else(|| reject("capability path has no parent"))?
        .canonicalize()
        .map_err(|_| reject("capability parent is unavailable"))?;
    if canonical_parent != canonical_root {
        return Err(reject("capability file is outside its private root"));
    }

    let metadata =
        fs::symlink_metadata(&path).map_err(|_| reject("capability file is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(reject("capability path is not a regular file"));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(reject("capability file permissions are not 0600"));
    }

    let content = fs::read_to_string(&path).map_err(|_| reject("capability file is unreadable"))?;
    let mut fields = BTreeMap::new();
    for line in content.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| reject("capability file is malformed"))?;
        if fields.insert(key, value).is_some() {
            return Err(reject("capability file contains duplicate fields"));
        }
    }
    if fields.len() != 5
        || fields.get("version") != Some(&"1")
        || fields.get("lane") != Some(&lane)
        || fields.get("run_id") != Some(&run_id.as_str())
        || fields.get("source_sha") != Some(&source_sha.as_str())
        || fields.get("token") != Some(&token.as_str())
    {
        return Err(reject("capability identity does not match this invocation"));
    }

    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .map_err(|_| reject("git source identity could not be checked"))?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != source_sha {
        return Err(reject("capability source does not match HEAD"));
    }

    // This is an accidental-execution boundary. A user with access to the
    // runner can reproduce its invocation and is not treated as hostile.
    Ok(())
}
