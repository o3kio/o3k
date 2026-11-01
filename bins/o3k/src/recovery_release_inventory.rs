//! Read-only verification of the active A10.1 release inventory.
//!
//! This remains part of production startup admission even though the
//! migration publisher itself is debug-qualification-only.

use std::{collections::BTreeMap, fs, io::Read, os::unix::fs::MetadataExt, path::Path};

use sha2::{Digest, Sha256};

const MAX_INPUT: u64 = 1024 * 1024;

#[cfg(feature = "a10-process-test-hooks")]
const RELEASE_VERIFY_KEY: &[u8] = include_bytes!("../tests/fixtures/a10-release-verify.pub");
#[cfg(not(feature = "a10-process-test-hooks"))]
const RELEASE_VERIFY_KEY: &[u8] = include_bytes!("../../../packaging/release-verify.pub");

pub(crate) fn verify_active_v2_release_inventory(
    state_directory: &crate::recovery_files::ProtectedDirectory,
    gid: u32,
    artifact_digest: &str,
    release_version: &str,
) -> Result<(), &'static str> {
    let digests_name = format!("migration-v2-release-digests-{artifact_digest}.txt");
    let signature_name = format!("migration-v2-release-signature-{artifact_digest}.sig");
    let digests = state_directory
        .read_bounded(&digests_name, 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| "authenticated target release provenance is unavailable")?;
    let signature = state_directory
        .read_bounded(&signature_name, 0, gid, 0o640, MAX_INPUT as usize)
        .map_err(|_| "authenticated target release signature is unavailable")?;
    verify_release_signature(&digests, &signature)?;

    let assets = parse_release_sums(&digests)?;
    let version = release_version.strip_prefix('v').unwrap_or(release_version);
    let bundle = format!("o3k-{version}");
    let archive = format!("{bundle}-linux-x86_64.tar.gz");
    let required = [
        "install.sh".to_owned(),
        archive.clone(),
        format!("{archive}.sha256"),
        format!("{bundle}/manifest.json"),
        format!("{bundle}/SHA256SUMS"),
        format!("{bundle}/sbom.spdx.json"),
    ];
    if assets.len() != required.len() || required.iter().any(|name| !assets.contains_key(name)) {
        return Err("target release provenance asset set is invalid");
    }
    if assets.get(&archive).map(String::as_str) != Some(artifact_digest) {
        return Err("target release provenance names a different artifact");
    }
    let expected_sums = assets
        .get(&format!("{bundle}/SHA256SUMS"))
        .ok_or("target release provenance omits executable inventory")?;
    let active_sums = read_root_file(Path::new("/usr/local/share/o3k/SHA256SUMS"))
        .map_err(|_| "active release checksum inventory is unavailable")?;
    if hex::encode(Sha256::digest(&active_sums)) != *expected_sums {
        return Err("active release checksum inventory is not the signed target inventory");
    }
    let hashes = parse_release_sums(&active_sums)
        .map_err(|_| "active release checksum inventory is malformed")?;
    for name in ["o3kd", "o3k", "o3k-compute", "o3k-network"] {
        let relative = format!("./bin/{name}");
        let expected = hashes
            .get(&relative)
            .ok_or("active release inventory omits a dual verifier")?;
        let path = Path::new("/usr/local/bin").join(name);
        crate::recovery_files::check_ancestors(&path)
            .map_err(|_| "installed dual-verifier path is unsafe")?;
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "installed dual verifier is unavailable")?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || (name != "o3k-compute" && metadata.mode() & 0o7777 != 0o755)
            || (name == "o3k-compute" && !matches!(metadata.mode() & 0o7777, 0o644 | 0o755))
        {
            return Err("installed dual-verifier posture is invalid");
        }
        let actual = digest_root_artifact(&path)
            .map_err(|_| "installed dual verifier cannot be authenticated")?;
        if actual != *expected {
            return Err("installed dual verifier differs from signed target inventory");
        }
    }
    Ok(())
}

fn parse_release_sums(bytes: &[u8]) -> Result<BTreeMap<String, String>, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "release checksum inventory is malformed")?;
    let mut assets = BTreeMap::new();
    for line in text.lines() {
        let mut columns = line.split_whitespace();
        let (Some(digest), Some(path)) = (columns.next(), columns.next()) else {
            return Err("release checksum inventory is malformed");
        };
        if columns.next().is_some()
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !path.starts_with("./")
            || path.contains("..")
            || assets.insert(path.to_owned(), digest.to_owned()).is_some()
        {
            return Err("release checksum inventory is malformed");
        }
    }
    Ok(assets)
}

fn verify_release_signature(digests: &[u8], signature: &[u8]) -> Result<(), &'static str> {
    use openssl::{pkey::PKey, sign::Verifier};

    let public_key = PKey::public_key_from_pem(RELEASE_VERIFY_KEY)
        .map_err(|_| "pinned release verification key is invalid")?;
    let mut verifier = Verifier::new_without_digest(&public_key)
        .map_err(|_| "release signature verifier is unavailable")?;
    if verifier
        .verify_oneshot(signature, digests)
        .map_err(|_| "release signature verification failed")?
    {
        Ok(())
    } else {
        Err("target release provenance signature is invalid")
    }
}

fn read_root_file(path: &Path) -> Result<Vec<u8>, ()> {
    use rustix::fs::{Mode, OFlags, fstat, open};

    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(());
    }
    crate::recovery_files::check_ancestors(path).map_err(|_| ())?;
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let before = fstat(&descriptor).map_err(|_| ())?;
    if before.st_mode & 0o170000 != 0o100000
        || before.st_nlink != 1
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_size < 0
        || before.st_size as u64 > MAX_INPUT
    {
        return Err(());
    }
    let file = fs::File::from(descriptor);
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    let after = file.metadata().map_err(|_| ())?;
    if bytes.len() as u64 > MAX_INPUT
        || before.st_dev != after.dev()
        || before.st_ino != after.ino()
        || before.st_size as u64 != after.len()
        || after.mtime() < 0
        || after.ctime() < 0
        || before.st_mtime != after.mtime() as u64
        || before.st_ctime != after.ctime() as u64
    {
        return Err(());
    }
    Ok(bytes)
}

fn digest_root_artifact(path: &Path) -> Result<String, ()> {
    use rustix::fs::{Mode, OFlags, fstat, open};

    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(());
    }
    crate::recovery_files::check_ancestors(path).map_err(|_| ())?;
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let before = fstat(&descriptor).map_err(|_| ())?;
    if before.st_mode & 0o170000 != 0o100000
        || before.st_nlink != 1
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_size <= 0
        || before.st_size as u64 > 512 * 1024 * 1024
    {
        return Err(());
    }
    let file = fs::File::from(descriptor);
    let mut hasher = Sha256::new();
    let mut reader = (&file).take(512 * 1024 * 1024 + 1);
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = reader.read(&mut buffer).map_err(|_| ())?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or(())?;
        if total > 512 * 1024 * 1024 {
            return Err(());
        }
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata().map_err(|_| ())?;
    if before.st_dev != after.dev()
        || before.st_ino != after.ino()
        || before.st_size < 0
        || before.st_size as u64 != total
        || after.mtime() < 0
        || after.ctime() < 0
        || before.st_mtime != after.mtime() as u64
        || before.st_ctime != after.ctime() as u64
    {
        return Err(());
    }
    Ok(hex::encode(hasher.finalize()))
}
