//! Descriptor-anchored filesystem operations for the C1 recovery designation.
//!
//! This module deliberately contains no recovery policy.  It only provides
//! the narrow, fail-closed filesystem primitive used by the policy consumer.

use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::AsFd,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

use rustix::{
    fs::{
        AtFlags, FlockOperation, Mode, OFlags, fchmod, flock, fstat, fstatfs, open, openat, statat,
    },
    process::geteuid,
};

const EXT4_MAGIC: u64 = 0xef53;

#[derive(Debug)]
pub enum RecoveryFileError {
    Io(io::Error),
    Unsafe(&'static str),
    TooLarge,
    CompareFailed,
}

impl From<io::Error> for RecoveryFileError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<rustix::io::Errno> for RecoveryFileError {
    fn from(value: rustix::io::Errno) -> Self {
        Self::Io(errno(value))
    }
}

pub struct ProtectedDirectory {
    dir: File,
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

/// An ownership/mode posture a protected directory may be opened with.  The
/// observed values are recorded at open time so every later use revalidates
/// the exact identity; only the initial open accepts any posture from the
/// caller-supplied set.  Which postures are acceptable is installation
/// policy, not a filesystem primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryPosture {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

impl ProtectedDirectory {
    /// Opens an absolute directory by walking every component with no-follow.
    /// The resulting descriptor, not a later path lookup, anchors all reads
    /// and writes.
    pub fn open(
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
        device: u64,
        inode: u64,
    ) -> Result<Self, RecoveryFileError> {
        Self::open_impl(path, Some((device, inode)), |u, g, m| {
            u == uid && g == gid && m == mode
        })
    }

    /// Opens with any of the accepted postures.  The no-follow walk,
    /// filesystem, device/inode binding, owner and type checks are identical
    /// to [`Self::open`]; only the owner/mode equality test is widened to
    /// the caller's closed posture set.
    pub fn open_accepted(
        path: &Path,
        accepted: &[DirectoryPosture],
        device: u64,
        inode: u64,
    ) -> Result<Self, RecoveryFileError> {
        Self::open_checked(path, Some((device, inode)), accepted)
    }

    /// Opens with any of the accepted postures without a caller-supplied
    /// device/inode binding.  The observed identity is recorded and reported
    /// by [`Self::identity`]; provisioning uses this to derive the exact
    /// values an offline signer binds into the installation policy.
    pub fn open_postured(
        path: &Path,
        accepted: &[DirectoryPosture],
    ) -> Result<Self, RecoveryFileError> {
        Self::open_checked(path, None, accepted)
    }

    fn open_checked(
        path: &Path,
        bound: Option<(u64, u64)>,
        accepted: &[DirectoryPosture],
    ) -> Result<Self, RecoveryFileError> {
        if accepted.is_empty() {
            return Err(RecoveryFileError::Unsafe("directory posture"));
        }
        Self::open_impl(path, bound, |u, g, m| {
            accepted
                .iter()
                .any(|p| p.uid == u && p.gid == g && p.mode == m)
        })
    }

    fn open_impl(
        path: &Path,
        bound: Option<(u64, u64)>,
        posture: impl FnOnce(u32, u32, u32) -> bool,
    ) -> Result<Self, RecoveryFileError> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Err(RecoveryFileError::Unsafe("directory path"));
        }
        check_ancestors(path)?;
        let mut current = PathBuf::from("/");
        let mut fd = open(
            &current,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        for component in path.components().skip(1) {
            let name = component.as_os_str();
            fd = openat(
                fd.as_fd(),
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )?;
            current.push(name);
        }
        let stat = fstat(&fd)?;
        let fsstat = fstatfs(&fd)?;
        if fsstat.f_type != EXT4_MAGIC as i64
            || !is_dev_ext4(stat.st_dev)
            || stat.st_mode & 0o170000 != 0o040000
            || !posture(stat.st_uid, stat.st_gid, stat.st_mode & 0o7777)
            || bound.is_some_and(|(device, inode)| stat.st_dev != device || stat.st_ino != inode)
        {
            return Err(RecoveryFileError::Unsafe("directory identity"));
        }
        Ok(Self {
            dir: File::from(fd),
            path: current,
            device: stat.st_dev,
            inode: stat.st_ino,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode & 0o7777,
        })
    }

    pub fn identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    fn check(&self) -> Result<(), RecoveryFileError> {
        let stat = fstat(self.dir.as_fd())?;
        if stat.st_dev != self.device
            || stat.st_ino != self.inode
            || stat.st_uid != self.uid
            || stat.st_gid != self.gid
            || stat.st_mode & 0o7777 != self.mode
        {
            return Err(RecoveryFileError::Unsafe("directory replaced"));
        }
        let reopened = open(
            &self.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(errno)?;
        let current = fstat(&reopened).map_err(errno)?;
        if current.st_dev != self.device || current.st_ino != self.inode {
            return Err(RecoveryFileError::Unsafe("directory path replaced"));
        }
        Ok(())
    }

    pub fn lock(&self) -> Result<(), RecoveryFileError> {
        self.check()?;
        flock(self.dir.as_fd(), FlockOperation::NonBlockingLockExclusive)
            .map_err(io::Error::from)?;
        Ok(())
    }

    pub fn read_bounded(
        &self,
        name: &str,
        uid: u32,
        gid: u32,
        mode: u32,
        max: usize,
    ) -> Result<Vec<u8>, RecoveryFileError> {
        validate_name(name)?;
        self.check()?;
        let fd = openat(
            self.dir.as_fd(),
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        let before = fstat(&fd)?;
        if before.st_mode & 0o170000 != 0o100000
            || before.st_nlink != 1
            || before.st_uid != uid
            || before.st_gid != gid
            || before.st_mode & 0o7777 != mode
        {
            return Err(RecoveryFileError::Unsafe("file metadata"));
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::with_capacity(max.min(8192));
        Read::by_ref(&mut file)
            .take((max as u64) + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > max {
            return Err(RecoveryFileError::TooLarge);
        }
        let after = fstat(file.as_fd())?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_size != after.st_size
            || before.st_mtime != after.st_mtime
        {
            return Err(RecoveryFileError::Unsafe("file changed"));
        }
        let entry = statat(self.dir.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW).map_err(errno)?;
        if entry.st_dev != before.st_dev || entry.st_ino != before.st_ino {
            return Err(RecoveryFileError::Unsafe("file entry replaced"));
        }
        Ok(bytes)
    }

    /// Root-only CAS replacement.  Unknown existing content is never overwritten.
    pub fn atomic_write(
        &self,
        name: &str,
        expected: Option<&[u8]>,
        bytes: &[u8],
        gid: u32,
    ) -> Result<(), RecoveryFileError> {
        self.atomic_write_checked(
            name,
            expected,
            bytes,
            0,
            gid,
            0o640,
            DirectoryPolicy::StateRoot,
        )
    }

    /// Root-only atomic publish into a protected installer directory of any
    /// accepted posture (`/etc/o3k` root-owned non-writable, or the D8
    /// journal directory owned by the service identity). The file lands with
    /// the exact uid/gid/mode given. The same no-follow, exclusive-create,
    /// fsync/rename/fsync/readback discipline applies.
    pub fn atomic_write_installer(
        &self,
        name: &str,
        expected: Option<&[u8]>,
        bytes: &[u8],
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> Result<(), RecoveryFileError> {
        self.atomic_write_checked(
            name,
            expected,
            bytes,
            uid,
            gid,
            mode,
            DirectoryPolicy::Installer,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn atomic_write_checked(
        &self,
        name: &str,
        expected: Option<&[u8]>,
        bytes: &[u8],
        uid: u32,
        gid: u32,
        mode: u32,
        policy: DirectoryPolicy,
    ) -> Result<(), RecoveryFileError> {
        validate_name(name)?;
        match policy {
            DirectoryPolicy::StateRoot => {
                if self.uid != 0 || self.mode != 0o750 {
                    return Err(RecoveryFileError::Unsafe(
                        "root-owned state directory required",
                    ));
                }
            }
            DirectoryPolicy::Installer => {
                if self.mode & 0o022 != 0 {
                    return Err(RecoveryFileError::Unsafe(
                        "installer directory must not be group or world writable",
                    ));
                }
            }
        }
        if geteuid().as_raw() != 0 {
            return Err(RecoveryFileError::Unsafe("root required"));
        }
        self.lock()?;
        if let Some(expected) = expected {
            let current = self.read_bounded(name, 0, gid, 0o640, expected.len())?;
            if current != expected {
                return Err(RecoveryFileError::CompareFailed);
            }
        } else {
            match openat(
                self.dir.as_fd(),
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            ) {
                Ok(_) => return Err(RecoveryFileError::CompareFailed),
                Err(error) if error != rustix::io::Errno::NOENT => {
                    return Err(RecoveryFileError::Io(errno(error)));
                }
                Err(_) => {}
            }
        }
        let temp = format! {".{name}.tmp-{}", std::process::id()};
        let fd = openat(
            self.dir.as_fd(),
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o640),
        )?;
        let mut file = File::from(fd);
        fchmod(file.as_fd(), Mode::from_raw_mode(mode)).map_err(errno)?;
        std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
        file.write_all(bytes)?;
        crash_hook("before-file-fsync")?;
        file.sync_all()?;
        crash_hook("after-file-fsync")?;
        rustix::fs::renameat(self.dir.as_fd(), temp.as_str(), self.dir.as_fd(), name)?;
        crash_hook("after-rename")?;
        self.dir.sync_all()?;
        crash_hook("after-directory-fsync")?;
        let readback = self.read_bounded(name, uid, gid, mode, bytes.len())?;
        if readback != bytes {
            return Err(RecoveryFileError::Unsafe("write readback"));
        }
        Ok(())
    }

    /// Root-only atomic upsert (create or replace) with the same no-follow,
    /// exclusive-temp, fsync/rename/fsync/readback discipline. Callers are
    /// responsible for the compare/classify policy; this primitive never
    /// leaves a partially written file and never follows a symlink.
    pub fn atomic_publish_installer(
        &self,
        name: &str,
        bytes: &[u8],
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> Result<(), RecoveryFileError> {
        validate_name(name)?;
        if self.mode & 0o022 != 0 {
            return Err(RecoveryFileError::Unsafe(
                "installer directory must not be group or world writable",
            ));
        }
        if geteuid().as_raw() != 0 {
            return Err(RecoveryFileError::Unsafe("root required"));
        }
        self.lock()?;
        let temp = format! {".{name}.tmp-{}", std::process::id()};
        let fd = openat(
            self.dir.as_fd(),
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o640),
        )?;
        let mut file = File::from(fd);
        fchmod(file.as_fd(), Mode::from_raw_mode(mode)).map_err(errno)?;
        std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
        file.write_all(bytes)?;
        crash_hook("before-file-fsync")?;
        file.sync_all()?;
        crash_hook("after-file-fsync")?;
        rustix::fs::renameat(self.dir.as_fd(), temp.as_str(), self.dir.as_fd(), name)?;
        crash_hook("after-rename")?;
        self.dir.sync_all()?;
        crash_hook("after-directory-fsync")?;
        let readback = self.read_bounded(name, uid, gid, mode, bytes.len())?;
        if readback != bytes {
            return Err(RecoveryFileError::Unsafe("write readback"));
        }
        Ok(())
    }

    /// The anchored absolute path, for bounded listings by policy consumers.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bounded entry listing of the anchored directory. Names only; entries
    /// are validated by the caller before any use.
    pub fn list_names(&self) -> Result<Vec<String>, RecoveryFileError> {
        self.check()?;
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryPolicy {
    /// The root-owned, `o3k`-group-readable recovery state root (0750).
    StateRoot,
    /// Any root-owned or service-owned, non-group/world-writable installer
    /// directory (`/etc/o3k`, the D8 journal directory).
    Installer,
}

fn errno(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

fn validate_name(name: &str) -> Result<(), RecoveryFileError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.as_bytes().contains(&0)
    {
        Err(RecoveryFileError::Unsafe("file name"))
    } else {
        Ok(())
    }
}

pub(crate) fn check_ancestors(path: &Path) -> Result<(), RecoveryFileError> {
    let mut current = PathBuf::from("/");
    for component in path
        .components()
        .skip(1)
        .take(path.components().count().saturating_sub(2))
    {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(RecoveryFileError::Unsafe("ancestor"));
        }
    }
    Ok(())
}

fn is_dev_ext4(device: u64) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    // Decode with the platform dev_t macros: majors exceed 8 bits (e.g. nvme
    // 259, device-mapper 253) and minors exceed 255 (loop, dm, nvme
    // namespaces), so the legacy `>> 8` / `& 0xff` split corrupts real
    // identities and can match the wrong mount source.
    let major = rustix::fs::major(device);
    let minor = rustix::fs::minor(device);
    mounts.lines().any(|line| {
        line.split(" - ").nth(1).is_some_and(|tail| {
            let fields: Vec<_> = tail.split_whitespace().collect();
            fields.first() == Some(&"ext4")
                && fields
                    .get(1)
                    .is_some_and(|source| source.starts_with("/dev/"))
                && line
                    .split_whitespace()
                    .nth(2)
                    .is_some_and(|dev| dev == format!("{major}:{minor}"))
        })
    })
}

fn crash_hook(_point: &str) -> Result<(), RecoveryFileError> {
    #[cfg(feature = "backup-test-hooks")]
    if std::env::var("O3K_RECOVERY_FILES_CRASH_AT").ok().as_deref() == Some(_point) {
        std::process::exit(86);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_relative_paths() {
        assert!(matches!(
            ProtectedDirectory::open(Path::new("relative"), 0, 0, 0o750, 0, 0),
            Err(RecoveryFileError::Unsafe("directory path"))
        ));
    }

    #[test]
    fn rejects_relative_and_non_absolute_paths() {
        for path in ["relative", "", "var/lib/o3k", "/var/lib/../lib/o3k"] {
            assert!(
                matches!(
                    ProtectedDirectory::open(Path::new(path), 0, 0, 0o750, 0, 0),
                    Err(RecoveryFileError::Unsafe("directory path"))
                ),
                "path {path:?} must be rejected before any filesystem access"
            );
        }
    }

    #[test]
    fn validate_name_rejects_traversal_and_nul() {
        for name in ["", ".", "..", "a/b", "a\u{0}b", "../state.json"] {
            assert!(
                matches!(
                    validate_name(name),
                    Err(RecoveryFileError::Unsafe("file name"))
                ),
                "name {name:?} must be rejected"
            );
        }
        assert!(validate_name("state.json").is_ok());
        assert!(validate_name(".hidden").is_ok());
    }

    #[test]
    fn open_accepted_rejects_empty_posture_set() {
        assert!(matches!(
            ProtectedDirectory::open_accepted(Path::new("/var/lib/o3k"), &[], 0, 0),
            Err(RecoveryFileError::Unsafe("directory posture"))
        ));
    }

    #[test]
    fn open_accepted_accepts_only_listed_postures() {
        let accepted = [
            DirectoryPosture {
                uid: 100,
                gid: 100,
                mode: 0o700,
            },
            DirectoryPosture {
                uid: 100,
                gid: 120,
                mode: 0o711,
            },
        ];
        // The packaged QEMU-traversal posture (o3k:o3k-compute 0711) and the
        // routine owner-only posture (o3k:o3k 0700) are both accepted.
        let matches = |u: u32, g: u32, m: u32| {
            accepted
                .iter()
                .any(|p| p.uid == u && p.gid == g && p.mode == m)
        };
        assert!(matches(100, 100, 0o700));
        assert!(matches(100, 120, 0o711));
        // Same mode with the wrong group is not the packaged posture.
        assert!(!matches(100, 100, 0o711));
        // World- or group-writable postures are never accepted.
        assert!(!matches(100, 120, 0o777));
        assert!(!matches(100, 120, 0o731));
        // A different owner is never accepted.
        assert!(!matches(0, 120, 0o711));
    }

    #[test]
    fn dev_t_major_minor_roundtrips_beyond_legacy_8bit_encoding() {
        use rustix::fs::{major, makedev, minor};
        // device-mapper (253) and nvme (259) majors and multi-namespace
        // minors appear on real hosts; the previous `>> 8` / `& 0xff` split
        // silently corrupted these into a different identity.
        for (maj, min) in [(8u32, 1u32), (253, 7), (259, 3), (7, 4096), (8, 300)] {
            let dev = makedev(maj, min);
            assert_eq!(major(dev), maj, "major roundtrip for {maj}:{min}");
            assert_eq!(minor(dev), min, "minor roundtrip for {maj}:{min}");
        }
        // The legacy encoding demonstrably diverges for these identities.
        let dev = makedev(259, 300);
        assert_ne!(
            dev >> 8,
            u64::from(259u32),
            "legacy major split corrupts 259"
        );
        assert_ne!(
            dev & 0xff,
            u64::from(300u32),
            "legacy minor split corrupts 300"
        );
    }
}
