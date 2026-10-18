//! Process-lifetime lock for local access to an O3K data directory.
//!
//! This only coordinates processes that use the same lock file on a filesystem
//! with working `flock` semantics. It does not fence remote PostgreSQL clients
//! or a privileged/same-owner actor that can replace the data-directory path.
//! Production deployments should place the data directory under a
//! root-managed parent that the daemon account cannot modify.

use std::{
    fs, io,
    os::fd::OwnedFd,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use rustix::{
    fs::{
        AtFlags, FileType, FlockOperation, Mode, OFlags, fchmod, flock, fstat, open, openat, statat,
    },
    process::geteuid,
};

const LOCK_FILE: &str = ".o3k-store.lock";
const DATA_DIR_MODE: u32 = 0o022;
const LOCK_FILE_MODE: u32 = 0o7777;
const PARENT_SETUP_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const PARENT_SETUP_LOCK_RETRY: Duration = Duration::from_millis(10);

/// Holds the local data-directory lock until dropped.
///
/// Acquire this before opening any store or starting any task that can access
/// canonical state. Concurrent daemon/maintenance processes fail with
/// `WouldBlock` instead of opening the store.
#[derive(Debug)]
pub struct StoreAccessLock {
    // Keep the data-directory and lock descriptors alive for the complete
    // guard lifetime. The directory lock prevents lock-file replacement from
    // splitting compliant openers.
    _lock_file: OwnedFd,
    _data_dir: OwnedFd,
}

impl StoreAccessLock {
    /// Creates the data directory if absent, validates it and acquires its
    /// exclusive local store-access lock.
    pub fn acquire(data_dir: impl AsRef<Path>) -> io::Result<Self> {
        let data_dir = data_dir.as_ref();
        let parent_path = data_dir
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent_path)?;
        let parent_fd = open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let parent_stat = fstat(&parent_fd)?;
        validate_parent_directory(&parent_stat)?;
        // Serialize path resolution only. Retaining this lock for the daemon
        // lifetime would incorrectly exclude distinct O3K installations that
        // share a parent directory.
        acquire_parent_setup_lock(&parent_fd)?;

        let creating_data_dir = match fs::symlink_metadata(data_dir) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error),
        };
        fs::create_dir_all(data_dir)?;

        let dir_fd = open(
            data_dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        if creating_data_dir {
            // Restrict a newly created directory even when the process umask
            // would otherwise leave it group-writable.
            fchmod(&dir_fd, Mode::from_raw_mode(0o700))?;
        }
        let dir_stat = fstat(&dir_fd)?;
        validate_directory(&dir_stat)?;

        // Lock the opened directory inode before touching the lock-file name.
        // The lock-file remains the shared, visible lock authority, while this
        // additional lock makes replacement of that name unable to split
        // processes that use this helper.
        flock(&dir_fd, FlockOperation::NonBlockingLockExclusive)?;
        drop(parent_fd);

        let lock_fd = openat(
            &dir_fd,
            LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )?;
        let lock_stat = fstat(&lock_fd)?;
        validate_lock_file(&dir_stat, &lock_stat)?;
        validate_directory_entry(&dir_fd, &lock_stat)?;

        // Nonblocking acquisition avoids allowing a second daemon to open
        // canonical state while it waits behind a supervisor restart race.
        flock(&lock_fd, FlockOperation::NonBlockingLockExclusive)?;
        // Recheck after acquisition so a replacement race fails closed.
        let locked_stat = fstat(&lock_fd)?;
        validate_lock_file(&dir_stat, &locked_stat)?;
        validate_directory_entry(&dir_fd, &locked_stat)?;

        Ok(Self {
            _lock_file: lock_fd,
            _data_dir: dir_fd,
        })
    }
}

fn acquire_parent_setup_lock(parent_fd: &OwnedFd) -> io::Result<()> {
    let deadline = Instant::now() + PARENT_SETUP_LOCK_TIMEOUT;
    loop {
        match flock(parent_fd, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(()),
            Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
                if Instant::now() >= deadline {
                    return Err(error.into());
                }
                thread::sleep(PARENT_SETUP_LOCK_RETRY);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn validate_parent_directory(stat: &rustix::fs::Stat) -> io::Result<()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(invalid_data("O3K data-directory parent is not a directory"));
    }
    // A root-owned parent is the normal /var/lib deployment. A process-owned
    // parent is also supported for portable installations. In either case,
    // group/other writers must not be able to replace the data-directory
    // entry while its lifetime lock is held.
    if stat.st_uid != 0 && stat.st_uid != geteuid().as_raw() {
        return Err(invalid_data(
            "O3K data-directory parent must be root-owned or process-owned",
        ));
    }
    // Shared temporary directories such as /tmp are safe as the immediate
    // parent when they are root-owned and sticky: the sticky bit prevents
    // another uid from renaming this process-owned data-directory entry.
    // Same-owner and root replacement remain outside this local lock's
    // authority, as documented above.
    let root_owned_sticky = stat.st_uid == 0 && stat.st_mode & 0o1000 != 0;
    if stat.st_mode & DATA_DIR_MODE != 0 && !root_owned_sticky {
        return Err(invalid_data(
            "O3K data-directory parent must not be group/other writable unless root-owned and sticky",
        ));
    }
    Ok(())
}

fn validate_directory(stat: &rustix::fs::Stat) -> io::Result<()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(invalid_data("O3K data path is not a directory"));
    }
    if stat.st_uid != geteuid().as_raw() {
        return Err(invalid_data(
            "O3K data directory is not owned by the effective uid",
        ));
    }
    if stat.st_mode & DATA_DIR_MODE != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "O3K data directory mode {:#o} is group/other writable",
                stat.st_mode
            ),
        ));
    }
    Ok(())
}

fn validate_lock_file(dir: &rustix::fs::Stat, lock: &rustix::fs::Stat) -> io::Result<()> {
    if FileType::from_raw_mode(lock.st_mode) != FileType::RegularFile
        || lock.st_uid != geteuid().as_raw()
        || lock.st_dev != dir.st_dev
        || lock.st_nlink != 1
        || lock.st_mode & LOCK_FILE_MODE != 0o600
    {
        return Err(invalid_data(
            "O3K store lock must be a process-owned, mode-0600 regular file on the data-directory device",
        ));
    }
    Ok(())
}

fn validate_directory_entry(dir_fd: &OwnedFd, opened: &rustix::fs::Stat) -> io::Result<()> {
    let entry = statat(dir_fd, LOCK_FILE, AtFlags::SYMLINK_NOFOLLOW)?;
    if entry.st_dev != opened.st_dev || entry.st_ino != opened.st_ino {
        return Err(invalid_data(
            "O3K store lock directory entry changed during acquisition",
        ));
    }
    Ok(())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::{
        fs, io,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::StoreAccessLock;

    struct TestDir(PathBuf);

    static NEXT_TEST_DIR_ID: AtomicU64 = AtomicU64::new(1);

    impl TestDir {
        fn new() -> io::Result<Self> {
            let suffix = NEXT_TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);
            let workspace = std::env::temp_dir()
                .join(format!("o3k-store-lock-{}-{suffix}", std::process::id()));
            fs::create_dir(&workspace)?;
            fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
            let data_dir = workspace.join("data");
            fs::create_dir(&data_dir)?;
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
            Ok(Self(data_dir))
        }
    }

    fn expect_error(path: impl AsRef<Path>) -> io::Result<io::Error> {
        match StoreAccessLock::acquire(path) {
            Ok(lock) => {
                drop(lock);
                Err(io::Error::other("store access lock unexpectedly acquired"))
            }
            Err(error) => Ok(error),
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            if let Some(workspace) = self.0.parent() {
                let _ = fs::remove_dir_all(workspace);
            }
        }
    }

    #[test]
    fn excludes_second_process_handle_until_first_guard_drops() -> io::Result<()> {
        let root = TestDir::new()?;
        let first = StoreAccessLock::acquire(&root.0).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("initial store lock acquisition failed: {error}"),
            )
        })?;
        let error = expect_error(&root.0)?;
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        drop(first);
        StoreAccessLock::acquire(&root.0).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("store lock remained unavailable after guard drop: {error}"),
            )
        })?;
        Ok(())
    }

    #[test]
    fn independent_data_directories_under_same_parent_can_be_locked() -> io::Result<()> {
        let root = TestDir::new()?;
        let site_a = root.0.join("site-a");
        let site_b = root.0.join("site-b");
        let _lock_a = StoreAccessLock::acquire(&site_a)?;
        let _lock_b = StoreAccessLock::acquire(&site_b)?;
        Ok(())
    }

    #[test]
    fn parent_setup_lock_waits_boundedly_for_another_opener() -> io::Result<()> {
        let root = TestDir::new()?;
        let parent = root
            .0
            .parent()
            .ok_or_else(|| io::Error::other("test directory has no parent"))?;
        let parent_fd = rustix::fs::open(
            parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )?;
        rustix::fs::flock(&parent_fd, rustix::fs::FlockOperation::LockExclusive)?;
        let release_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(parent_fd);
        });

        let lock = StoreAccessLock::acquire(parent.join("another-data-dir"))?;
        release_thread
            .join()
            .map_err(|_| io::Error::other("parent setup lock release thread panicked"))?;
        drop(lock);
        Ok(())
    }

    #[test]
    fn concurrent_independent_data_directories_share_parent_setup_lock() -> io::Result<()> {
        let root = TestDir::new()?;
        let parent = root
            .0
            .parent()
            .ok_or_else(|| io::Error::other("test directory has no parent"))?
            .to_path_buf();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let handles = ["site-a", "site-b"].map(|name| {
            let barrier = barrier.clone();
            let path = parent.join(name);
            std::thread::spawn(move || {
                barrier.wait();
                StoreAccessLock::acquire(path)
            })
        });
        barrier.wait();
        for handle in handles {
            handle
                .join()
                .map_err(|_| io::Error::other("concurrent store lock thread panicked"))??;
        }
        Ok(())
    }

    #[test]
    fn permits_data_directory_under_root_owned_sticky_temp_parent() -> io::Result<()> {
        let temp_parent = std::env::temp_dir();
        let metadata = fs::metadata(&temp_parent)?;
        let mode = metadata.permissions().mode();
        if metadata.uid() != 0 || mode & 0o1000 == 0 {
            eprintln!(
                "skipping sticky-parent case: {} is not root-owned and sticky",
                temp_parent.display()
            );
            return Ok(());
        }
        let data_dir = temp_parent.join(format!(
            "o3k-store-lock-sticky-{}-{}",
            std::process::id(),
            NEXT_TEST_DIR_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _lock = StoreAccessLock::acquire(&data_dir)?;
        drop(_lock);
        fs::remove_dir_all(data_dir)?;
        Ok(())
    }

    #[test]
    fn lock_child_process() -> io::Result<()> {
        let Some(path) = std::env::var_os("O3K_TEST_STORE_LOCK_PATH") else {
            return Ok(());
        };
        let error = expect_error(path)?;
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        Ok(())
    }

    #[test]
    fn excludes_separate_process_until_first_guard_drops() -> io::Result<()> {
        let root = TestDir::new()?;
        let first = StoreAccessLock::acquire(&root.0)?;
        let output = Command::new(std::env::current_exe()?)
            .args(["--exact", "access_lock::tests::lock_child_process"])
            .env("O3K_TEST_STORE_LOCK_PATH", &root.0)
            .output()?;
        assert!(
            output.status.success(),
            "child process lock attempt failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        drop(first);
        Ok(())
    }

    #[test]
    fn newly_created_data_directory_is_private_even_with_permissive_umask() -> io::Result<()> {
        let root = TestDir::new()?;
        let data_dir = root.0.join("created-by-lock");
        let _lock = StoreAccessLock::acquire(&data_dir)?;
        let mode = fs::metadata(data_dir)?.permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700);
        Ok(())
    }

    #[test]
    fn rejects_symlink_lock_file() -> io::Result<()> {
        let root = TestDir::new()?;
        let target = root.0.join("target");
        fs::write(&target, b"unrelated")?;
        symlink(&target, root.0.join(".o3k-store.lock"))?;
        let error = expect_error(&root.0)?;
        assert!(error.raw_os_error().is_some());
        assert_eq!(fs::read(target)?, b"unrelated");
        Ok(())
    }

    #[test]
    fn rejects_symlink_data_directory() -> io::Result<()> {
        let root = TestDir::new()?;
        let target = root.0.join("actual");
        fs::create_dir(&target)?;
        let alias = root.0.join("alias");
        symlink(&target, &alias)?;
        let error = expect_error(alias)?;
        assert!(error.raw_os_error().is_some());
        assert!(!target.join(".o3k-store.lock").exists());
        Ok(())
    }

    #[test]
    fn rejects_group_or_other_writable_data_directory() -> io::Result<()> {
        let root = TestDir::new()?;
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777))?;
        let error = expect_error(&root.0)?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        Ok(())
    }

    #[test]
    fn rejects_group_or_other_writable_non_sticky_parent() -> io::Result<()> {
        let root = TestDir::new()?;
        let Some(parent) = root.0.parent() else {
            return Err(io::Error::other("test data directory has no parent"));
        };
        fs::set_permissions(parent, fs::Permissions::from_mode(0o777))?;
        let error = expect_error(parent.join("replacement"))?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        Ok(())
    }

    #[test]
    fn rejects_preexisting_lock_with_broad_permissions() -> io::Result<()> {
        let root = TestDir::new()?;
        let lock_path = root.0.join(".o3k-store.lock");
        fs::write(&lock_path, b"")?;
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644))?;
        let error = expect_error(&root.0)?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        Ok(())
    }

    #[test]
    fn replacement_lock_file_cannot_split_local_openers() -> io::Result<()> {
        let root = TestDir::new()?;
        let first = StoreAccessLock::acquire(&root.0)?;
        let lock_path = root.0.join(".o3k-store.lock");
        let replaced_path = root.0.join(".o3k-store.lock.old");
        fs::rename(&lock_path, &replaced_path)?;
        fs::write(&lock_path, b"")?;
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))?;

        let error = expect_error(&root.0)?;
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        drop(first);
        StoreAccessLock::acquire(&root.0)?;
        Ok(())
    }

    #[test]
    fn same_owner_can_replace_data_directory_path_outside_lock_authority() -> io::Result<()> {
        let root = TestDir::new()?;
        let original = StoreAccessLock::acquire(&root.0)?;
        let displaced = root.0.with_extension("displaced");
        fs::rename(&root.0, &displaced)?;
        fs::create_dir(&root.0)?;
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700))?;

        // The advisory lock binds to an inode, not an immutable pathname.
        // Production keeps the parent root-managed so the daemon cannot do
        // this; a same-owner actor is outside this local-lock threat boundary.
        let replacement = StoreAccessLock::acquire(&root.0)?;
        drop(replacement);
        drop(original);
        fs::remove_dir_all(displaced)?;
        Ok(())
    }
}
