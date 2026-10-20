//! Process-lifetime lock for local access to an O3K data directory.
//!
//! This only coordinates processes that use the same lock file on a filesystem
//! with working `flock` semantics. It does not fence remote PostgreSQL clients
//! or a privileged/same-owner actor that can replace the data-directory path.
//! Production deployments should place the data directory under a
//! root-managed parent that the daemon account cannot modify.

use std::{
    error::Error,
    fmt, fs, io,
    io::{IoSlice, IoSliceMut, Read, Write},
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream,
    },
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

#[cfg(target_os = "linux")]
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

const LOCK_FILE: &str = ".o3k-store.lock";
const DATA_DIR_MODE: u32 = 0o022;
const LOCK_FILE_MODE: u32 = 0o7777;
const PARENT_SETUP_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const PARENT_SETUP_LOCK_RETRY: Duration = Duration::from_millis(10);
#[cfg(target_os = "linux")]
const HANDOFF_FRAME: &[u8; 8] = b"O3KLOCK1";
#[cfg(target_os = "linux")]
const HANDOFF_ACK: &[u8; 8] = b"LOCKACK1";
// Linux permits at most 253 SCM_RIGHTS descriptors in one message. Reserve
// enough control space to receive and close the entire valid maximum before
// rejecting any set other than the two protocol descriptors.
#[cfg(target_os = "linux")]
const HANDOFF_CONTROL_BUFFER_BYTES: usize = 4096;

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
        acquire_parent_setup_lock(&parent_fd).map_err(|error| {
            with_lock_context(
                "failed to acquire O3K data-directory parent setup lock",
                error,
            )
        })?;

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
        flock(&dir_fd, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            with_lock_context(
                "failed to acquire O3K data-directory lifetime lock",
                io::Error::from(error),
            )
        })?;
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
        flock(&lock_fd, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            with_lock_context(
                "failed to acquire O3K store lock-file lock",
                io::Error::from(error),
            )
        })?;
        // Recheck after acquisition so a replacement race fails closed.
        let locked_stat = fstat(&lock_fd)?;
        validate_lock_file(&dir_stat, &locked_stat)?;
        validate_directory_entry(&dir_fd, &locked_stat)?;

        Ok(Self {
            _lock_file: lock_fd,
            _data_dir: dir_fd,
        })
    }

    /// Transfers this lock to a connected local executor without releasing
    /// either kernel lock between owners. The receiver must call
    /// [`Self::receive_handoff`] and retain the returned guard before it sends
    /// the acknowledgement. If the exchange fails, the sender still owns the
    /// guard until this method returns and drops it.
    ///
    /// The peer must be authenticated by the caller (normally a private,
    /// operation-scoped Unix socket). This transfers only the local lock; it
    /// does not fence remote PostgreSQL sessions.
    ///
    /// An error after sending may mean the peer retained the descriptors but
    /// its acknowledgement was lost. The caller must treat that outcome as
    /// unknown and must not start another store owner until it has established
    /// which process still holds the lock. The error returns this guard to the
    /// caller so a failed transfer cannot itself release the last known lock.
    #[cfg(target_os = "linux")]
    pub fn handoff(
        self,
        stream: &mut UnixStream,
        timeout: Duration,
    ) -> Result<(), (Self, io::Error)> {
        match self.handoff_inner(stream, timeout) {
            Ok(()) => Ok(()),
            Err(error) => Err((self, error)),
        }
    }

    #[cfg(target_os = "linux")]
    fn handoff_inner(&self, stream: &mut UnixStream, timeout: Duration) -> io::Result<()> {
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "store-lock handoff timeout must be positive",
            ));
        }
        let descriptors = [self._lock_file.as_fd(), self._data_dir.as_fd()];
        let mut control = [0_u8; rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut control);
        if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err(io::Error::other("store-lock handoff buffer is unavailable"));
        }
        let payload = [IoSlice::new(HANDOFF_FRAME)];
        let previous_write_timeout = stream.write_timeout()?;
        stream.set_write_timeout(Some(timeout))?;
        let send_result = sendmsg(&mut *stream, &payload, &mut ancillary, SendFlags::empty())
            .map_err(io::Error::from);
        let restore_timeout = stream.set_write_timeout(previous_write_timeout);
        let sent = send_result?;
        restore_timeout?;
        if sent != HANDOFF_FRAME.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "store-lock handoff frame was incomplete",
            ));
        }
        let mut acknowledgement = [0_u8; HANDOFF_ACK.len()];
        read_exact_with_timeout(stream, &mut acknowledgement, timeout)?;
        if &acknowledgement != HANDOFF_ACK {
            return Err(invalid_data(
                "store-lock handoff acknowledgement is invalid",
            ));
        }
        Ok(())
    }

    /// Receives the same locked open-file descriptions sent by
    /// [`Self::handoff`]. It validates the opened directory and lock-file
    /// identities, confirms the exclusive flock remains held, and only then
    /// acknowledges ownership to the sender. The operation-scoped socket is
    /// consumed so any failed exchange closes it and releases unaccepted
    /// ancillary descriptors; it is returned only after a valid handoff.
    #[cfg(target_os = "linux")]
    pub fn receive_handoff(
        mut stream: UnixStream,
        timeout: Duration,
    ) -> io::Result<(Self, UnixStream)> {
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "store-lock handoff timeout must be positive",
            ));
        }
        let previous_timeout = stream.read_timeout()?;
        stream.set_read_timeout(Some(timeout))?;
        let result = (|| {
            let mut frame = [0_u8; HANDOFF_FRAME.len()];
            let mut payload = [IoSliceMut::new(&mut frame)];
            let mut control = [0_u8; HANDOFF_CONTROL_BUFFER_BYTES];
            let mut ancillary = RecvAncillaryBuffer::new(&mut control);
            let received = recvmsg(
                &mut stream,
                &mut payload,
                &mut ancillary,
                RecvFlags::CMSG_CLOEXEC,
            )
            .map_err(|error| {
                let error = io::Error::from(error);
                if error.kind() == io::ErrorKind::WouldBlock {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "store-lock handoff descriptor receive timed out",
                    )
                } else {
                    error
                }
            })?;
            // Convert every received SCM_RIGHTS entry to owned descriptors
            // before any validation can return. This ensures malformed frames,
            // unexpected control messages and MSG_CTRUNC all close descriptors
            // that the kernel installed for this recvmsg.
            let mut descriptors = Vec::with_capacity(2);
            let mut unexpected_ancillary = false;
            for message in ancillary.drain() {
                match message {
                    RecvAncillaryMessage::ScmRights(received) => descriptors.extend(received),
                    _ => unexpected_ancillary = true,
                }
            }
            // rustix 0.38 exposes returned recvmsg flags as RecvFlags but does
            // not name MSG_CTRUNC. Linux UAPI assigns this output bit 0x08.
            if received.flags.bits() & 0x08 != 0 {
                return Err(invalid_data(
                    "store-lock handoff ancillary data was truncated",
                ));
            }
            if received.bytes == 0 || received.bytes > HANDOFF_FRAME.len() {
                return Err(invalid_data("store-lock handoff frame is invalid"));
            }
            if received.bytes < HANDOFF_FRAME.len() {
                read_exact_with_timeout(&mut stream, &mut frame[received.bytes..], timeout)?;
            }
            if &frame != HANDOFF_FRAME {
                return Err(invalid_data("store-lock handoff frame is invalid"));
            }
            if unexpected_ancillary {
                return Err(invalid_data("store-lock handoff contains unexpected data"));
            }
            if descriptors.len() != 2 {
                return Err(invalid_data("store-lock handoff descriptor set is invalid"));
            }
            let lock_file = descriptors.remove(0);
            let data_dir = descriptors.remove(0);
            let directory_stat = fstat(&data_dir)?;
            validate_directory(&directory_stat)?;
            let lock_stat = fstat(&lock_file)?;
            validate_lock_file(&directory_stat, &lock_stat)?;
            validate_directory_entry(&data_dir, &lock_stat)?;
            // Re-locking the same open-file description is idempotent. If the
            // sender passed a separately opened descriptor, this fails while
            // the original owner still holds the lock.
            flock(&data_dir, FlockOperation::NonBlockingLockExclusive).map_err(io::Error::from)?;
            flock(&lock_file, FlockOperation::NonBlockingLockExclusive).map_err(io::Error::from)?;

            let lock = Self {
                _lock_file: lock_file,
                _data_dir: data_dir,
            };
            lock.validate_current_entries()?;
            stream.set_read_timeout(previous_timeout)?;
            write_all_with_timeout(&mut stream, HANDOFF_ACK, timeout)?;
            Ok(lock)
        })();
        if result.is_err() {
            let _ = stream.set_read_timeout(previous_timeout);
        }
        result.map(|lock| (lock, stream))
    }

    #[cfg(target_os = "linux")]
    fn validate_current_entries(&self) -> io::Result<()> {
        let directory_stat = fstat(&self._data_dir)?;
        let lock_stat = fstat(&self._lock_file)?;
        validate_directory(&directory_stat)?;
        validate_lock_file(&directory_stat, &lock_stat)?;
        validate_directory_entry(&self._data_dir, &lock_stat)
    }
}

#[cfg(target_os = "linux")]
fn write_all_with_timeout(
    stream: &mut UnixStream,
    buffer: &[u8],
    timeout: Duration,
) -> io::Result<()> {
    let previous_timeout = stream.write_timeout()?;
    stream.set_write_timeout(Some(timeout))?;
    let result = stream.write_all(buffer).map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "store-lock handoff acknowledgement write timed out",
            )
        } else {
            error
        }
    });
    let restore_result = stream.set_write_timeout(previous_timeout);
    result?;
    restore_result
}

#[cfg(target_os = "linux")]
fn read_exact_with_timeout(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    timeout: Duration,
) -> io::Result<()> {
    let previous_timeout = stream.read_timeout()?;
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "handoff timeout is too large")
    })?;
    let mut offset = 0;
    let result = (|| {
        while offset < buffer.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "store-lock handoff acknowledgement timed out",
                ));
            }
            stream.set_read_timeout(Some(remaining))?;
            match stream.read(&mut buffer[offset..]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(read) => offset += read,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) && Instant::now() < deadline =>
                {
                    continue;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "store-lock handoff acknowledgement timed out",
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    })();
    let restore_result = stream.set_read_timeout(previous_timeout);
    result?;
    restore_result
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

fn with_lock_context(context: &'static str, source: io::Error) -> io::Error {
    let kind = source.kind();
    io::Error::new(kind, LockContextError { context, source })
}

#[derive(Debug)]
struct LockContextError {
    context: &'static str,
    source: io::Error,
}

impl fmt::Display for LockContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.context, self.source)
    }
}

impl Error for LockContextError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
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
        io::{IoSlice, Read, Write},
        os::fd::AsFd,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        os::unix::net::{UnixListener, UnixStream},
        path::{Path, PathBuf},
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };

    use super::{LOCK_FILE, StoreAccessLock};
    #[cfg(target_os = "linux")]
    use rustix::net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
    };

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

    #[cfg(target_os = "linux")]
    fn accept_handoff_child(
        listener: &UnixListener,
        child: &mut std::process::Child,
        timeout: Duration,
    ) -> io::Result<UnixStream> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout is too large"))?;
        let result = (|| loop {
            match listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "handoff helper exited before connecting: {status}"
                )));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "handoff helper did not connect before the deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        })();
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
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
    fn lock_context_preserves_os_error_source() {
        let source = io::Error::from(rustix::io::Errno::WOULDBLOCK);
        let raw_os_error = source.raw_os_error();
        let error = super::with_lock_context("test lock stage", source);

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(error.to_string().contains("test lock stage"));
        let preserved_raw_os_error = error
            .get_ref()
            .and_then(|error| std::error::Error::source(error))
            .and_then(|error| error.downcast_ref::<io::Error>())
            .and_then(io::Error::raw_os_error);
        assert_eq!(preserved_raw_os_error, raw_os_error);
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

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "subprocess helper invoked by handoff_keeps_lock_continuously_owned_across_processes"]
    fn store_lock_handoff_child() -> io::Result<()> {
        let socket_path = std::env::var_os("O3K_STORE_LOCK_HANDOFF_SOCKET").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "subprocess handoff socket environment is missing",
            )
        })?;
        let stream = UnixStream::connect(socket_path)?;
        let (lock, mut stream) = StoreAccessLock::receive_handoff(stream, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(b"READY001")?;
        let mut release = [0_u8; 8];
        stream.read_exact(&mut release)?;
        if &release != b"RELEASE1" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad test release",
            ));
        }
        drop(lock);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn handoff_helper_exit_does_not_leave_parent_waiting_for_connection() -> io::Result<()> {
        let root = TestDir::new()?;
        let listener = UnixListener::bind(root.0.join("handoff.sock"))?;
        listener.set_nonblocking(true)?;
        let mut child = Command::new(std::env::current_exe()?)
            .arg("--help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let error = match accept_handoff_child(&listener, &mut child, Duration::from_secs(5)) {
            Ok(_) => return Err(io::Error::other("child connected without its socket")),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exited before connecting"));
        assert!(child.wait()?.success());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn handoff_keeps_lock_continuously_owned_across_processes() -> io::Result<()> {
        let root = TestDir::new()?;
        let data_dir = root.0.join("data");
        let socket_path = root.0.join("handoff.sock");
        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;
        let lock = StoreAccessLock::acquire(&data_dir)?;
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "access_lock::tests::store_lock_handoff_child",
            ])
            .env("O3K_STORE_LOCK_HANDOFF_SOCKET", &socket_path)
            .spawn()?;
        let mut stream = accept_handoff_child(&listener, &mut child, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        lock.handoff(&mut stream, Duration::from_secs(5))
            .map_err(|(_, error)| error)?;

        let mut ready = [0_u8; 8];
        stream.read_exact(&mut ready)?;
        assert_eq!(&ready, b"READY001");
        let blocked = match StoreAccessLock::acquire(&data_dir) {
            Err(error) => error.kind() == io::ErrorKind::WouldBlock,
            Ok(lock) => {
                drop(lock);
                false
            }
        };
        assert!(blocked, "child must retain the transferred lock");

        stream.write_all(b"RELEASE1")?;
        assert!(child.wait()?.success());
        let _reacquired = StoreAccessLock::acquire(&data_dir)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn handoff_rejects_excess_descriptors_and_releases_received_handles() -> io::Result<()> {
        let root = TestDir::new()?;
        let data_dir = root.0.join("data");
        let lock = StoreAccessLock::acquire(&data_dir)?;
        let (mut sender, receiver) = UnixStream::pair()?;

        let descriptors = [lock._lock_file.as_fd(); 100];
        let mut send_control = [0_u8; rustix::cmsg_space!(ScmRights(100))];
        let mut send_ancillary = SendAncillaryBuffer::new(&mut send_control);
        assert!(send_ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        let payload = [std::io::IoSlice::new(b"O3KLOCK1")];
        assert_eq!(
            sendmsg(
                &mut sender,
                &payload,
                &mut send_ancillary,
                SendFlags::empty()
            )?,
            8
        );

        let error = match StoreAccessLock::receive_handoff(receiver, Duration::from_millis(10)) {
            Ok(lock) => {
                drop(lock);
                return Err(io::Error::other("truncated descriptor sets were accepted"));
            }
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "store-lock handoff descriptor set is invalid"
        );
        assert!(matches!(
            StoreAccessLock::acquire(&data_dir),
            Err(ref error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        drop(sender);
        drop(lock);
        let _reacquired = StoreAccessLock::acquire(&data_dir)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn handoff_malformed_frame_closes_received_descriptors() -> io::Result<()> {
        let root = TestDir::new()?;
        let data_dir = root.0.join("data");
        let lock_path = data_dir.join(LOCK_FILE);
        let lock = StoreAccessLock::acquire(&data_dir)?;
        let (mut sender, receiver) = UnixStream::pair()?;
        let before = open_descriptors_for(&lock_path)?;

        let descriptors = [lock._lock_file.as_fd(), lock._data_dir.as_fd()];
        let mut control = [0_u8; rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut control);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        let payload = [IoSlice::new(b"BADFRAME")];
        assert_eq!(
            sendmsg(&mut sender, &payload, &mut ancillary, SendFlags::empty())?,
            8
        );

        let error = match StoreAccessLock::receive_handoff(receiver, Duration::from_secs(1)) {
            Ok((received, _)) => {
                drop(received);
                return Err(io::Error::other("malformed handoff frame was accepted"));
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(open_descriptors_for(&lock_path)?, before);
        drop(sender);
        drop(lock);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn open_descriptors_for(path: &Path) -> io::Result<usize> {
        let mut count = 0;
        for entry in fs::read_dir("/proc/self/fd")? {
            if let Ok(opened) = fs::read_link(entry?.path())
                && opened == path
            {
                count += 1;
            }
        }
        Ok(count)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn handoff_timeout_keeps_peer_transferred_lock_until_peer_drops_it() -> io::Result<()> {
        let root = TestDir::new()?;
        let data_dir = root.0.join("data");
        let lock = StoreAccessLock::acquire(&data_dir)?;
        let (mut sender, mut receiver) = UnixStream::pair()?;
        let (retained_sender, retained_receiver) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || -> io::Result<()> {
            let mut frame = [0_u8; 8];
            let mut payload = [std::io::IoSliceMut::new(&mut frame)];
            let mut control = [0_u8; rustix::cmsg_space!(ScmRights(2))];
            let mut ancillary = RecvAncillaryBuffer::new(&mut control);
            let received = recvmsg(
                &mut receiver,
                &mut payload,
                &mut ancillary,
                RecvFlags::CMSG_CLOEXEC,
            )?;
            if received.bytes != 8 || &frame != b"O3KLOCK1" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid test handoff frame",
                ));
            }
            let mut descriptors = Vec::new();
            for message in ancillary.drain() {
                match message {
                    RecvAncillaryMessage::ScmRights(received) => descriptors.extend(received),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid test ancillary data",
                        ));
                    }
                }
            }
            if descriptors.len() != 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid test descriptor set",
                ));
            }
            retained_sender
                .send(())
                .map_err(|_| io::Error::other("test receiver disappeared"))?;
            std::thread::sleep(Duration::from_millis(100));
            drop(descriptors);
            Ok(())
        });

        let (returned_lock, error) = match lock.handoff(&mut sender, Duration::from_millis(20)) {
            Ok(()) => return Err(io::Error::other("unacknowledged handoff did not time out")),
            Err((lock, error)) => (lock, error),
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        retained_receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| io::Error::other("receiver did not retain transferred descriptors"))?;
        assert!(matches!(
            StoreAccessLock::acquire(&data_dir),
            Err(ref error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        peer.join()
            .map_err(|_| io::Error::other("test handoff receiver panicked"))??;
        assert!(
            matches!(
                StoreAccessLock::acquire(&data_dir),
                Err(ref error) if error.kind() == io::ErrorKind::WouldBlock
            ),
            "sender must retain the lock after an unacknowledged handoff"
        );
        drop(returned_lock);
        let _reacquired = StoreAccessLock::acquire(&data_dir)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn handoff_receiver_timeout_is_reported_as_timed_out() -> io::Result<()> {
        let root = TestDir::new()?;
        let data_dir = root.0.join("data");
        let lock = StoreAccessLock::acquire(&data_dir)?;
        let (_sender, receiver) = UnixStream::pair()?;
        let error = match StoreAccessLock::receive_handoff(receiver, Duration::from_millis(10)) {
            Ok((lock, _)) => {
                drop(lock);
                return Err(io::Error::other("empty handoff was accepted"));
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(matches!(
            StoreAccessLock::acquire(&data_dir),
            Err(ref error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        drop(lock);
        let _reacquired = StoreAccessLock::acquire(&data_dir)?;
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
