//! Authenticated backup handoff control channel (PP.6, ADR-0189 D4/D8,
//! SPEC-0050 sections 3 and 8).
//!
//! This module implements the private, host-local Unix-socket protocol that an
//! authorized local executor (`o3k` CLI) speaks to the daemon (`o3kd`) *before*
//! [`crate::StoreAccessLock::handoff`] transfers the store-access lock descriptors.
//! The daemon listens on `<data_dir>/control/backup.sock`; only after the
//! executor passes the checks below does the daemon send the acceptance frame
//! and then speak the existing `O3KLOCK1` handoff frame on the same stream.
//!
//! # Installation/site binding
//!
//! O3K does not configure a separate installation or site identity today, so
//! both identity tokens are derived deterministically from the canonical data
//! directory: the first 16 bytes of SHA-256 over a domain separator and the
//! canonical data-dir path string. Both the daemon and the executor resolve
//! the same data directory, so both derive identical values independently.
//! See [`installation_token`], [`site_token`], and [`identity_tokens`].
//!
//! # Protocol (fixed-size frames, no peer-supplied lengths)
//!
//! Request (executor -> daemon), exactly 64 bytes:
//!
//! ```text
//! bytes  0..8   magic "O3KBKQ1\0"
//! byte   8      protocol version 1
//! bytes  9..25  operation UUID (raw 16 bytes)
//! bytes 25..41  installation identity token (16 bytes)
//! bytes 41..57  site identity token (16 bytes)
//! bytes 57..64  reserved, must be zero
//! ```
//!
//! Response (daemon -> executor), exactly 8 bytes: `O3KBKAC\0` on acceptance,
//! or `O3KBKRJ` plus one reason byte on rejection
//! (1=unauthorized-peer, 2=malformed, 3=duplicate-operation,
//! 4=backup-already-active, 5=identity-mismatch, 6=drain-failed). After the
//! acceptance frame the daemon proceeds to [`crate::StoreAccessLock::handoff`].
//!
//! # Authentication (fail closed)
//!
//! - Peer credentials come from `SO_PEERCRED` via rustix, cross-checked
//!   against the effective uid parsed from `/proc/<pid>/status`.
//! - The peer executable is identified by device+inode, not by path:
//!   `fs::metadata("/proc/<pid>/exe")` follows the magic link into the
//!   peer's mount namespace and stats the real executable inode, which is
//!   compared against `fs::metadata(expected_exe)`. The readlink exists
//!   only to reject a ` (deleted)` suffix: an unlinked executable fails
//!   closed. Path comparison alone is bypassable via a mount namespace
//!   (the resolved path is compared with itself).
//! - `/proc/<pid>/stat` field 22 (starttime, parsed after the last `)`) is
//!   recorded at accept; [`AcceptedBackupRequest::revalidate_peer`] re-reads it
//!   immediately before the lock handoff so PID reuse fails closed, and
//!   re-checks the executable dev+ino and the peer uid recorded at accept.
//! - One authenticated attempt at a time per listener: a second
//!   [`BackupControlListener::accept_authenticated`] call while one request is
//!   active is rejected with [`BackupControlError::AlreadyActive`], and a
//!   previously accepted operation UUID is never accepted again
//!   ([`HandoffRejectReason::DuplicateOperation`]).
//! - Every socket step is bounded by the supplied timeout; a zero timeout is
//!   [`BackupControlError::InvalidInput`].
//!
//! # Logging
//!
//! No secrets appear in arguments, environment, or logs: identity tokens never
//! leave the socket frame, and this module performs no logging at all (o3k-store
//! has no logger dependency); rejection reasons travel only in-band to the
//! connected peer. Callers may log the operation id, peer pid/uid, and reason
//! codes, nothing more.
//!
//! The module is Linux-only, mirroring the handoff gating in
//! `access_lock.rs`; it is entirely synchronous so it stays usable from sync
//! code (the listener polls a nonblocking `std` `UnixListener` against the
//! deadline).

use std::{
    fmt, fs, io,
    io::{Read, Write},
    os::{
        fd::AsFd,
        unix::fs::{FileTypeExt, MetadataExt},
        unix::net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use rustix::{
    fs::{AtFlags, FileType, Mode, OFlags, open, openat, statat, unlinkat},
    net::sockopt::get_socket_peercred,
    process::{Pid, geteuid},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Control subdirectory (inside the validated data directory) holding the
/// backup control socket.
pub const BACKUP_CONTROL_DIR: &str = "control";
/// Name of the private backup control socket inside [`BACKUP_CONTROL_DIR`].
pub const BACKUP_CONTROL_SOCKET: &str = "backup.sock";

const REQUEST_MAGIC: &[u8; 8] = b"O3KBKQ1\0";
const PROTOCOL_VERSION: u8 = 1;
const REQUEST_FRAME_LEN: usize = 64;
const ACCEPT_FRAME: &[u8; 8] = b"O3KBKAC\0";
const REJECT_MAGIC: &[u8; 7] = b"O3KBKRJ";
const RESPONSE_FRAME_LEN: usize = 8;
const INSTALLATION_TOKEN_DOMAIN: &[u8] = b"o3k-backup-installation-identity-v1";
const SITE_TOKEN_DOMAIN: &[u8] = b"o3k-backup-site-identity-v1";
const LISTENER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const REJECT_FRAME_TIMEOUT: Duration = Duration::from_millis(500);
/// Per-connection write bound for the in-band `AlreadyActive` rejection sent
/// to connectors that arrive after the single authenticated attempt (a
/// stalled peer must never pin the accept thread).
const ALREADY_ACTIVE_REJECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Mask of permissions that must never be present on the data directory or
/// the control directory (mirrors the store-access lock posture).
const PUBLIC_WRITABLE_MASK: u32 = 0o022;
const CONTROL_DIR_MODE: u32 = 0o700;
const CONTROL_SOCKET_MODE: u32 = 0o600;

const STATE_IDLE: u8 = 0;
const STATE_ACCEPTING: u8 = 1;
const STATE_ACTIVE: u8 = 2;

/// Rejection reason codes sent after the `O3KBKRJ` response magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffRejectReason {
    /// Peer credentials or executable identity do not match the expected
    /// executor.
    UnauthorizedPeer,
    /// The request frame was truncated or failed magic/version/reserved
    /// validation.
    Malformed,
    /// This operation UUID was already accepted by this listener.
    DuplicateOperation,
    /// Another backup handoff attempt is already active on this listener.
    AlreadyActive,
    /// The installation or site identity token does not match this data
    /// directory.
    IdentityMismatch,
    /// The daemon failed to drain writers before the handoff.
    DrainFailed,
}

impl HandoffRejectReason {
    fn reason_byte(self) -> u8 {
        match self {
            Self::UnauthorizedPeer => 1,
            Self::Malformed => 2,
            Self::DuplicateOperation => 3,
            Self::AlreadyActive => 4,
            Self::IdentityMismatch => 5,
            Self::DrainFailed => 6,
        }
    }

    fn from_reason_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::UnauthorizedPeer),
            2 => Some(Self::Malformed),
            3 => Some(Self::DuplicateOperation),
            4 => Some(Self::AlreadyActive),
            5 => Some(Self::IdentityMismatch),
            6 => Some(Self::DrainFailed),
            _ => None,
        }
    }
}

/// Errors returned by the backup control channel.
#[derive(Debug)]
pub enum BackupControlError {
    /// An OS-level I/O failure.
    Io(io::Error),
    /// The overall deadline expired before the step completed.
    Timeout,
    /// The daemon rejected the request in-band with a typed reason.
    Rejected(HandoffRejectReason),
    /// The authenticated peer process disappeared or was replaced (PID reuse)
    /// since acceptance.
    PeerChanged,
    /// A live peer no longer matches the recorded executable identity.
    Unauthorized,
    /// A backup handoff attempt is already active on this listener.
    AlreadyActive,
    /// A caller-supplied value (such as a zero timeout) is not usable.
    InvalidInput,
}

impl fmt::Display for BackupControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "backup control I/O error: {error}"),
            Self::Timeout => write!(formatter, "backup control operation timed out"),
            Self::Rejected(reason) => write!(formatter, "backup handoff rejected: {reason:?}"),
            Self::PeerChanged => write!(
                formatter,
                "authenticated peer process disappeared or was replaced"
            ),
            Self::Unauthorized => write!(
                formatter,
                "peer executable identity no longer matches the expected executor"
            ),
            Self::AlreadyActive => write!(
                formatter,
                "another backup handoff attempt is already active"
            ),
            Self::InvalidInput => write!(formatter, "invalid backup control input"),
        }
    }
}

impl std::error::Error for BackupControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for BackupControlError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Backup handoff request sent by the executor over the control socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupHandoffRequest {
    /// Durable identity of the backup operation.
    pub operation_id: Uuid,
    /// Installation identity token (see [`installation_token`]).
    pub installation: [u8; 16],
    /// Site identity token (see [`site_token`]).
    pub site: [u8; 16],
}

impl BackupHandoffRequest {
    fn encode(&self) -> [u8; REQUEST_FRAME_LEN] {
        let mut frame = [0_u8; REQUEST_FRAME_LEN];
        frame[..REQUEST_MAGIC.len()].copy_from_slice(REQUEST_MAGIC);
        frame[REQUEST_MAGIC.len()] = PROTOCOL_VERSION;
        frame[9..25].copy_from_slice(self.operation_id.as_bytes());
        frame[25..41].copy_from_slice(&self.installation);
        frame[41..57].copy_from_slice(&self.site);
        frame
    }
}

/// Authenticated identity of the connected executor process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Peer process id (from `SO_PEERCRED`).
    pub pid: u32,
    /// Peer effective uid (from `SO_PEERCRED`).
    pub uid: u32,
    /// Peer effective gid (from `SO_PEERCRED`).
    pub gid: u32,
    /// Canonical path of the peer executable observed via `/proc/<pid>/exe`.
    pub exe: PathBuf,
    /// Device of the real peer executable inode (via
    /// `metadata("/proc/<pid>/exe")`, which follows the magic link into the
    /// peer's mount namespace). Identity is decided by dev+ino, not path.
    pub exe_dev: u64,
    /// Inode of the real peer executable inode (see [`Self::exe_dev`]).
    pub exe_ino: u64,
    /// `/proc/<pid>/stat` field 22 (starttime in clock ticks) observed at
    /// accept; [`AcceptedBackupRequest::revalidate_peer`] requires it to be
    /// unchanged.
    pub start_time_ticks: u64,
}

/// The executor the daemon expects for a backup handoff.
#[derive(Debug, Clone)]
pub struct ExpectedExecutor {
    /// Canonical path of the expected executor executable (the sibling `o3k`
    /// of the running `o3kd` executable).
    pub exe: PathBuf,
    /// Effective uid the peer must run as.
    pub uid: u32,
    /// Installation identity token the request must carry.
    pub installation: [u8; 16],
    /// Site identity token the request must carry.
    pub site: [u8; 16],
}

/// Derives the installation identity token for a data directory.
///
/// O3K does not configure a separate installation identity, so the token is
/// the first 16 bytes of SHA-256 over a domain separator and the canonical
/// data-dir path string. The daemon and the executor resolve the same data
/// directory, so both derive this value independently and it binds the
/// request to the installation whose data directory is being handed off.
pub fn installation_token(data_dir: &Path) -> io::Result<[u8; 16]> {
    derive_token(INSTALLATION_TOKEN_DOMAIN, data_dir)
}

/// Derives the site identity token for a data directory; same construction as
/// [`installation_token`] with a distinct domain separator.
pub fn site_token(data_dir: &Path) -> io::Result<[u8; 16]> {
    derive_token(SITE_TOKEN_DOMAIN, data_dir)
}

/// Derives both identity tokens for a data directory.
pub fn identity_tokens(data_dir: &Path) -> io::Result<([u8; 16], [u8; 16])> {
    Ok((installation_token(data_dir)?, site_token(data_dir)?))
}

fn derive_token(domain: &[u8], data_dir: &Path) -> io::Result<[u8; 16]> {
    let canonical = fs::canonicalize(data_dir)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(canonical.as_os_str().as_encoded_bytes());
    let digest = hasher.finalize();
    let mut token = [0_u8; 16];
    token.copy_from_slice(&digest[..16]);
    Ok(token)
}

#[derive(Debug)]
struct ListenerShared {
    state: AtomicU8,
    accepted_operations: Mutex<Vec<[u8; 16]>>,
}

impl ListenerShared {
    fn release_to_idle(&self) {
        // Only an active attempt transitions back to idle; an accepting or
        // already-idle listener must not be disturbed.
        let _ = self.state.compare_exchange(
            STATE_ACTIVE,
            STATE_IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn has_accepted(&self, operation_id: &[u8; 16]) -> bool {
        self.accepted_operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(operation_id)
    }
}

/// Private backup control listener bound under the validated data directory.
///
/// Dropping the listener removes the socket file (when it is still a socket).
/// Exactly one authenticated attempt may be in flight at a time; releasing it
/// (by dropping or rejecting the [`AcceptedBackupRequest`]) allows a later
/// attempt with a new operation UUID.
#[derive(Debug)]
pub struct BackupControlListener {
    listener: UnixListener,
    socket_path: PathBuf,
    shared: Arc<ListenerShared>,
}

impl BackupControlListener {
    /// Creates `<data_dir>/control` with mode 0700 (validating that the data
    /// directory is symlink-free, effective-uid-owned, and not group/other
    /// writable), binds `<data_dir>/control/backup.sock` with mode 0600, and
    /// removes a stale socket file only after verifying it is a socket owned
    /// by the effective uid (no-follow lookup throughout).
    pub fn bind(data_dir: &Path) -> io::Result<Self> {
        let dir_fd = open(
            data_dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let dir_stat = rustix::fs::fstat(&dir_fd)?;
        validate_private_directory(&dir_stat, "O3K data directory")?;

        let control_fd = open_control_dir(&dir_fd)?;
        let control_stat = rustix::fs::fstat(&control_fd)?;
        validate_private_directory(&control_stat, "O3K backup control directory")?;

        let socket_path = data_dir
            .join(BACKUP_CONTROL_DIR)
            .join(BACKUP_CONTROL_SOCKET);
        match statat(
            &control_fd,
            BACKUP_CONTROL_SOCKET,
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(existing) => {
                if FileType::from_raw_mode(existing.st_mode) != FileType::Socket
                    || existing.st_uid != geteuid().as_raw()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "refusing to replace a non-socket or foreign-owned backup control path",
                    ));
                }
                unlinkat(&control_fd, BACKUP_CONTROL_SOCKET, AtFlags::empty())?;
            }
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error) => return Err(error.into()),
        }

        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;
        // Some kernels ignore fchmod on socket file descriptors, so chmod
        // through the already-validated control-directory descriptor instead.
        rustix::fs::chmodat(
            &control_fd,
            BACKUP_CONTROL_SOCKET,
            Mode::from_raw_mode(CONTROL_SOCKET_MODE),
            AtFlags::empty(),
        )?;
        let bound = statat(
            &control_fd,
            BACKUP_CONTROL_SOCKET,
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        if FileType::from_raw_mode(bound.st_mode) != FileType::Socket
            || bound.st_uid != geteuid().as_raw()
            || bound.st_mode & 0o7777 != CONTROL_SOCKET_MODE
        {
            let _ = fs::remove_file(&socket_path);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "backup control socket bound with unexpected identity or mode",
            ));
        }
        Ok(Self {
            listener,
            socket_path,
            shared: Arc::new(ListenerShared {
                state: AtomicU8::new(STATE_IDLE),
                accepted_operations: Mutex::new(Vec::new()),
            }),
        })
    }

    /// Accepts and fully authenticates ONE backup handoff request within the
    /// overall `timeout` deadline. A second call while a request is active (or
    /// after one was accepted and is still live) fails with
    /// [`BackupControlError::AlreadyActive`]; a request carrying an already
    /// accepted operation UUID fails with
    /// [`BackupControlError::Rejected`]`(`[`HandoffRejectReason::DuplicateOperation`]`)`.
    pub fn accept_authenticated(
        &self,
        expected: &ExpectedExecutor,
        timeout: Duration,
    ) -> Result<AcceptedBackupRequest, BackupControlError> {
        if timeout.is_zero() {
            return Err(BackupControlError::InvalidInput);
        }
        self.shared
            .state
            .compare_exchange(
                STATE_IDLE,
                STATE_ACCEPTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| BackupControlError::AlreadyActive)?;
        let result = self.accept_inner(expected, timeout);
        match result {
            Ok(accepted) => {
                self.shared
                    .accepted_operations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(accepted.operation_id);
                self.shared.state.store(STATE_ACTIVE, Ordering::Release);
                Ok(accepted)
            }
            Err(error) => {
                self.shared.state.store(STATE_IDLE, Ordering::Release);
                Err(error)
            }
        }
    }

    /// Accepts the next pending connection WITHOUT authentication.
    ///
    /// After the daemon's single authenticated attempt is active, the accept
    /// thread uses this to take every further connector and answer it with
    /// [`reject_already_active`] instead of leaving it to wait out its own
    /// request timeout. The wait is bounded by `timeout` exactly like
    /// [`Self::accept_authenticated`].
    pub fn accept_raw(&self, timeout: Duration) -> Result<UnixStream, BackupControlError> {
        if timeout.is_zero() {
            return Err(BackupControlError::InvalidInput);
        }
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "backup control timeout is too large",
            )
        })?;
        Ok(accept_pending(&self.listener, deadline)?.0)
    }

    fn accept_inner(
        &self,
        expected: &ExpectedExecutor,
        timeout: Duration,
    ) -> Result<AcceptedBackupRequest, BackupControlError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "backup control timeout is too large",
            )
        })?;
        let (mut stream, _) = accept_pending(&self.listener, deadline)?;

        let frame = match read_request_frame(&mut stream, deadline) {
            Ok(frame) => frame,
            Err(FrameReadError::TimedOut) => return Err(BackupControlError::Timeout),
            Err(FrameReadError::Truncated) => {
                reject_stream(&mut stream, HandoffRejectReason::Malformed);
                return Err(BackupControlError::Rejected(HandoffRejectReason::Malformed));
            }
            Err(FrameReadError::Io(error)) => return Err(BackupControlError::Io(error)),
        };
        let request = match parse_request(&frame) {
            Ok(request) => request,
            Err(reason) => {
                reject_stream(&mut stream, reason);
                return Err(BackupControlError::Rejected(reason));
            }
        };

        let credentials = match get_socket_peercred(stream.as_fd()) {
            Ok(credentials) => credentials,
            Err(error) => {
                reject_stream(&mut stream, HandoffRejectReason::UnauthorizedPeer);
                return Err(BackupControlError::Io(error.into()));
            }
        };
        let uid = credentials.uid.as_raw();
        let gid = credentials.gid.as_raw();
        let pid_raw = Pid::as_raw(Some(credentials.pid));
        if uid != expected.uid || pid_raw <= 0 {
            reject_stream(&mut stream, HandoffRejectReason::UnauthorizedPeer);
            return Err(BackupControlError::Rejected(
                HandoffRejectReason::UnauthorizedPeer,
            ));
        }
        let pid = pid_raw as u32;

        let identity = match read_process_identity(pid) {
            Ok(identity) => identity,
            Err(_) => {
                reject_stream(&mut stream, HandoffRejectReason::UnauthorizedPeer);
                return Err(BackupControlError::Rejected(
                    HandoffRejectReason::UnauthorizedPeer,
                ));
            }
        };
        // The procfs identity must agree with the socket credentials: a
        // process whose /proc effective uid no longer matches the peer that
        // connected is not the authenticated executor.
        if identity.uid != uid {
            reject_stream(&mut stream, HandoffRejectReason::UnauthorizedPeer);
            return Err(BackupControlError::Rejected(
                HandoffRejectReason::UnauthorizedPeer,
            ));
        }
        match executable_matches(&identity, &expected.exe) {
            Ok(true) => {}
            Ok(false) => {
                reject_stream(&mut stream, HandoffRejectReason::UnauthorizedPeer);
                return Err(BackupControlError::Rejected(
                    HandoffRejectReason::UnauthorizedPeer,
                ));
            }
            Err(error) => {
                reject_stream(&mut stream, HandoffRejectReason::UnauthorizedPeer);
                return Err(BackupControlError::Io(error));
            }
        }

        if request.installation != expected.installation || request.site != expected.site {
            reject_stream(&mut stream, HandoffRejectReason::IdentityMismatch);
            return Err(BackupControlError::Rejected(
                HandoffRejectReason::IdentityMismatch,
            ));
        }
        if self.shared.has_accepted(&request.operation_id) {
            reject_stream(&mut stream, HandoffRejectReason::DuplicateOperation);
            return Err(BackupControlError::Rejected(
                HandoffRejectReason::DuplicateOperation,
            ));
        }

        // The authenticated stream must not carry leftover socket timeouts
        // into the subsequent `StoreAccessLock::handoff` exchange.
        stream
            .set_read_timeout(None)
            .map_err(BackupControlError::Io)?;
        stream
            .set_write_timeout(None)
            .map_err(BackupControlError::Io)?;
        Ok(AcceptedBackupRequest {
            operation_id: request.operation_id,
            stream,
            peer: PeerIdentity {
                pid,
                uid,
                gid,
                exe: identity.exe,
                exe_dev: identity.exe_dev,
                exe_ino: identity.exe_ino,
                start_time_ticks: identity.start_time_ticks,
            },
            shared: self.shared.clone(),
        })
    }
}

impl Drop for BackupControlListener {
    fn drop(&mut self) {
        // Best-effort removal, refusing to delete anything that is no longer
        // a plain socket entry (a same-owner replacement race).
        if let Ok(metadata) = fs::symlink_metadata(&self.socket_path)
            && metadata.file_type().is_socket()
        {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

/// A fully authenticated backup handoff request, ready for
/// [`crate::StoreAccessLock::handoff`].
///
/// Dropping this value (including via [`AcceptedBackupRequest::reject`])
/// releases the listener's single-attempt slot so a later backup operation can
/// be accepted; the operation UUID remains permanently recorded for duplicate
/// rejection. The caller must keep this value alive until the lock handoff has
/// completed.
#[derive(Debug)]
pub struct AcceptedBackupRequest {
    /// Raw operation UUID carried by the accepted request.
    pub operation_id: [u8; 16],
    /// Authenticated connection; after [`Self::send_accept`] this is the
    /// stream passed to [`crate::StoreAccessLock::handoff`].
    pub stream: UnixStream,
    /// Authenticated peer identity observed at accept time.
    pub peer: PeerIdentity,
    shared: Arc<ListenerShared>,
}

impl AcceptedBackupRequest {
    /// Writes the rejection frame (`O3KBKRJ` + reason) to the peer, best
    /// effort, and releases the listener's single-attempt slot.
    pub fn reject(self, reason: HandoffRejectReason) {
        let mut this = self;
        reject_stream(&mut this.stream, reason);
    }

    /// Writes the 8-byte `O3KBKAC\0` acceptance frame. After this returns the
    /// daemon must drain writers and then call [`crate::StoreAccessLock::handoff`] on
    /// [`Self::stream`].
    pub fn send_accept(&mut self) -> io::Result<()> {
        write_all_bounded(&mut self.stream, ACCEPT_FRAME, REJECT_FRAME_TIMEOUT)?;
        Ok(())
    }

    /// PID-reuse revalidation: re-reads `/proc/<pid>/stat`, `/proc/<pid>/exe`,
    /// and `/proc/<pid>/status` and requires the peer to still be alive with
    /// an identical starttime, the same canonical executable path and
    /// executable dev+ino, and the uid recorded at accept. Call immediately
    /// before [`crate::StoreAccessLock::handoff`].
    pub fn revalidate_peer(&self) -> Result<(), BackupControlError> {
        let identity =
            read_process_identity(self.peer.pid).map_err(|_| BackupControlError::PeerChanged)?;
        if identity.start_time_ticks != self.peer.start_time_ticks {
            return Err(BackupControlError::PeerChanged);
        }
        if identity.exe != self.peer.exe
            || identity.exe_dev != self.peer.exe_dev
            || identity.exe_ino != self.peer.exe_ino
            || identity.uid != self.peer.uid
        {
            return Err(BackupControlError::Unauthorized);
        }
        Ok(())
    }
}

impl Drop for AcceptedBackupRequest {
    fn drop(&mut self) {
        self.shared.release_to_idle();
    }
}

/// Connects to `<data_dir>/control/backup.sock` (resolving each path component
/// with no-follow checks), sends the 64-byte request frame, and waits up to
/// `timeout` for the 8-byte response. On acceptance the returned stream is
/// ready for [`crate::StoreAccessLock::receive_handoff`]; on rejection a typed
/// [`BackupControlError::Rejected`] is returned.
///
/// This is [`connect_control`] followed by [`send_request_and_read_accept`].
/// A caller that must authenticate the peer **before** asking it to stop
/// serving (the executor's `daemon-identity-*` check) uses the two steps
/// directly, so a local impostor is rejected without a needless drain.
pub fn connect_and_request(
    data_dir: &Path,
    request: &BackupHandoffRequest,
    timeout: Duration,
) -> Result<UnixStream, BackupControlError> {
    let mut stream = connect_control(data_dir, timeout)?;
    send_request_and_read_accept(&mut stream, request, timeout)?;
    Ok(stream)
}

/// Connects to the backup control socket without sending a request.
///
/// The returned stream carries the caller's timeouts, so
/// [`send_request_and_read_accept`] inherits the same bound. Authentication
/// ([`verify_daemon_peer`]) can therefore run between connect and request.
pub fn connect_control(
    data_dir: &Path,
    timeout: Duration,
) -> Result<UnixStream, BackupControlError> {
    if timeout.is_zero() {
        return Err(BackupControlError::InvalidInput);
    }
    let socket_path = resolve_socket_path(data_dir)?;
    let stream = UnixStream::connect(socket_path).map_err(BackupControlError::Io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(BackupControlError::Io)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(BackupControlError::Io)?;
    Ok(stream)
}

/// Sends the 64-byte request frame on an already-connected stream and reads the
/// 8-byte response, leaving the stream ready for
/// [`crate::StoreAccessLock::receive_handoff`] on acceptance.
pub fn send_request_and_read_accept(
    stream: &mut UnixStream,
    request: &BackupHandoffRequest,
    timeout: Duration,
) -> Result<(), BackupControlError> {
    if timeout.is_zero() {
        return Err(BackupControlError::InvalidInput);
    }
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup control timeout is too large",
        )
    })?;
    let frame = request.encode();
    write_all_bounded(stream, &frame, timeout).map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            BackupControlError::Timeout
        } else {
            BackupControlError::Io(error)
        }
    })?;

    let response = read_response_frame(stream, deadline).map_err(|error| match error {
        FrameReadError::TimedOut => BackupControlError::Timeout,
        FrameReadError::Truncated => BackupControlError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "backup control connection closed without a response",
        )),
        FrameReadError::Io(error) => BackupControlError::Io(error),
    })?;
    if &response == ACCEPT_FRAME {
        stream
            .set_read_timeout(None)
            .map_err(BackupControlError::Io)?;
        stream
            .set_write_timeout(None)
            .map_err(BackupControlError::Io)?;
        return Ok(());
    }
    if response[..REJECT_MAGIC.len()] == *REJECT_MAGIC {
        let Some(reason) = HandoffRejectReason::from_reason_byte(response[REJECT_MAGIC.len()])
        else {
            return Err(BackupControlError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "backup control rejection carried an unknown reason",
            )));
        };
        return Err(BackupControlError::Rejected(reason));
    }
    Err(BackupControlError::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        "backup control response frame is invalid",
    )))
}

/// Authenticates the daemon side of an accepted handoff stream.
///
/// The executor calls this after [`connect_control`] and before
/// [`send_request_and_read_accept`] (so an impostor never receives the
/// request), and again the connection is then used with
/// [`crate::StoreAccessLock::receive_handoff`]. It requires:
///
/// * `SO_PEERCRED` uid equal to `expected_uid` (the resolved data-directory
///   owner);
/// * `/proc/<pid>/status` effective uid equal to the socket credential, so a
///   process whose credentials changed after connect is refused;
/// * `/proc/<pid>/exe` device+inode equal to `expected_exe`, using the same
///   mount-namespace-safe identity comparison as the listener.
///
/// A mismatch is [`BackupControlError::Unauthorized`]; an unreadable peer is
/// [`BackupControlError::PeerChanged`]. Both fail closed.
pub fn verify_daemon_peer(
    stream: &UnixStream,
    expected_exe: &Path,
    expected_uid: u32,
) -> Result<(), BackupControlError> {
    let credentials = get_socket_peercred(stream.as_fd())
        .map_err(|error| BackupControlError::Io(error.into()))?;
    let uid = credentials.uid.as_raw();
    let pid = Pid::as_raw(Some(credentials.pid));
    if uid != expected_uid || pid <= 0 {
        return Err(BackupControlError::Unauthorized);
    }
    let identity =
        read_process_identity(pid as u32).map_err(|_| BackupControlError::PeerChanged)?;
    if identity.uid != uid {
        return Err(BackupControlError::Unauthorized);
    }
    match executable_matches(&identity, expected_exe) {
        Ok(true) => Ok(()),
        Ok(false) => Err(BackupControlError::Unauthorized),
        Err(error) => Err(BackupControlError::Io(error)),
    }
}

fn open_control_dir(data_dir_fd: &rustix::fd::OwnedFd) -> io::Result<rustix::fd::OwnedFd> {
    match openat(
        data_dir_fd,
        BACKUP_CONTROL_DIR,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(control_fd) => Ok(control_fd),
        Err(error) if error == rustix::io::Errno::NOENT => {
            // A directory cannot be created with openat(O_CREAT); mkdirat
            // honors the umask-explicit mode.
            match rustix::fs::mkdirat(
                data_dir_fd,
                BACKUP_CONTROL_DIR,
                Mode::from_raw_mode(CONTROL_DIR_MODE),
            ) {
                Ok(()) => {}
                // A concurrent creator won the race; open its directory and
                // validate it below.
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(error) => return Err(error.into()),
            }
            openat(
                data_dir_fd,
                BACKUP_CONTROL_DIR,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(io::Error::from)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_private_directory(stat: &rustix::fs::Stat, description: &str) -> io::Result<()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} is not a directory"),
        ));
    }
    if stat.st_uid != geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} is not owned by the effective uid"),
        ));
    }
    if stat.st_mode & PUBLIC_WRITABLE_MASK != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} must not be group/other writable"),
        ));
    }
    Ok(())
}

fn resolve_socket_path(data_dir: &Path) -> Result<PathBuf, BackupControlError> {
    let dir_fd = open(
        data_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| BackupControlError::Io(error.into()))?;
    let dir_stat =
        rustix::fs::fstat(&dir_fd).map_err(|error| BackupControlError::Io(error.into()))?;
    validate_private_directory(&dir_stat, "O3K data directory").map_err(BackupControlError::Io)?;
    let control_fd = open_control_dir(&dir_fd).map_err(BackupControlError::Io)?;
    let control_stat =
        rustix::fs::fstat(&control_fd).map_err(|error| BackupControlError::Io(error.into()))?;
    validate_private_directory(&control_stat, "O3K backup control directory")
        .map_err(BackupControlError::Io)?;
    let socket = statat(
        &control_fd,
        BACKUP_CONTROL_SOCKET,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| BackupControlError::Io(error.into()))?;
    if FileType::from_raw_mode(socket.st_mode) != FileType::Socket {
        return Err(BackupControlError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "backup control path is not a socket",
        )));
    }
    Ok(data_dir
        .join(BACKUP_CONTROL_DIR)
        .join(BACKUP_CONTROL_SOCKET))
}

/// Waits for the next pending connection until `deadline`.
fn accept_pending(
    listener: &UnixListener,
    deadline: Instant,
) -> Result<(UnixStream, std::os::unix::net::SocketAddr), BackupControlError> {
    loop {
        match listener.accept() {
            Ok(accepted) => return Ok(accepted),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(BackupControlError::Io(error)),
        }
        if Instant::now() >= deadline {
            return Err(BackupControlError::Timeout);
        }
        thread::sleep(LISTENER_POLL_INTERVAL);
    }
}

struct ProcIdentity {
    exe: PathBuf,
    exe_dev: u64,
    exe_ino: u64,
    uid: u32,
    start_time_ticks: u64,
}

fn read_process_identity(pid: u32) -> io::Result<ProcIdentity> {
    let (exe, exe_dev, exe_ino) = read_process_exe(pid)?;
    let uid = read_process_effective_uid(pid)?;
    let start_time_ticks = read_process_start_time(pid)?;
    Ok(ProcIdentity {
        exe,
        exe_dev,
        exe_ino,
        uid,
        start_time_ticks,
    })
}

fn read_process_exe(pid: u32) -> io::Result<(PathBuf, u64, u64)> {
    let proc_exe = format!("/proc/{pid}/exe");
    let target = fs::read_link(&proc_exe)?;
    let text = target.to_string_lossy();
    // A deleted executable fails closed: acceptance must bind to a live
    // binary on disk, and the readlink suffix is the kernel's own signal
    // that the executable inode was unlinked after exec.
    if text.ends_with(" (deleted)") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer executable was deleted after exec",
        ));
    }
    // `metadata` on the magic link follows it into the peer's mount
    // namespace and stats the REAL executable inode; identity is decided by
    // comparing dev+ino with the expected executor's inode (path comparison
    // alone compares a path with itself across namespaces).
    let metadata = fs::metadata(&proc_exe)?;
    let canonical = fs::canonicalize(&proc_exe)?;
    Ok((canonical, metadata.dev(), metadata.ino()))
}

/// Parses the effective uid (second field) of the `Uid:` line of
/// `/proc/<pid>/status`.
fn read_process_effective_uid(pid: u32) -> io::Result<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    for line in status.lines() {
        let Some(fields) = line.strip_prefix("Uid:") else {
            continue;
        };
        let effective = fields
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| invalid_stat("effective uid field is missing"))?;
        return effective
            .parse::<u32>()
            .map_err(|_| invalid_stat("effective uid field is not numeric"));
    }
    Err(invalid_stat("Uid line is missing"))
}

fn read_process_start_time(pid: u32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_start_time_ticks(&stat)
}

/// Parses field 22 (starttime) of `/proc/<pid>/stat`. `comm` may contain
/// spaces and parentheses, so parsing happens after the LAST `)`: the first
/// whitespace-separated token after it is field 3, making starttime token
/// index 19.
fn parse_start_time_ticks(stat: &str) -> io::Result<u64> {
    let Some(close) = stat.rfind(')') else {
        return Err(invalid_stat("missing comm terminator"));
    };
    let mut fields = stat[close + 1..].split_whitespace();
    let Some(start_time) = fields.nth(19) else {
        return Err(invalid_stat("starttime field is missing"));
    };
    start_time
        .parse::<u64>()
        .map_err(|_| invalid_stat("starttime field is not numeric"))
}

fn invalid_stat(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Decides executable identity by device+inode: the peer's real executable
/// inode (observed through the `/proc/<pid>/exe` magic link, i.e. in the
/// peer's own mount namespace) must be the same file as the expected
/// executor's inode.
fn executable_matches(identity: &ProcIdentity, expected_exe: &Path) -> io::Result<bool> {
    let expected_stat = fs::metadata(expected_exe)?;
    Ok(identity.exe_dev == expected_stat.dev() && identity.exe_ino == expected_stat.ino())
}

enum FrameReadError {
    TimedOut,
    Truncated,
    Io(io::Error),
}

/// Reads the request frame with a shrinking absolute deadline: the read
/// timeout is recomputed before EVERY read syscall, so a drip-feeding peer
/// cannot stretch the exchange to one timeout per byte.
fn read_request_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<[u8; REQUEST_FRAME_LEN], FrameReadError> {
    let mut frame = [0_u8; REQUEST_FRAME_LEN];
    let mut offset = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(FrameReadError::TimedOut);
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(FrameReadError::Io)?;
        match stream.read(&mut frame[offset..]) {
            Ok(0) => return Err(FrameReadError::Truncated),
            Ok(read) => {
                offset += read;
                if offset == frame.len() {
                    return Ok(frame);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(FrameReadError::TimedOut);
            }
            Err(error) => return Err(FrameReadError::Io(error)),
        }
    }
}

/// Reads the response frame with a shrinking absolute deadline (see
/// [`read_request_frame`]).
fn read_response_frame(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<[u8; RESPONSE_FRAME_LEN], FrameReadError> {
    let mut response = [0_u8; RESPONSE_FRAME_LEN];
    let mut offset = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(FrameReadError::TimedOut);
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(FrameReadError::Io)?;
        match stream.read(&mut response[offset..]) {
            Ok(0) => return Err(FrameReadError::Truncated),
            Ok(read) => {
                offset += read;
                if offset == response.len() {
                    return Ok(response);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(FrameReadError::TimedOut);
            }
            Err(error) => return Err(FrameReadError::Io(error)),
        }
    }
}

struct ParsedRequest {
    operation_id: [u8; 16],
    installation: [u8; 16],
    site: [u8; 16],
}

fn parse_request(frame: &[u8; REQUEST_FRAME_LEN]) -> Result<ParsedRequest, HandoffRejectReason> {
    if &frame[..REQUEST_MAGIC.len()] != REQUEST_MAGIC {
        return Err(HandoffRejectReason::Malformed);
    }
    if frame[REQUEST_MAGIC.len()] != PROTOCOL_VERSION {
        return Err(HandoffRejectReason::Malformed);
    }
    if frame[57..].iter().any(|byte| *byte != 0) {
        return Err(HandoffRejectReason::Malformed);
    }
    let mut operation_id = [0_u8; 16];
    operation_id.copy_from_slice(&frame[9..25]);
    let mut installation = [0_u8; 16];
    installation.copy_from_slice(&frame[25..41]);
    let mut site = [0_u8; 16];
    site.copy_from_slice(&frame[41..57]);
    Ok(ParsedRequest {
        operation_id,
        installation,
        site,
    })
}

/// Writes `buffer` with a shrinking absolute deadline: the write timeout is
/// recomputed before EVERY write syscall (mirroring the frame readers), so a
/// drip-reading peer cannot stretch the exchange to one timeout per byte.
fn write_all_bounded(stream: &mut UnixStream, buffer: &[u8], timeout: Duration) -> io::Result<()> {
    let previous = stream.write_timeout()?;
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup control timeout is too large",
        )
    })?;
    let result = (|| {
        let mut offset = 0;
        while offset < buffer.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "backup control write timed out",
                ));
            }
            stream.set_write_timeout(Some(remaining))?;
            match stream.write(&buffer[offset..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "backup control write wrote zero bytes",
                    ));
                }
                Ok(written) => offset += written,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    })();
    let restore_result = stream.set_write_timeout(previous);
    result?;
    restore_result
}

fn reject_stream(stream: &mut UnixStream, reason: HandoffRejectReason) {
    reject_stream_with_timeout(stream, reason, REJECT_FRAME_TIMEOUT);
}

fn reject_stream_with_timeout(
    stream: &mut UnixStream,
    reason: HandoffRejectReason,
    timeout: Duration,
) {
    let mut frame = [0_u8; RESPONSE_FRAME_LEN];
    frame[..REJECT_MAGIC.len()].copy_from_slice(REJECT_MAGIC);
    frame[REJECT_MAGIC.len()] = reason.reason_byte();
    // Best effort: the peer may already be gone; the connection closes when
    // the stream is dropped regardless.
    let _ = write_all_bounded(stream, &frame, timeout);
}

/// Best-effort in-band `AlreadyActive` rejection (bounded to
/// [`ALREADY_ACTIVE_REJECT_TIMEOUT`]) for a connection that arrives after the
/// single authenticated attempt has been accepted: the concurrent executor
/// learns the backup slot is taken (exit 2) instead of waiting out its own
/// request timeout.
pub fn reject_already_active(stream: &mut UnixStream) {
    reject_stream_with_timeout(
        stream,
        HandoffRejectReason::AlreadyActive,
        ALREADY_ACTIVE_REJECT_TIMEOUT,
    );
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use super::*;

    static NEXT_DIR_ID: AtomicU64 = AtomicU64::new(1);

    struct TestDataDir(PathBuf);

    impl TestDataDir {
        fn new() -> io::Result<Self> {
            let suffix = NEXT_DIR_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "o3k-backup-control-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            Ok(Self(path))
        }

        fn socket_path(&self) -> PathBuf {
            self.0.join(BACKUP_CONTROL_DIR).join(BACKUP_CONTROL_SOCKET)
        }
    }

    impl Drop for TestDataDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn current_uid() -> u32 {
        geteuid().as_raw()
    }

    fn expected_for_current_process(
        data_dir: &Path,
    ) -> io::Result<(ExpectedExecutor, BackupHandoffRequest)> {
        let (installation, site) = identity_tokens(data_dir)?;
        Ok((
            ExpectedExecutor {
                exe: std::env::current_exe()?,
                uid: current_uid(),
                installation,
                site,
            },
            BackupHandoffRequest {
                operation_id: Uuid::new_v4(),
                installation,
                site,
            },
        ))
    }

    fn client_request(
        data_dir: &Path,
        request: BackupHandoffRequest,
    ) -> Result<UnixStream, BackupControlError> {
        connect_and_request(data_dir, &request, Duration::from_secs(5))
    }

    fn join_client(
        join: thread::Result<Result<UnixStream, BackupControlError>>,
    ) -> io::Result<UnixStream> {
        join.map_err(|_| io::Error::other("client thread panicked"))?
            .map_err(|error| io::Error::other(error.to_string()))
    }

    fn expect_rejected(
        result: Result<UnixStream, BackupControlError>,
        reason: HandoffRejectReason,
    ) -> io::Result<()> {
        match result {
            Err(BackupControlError::Rejected(actual)) if actual == reason => Ok(()),
            other => Err(io::Error::other(format!(
                "expected rejection {reason:?}, got {other:?}"
            ))),
        }
    }

    /// Writes a raw 64-byte frame directly (bypassing `connect_and_request`)
    /// and returns the 8-byte response frame.
    fn raw_frame_exchange(
        data_dir: &Path,
        frame: &[u8; REQUEST_FRAME_LEN],
    ) -> io::Result<[u8; RESPONSE_FRAME_LEN]> {
        let mut stream = UnixStream::connect(
            data_dir
                .join(BACKUP_CONTROL_DIR)
                .join(BACKUP_CONTROL_SOCKET),
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(frame)?;
        let mut response = [0_u8; RESPONSE_FRAME_LEN];
        stream.read_exact(&mut response)?;
        Ok(response)
    }

    fn reject_frame_matches(response: &[u8; RESPONSE_FRAME_LEN], reason: HandoffRejectReason) {
        assert_eq!(&response[..REJECT_MAGIC.len()], &REJECT_MAGIC[..]);
        assert_eq!(response[REJECT_MAGIC.len()], reason.reason_byte());
    }

    #[test]
    fn reason_bytes_round_trip() {
        for reason in [
            HandoffRejectReason::UnauthorizedPeer,
            HandoffRejectReason::Malformed,
            HandoffRejectReason::DuplicateOperation,
            HandoffRejectReason::AlreadyActive,
            HandoffRejectReason::IdentityMismatch,
            HandoffRejectReason::DrainFailed,
        ] {
            let byte = reason.reason_byte();
            assert_eq!(HandoffRejectReason::from_reason_byte(byte), Some(reason));
        }
        assert_eq!(HandoffRejectReason::from_reason_byte(0), None);
        assert_eq!(HandoffRejectReason::from_reason_byte(7), None);
    }

    #[test]
    fn token_derivation_is_deterministic_and_domain_separated() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let first_installation = installation_token(&root.0)?;
        let second_installation = installation_token(&root.0)?;
        let site = site_token(&root.0)?;
        assert_eq!(first_installation, second_installation);
        assert_ne!(first_installation, site);
        Ok(())
    }

    #[test]
    fn daemon_peer_requires_the_expected_uid_and_executable() -> io::Result<()> {
        let (stream, _peer) = UnixStream::pair()?;
        let uid = geteuid().as_raw();
        let current_exe = fs::canonicalize(std::env::current_exe()?)?;
        verify_daemon_peer(&stream, &current_exe, uid)
            .map_err(|_| io::Error::other("matching daemon identity was rejected"))?;

        let wrong_uid = uid.wrapping_add(1);
        assert!(matches!(
            verify_daemon_peer(&stream, &current_exe, wrong_uid),
            Err(BackupControlError::Unauthorized)
        ));

        // A different executable inode is rejected even with the right uid:
        // this is the fake-handoff-server case.
        let mut candidates = ["/bin/sh", "/usr/bin/env", "/lib/systemd/systemd"]
            .into_iter()
            .filter(|path| fs::metadata(path).is_ok());
        let other = candidates
            .next()
            .ok_or_else(|| io::Error::other("no alternative executable for the test"))?;
        let other = fs::canonicalize(other)?;
        if fs::metadata(&other)?.ino() != fs::metadata(&current_exe)?.ino() {
            assert!(matches!(
                verify_daemon_peer(&stream, &other, uid),
                Err(BackupControlError::Unauthorized)
            ));
        }
        Ok(())
    }

    #[test]
    fn roundtrip_accept_with_correct_peer() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let listener = BackupControlListener::bind(&root.0)?;
        assert_eq!(
            fs::metadata(root.0.join(BACKUP_CONTROL_DIR))?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.socket_path())?.permissions().mode() & 0o777,
            0o600
        );

        let (expected, request) = expected_for_current_process(&root.0)?;
        let data_dir = root.0.clone();
        let client = thread::spawn(move || client_request(&data_dir, request));
        let mut accepted = listener
            .accept_authenticated(&expected, Duration::from_secs(5))
            .map_err(io::Error::other)?;
        assert_eq!(accepted.operation_id, *request.operation_id.as_bytes());
        assert_eq!(accepted.peer.uid, current_uid());
        assert_eq!(
            accepted.peer.exe,
            fs::canonicalize(std::env::current_exe()?)?
        );
        accepted.revalidate_peer().map_err(io::Error::other)?;
        accepted.send_accept()?;
        let stream = join_client(client.join())?;
        // The accepted stream is the same connection the client holds: after
        // the acceptance frame it is ready for the `O3KLOCK1` handoff frame.
        drop(stream);
        drop(accepted);
        Ok(())
    }

    #[test]
    fn rejects_wrong_magic() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let listener = BackupControlListener::bind(&root.0)?;
        let (expected, _) = expected_for_current_process(&root.0)?;
        let mut frame = [0_u8; REQUEST_FRAME_LEN];
        frame[..8].copy_from_slice(b"BADMAGIC");
        let client = thread::spawn(move || raw_frame_exchange(&root.0, &frame));
        match listener.accept_authenticated(&expected, Duration::from_secs(5)) {
            Err(BackupControlError::Rejected(HandoffRejectReason::Malformed)) => {}
            other => return Err(io::Error::other(format!("wrong magic accepted: {other:?}"))),
        }
        let response = client
            .join()
            .map_err(|_| io::Error::other("client thread panicked"))??;
        reject_frame_matches(&response, HandoffRejectReason::Malformed);
        Ok(())
    }

    #[test]
    fn rejects_bad_version_and_nonzero_reserved() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let (expected, request) = expected_for_current_process(&root.0)?;

        let listener = BackupControlListener::bind(&root.0)?;
        let mut bad_version = request.encode();
        bad_version[8] = 2;
        let data_dir = root.0.clone();
        let client = thread::spawn(move || raw_frame_exchange(&data_dir, &bad_version));
        match listener.accept_authenticated(&expected, Duration::from_secs(5)) {
            Err(BackupControlError::Rejected(HandoffRejectReason::Malformed)) => {}
            other => return Err(io::Error::other(format!("bad version accepted: {other:?}"))),
        }
        reject_frame_matches(
            &client
                .join()
                .map_err(|_| io::Error::other("client thread panicked"))??,
            HandoffRejectReason::Malformed,
        );
        drop(listener);

        let listener = BackupControlListener::bind(&root.0)?;
        let mut nonzero_reserved = request.encode();
        nonzero_reserved[63] = 1;
        let data_dir = root.0.clone();
        let client = thread::spawn(move || raw_frame_exchange(&data_dir, &nonzero_reserved));
        match listener.accept_authenticated(&expected, Duration::from_secs(5)) {
            Err(BackupControlError::Rejected(HandoffRejectReason::Malformed)) => {}
            other => {
                return Err(io::Error::other(format!(
                    "nonzero reserved accepted: {other:?}"
                )));
            }
        }
        reject_frame_matches(
            &client
                .join()
                .map_err(|_| io::Error::other("client thread panicked"))??,
            HandoffRejectReason::Malformed,
        );
        Ok(())
    }

    #[test]
    fn rejects_short_frame() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let listener = BackupControlListener::bind(&root.0)?;
        let (expected, _) = expected_for_current_process(&root.0)?;
        let socket_path = root.socket_path();
        let client = thread::spawn(move || -> io::Result<()> {
            let mut stream = UnixStream::connect(socket_path)?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            stream.write_all(&[0_u8; 16])?;
            Ok(())
        });
        match listener.accept_authenticated(&expected, Duration::from_secs(5)) {
            Err(BackupControlError::Rejected(HandoffRejectReason::Malformed)) => {}
            other => return Err(io::Error::other(format!("short frame accepted: {other:?}"))),
        }
        client
            .join()
            .map_err(|_| io::Error::other("client thread panicked"))??;
        Ok(())
    }

    #[test]
    fn rejects_wrong_installation_or_site_token() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let (expected, request) = expected_for_current_process(&root.0)?;

        let listener = BackupControlListener::bind(&root.0)?;
        let mut wrong_installation = request;
        wrong_installation.installation[0] ^= 0xff;
        let data_dir = root.0.clone();
        let client = thread::spawn(move || client_request(&data_dir, wrong_installation));
        match listener.accept_authenticated(&expected, Duration::from_secs(5)) {
            Err(BackupControlError::Rejected(HandoffRejectReason::IdentityMismatch)) => {}
            other => {
                return Err(io::Error::other(format!(
                    "wrong installation token accepted: {other:?}"
                )));
            }
        }
        expect_rejected(
            client
                .join()
                .map_err(|_| io::Error::other("client thread panicked"))?,
            HandoffRejectReason::IdentityMismatch,
        )?;
        drop(listener);

        let listener = BackupControlListener::bind(&root.0)?;
        let mut wrong_site = request;
        wrong_site.site[0] ^= 0xff;
        let data_dir = root.0.clone();
        let client = thread::spawn(move || client_request(&data_dir, wrong_site));
        match listener.accept_authenticated(&expected, Duration::from_secs(5)) {
            Err(BackupControlError::Rejected(HandoffRejectReason::IdentityMismatch)) => {}
            other => {
                return Err(io::Error::other(format!(
                    "wrong site token accepted: {other:?}"
                )));
            }
        }
        expect_rejected(
            client
                .join()
                .map_err(|_| io::Error::other("client thread panicked"))?,
            HandoffRejectReason::IdentityMismatch,
        )?;
        Ok(())
    }

    #[test]
    fn rejects_duplicate_operation_id() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let (expected, request) = expected_for_current_process(&root.0)?;
        let listener = BackupControlListener::bind(&root.0)?;

        let data_dir = root.0.clone();
        let first_client = thread::spawn(move || client_request(&data_dir, request));
        let mut accepted = listener
            .accept_authenticated(&expected, Duration::from_secs(5))
            .map_err(io::Error::other)?;
        accepted.send_accept()?;
        let stream = join_client(first_client.join())?;
        drop(stream);
        // Completing the first attempt releases the single-attempt slot, but
        // the operation UUID remains recorded.
        drop(accepted);

        let data_dir = root.0.clone();
        let second_client = thread::spawn(move || client_request(&data_dir, request));
        match listener.accept_authenticated(&expected, Duration::from_secs(5)) {
            Err(BackupControlError::Rejected(HandoffRejectReason::DuplicateOperation)) => {}
            other => {
                return Err(io::Error::other(format!(
                    "duplicate operation was accepted: {other:?}"
                )));
            }
        }
        expect_rejected(
            second_client
                .join()
                .map_err(|_| io::Error::other("client thread panicked"))?,
            HandoffRejectReason::DuplicateOperation,
        )?;
        Ok(())
    }

    #[test]
    fn rejects_second_attempt_while_one_is_active() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let (expected, first_request) = expected_for_current_process(&root.0)?;
        let listener = BackupControlListener::bind(&root.0)?;

        let data_dir = root.0.clone();
        let first_client = thread::spawn(move || client_request(&data_dir, first_request));
        let mut accepted = listener
            .accept_authenticated(&expected, Duration::from_secs(5))
            .map_err(io::Error::other)?;
        // The first client stays blocked on the acceptance response until the
        // active attempt below is released.

        // A queued second connection must not unstick the active attempt.
        let data_dir = root.0.clone();
        let (_, second_request) = expected_for_current_process(&data_dir)?;
        let second_operation = second_request.operation_id;
        let second_client = thread::spawn(move || client_request(&data_dir, second_request));
        thread::sleep(Duration::from_millis(50));
        match listener.accept_authenticated(&expected, Duration::from_millis(200)) {
            Err(BackupControlError::AlreadyActive) => {}
            other => {
                return Err(io::Error::other(format!(
                    "second accept while active was not rejected: {other:?}"
                )));
            }
        }

        // Releasing the first attempt unblocks the queued connection, which a
        // fresh accept then services.
        accepted.send_accept()?;
        drop(accepted);
        let first_stream = join_client(first_client.join())?;
        drop(first_stream);
        let mut second = listener
            .accept_authenticated(&expected, Duration::from_secs(5))
            .map_err(io::Error::other)?;
        assert_eq!(second.operation_id, *second_operation.as_bytes());
        second.send_accept()?;
        drop(second);
        let stream = join_client(second_client.join())?;
        drop(stream);
        Ok(())
    }

    #[test]
    fn rejects_peer_with_wrong_executable() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let (mut expected, request) = expected_for_current_process(&root.0)?;
        let impostor = ["/bin/false", "/usr/bin/false", "/bin/true"]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
            .ok_or_else(|| io::Error::other("no known executable available for impostor test"))?;
        expected.exe = impostor;
        let listener = BackupControlListener::bind(&root.0)?;
        let data_dir = root.0.clone();
        let client = thread::spawn(move || client_request(&data_dir, request));
        match listener.accept_authenticated(&expected, Duration::from_secs(5)) {
            Err(BackupControlError::Rejected(HandoffRejectReason::UnauthorizedPeer)) => {}
            other => {
                return Err(io::Error::other(format!(
                    "wrong executable was accepted: {other:?}"
                )));
            }
        }
        expect_rejected(
            client
                .join()
                .map_err(|_| io::Error::other("client thread panicked"))?,
            HandoffRejectReason::UnauthorizedPeer,
        )?;
        Ok(())
    }

    #[test]
    fn accept_times_out_when_nobody_connects() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let listener = BackupControlListener::bind(&root.0)?;
        let (expected, _) = expected_for_current_process(&root.0)?;
        match listener.accept_authenticated(&expected, Duration::from_millis(150)) {
            Err(BackupControlError::Timeout) => Ok(()),
            other => Err(io::Error::other(format!(
                "expected timeout with no peer, got {other:?}"
            ))),
        }
    }

    #[test]
    fn zero_timeouts_are_rejected() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let listener = BackupControlListener::bind(&root.0)?;
        let (expected, request) = expected_for_current_process(&root.0)?;
        match listener.accept_authenticated(&expected, Duration::ZERO) {
            Err(BackupControlError::InvalidInput) => {}
            other => {
                return Err(io::Error::other(format!(
                    "zero accept timeout was not rejected: {other:?}"
                )));
            }
        }
        match connect_and_request(&root.0, &request, Duration::ZERO) {
            Err(BackupControlError::InvalidInput) => Ok(()),
            other => Err(io::Error::other(format!(
                "zero connect timeout was not rejected: {other:?}"
            ))),
        }
    }

    #[test]
    fn stale_socket_file_is_replaced_at_bind() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let control_dir = root.0.join(BACKUP_CONTROL_DIR);
        fs::create_dir(&control_dir)?;
        fs::set_permissions(&control_dir, fs::Permissions::from_mode(0o700))?;
        let stale = UnixListener::bind(root.socket_path())?;
        drop(stale);
        let listener = BackupControlListener::bind(&root.0)?;
        let (expected, request) = expected_for_current_process(&root.0)?;
        let data_dir = root.0.clone();
        let client = thread::spawn(move || client_request(&data_dir, request));
        let mut accepted = listener
            .accept_authenticated(&expected, Duration::from_secs(5))
            .map_err(io::Error::other)?;
        accepted.send_accept()?;
        let stream = join_client(client.join())?;
        drop(stream);
        drop(accepted);
        Ok(())
    }

    #[test]
    fn bind_refuses_non_socket_at_socket_path() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let control_dir = root.0.join(BACKUP_CONTROL_DIR);
        fs::create_dir(&control_dir)?;
        fs::set_permissions(&control_dir, fs::Permissions::from_mode(0o700))?;
        fs::write(root.socket_path(), b"attacker")?;
        match BackupControlListener::bind(&root.0) {
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {}
            other => {
                return Err(io::Error::other(format!(
                    "non-socket socket path was not refused: {other:?}"
                )));
            }
        }

        fs::remove_file(root.socket_path())?;
        let target = root.0.join("elsewhere");
        fs::write(&target, b"elsewhere")?;
        symlink(&target, root.socket_path())?;
        match BackupControlListener::bind(&root.0) {
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {}
            other => {
                return Err(io::Error::other(format!(
                    "symlink socket path was not refused: {other:?}"
                )));
            }
        }
        Ok(())
    }

    #[test]
    fn bind_refuses_foreign_control_directory() -> io::Result<()> {
        let root = TestDataDir::new()?;
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777))?;
        match BackupControlListener::bind(&root.0) {
            Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(()),
            other => Err(io::Error::other(format!(
                "group/other writable data directory was not refused: {other:?}"
            ))),
        }
    }

    #[test]
    fn revalidate_detects_dead_peer() -> io::Result<()> {
        let sleep_path = ["/bin/sleep", "/usr/bin/sleep"]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
            .ok_or_else(|| io::Error::other("no sleep executable available for test"))?;
        let canonical_sleep = fs::canonicalize(&sleep_path)?;
        let mut child = Command::new(sleep_path).arg("60").spawn()?;
        let pid = child.id();
        // spawn() returns before the child's execve completes; wait until
        // /proc/<pid>/exe reflects the sleep binary before recording the
        // identity, otherwise revalidation would observe an exe change.
        let identity = loop {
            match read_process_identity(pid) {
                Ok(identity) if identity.exe == canonical_sleep => break identity,
                Ok(_) => {}
                Err(_) => {}
            }
            if let Some(status) = child.try_wait()? {
                let _ = child.wait();
                return Err(io::Error::other(format!(
                    "sleep child exited before exec settled: {status}"
                )));
            }
            thread::sleep(Duration::from_millis(5));
        };
        let peer = PeerIdentity {
            pid,
            uid: current_uid(),
            gid: 0,
            exe: identity.exe,
            exe_dev: identity.exe_dev,
            exe_ino: identity.exe_ino,
            start_time_ticks: identity.start_time_ticks,
        };
        let accepted = accepted_request_for(peer)?;
        accepted.revalidate_peer().map_err(io::Error::other)?;
        child.kill()?;
        child.wait()?;
        match accepted.revalidate_peer() {
            Err(BackupControlError::PeerChanged) => Ok(()),
            other => Err(io::Error::other(format!(
                "dead peer revalidated successfully: {other:?}"
            ))),
        }
    }

    fn accepted_request_for(peer: PeerIdentity) -> io::Result<AcceptedBackupRequest> {
        let (pair_left, _pair_right) = UnixStream::pair()?;
        let shared = Arc::new(ListenerShared {
            state: AtomicU8::new(STATE_IDLE),
            accepted_operations: Mutex::new(Vec::new()),
        });
        Ok(AcceptedBackupRequest {
            operation_id: [7_u8; 16],
            stream: pair_left,
            peer,
            shared,
        })
    }

    /// Spawns `sleep 60` and waits until its procfs identity settles on the
    /// sleep executable, returning the child and its recorded identity.
    fn spawn_settled_sleep() -> io::Result<(std::process::Child, ProcIdentity)> {
        let sleep_path = ["/bin/sleep", "/usr/bin/sleep"]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
            .ok_or_else(|| io::Error::other("no sleep executable available for test"))?;
        let canonical_sleep = fs::canonicalize(&sleep_path)?;
        let mut child = Command::new(sleep_path).arg("60").spawn()?;
        let pid = child.id();
        let identity = loop {
            match read_process_identity(pid) {
                Ok(identity) if identity.exe == canonical_sleep => break identity,
                Ok(_) => {}
                Err(_) => {}
            }
            if let Some(status) = child.try_wait()? {
                let _ = child.wait();
                return Err(io::Error::other(format!(
                    "sleep child exited before exec settled: {status}"
                )));
            }
            thread::sleep(Duration::from_millis(5));
        };
        Ok((child, identity))
    }

    #[test]
    fn revalidate_detects_changed_executable_inode_and_uid() -> io::Result<()> {
        let (mut child, identity) = spawn_settled_sleep()?;
        let base = PeerIdentity {
            pid: child.id(),
            uid: current_uid(),
            gid: 0,
            exe: identity.exe.clone(),
            exe_dev: identity.exe_dev,
            exe_ino: identity.exe_ino,
            start_time_ticks: identity.start_time_ticks,
        };
        // The live child revalidates cleanly.
        accepted_request_for(base.clone())?
            .revalidate_peer()
            .map_err(io::Error::other)?;
        // A recorded executable inode that no longer matches the live
        // process (the file was replaced under the same path) fails closed.
        let mut swapped_inode = base.clone();
        swapped_inode.exe_ino ^= 1;
        match accepted_request_for(swapped_inode)?.revalidate_peer() {
            Err(BackupControlError::Unauthorized) => {}
            other => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other(format!(
                    "swapped executable inode revalidated successfully: {other:?}"
                )));
            }
        }
        // A recorded uid that no longer matches the live process fails closed.
        let mut swapped_uid = base;
        swapped_uid.uid ^= 1;
        match accepted_request_for(swapped_uid)?.revalidate_peer() {
            Err(BackupControlError::Unauthorized) => {}
            other => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other(format!(
                    "swapped uid revalidated successfully: {other:?}"
                )));
            }
        }
        child.kill()?;
        child.wait()?;
        Ok(())
    }

    #[test]
    fn deleted_executable_identity_fails_closed() -> io::Result<()> {
        let sleep_path = ["/bin/sleep", "/usr/bin/sleep"]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
            .ok_or_else(|| io::Error::other("no sleep executable available for test"))?;
        let root = TestDataDir::new()?;
        let copy = root.0.join("sleep-copy");
        fs::copy(&sleep_path, &copy)?;
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o700))?;
        let mut child = Command::new(&copy).arg("60").spawn()?;
        let pid = child.id();
        let canonical = fs::canonicalize(&copy)?;
        loop {
            match read_process_identity(pid) {
                Ok(identity) if identity.exe == canonical => break,
                Ok(_) => {}
                Err(_) => {}
            }
            if let Some(status) = child.try_wait()? {
                let _ = child.wait();
                return Err(io::Error::other(format!(
                    "sleep copy exited before exec settled: {status}"
                )));
            }
            thread::sleep(Duration::from_millis(5));
        }
        fs::remove_file(&copy)?;
        // The unlinked executable must fail closed: the peer can no longer be
        // bound to a live binary on disk, so neither identity recording nor
        // revalidation may succeed.
        match read_process_identity(pid) {
            Err(_) => {}
            Ok(identity) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other(format!(
                    "deleted executable was still identified: {}",
                    identity.exe.display()
                )));
            }
        }
        child.kill()?;
        child.wait()?;
        Ok(())
    }

    #[test]
    fn executable_identity_matches_by_inode_not_path() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let original = root.0.join("executor-a");
        fs::write(&original, b"binary-a")?;
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700))?;
        let alias = root.0.join("executor-a-alias");
        fs::hard_link(&original, &alias)?;
        let other = root.0.join("executor-b");
        fs::write(&other, b"binary-b")?;
        let stat_a = fs::metadata(&original)?;
        let identity = ProcIdentity {
            exe: fs::canonicalize(&original)?,
            exe_dev: stat_a.dev(),
            exe_ino: stat_a.ino(),
            uid: current_uid(),
            start_time_ticks: 0,
        };
        assert!(executable_matches(&identity, &original)?);
        // A hardlink alias resolves to the same inode: same binary, even
        // though the path differs.
        assert!(executable_matches(&identity, &alias)?);
        // A different file can never match on path alone.
        assert!(!executable_matches(&identity, &other)?);
        Ok(())
    }

    #[test]
    fn drip_fed_request_frame_times_out_at_deadline() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let listener = BackupControlListener::bind(&root.0)?;
        let (expected, _) = expected_for_current_process(&root.0)?;
        let socket_path = root.socket_path();
        let client = thread::spawn(move || {
            let Ok(mut stream) = UnixStream::connect(socket_path) else {
                return;
            };
            // One byte per 200ms: a per-read timeout fixed at the start of
            // the read loop would let this drip for ~13s; the shrinking
            // deadline must cut it at ~1s.
            for byte in 0..REQUEST_FRAME_LEN as u8 {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(200));
            }
        });
        let started = std::time::Instant::now();
        match listener.accept_authenticated(&expected, Duration::from_secs(1)) {
            Err(BackupControlError::Timeout) => {}
            other => {
                client
                    .join()
                    .map_err(|_| io::Error::other("client thread panicked"))?;
                return Err(io::Error::other(format!(
                    "drip-fed frame was not timed out: {other:?}"
                )));
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "drip-fed frame was not bounded by the absolute deadline"
        );
        client
            .join()
            .map_err(|_| io::Error::other("client thread panicked"))?;
        Ok(())
    }

    #[test]
    fn post_accept_connection_gets_in_band_already_active_rejection() -> io::Result<()> {
        let root = TestDataDir::new()?;
        let listener = BackupControlListener::bind(&root.0)?;
        let (expected, request) = expected_for_current_process(&root.0)?;
        let data_dir = root.0.clone();
        let client = thread::spawn(move || client_request(&data_dir, request));
        let mut accepted = listener
            .accept_authenticated(&expected, Duration::from_secs(5))
            .map_err(io::Error::other)?;
        accepted.send_accept()?;
        let stream = join_client(client.join())?;
        drop(stream);
        // A connector arriving after the accepted request is taken by
        // `accept_raw` and answered with the in-band AlreadyActive frame
        // (the daemon's post-accept loop behavior).
        let mut late = UnixStream::connect(root.socket_path())?;
        let mut served = listener
            .accept_raw(Duration::from_secs(5))
            .map_err(io::Error::other)?;
        reject_already_active(&mut served);
        drop(served);
        late.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut response = [0_u8; RESPONSE_FRAME_LEN];
        late.read_exact(&mut response)?;
        reject_frame_matches(&response, HandoffRejectReason::AlreadyActive);
        Ok(())
    }

    #[test]
    fn parses_start_time_after_last_paren() -> io::Result<()> {
        // comm contains spaces and parentheses; field 22 must still parse.
        let stat =
            "123 (weird (name) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 999 20";
        assert_eq!(parse_start_time_ticks(stat)?, 999);
        match parse_start_time_ticks("123 (no terminator") {
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {}
            other => {
                return Err(io::Error::other(format!(
                    "unterminated stat was not rejected: {other:?}"
                )));
            }
        }
        Ok(())
    }
}
