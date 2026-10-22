//! Authenticated backup handoff control wiring (PP.6, ADR-0189 D4/D8).
//!
//! Owns the daemon side of the private backup control channel: a dedicated
//! std thread accepts and authenticates at most one executor request for the
//! daemon lifetime, then forwards it to the async main flow over an unbounded
//! channel and triggers the same graceful shutdown as an OS signal. The
//! thread deliberately is not a composition-owned tokio task: it performs no
//! canonical writes and must not be aborted/joined by the writer drain.

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use o3k_store::{
    AcceptedBackupRequest, BackupControlError, BackupControlListener, ExpectedExecutor,
    HandoffRejectReason,
};
use tracing::{info, warn};
use uuid::Uuid;

/// How long one accept attempt waits for a connection before re-arming. Long
/// enough that an idle daemon is not woken for the life of the process, yet
/// bounded so the loop can never block forever inside a single accept call.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(3600);
/// Grace period for the accepted request to appear on the channel after the
/// shutdown notify fired. The accept thread always sends before notifying, so
/// this only covers a scheduler race.
const ACCEPTED_FORWARD_GRACE: Duration = Duration::from_secs(5);

/// Handle for the optional backup control channel.
pub struct BackupControl {
    accepted_rx: tokio::sync::mpsc::UnboundedReceiver<AcceptedBackupRequest>,
    shutdown: Arc<tokio::sync::Notify>,
    requested: Arc<AtomicBool>,
}

impl BackupControl {
    /// The notify wired into the axum graceful-shutdown signal; firing it ends
    /// the serve exactly like SIGTERM.
    pub fn shutdown_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.shutdown)
    }

    /// Takes the authenticated request that triggered the shutdown, if a
    /// backup was requested. Returns immediately for an ordinary
    /// signal-only shutdown.
    pub async fn take_accepted(&mut self) -> Option<AcceptedBackupRequest> {
        if !self.requested.load(Ordering::SeqCst) {
            return None;
        }
        match tokio::time::timeout(ACCEPTED_FORWARD_GRACE, self.accepted_rx.recv()).await {
            Ok(request) => request,
            Err(_) => {
                tracing::error!(
                    "backup handoff was signalled but no accepted request arrived in time"
                );
                None
            }
        }
    }
}

/// Binds the backup control listener under `data_dir` and spawns the
/// dedicated accept thread. Returns `None` — backups disabled, ordinary
/// daemon operation unaffected — when the listener cannot be bound or the
/// accept thread cannot start.
pub fn start_backup_control(expected: &ExpectedExecutor, data_dir: &Path) -> Option<BackupControl> {
    let listener = match BackupControlListener::bind(data_dir) {
        Ok(listener) => listener,
        Err(error) => {
            warn!(%error, "backup control listener unavailable; backups disabled");
            return None;
        }
    };
    let (accepted_tx, accepted_rx) = tokio::sync::mpsc::unbounded_channel();
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let requested = Arc::new(AtomicBool::new(false));
    let thread_expected = expected.clone();
    let thread_shutdown = Arc::clone(&shutdown);
    let thread_requested = Arc::clone(&requested);
    if let Err(error) = std::thread::Builder::new()
        .name("o3kd-backup-control".to_owned())
        .spawn(move || {
            accept_loop(
                listener,
                thread_expected,
                accepted_tx,
                thread_shutdown,
                thread_requested,
            );
        })
    {
        warn!(%error, "backup control accept thread did not start; backups disabled");
        return None;
    }
    Some(BackupControl {
        accepted_rx,
        shutdown,
        requested,
    })
}

fn accept_loop(
    listener: BackupControlListener,
    expected: ExpectedExecutor,
    accepted_tx: tokio::sync::mpsc::UnboundedSender<AcceptedBackupRequest>,
    shutdown: Arc<tokio::sync::Notify>,
    requested: Arc<AtomicBool>,
) {
    loop {
        let mut accepted = match listener.accept_authenticated(&expected, ACCEPT_TIMEOUT) {
            Ok(accepted) => accepted,
            Err(BackupControlError::Timeout) => continue,
            Err(BackupControlError::AlreadyActive) => {
                // A successful accept leaves the listener active until process
                // exit and this thread returns, so this cannot recur; sleep so
                // an unexpected recurrence can never hot-spin.
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            Err(BackupControlError::Rejected(reason)) => {
                info!(
                    ?reason,
                    "backup handoff request rejected during authentication"
                );
                continue;
            }
            Err(error) => {
                warn!(%error, "backup control accept failed; continuing");
                continue;
            }
        };
        let operation_id = Uuid::from_bytes(accepted.operation_id);
        // Revalidate immediately before acceptance: the peer must still be the
        // same live process recorded at connect time (PID-reuse fail closed).
        if let Err(error) = accepted.revalidate_peer() {
            warn!(
                %error,
                %operation_id,
                peer_pid = accepted.peer.pid,
                "backup handoff peer revalidation failed; rejecting"
            );
            accepted.reject(HandoffRejectReason::UnauthorizedPeer);
            continue;
        }
        if let Err(error) = accepted.send_accept() {
            // The connection is almost certainly broken, so the rejection
            // frame is best-effort; the executor observes EOF/timeout.
            warn!(
                %error,
                %operation_id,
                peer_pid = accepted.peer.pid,
                "backup handoff acceptance frame failed; rejecting"
            );
            accepted.reject(HandoffRejectReason::UnauthorizedPeer);
            continue;
        }
        info!(
            %operation_id,
            peer_pid = accepted.peer.pid,
            peer_uid = accepted.peer.uid,
            "backup handoff request accepted; draining controller for lock transfer"
        );
        requested.store(true, Ordering::SeqCst);
        if accepted_tx.send(accepted).is_err() {
            // The receiver only drops as the daemon exits; the request dies
            // with the process and the executor sees EOF.
            warn!(%operation_id, "backup handoff request arrived after shutdown began; dropping it");
        }
        shutdown.notify_one();
        // One authenticated backup handoff per process lifetime: after a
        // successful accept the listener stays active until process exit, so
        // this thread has nothing more to do.
        return;
    }
}
