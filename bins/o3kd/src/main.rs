use o3kd::composition;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Hard bound on the API-serve connection drain once the shutdown signal
/// fires. A stalled client must not delay the authenticated backup handoff
/// past the executor's overall deadline; on expiry the serve future is
/// dropped, which closes the listener (axum 0.8 detaches connection tasks,
/// so stalled handlers keep running until process exit), and the bounded
/// writer drain begins either way.
const SERVE_DRAIN_BOUND: std::time::Duration = std::time::Duration::from_secs(15);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = o3k_config::Config::from_sources(std::env::args(), std::env::vars())?;
    let subscriber =
        tracing_subscriber::fmt().with_env_filter(EnvFilter::try_new(&config.log_filter)?);
    match config.log_format {
        o3k_config::LogFormat::Json => subscriber.json().init(),
        o3k_config::LogFormat::Pretty => subscriber.pretty().init(),
    }

    let listen_addr = config.listen_addr;
    let data_dir = config.data_dir.clone();
    let provider = config.provider;
    // Acquire the lifetime store guard and reject restore quarantine before
    // opening even an API listener. Keep the exact guard through composition
    // and daemon shutdown.
    let startup_guard = composition::acquire_startup_guard(&data_dir, config.database_backend)?;
    // Bind before composition starts workers or opens canonical storage, so a
    // bind failure cannot leave detached background tasks behind the lock.
    let listener = TcpListener::bind(listen_addr).await?;
    let composition = composition::build_composition_with_guard(config, startup_guard).await?;

    // Optional authenticated backup handoff control channel (PP.6). A missing
    // sibling `o3k` executable or a bind failure disables backups with a
    // warning; ordinary daemon operation is unaffected (fail-closed semantics
    // apply to the lock handoff itself, not to daemon liveness).
    #[cfg(target_os = "linux")]
    let mut backup_control = match composition::expected_backup_executor(&data_dir) {
        Some(expected) => composition::backup::start_backup_control(&expected, &data_dir),
        None => {
            tracing::warn!(
                "backup control listener unavailable: sibling o3k executable not found; \
                 backups disabled"
            );
            None
        }
    };
    // Backup handoff is Linux-only; this binding only mirrors the shape of
    // the Linux arm (nothing consumes it off-Linux).
    #[cfg(not(target_os = "linux"))]
    let _backup_control: Option<()> = None;

    info!(
        address = %listen_addr,
        data_dir = %data_dir.display(),
        provider = ?provider,
        "o3kd listening"
    );

    let serve_state = composition.state.clone();
    let shutdown_state = composition.state.clone();
    #[cfg(target_os = "linux")]
    let graceful_shutdown = composition::shutdown_signal_with_backup(
        shutdown_state,
        backup_control.as_ref().map_or_else(
            || std::sync::Arc::new(tokio::sync::Notify::new()),
            composition::backup::BackupControl::shutdown_notify,
        ),
    );
    #[cfg(not(target_os = "linux"))]
    let graceful_shutdown = composition::shutdown_signal(shutdown_state);
    // Bound the post-signal connection drain: the wrapped signal future
    // notifies `serve_shutdown_began` the moment shutdown initiates, and the
    // serve gets at most `SERVE_DRAIN_BOUND` from then to finish. On expiry
    // the select drops the serve future, which closes only the listener
    // (axum 0.8 detaches connection tasks, so stalled handlers run until
    // process exit), and the bounded writer drain below begins either way.
    let serve_shutdown_began = std::sync::Arc::new(tokio::sync::Notify::new());
    let serve_graceful_shutdown = {
        let serve_shutdown_began = std::sync::Arc::clone(&serve_shutdown_began);
        async move {
            graceful_shutdown.await;
            serve_shutdown_began.notify_one();
        }
    };
    let serve = axum::serve(listener, o3k_api::router_with_state(serve_state))
        .with_graceful_shutdown(serve_graceful_shutdown);
    let serve_result = tokio::select! {
        result = serve => result,
        _ = async {
            serve_shutdown_began.notified().await;
            tokio::time::sleep(SERVE_DRAIN_BOUND).await;
        } => {
            tracing::warn!(
                ?SERVE_DRAIN_BOUND,
                "axum serve did not drain after the shutdown signal; closing the listener \
                 (stalled connection handlers run until process exit) and proceeding to the \
                 writer drain"
            );
            Ok(())
        }
    };

    let drain = composition.shutdown().await;

    // A backup request ends the serve through the same readiness path as an
    // OS signal; complete the authenticated handoff instead of an ordinary
    // exit. Every failure here retains the drained store lock until process
    // exit (fail closed).
    #[cfg(target_os = "linux")]
    if let Some(control) = backup_control.as_mut()
        && control.was_requested()
    {
        let Some(request) = control.take_accepted().await else {
            // `take_accepted` already logged why. The daemon drained but the
            // authenticated request never arrived; masquerading as an
            // ordinary exit-0 would obscure the failure.
            tracing::error!(
                "backup handoff was requested but the accepted request never arrived; \
                 exiting non-zero"
            );
            std::process::exit(1);
        };
        let handoff_result = match drain {
            Ok(proof) => finish_backup_handoff(proof, request),
            Err(error) => {
                request.reject(o3k_store::HandoffRejectReason::DrainFailed);
                Err(error)
            }
        };
        // The API serve must also have ended cleanly; an errored serve is a
        // failed daemon even when the handoff itself succeeded.
        if let Err(error) = serve_result {
            tracing::error!(
                %error,
                "API serve ended with an error during the backup handoff shutdown"
            );
            let error: Box<dyn std::error::Error> = Box::new(error);
            return Err(error);
        }
        return handoff_result;
    }

    let _drain_proof = drain_result_for_normal_exit(drain)?;
    serve_result?;
    Ok(())
}

/// Completes the authenticated backup handoff after a successful drain:
/// revalidates the executor against PID reuse, transfers the lifetime store
/// lock, and exits. On any failure the lock is retained until process exit
/// and the process exits non-zero.
#[cfg(target_os = "linux")]
fn finish_backup_handoff(
    proof: composition::ControllerDrainProof,
    mut request: o3k_store::AcceptedBackupRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    // The drain took bounded wall-clock time; revalidate against PID reuse
    // before transferring lock ownership.
    if let Err(error) = request.revalidate_peer() {
        tracing::error!(
            %error,
            operation_id = %uuid::Uuid::from_bytes(request.operation_id),
            "backup executor changed while the controller drained; \
             exiting without lock transfer"
        );
        std::process::exit(1);
    }
    let operation_id = uuid::Uuid::from_bytes(request.operation_id);
    match proof.handoff_store_lock(&mut request.stream, std::time::Duration::from_secs(10)) {
        Ok(()) => {
            info!(
                %operation_id,
                "store lock ownership transferred to the backup executor; source exiting"
            );
            // Test-only barrier (feature `backup-test-hooks`): hold the
            // process briefly after the transfer so a failure-injection test
            // can SIGKILL the daemon at the last point where it still exists,
            // proving the executor's capture does not depend on sender
            // survival. Never enabled in release or production builds.
            #[cfg(feature = "backup-test-hooks")]
            test_handoff_barrier();
            Ok(())
        }
        Err(error) => {
            tracing::error!(
                %error,
                %operation_id,
                "store lock handoff failed; lock retained until process exit"
            );
            std::process::exit(1);
        }
    }
}

/// Test-only two-way file barrier (feature `backup-test-hooks`): creates the
/// `O3K_BACKUP_TEST_DAEMON_BARRIER_READY_FILE` after the lock handoff has
/// completed, then polls for `O3K_BACKUP_TEST_DAEMON_BARRIER_WAIT_FILE` before
/// the daemon would ordinarily exit. Bounded; a broken barrier exits 91.
#[cfg(all(feature = "backup-test-hooks", target_os = "linux"))]
fn test_handoff_barrier() {
    use std::time::{Duration, Instant};
    let Some(ready) = std::env::var_os("O3K_BACKUP_TEST_DAEMON_BARRIER_READY_FILE") else {
        return;
    };
    if std::fs::File::create(std::path::PathBuf::from(&ready)).is_err() {
        std::process::exit(91);
    }
    let Some(wait) = std::env::var_os("O3K_BACKUP_TEST_DAEMON_BARRIER_WAIT_FILE") else {
        return;
    };
    let wait = std::path::PathBuf::from(wait);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !wait.exists() {
        if Instant::now() >= deadline {
            std::process::exit(91);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Ordinary daemon exit must remain available for adapters that cannot prove
/// backup quiescence. The drain API itself still returns an error and never
/// supplies a proof for them; its failed-drain guard retains exclusion until
/// process exit. Every other failure remains a failed daemon shutdown.
fn drain_result_for_normal_exit(
    result: Result<composition::ControllerDrainProof, Box<dyn std::error::Error>>,
) -> Result<Option<composition::ControllerDrainProof>, Box<dyn std::error::Error>> {
    match result {
        Ok(proof) => Ok(Some(proof)),
        Err(error)
            if matches!(
                error.downcast_ref::<o3k_store::StoreError>(),
                Some(o3k_store::StoreError::WriterDrainUnavailable)
            ) =>
        {
            info!("controller exiting without backup drain proof: unsupported storage adapter");
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::drain_result_for_normal_exit;

    #[test]
    fn unsupported_adapter_allows_normal_exit_without_a_drain_proof() {
        assert!(matches!(
            drain_result_for_normal_exit(Err(o3k_store::StoreError::WriterDrainUnavailable.into())),
            Ok(None)
        ));
    }

    #[test]
    fn failed_writer_drain_still_fails_normal_exit() {
        assert!(
            drain_result_for_normal_exit(
                Err(std::io::Error::other("writer remains active").into())
            )
            .is_err()
        );
    }
}
