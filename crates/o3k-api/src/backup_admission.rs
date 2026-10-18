//! Internal request admission used by bounded backup coordination.
//!
//! This gate covers router requests only. A complete backup exclusion must
//! also quiesce background workers, direct store writers, startup, and remote
//! database sessions at their owning boundaries.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

#[derive(Clone, Default)]
pub(crate) struct BackupAdmission {
    inner: Arc<AdmissionInner>,
}

#[derive(Default)]
struct AdmissionInner {
    active: AtomicBool,
    requests: Arc<RwLock<()>>,
}

impl BackupAdmission {
    pub(crate) fn is_active(&self) -> bool {
        self.inner.active.load(Ordering::Acquire)
    }

    pub(crate) async fn enter_request(&self) -> Option<OwnedRwLockReadGuard<()>> {
        if self.is_active() {
            return None;
        }
        let permit = Arc::clone(&self.inner.requests).read_owned().await;
        if self.is_active() {
            return None;
        }
        Some(permit)
    }

    pub(crate) async fn begin_exclusive(
        &self,
        timeout: Duration,
    ) -> Result<BackupExclusion, BackupAdmissionError> {
        self.inner
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| BackupAdmissionError::AlreadyActive)?;

        let claim = ActiveClaim(Arc::clone(&self.inner));
        let writer = tokio::time::timeout(timeout, Arc::clone(&self.inner.requests).write_owned())
            .await
            .map_err(|_| BackupAdmissionError::DrainTimeout)?;

        Ok(BackupExclusion {
            _writer: writer,
            _claim: claim,
        })
    }
}

/// Exclusive API-request admission held for the lifetime of a backup phase.
///
/// This guard only excludes router requests; it does not stop background
/// workers or writers outside this API crate.
pub struct BackupExclusion {
    _writer: OwnedRwLockWriteGuard<()>,
    _claim: ActiveClaim,
}

struct ActiveClaim(Arc<AdmissionInner>);

impl Drop for ActiveClaim {
    fn drop(&mut self) {
        self.0.active.store(false, Ordering::Release);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupAdmissionError {
    /// Another backup phase already owns exclusive request admission.
    AlreadyActive,
    /// In-flight API handlers did not finish before the configured deadline.
    DrainTimeout,
}

impl fmt::Display for BackupAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyActive => formatter.write_str("backup exclusion is already active"),
            Self::DrainTimeout => formatter.write_str("API requests did not drain before timeout"),
        }
    }
}

impl std::error::Error for BackupAdmissionError {}
