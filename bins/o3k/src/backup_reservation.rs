//! D9 staging-space reservation for the authenticated PP.6 backup artifact.
//!
//! ADR-0189 D9/A7 accepts a 4 GiB aggregate measured-source bound, a
//! `max(2 × measured source bytes + 1 GiB, 6 GiB)` staging reservation and a
//! 9 GiB reservation cap. The computed reservation is never truncated: when
//! the bound, the cap or the available space is not satisfied, the preflight
//! fails instead of proceeding with less space than the formula requires.
//!
//! Measurements are restricted to allowlisted regular files. A symbolic link,
//! directory, device or any other entry is rejected rather than followed.
//!
//! The reservation is enforced, not merely preflighted: [`StagingReservation`]
//! creates a private hold file in the operation staging directory and
//! allocates the remaining reservation with non-sparse `fallocate(2)`. The
//! allocated blocks cannot be used by another process, so the staging tree's
//! own consumption plus the hold never exceeds the computed reservation.
//! Capacity is released just before each staging write and reconciled back to
//! `reserved - staged` afterwards; the guard truncates and unlinks the hold on
//! every drop path, and a restart removes a hold left by a crashed attempt.

use std::{
    fmt,
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use rustix::{
    fs::{FallocateFlags, FileType, Mode, OFlags, fallocate, fstat, ftruncate, open, statvfs},
    process::geteuid,
};

const GIB: u64 = 1024 * 1024 * 1024;

/// Name of the private hold file inside an operation staging directory.
pub const STAGING_HOLD_FILE: &str = "reservation.hold";

/// Accepted D9 format/manifest overhead allowance. It is released alongside a
/// phase write so the ciphertext framing and canonical manifest never push the
/// staging tree past the reservation.
pub const FORMAT_OVERHEAD_BOUND: u64 = 64 * 1024 * 1024;

/// Maximum aggregate measured source plaintext accepted for an artifact.
pub const SOURCE_PLAINTEXT_BOUND: u64 = 4 * GIB;

/// Maximum staging reservation this profile may hold.
pub const RESERVATION_CAP: u64 = 9 * GIB;

/// Minimum staging reservation for any accepted source.
pub const MIN_RESERVATION: u64 = 6 * GIB;

/// Stable measurement codes for source entries that cannot be measured.
const REASON_SOURCE_NOT_REGULAR: &str = "source-not-regular-file";
const REASON_SOURCE_SYMLINK: &str = "source-symlink";
const REASON_SOURCE_UNAVAILABLE: &str = "source-unavailable";
const REASON_SOURCE_SIZE_OVERFLOW: &str = "source-size-overflow";
const REASON_DESTINATION_UNAVAILABLE: &str = "destination-unavailable";
const REASON_FILESYSTEM_STATISTICS_OVERFLOW: &str = "filesystem-statistics-overflow";

/// Typed reservation failure. [`Self::reason`] is the stable string callers
/// may log or emit; no path is ever included.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReservationError {
    /// The measured source exceeds [`SOURCE_PLAINTEXT_BOUND`].
    SourceBoundExceeded { source_bytes: u64 },
    /// The formula would reserve more than [`RESERVATION_CAP`].
    ReservationCapExceeded { reserved_bytes: u64 },
    /// The destination filesystem has less free space than required.
    SpaceUnavailable {
        reserved_bytes: u64,
        available_bytes: u64,
    },
    /// The staged tree already exceeds the accepted reservation.
    StagedExceedsReservation {
        staged_bytes: u64,
        reserved_bytes: u64,
    },
    /// The private hold file could not be created, inspected or released.
    StagingHoldUnavailable,
    /// A source or destination could not be measured. The value is a stable
    /// code such as `source-symlink`, never a path.
    Measurement(String),
}

impl ReservationError {
    /// Stable reason string for operator output.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::SourceBoundExceeded { .. } => "source-bound-exceeded",
            Self::ReservationCapExceeded { .. } => "reservation-cap-exceeded",
            Self::SpaceUnavailable { .. } => "space-unavailable",
            Self::StagedExceedsReservation { .. } => "staging-quota-exceeded",
            Self::StagingHoldUnavailable => "staging-hold-unavailable",
            Self::Measurement(_) => "measurement-failed",
        }
    }

    /// Stable measurement code when this is a [`Self::Measurement`] failure.
    ///
    /// The returned value is one of this module's static reason constants, so
    /// it can be emitted directly as an operator reason.
    #[must_use]
    pub fn measurement_code(&self) -> Option<&'static str> {
        match self {
            Self::Measurement(code) => Some(match code.as_str() {
                REASON_SOURCE_NOT_REGULAR => REASON_SOURCE_NOT_REGULAR,
                REASON_SOURCE_SYMLINK => REASON_SOURCE_SYMLINK,
                REASON_SOURCE_UNAVAILABLE => REASON_SOURCE_UNAVAILABLE,
                REASON_SOURCE_SIZE_OVERFLOW => REASON_SOURCE_SIZE_OVERFLOW,
                REASON_DESTINATION_UNAVAILABLE => REASON_DESTINATION_UNAVAILABLE,
                REASON_FILESYSTEM_STATISTICS_OVERFLOW => REASON_FILESYSTEM_STATISTICS_OVERFLOW,
                _ => "measurement-failed",
            }),
            _ => None,
        }
    }
}

impl fmt::Display for ReservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceBoundExceeded { source_bytes } => {
                write!(formatter, "source-bound-exceeded: {source_bytes} bytes")
            }
            Self::ReservationCapExceeded { reserved_bytes } => {
                write!(
                    formatter,
                    "reservation-cap-exceeded: {reserved_bytes} bytes"
                )
            }
            Self::SpaceUnavailable {
                reserved_bytes,
                available_bytes,
            } => write!(
                formatter,
                "space-unavailable: {reserved_bytes} bytes required, {available_bytes} available"
            ),
            Self::StagedExceedsReservation {
                staged_bytes,
                reserved_bytes,
            } => write!(
                formatter,
                "staging-quota-exceeded: {staged_bytes} bytes staged, {reserved_bytes} reserved"
            ),
            Self::StagingHoldUnavailable => {
                write!(formatter, "staging-hold-unavailable")
            }
            Self::Measurement(code) => write!(formatter, "measurement-failed: {code}"),
        }
    }
}

impl std::error::Error for ReservationError {}

/// An accepted reservation: the measured source and the staging space that
/// must be held for the whole artifact lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    /// Aggregate measured source plaintext bytes.
    pub source_bytes: u64,
    /// Bytes that must stay reserved on the destination filesystem.
    pub reserved_bytes: u64,
}

/// Computes the D9 staging reservation for a measured source.
///
/// # Errors
///
/// Returns [`ReservationError::SourceBoundExceeded`] above the 4 GiB bound and
/// [`ReservationError::ReservationCapExceeded`] if the formula ever exceeds
/// the 9 GiB cap.
pub fn compute_reservation(source_bytes: u64) -> Result<u64, ReservationError> {
    if source_bytes > SOURCE_PLAINTEXT_BOUND {
        return Err(ReservationError::SourceBoundExceeded { source_bytes });
    }
    let doubled = source_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(GIB))
        .ok_or(ReservationError::SourceBoundExceeded { source_bytes })?;
    let reserved = doubled.max(MIN_RESERVATION);
    if reserved > RESERVATION_CAP {
        return Err(ReservationError::ReservationCapExceeded {
            reserved_bytes: reserved,
        });
    }
    Ok(reserved)
}

/// Measures the aggregate size of allowlisted regular-file sources.
///
/// Symbolic links are rejected (`source-symlink`); directories, devices and
/// other non-regular entries are rejected (`source-not-regular-file`).
///
/// # Errors
///
/// Returns [`ReservationError::Measurement`] with a stable code when a source
/// is unavailable, not a regular file, a symbolic link, or when the sum
/// overflows.
pub fn measure_source_bytes<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
) -> Result<u64, ReservationError> {
    let mut total = 0_u64;
    for path in paths {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| ReservationError::Measurement(REASON_SOURCE_UNAVAILABLE.to_owned()))?;
        if metadata.file_type().is_symlink() {
            return Err(ReservationError::Measurement(
                REASON_SOURCE_SYMLINK.to_owned(),
            ));
        }
        if !metadata.file_type().is_file() {
            return Err(ReservationError::Measurement(
                REASON_SOURCE_NOT_REGULAR.to_owned(),
            ));
        }
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| ReservationError::Measurement(REASON_SOURCE_SIZE_OVERFLOW.to_owned()))?;
    }
    Ok(total)
}

/// Applies the D9 formula to a known available-space figure.
fn reserve_with_available(
    source_bytes: u64,
    available_bytes: u64,
) -> Result<Reservation, ReservationError> {
    let reserved_bytes = compute_reservation(source_bytes)?;
    if available_bytes < reserved_bytes {
        return Err(ReservationError::SpaceUnavailable {
            reserved_bytes,
            available_bytes,
        });
    }
    Ok(Reservation {
        source_bytes,
        reserved_bytes,
    })
}

/// Free bytes for an unprivileged writer on the filesystem holding `path`
/// (`f_bavail * f_frsize`).
///
/// # Errors
///
/// Returns a [`ReservationError::Measurement`] code when the filesystem
/// statistics are unavailable or overflow.
pub fn available_bytes(path: &Path) -> Result<u64, ReservationError> {
    let statistics = statvfs(path)
        .map_err(|_| ReservationError::Measurement(REASON_DESTINATION_UNAVAILABLE.to_owned()))?;
    statistics
        .f_bavail
        .checked_mul(statistics.f_frsize)
        .ok_or_else(|| {
            ReservationError::Measurement(REASON_FILESYSTEM_STATISTICS_OVERFLOW.to_owned())
        })
}

/// An enforced staging reservation backed by a non-sparse hold file.
///
/// The guard owns a private regular file inside the operation staging
/// directory. `held_bytes` blocks are allocated with `fallocate(2)` and stay
/// allocated until the guard releases them, so no concurrent writer can
/// consume that capacity. The invariant maintained by every method is
/// `held_bytes + staged_bytes <= reserved_bytes`.
///
/// Capacity is released immediately before a phase write
/// ([`Self::prepare_for_write`]) and reconciled back to
/// `reserved_bytes - staged_bytes` once the write is durable
/// ([`Self::reconcile`]). Bytes released but not yet written are the only
/// window in which another process can race for them.
#[derive(Debug)]
pub struct StagingReservation {
    directory: PathBuf,
    path: PathBuf,
    file: File,
    reserved_bytes: u64,
    held_bytes: u64,
}

impl StagingReservation {
    /// Creates (or reuses, truncating a stale crashed hold) the private hold
    /// file and allocates `reserved_bytes - staged_bytes`.
    ///
    /// `staged_bytes` is the size of the staging tree that already exists and
    /// is therefore already consuming capacity on this filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationError::StagedExceedsReservation`] when the tree is
    /// already over the accepted reservation,
    /// [`ReservationError::StagingHoldUnavailable`] when the private hold file
    /// cannot be created or inspected, and
    /// [`ReservationError::SpaceUnavailable`] when `fallocate(2)` cannot
    /// allocate the remaining reservation. A failed allocation removes the
    /// hold file rather than leaving a partial reservation behind.
    pub fn acquire(
        directory: &Path,
        reserved_bytes: u64,
        staged_bytes: u64,
    ) -> Result<Self, ReservationError> {
        if staged_bytes > reserved_bytes {
            return Err(ReservationError::StagedExceedsReservation {
                staged_bytes,
                reserved_bytes,
            });
        }
        let held_bytes = reserved_bytes - staged_bytes;
        let path = directory.join(STAGING_HOLD_FILE);
        let descriptor = open(
            &path,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| ReservationError::StagingHoldUnavailable)?;
        let metadata = fstat(&descriptor).map_err(|_| ReservationError::StagingHoldUnavailable)?;
        let expected_uid = geteuid().as_raw();
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || (metadata.st_uid != 0 && metadata.st_uid != expected_uid)
            || metadata.st_mode & 0o077 != 0
        {
            return Err(ReservationError::StagingHoldUnavailable);
        }
        let file = File::from(descriptor);
        // A hold left by a crashed attempt is not authoritative: reset it
        // before allocating the reservation this invocation needs.
        if ftruncate(&file, 0).is_err() {
            let _ = fs::remove_file(&path);
            return Err(ReservationError::StagingHoldUnavailable);
        }
        if held_bytes > 0 && fallocate(&file, FallocateFlags::empty(), 0, held_bytes).is_err() {
            let _ = ftruncate(&file, 0);
            let _ = fs::remove_file(&path);
            return Err(ReservationError::SpaceUnavailable {
                reserved_bytes: held_bytes,
                available_bytes: available_bytes(directory).unwrap_or(0),
            });
        }
        Ok(Self {
            directory: directory.to_path_buf(),
            path,
            file,
            reserved_bytes,
            held_bytes,
        })
    }

    /// Blocks currently allocated by the hold file.
    #[must_use]
    pub const fn held_bytes(&self) -> u64 {
        self.held_bytes
    }

    /// Reservation this guard enforces.
    #[must_use]
    pub const fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    /// Releases `additional_bytes` from the hold immediately before a write
    /// that may consume them.
    ///
    /// The caller must not write more than `additional_bytes` before the next
    /// [`Self::reconcile`]. Keeping the remainder allocated means a concurrent
    /// writer cannot consume the part of the reservation not being written
    /// right now.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationError::SpaceUnavailable`] when the request exceeds
    /// the currently held capacity, and
    /// [`ReservationError::StagingHoldUnavailable`] when the hold file cannot
    /// be truncated.
    pub fn prepare_for_write(&mut self, additional_bytes: u64) -> Result<(), ReservationError> {
        if additional_bytes > self.held_bytes {
            return Err(ReservationError::SpaceUnavailable {
                reserved_bytes: additional_bytes,
                available_bytes: self.held_bytes,
            });
        }
        let target = self.held_bytes - additional_bytes;
        ftruncate(&self.file, target).map_err(|_| ReservationError::StagingHoldUnavailable)?;
        self.held_bytes = target;
        Ok(())
    }

    /// Reconciles the hold after a write: `held = reserved - staged`.
    ///
    /// Shrinking releases capacity the write did not consume. Growing
    /// re-claims capacity released before the write, and fails closed with
    /// [`ReservationError::SpaceUnavailable`] if a concurrent writer took it.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationError::StagedExceedsReservation`] when the staged
    /// tree grew past the reservation, [`ReservationError::SpaceUnavailable`]
    /// when the released capacity cannot be re-claimed, or
    /// [`ReservationError::StagingHoldUnavailable`] for hold-file I/O failure.
    pub fn reconcile(&mut self, staged_bytes: u64) -> Result<(), ReservationError> {
        if staged_bytes > self.reserved_bytes {
            return Err(ReservationError::StagedExceedsReservation {
                staged_bytes,
                reserved_bytes: self.reserved_bytes,
            });
        }
        let target = self.reserved_bytes - staged_bytes;
        if target < self.held_bytes {
            ftruncate(&self.file, target).map_err(|_| ReservationError::StagingHoldUnavailable)?;
            self.held_bytes = target;
        } else if target > self.held_bytes {
            let growth = target - self.held_bytes;
            if fallocate(&self.file, FallocateFlags::empty(), self.held_bytes, growth).is_err() {
                return Err(ReservationError::SpaceUnavailable {
                    reserved_bytes: target,
                    available_bytes: available_bytes(&self.directory).unwrap_or(0),
                });
            }
            self.held_bytes = target;
        }
        Ok(())
    }
}

impl Drop for StagingReservation {
    fn drop(&mut self) {
        // Both operations are best effort: Drop must never panic, and the
        // blocks are returned to the filesystem when the descriptor closes
        // even if the directory entry is already gone.
        let _ = ftruncate(&self.file, 0);
        let _ = fs::remove_file(&self.path);
    }
}

/// Allocated bytes of regular files under a staging directory, excluding the
/// hold file.
///
/// This is the `staged` term of `held + staged <= reserved`. It uses
/// `st_blocks * 512` rather than the byte length so the accounting matches the
/// capacity the filesystem actually removed from `f_bavail` (including block
/// rounding). Unreadable or non-regular entries count as zero, which only
/// makes the accounting stricter.
#[must_use]
pub fn staging_tree_bytes(directory: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(directory) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| {
            if entry.file_name().as_encoded_bytes() == STAGING_HOLD_FILE.as_bytes() {
                return 0;
            }
            match entry.file_type() {
                Ok(file_type) if file_type.is_dir() => staging_tree_bytes(&entry.path()),
                Ok(file_type) if file_type.is_file() => entry
                    .metadata()
                    .map(|metadata| metadata.blocks().saturating_mul(512))
                    .unwrap_or(0),
                _ => 0,
            }
        })
        .sum()
}

/// Re-checks the reservation while a hold file is active.
///
/// The statvfs reading is retained, but the bytes already allocated by the
/// hold count as covered reservation: `f_bavail + held` must cover what the
/// staging tree still needs. This keeps the boundary check meaningful without
/// double-counting the hold.
///
/// # Errors
///
/// Propagates the measurement failure, or [`ReservationError::SpaceUnavailable`]
/// when the held plus free bytes cannot cover the remaining reservation.
pub fn ensure_reserved_space_with_hold(
    destination: &Path,
    reserved_bytes: u64,
    already_staged_bytes: u64,
    held_bytes: u64,
) -> Result<(), ReservationError> {
    let required = reserved_bytes.saturating_sub(already_staged_bytes);
    let available = available_bytes(destination)?;
    let covered = available.saturating_add(held_bytes);
    if covered < required {
        return Err(ReservationError::SpaceUnavailable {
            reserved_bytes: required,
            available_bytes: covered,
        });
    }
    Ok(())
}

/// Re-checks the reservation at a phase boundary.
///
/// `already_staged_bytes` is the space the staging tree of this operation
/// already occupies on the same filesystem; the remaining requirement is the
/// full reservation minus that amount. The check never lowers the reserve: a
/// shortfall fails closed with [`ReservationError::SpaceUnavailable`]
/// (`space-unavailable`) and nothing is truncated.
///
/// This is the pre-hold boundary check. Once [`StagingReservation`] exists,
/// [`ensure_reserved_space_with_hold`] accounts for the allocated hold; the
/// statvfs reading alone is not treated as a quota.
///
/// # Errors
///
/// Propagates the measurement failure, or [`ReservationError::SpaceUnavailable`]
/// when the destination cannot hold the remaining reservation.
pub fn ensure_reserved_space(
    destination: &Path,
    reserved_bytes: u64,
    already_staged_bytes: u64,
) -> Result<(), ReservationError> {
    let required = reserved_bytes.saturating_sub(already_staged_bytes);
    let available = available_bytes(destination)?;
    if available < required {
        return Err(ReservationError::SpaceUnavailable {
            reserved_bytes: required,
            available_bytes: available,
        });
    }
    Ok(())
}

/// Measures the sources and verifies that `destination` has at least the D9
/// reservation free for unprivileged writers (`f_bavail * f_frsize`).
///
/// # Errors
///
/// Propagates [`ReservationError`] from measurement or sizing, and
/// [`ReservationError::SpaceUnavailable`] when the destination filesystem
/// cannot hold the full reservation.
pub fn preflight_reservation(
    source_paths: &[&Path],
    destination: &Path,
) -> Result<Reservation, ReservationError> {
    let source_bytes = measure_source_bytes(source_paths.iter().copied())?;
    let available_bytes = available_bytes(destination)?;
    reserve_with_available(source_bytes, available_bytes)
}

#[cfg(test)]
pub(crate) static STAGING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serialises tests that measure filesystem-wide free space. Real capture
/// tests take the same lock through `execute_inner`, so a parallel test's
/// transient hold cannot masquerade as this test's allocation.
#[cfg(test)]
pub(crate) fn staging_test_lock() -> std::sync::MutexGuard<'static, ()> {
    STAGING_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
    use uuid::Uuid;

    fn fixture_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!("o3k-pp6-reserve-{}", Uuid::now_v7()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("create reservation fixture directory");
        path
    }

    /// Free-space assertions tolerate filesystem metadata and unrelated
    /// activity on the shared test filesystem.
    const SPACE_TOLERANCE: u64 = 64 * 1024 * 1024;

    fn require_space(root: &Path, required: u64) -> bool {
        match available_bytes(root) {
            Ok(available) if available >= required + SPACE_TOLERANCE => true,
            Ok(available) => {
                eprintln!(
                    "NOT-COVERED: {required} bytes reserved, only {available} available on the test filesystem"
                );
                false
            }
            Err(_) => false,
        }
    }

    fn allocated_blocks(file: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(file)
            .map(|metadata| metadata.blocks().saturating_mul(512))
            .unwrap_or(0)
    }

    #[test]
    fn reservation_hold_allocates_and_release_returns_capacity() {
        let _serial = staging_test_lock();
        let root = fixture_dir();
        let reserved = compute_reservation(0).expect("empty source reservation");
        assert_eq!(reserved, MIN_RESERVATION);
        if !require_space(&root, reserved) {
            let _ = fs::remove_dir_all(&root);
            return;
        }
        let before = available_bytes(&root).expect("free space before");

        let hold = StagingReservation::acquire(&root, reserved, 0).expect("allocate reservation");
        let hold_path = root.join(STAGING_HOLD_FILE);
        assert_eq!(hold.held_bytes(), reserved);
        assert!(hold_path.is_file(), "the hold file must exist while held");
        // The hold's own inode proves the blocks are allocated (not sparse),
        // independently of any concurrent activity on the shared filesystem.
        assert!(
            allocated_blocks(&hold_path) >= reserved,
            "fallocate must allocate the full reservation"
        );
        let held_available = available_bytes(&root).expect("free space while held");
        assert!(
            before.saturating_sub(held_available) + SPACE_TOLERANCE >= reserved,
            "holding {reserved} bytes must reduce f_bavail by about that much"
        );

        drop(hold);
        let released = available_bytes(&root).expect("free space after release");
        assert!(
            released + SPACE_TOLERANCE >= before,
            "dropping the guard must release the reservation"
        );
        assert!(!hold_path.exists(), "the hold file must be unlinked");

        fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn concurrent_write_cannot_consume_reserved_capacity() {
        let _serial = staging_test_lock();
        let root = fixture_dir();
        let reserved = compute_reservation(0).expect("empty source reservation");
        if !require_space(&root, reserved) {
            let _ = fs::remove_dir_all(&root);
            return;
        }
        let before = available_bytes(&root).expect("free space before");
        let hold = StagingReservation::acquire(&root, reserved, 0).expect("allocate reservation");
        let hold_path = root.join(STAGING_HOLD_FILE);

        // Blocks allocated to the hold inode are not available to any other
        // writer. f_bavail drops accordingly, which is exactly the capacity a
        // competing allocation would try to consume. (A literal
        // `fallocate(remaining + N)` probe is not used on the shared CI
        // filesystem: it would temporarily fill ~170 GiB before failing.
        // The block count plus the f_bavail reduction proves the same
        // exclusion without that side effect.)
        assert!(allocated_blocks(&hold_path) >= reserved);
        let competing_free = available_bytes(&root).expect("free space while held");
        assert!(
            before.saturating_sub(competing_free) + SPACE_TOLERANCE >= reserved,
            "the hold must remove the reserved capacity from f_bavail"
        );
        assert!(competing_free < before);

        drop(hold);
        assert!(!hold_path.exists());
        fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn reservation_failure_fails_closed_space_unavailable() {
        let _serial = staging_test_lock();
        let root = fixture_dir();
        // An impossible length fails in fallocate without touching the disk;
        // the guard must report the existing fail-closed space reason and
        // leave no partial hold behind.
        let error = StagingReservation::acquire(&root, u64::MAX, 0)
            .expect_err("impossible reservation must fail");
        assert_eq!(error.reason(), "space-unavailable");
        assert!(!root.join(STAGING_HOLD_FILE).exists());

        // A staging tree already over the reservation is never accepted.
        let error = StagingReservation::acquire(&root, 1024, 2048)
            .expect_err("staged bytes over the reservation");
        assert_eq!(error.reason(), "staging-quota-exceeded");
        assert!(!root.join(STAGING_HOLD_FILE).exists());

        fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn reservation_released_on_error_and_cancel_paths() {
        let _serial = staging_test_lock();
        let root = fixture_dir();
        let reserved = compute_reservation(0).expect("empty source reservation");
        if !require_space(&root, reserved) {
            let _ = fs::remove_dir_all(&root);
            return;
        }
        let before = available_bytes(&root).expect("free space before");
        let hold_path = root.join(STAGING_HOLD_FILE);

        // A function that acquires the guard and then fails must still release
        // the reservation through Drop (the `?` early-return path).
        fn cancelled_operation(root: &Path, reserved: u64) -> Result<(), ReservationError> {
            let mut hold = StagingReservation::acquire(root, reserved, 0)?;
            hold.prepare_for_write(1024 * 1024)?;
            Err(ReservationError::Measurement(
                REASON_SOURCE_UNAVAILABLE.to_owned(),
            ))
        }
        assert!(cancelled_operation(&root, reserved).is_err());
        assert!(!hold_path.exists(), "the error path must unlink the hold");
        let after = available_bytes(&root).expect("free space after error");
        assert!(after + SPACE_TOLERANCE >= before);

        // A partial write release survives a failure too.
        fn failed_write(root: &Path, reserved: u64) -> Result<(), ReservationError> {
            let mut hold = StagingReservation::acquire(root, reserved, 0)?;
            hold.prepare_for_write(reserved / 2)?;
            Err(ReservationError::SpaceUnavailable {
                reserved_bytes: 1,
                available_bytes: 0,
            })
        }
        assert!(failed_write(&root, reserved).is_err());
        assert!(!hold_path.exists());
        let after = available_bytes(&root).expect("free space after failed write");
        assert!(after + SPACE_TOLERANCE >= before);

        fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn crashed_staging_hold_is_cleaned_up() {
        let _serial = staging_test_lock();
        let root = fixture_dir();
        let reserved = compute_reservation(0).expect("empty source reservation");
        if !require_space(&root, reserved) {
            let _ = fs::remove_dir_all(&root);
            return;
        }
        let before = available_bytes(&root).expect("free space before");
        let hold_path = root.join(STAGING_HOLD_FILE);

        // Simulate a process that died while holding the reservation: the
        // guard's Drop never runs, so the allocated hold file survives.
        let hold = StagingReservation::acquire(&root, reserved, 0).expect("allocate reservation");
        std::mem::forget(hold);
        assert!(hold_path.is_file(), "a crashed attempt leaves the hold");
        assert!(allocated_blocks(&hold_path) >= reserved);
        let after_crash = available_bytes(&root).expect("free space after crash");
        assert!(before.saturating_sub(after_crash) + SPACE_TOLERANCE >= reserved);

        // Restart path: acquiring the same reservation truncates the stale
        // hold and re-allocates exactly once, not twice.
        let restarted =
            StagingReservation::acquire(&root, reserved, 0).expect("restart cleans stale hold");
        assert_eq!(restarted.held_bytes(), reserved);
        assert!(allocated_blocks(&hold_path) >= reserved);
        assert!(allocated_blocks(&hold_path) <= reserved + SPACE_TOLERANCE);
        let after_restart = available_bytes(&root).expect("free space after restart");
        assert!(
            before.saturating_sub(after_restart) + SPACE_TOLERANCE >= reserved,
            "the restarted hold must keep the reservation"
        );
        assert!(
            after_restart + SPACE_TOLERANCE >= after_crash,
            "a stale hold must not be allocated twice"
        );

        drop(restarted);
        assert!(!hold_path.exists());
        let released = available_bytes(&root).expect("free space after release");
        assert!(released + SPACE_TOLERANCE >= before);

        fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn hold_plus_staged_never_exceeds_the_reservation() {
        let _serial = staging_test_lock();
        let root = fixture_dir();
        let reserved = 64 * 1024 * 1024;
        let mut hold = StagingReservation::acquire(&root, reserved, 0).expect("hold");
        assert_eq!(hold.held_bytes(), reserved);

        // Release exactly the bytes the next write may consume.
        hold.prepare_for_write(16 * 1024 * 1024).expect("release");
        assert_eq!(hold.held_bytes(), reserved - 16 * 1024 * 1024);
        let staged_file = root.join("staged.bin");
        fs::write(&staged_file, vec![0_u8; 8 * 1024 * 1024]).expect("write staged data");
        let staged = staging_tree_bytes(&root);
        assert_eq!(staged, 8 * 1024 * 1024);
        hold.reconcile(staged).expect("reconcile");
        assert_eq!(hold.held_bytes() + staged, reserved);
        drop(hold);

        // A resume with existing staged data holds only the remainder.
        let remainder = StagingReservation::acquire(&root, reserved, staged).expect("resume hold");
        assert_eq!(remainder.held_bytes(), reserved - staged);
        drop(remainder);

        fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn reservation_boundaries_follow_d9() {
        assert_eq!(
            compute_reservation(0).expect("empty source"),
            MIN_RESERVATION
        );
        assert_eq!(
            compute_reservation(SOURCE_PLAINTEXT_BOUND).expect("bound source"),
            RESERVATION_CAP
        );
        assert_eq!(
            compute_reservation(1).expect("small source"),
            MIN_RESERVATION
        );
        assert_eq!(
            compute_reservation(2 * GIB).expect("doubled minimum"),
            MIN_RESERVATION
        );
        assert_eq!(
            compute_reservation(3 * GIB).expect("mid source"),
            2 * 3 * GIB + GIB
        );
        assert_eq!(
            compute_reservation(SOURCE_PLAINTEXT_BOUND + 1),
            Err(ReservationError::SourceBoundExceeded {
                source_bytes: SOURCE_PLAINTEXT_BOUND + 1
            })
        );
        assert_eq!(
            compute_reservation(u64::MAX),
            Err(ReservationError::SourceBoundExceeded {
                source_bytes: u64::MAX
            })
        );
    }

    #[test]
    fn space_boundaries_never_truncate_the_reservation() {
        assert_eq!(
            reserve_with_available(0, MIN_RESERVATION).expect("exact minimum"),
            Reservation {
                source_bytes: 0,
                reserved_bytes: MIN_RESERVATION
            }
        );
        assert_eq!(
            reserve_with_available(SOURCE_PLAINTEXT_BOUND, RESERVATION_CAP).expect("exact cap"),
            Reservation {
                source_bytes: SOURCE_PLAINTEXT_BOUND,
                reserved_bytes: RESERVATION_CAP
            }
        );
        assert_eq!(
            reserve_with_available(SOURCE_PLAINTEXT_BOUND, RESERVATION_CAP - 1),
            Err(ReservationError::SpaceUnavailable {
                reserved_bytes: RESERVATION_CAP,
                available_bytes: RESERVATION_CAP - 1
            })
        );
        assert_eq!(
            reserve_with_available(0, MIN_RESERVATION - 1),
            Err(ReservationError::SpaceUnavailable {
                reserved_bytes: MIN_RESERVATION,
                available_bytes: MIN_RESERVATION - 1
            })
        );
    }

    #[test]
    fn measures_regular_files_in_a_real_directory() {
        let root = fixture_dir();
        let first = root.join("state.sqlite");
        let second = root.join("o3kd.env");
        fs::write(&first, vec![0_u8; 4096]).expect("write first source");
        fs::write(&second, vec![0_u8; 2048]).expect("write second source");

        let measured = measure_source_bytes([first.as_path(), second.as_path()])
            .expect("measure regular sources");
        assert_eq!(measured, 6144);

        let reservation = preflight_reservation(&[&first, &second], &root)
            .expect("real preflight on a writable temporary directory");
        assert_eq!(reservation.source_bytes, 6144);
        assert_eq!(reservation.reserved_bytes, MIN_RESERVATION);

        fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn rejects_symlinked_or_non_regular_sources() {
        let root = fixture_dir();
        let file = root.join("state.sqlite");
        fs::write(&file, b"state").expect("write source");
        let link = root.join("state-link.sqlite");
        std::os::unix::fs::symlink(&file, &link).expect("create source symlink");

        assert_eq!(
            measure_source_bytes([link.as_path()]),
            Err(ReservationError::Measurement(
                REASON_SOURCE_SYMLINK.to_owned()
            ))
        );
        assert_eq!(
            measure_source_bytes([root.as_path()]),
            Err(ReservationError::Measurement(
                REASON_SOURCE_NOT_REGULAR.to_owned()
            ))
        );
        assert_eq!(
            measure_source_bytes([root.join("absent").as_path()]),
            Err(ReservationError::Measurement(
                REASON_SOURCE_UNAVAILABLE.to_owned()
            ))
        );

        fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn reports_stable_reason_strings() {
        assert_eq!(
            ReservationError::SourceBoundExceeded { source_bytes: 1 }.reason(),
            "source-bound-exceeded"
        );
        assert_eq!(
            ReservationError::ReservationCapExceeded { reserved_bytes: 1 }.reason(),
            "reservation-cap-exceeded"
        );
        assert_eq!(
            ReservationError::SpaceUnavailable {
                reserved_bytes: 1,
                available_bytes: 0
            }
            .reason(),
            "space-unavailable"
        );
        assert_eq!(
            ReservationError::Measurement(REASON_SOURCE_SYMLINK.to_owned()).reason(),
            "measurement-failed"
        );
        assert_eq!(
            ReservationError::StagedExceedsReservation {
                staged_bytes: 2,
                reserved_bytes: 1
            }
            .reason(),
            "staging-quota-exceeded"
        );
        assert_eq!(
            ReservationError::StagingHoldUnavailable.reason(),
            "staging-hold-unavailable"
        );
    }

    #[test]
    fn boundary_recheck_never_truncates_the_remaining_reservation() {
        let root = fixture_dir();
        // A real filesystem always has more free space than this; the fixture
        // only proves the arithmetic and the fail-closed direction.
        assert_eq!(ensure_reserved_space(&root, MIN_RESERVATION, 0), Ok(()));
        assert_eq!(
            ensure_reserved_space(&root, MIN_RESERVATION, MIN_RESERVATION - 1),
            Ok(()),
            "space already staged is deducted from the remaining requirement"
        );
        assert_eq!(
            ensure_reserved_space(&root, u64::MAX, 0),
            Err(ReservationError::SpaceUnavailable {
                reserved_bytes: u64::MAX,
                available_bytes: available_bytes(&root).expect("filesystem statistics"),
            })
        );
        assert_eq!(
            ensure_reserved_space(&root, u64::MAX, 0)
                .expect_err("impossible reservation")
                .reason(),
            "space-unavailable"
        );
        fs::remove_dir_all(root).expect("remove fixture directory");
    }
}
