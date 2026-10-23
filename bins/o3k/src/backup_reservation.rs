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

use std::{fmt, path::Path};

use rustix::fs::statvfs;

const GIB: u64 = 1024 * 1024 * 1024;

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
            Self::Measurement(_) => "measurement-failed",
        }
    }

    /// Stable measurement code when this is a [`Self::Measurement`] failure.
    #[must_use]
    pub fn measurement_code(&self) -> Option<&str> {
        match self {
            Self::Measurement(code) => Some(code),
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
    let statistics = statvfs(destination)
        .map_err(|_| ReservationError::Measurement(REASON_DESTINATION_UNAVAILABLE.to_owned()))?;
    let available_bytes = statistics
        .f_bavail
        .checked_mul(statistics.f_frsize)
        .ok_or_else(|| {
            ReservationError::Measurement(REASON_FILESYSTEM_STATISTICS_OVERFLOW.to_owned())
        })?;
    reserve_with_available(source_bytes, available_bytes)
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
    }
}
