//! Release version parsing and prerelease-aware ordering (issue #626).
//!
//! O3K release versions are semver `MAJOR.MINOR.PATCH` with an optional dot
//! separated prerelease (for example `0.3.0-alpha.1`). A single optional `v`
//! prefix is accepted on input; `Display` never emits it. The comparison
//! follows the semver precedence rules the release fence depends on:
//! `0.4.0-alpha.1 < 0.4.0` and `alpha < beta` for equal core versions.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// A parsed O3K release version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReleaseVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Dot-separated prerelease identifiers (empty for a stable release).
    pub prerelease: Vec<String>,
}

impl ReleaseVersion {
    /// Builds a version from its components.
    #[must_use]
    pub fn new(major: u64, minor: u64, patch: u64, prerelease: Vec<String>) -> Self {
        Self {
            major,
            minor,
            patch,
            prerelease,
        }
    }

    /// Whether this version carries a prerelease tag.
    #[must_use]
    pub fn is_prerelease(&self) -> bool {
        !self.prerelease.is_empty()
    }

    /// Release channel family. O3K ships `alpha` and `beta` prereleases and
    /// `rc` release candidates; a stable release (no prerelease) is `stable`.
    /// An `rc` prerelease is treated as `stable`-family (it is a candidate
    /// FOR the stable line): upgrading from an alpha/beta install to an rc
    /// target is a cross-channel path and remains fenced. Unknown prerelease
    /// identifiers must not accidentally pattern-match the alpha fence.
    #[must_use]
    pub fn channel(&self) -> &'static str {
        match self.prerelease.first().map(String::as_str) {
            Some("alpha") => "alpha",
            Some("beta") => "beta",
            None => "stable",
            Some(_) => "stable",
        }
    }
}

/// Error produced while parsing a release version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionParseError {
    message: String,
}

impl fmt::Display for VersionParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl FromStr for ReleaseVersion {
    type Err = VersionParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_version(text)
    }
}

/// Validates one semver identifier (core component or prerelease
/// identifier): non-empty, alphanumeric or `-`, no leading zeros for
/// all-digit identifiers.
fn validate_identifier(identifier: &str) -> Result<(), VersionParseError> {
    if identifier.is_empty() {
        return Err(invalid("empty version identifier"));
    }
    if !identifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(invalid("version identifier contains invalid characters"));
    }
    if identifier.len() > 1
        && identifier.starts_with('0')
        && identifier.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid("numeric version identifier has leading zeros"));
    }
    Ok(())
}

fn invalid(what: &str) -> VersionParseError {
    VersionParseError {
        message: format!("invalid release version: {what}"),
    }
}

/// Parses `[v]MAJOR.MINOR.PATCH[-prerelease]`. Build metadata (`+...`) is
/// rejected: O3K releases never carry it.
fn parse_version(text: &str) -> Result<ReleaseVersion, VersionParseError> {
    let stripped = text.strip_prefix('v').unwrap_or(text);
    if stripped.is_empty() || stripped.contains('+') || stripped.contains(char::is_whitespace) {
        return Err(invalid("expected [v]MAJOR.MINOR.PATCH[-prerelease]"));
    }
    let (core, prerelease_text) = match stripped.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (stripped, None),
    };
    let mut parts = core.split('.');
    let major = parts
        .next()
        .ok_or_else(|| invalid("missing major component"))?;
    let minor = parts
        .next()
        .ok_or_else(|| invalid("missing minor component"))?;
    let patch = parts
        .next()
        .ok_or_else(|| invalid("missing patch component"))?;
    if parts.next().is_some() {
        return Err(invalid("too many core components"));
    }
    validate_identifier(major)?;
    validate_identifier(minor)?;
    validate_identifier(patch)?;
    let parse_component = |component: &str| {
        component
            .parse::<u64>()
            .map_err(|_| invalid("core component is not a number"))
    };
    let parsed = ReleaseVersion {
        major: parse_component(major)?,
        minor: parse_component(minor)?,
        patch: parse_component(patch)?,
        prerelease: Vec::new(),
    };
    let Some(prerelease_text) = prerelease_text else {
        return Ok(parsed);
    };
    if prerelease_text.is_empty() {
        return Err(invalid("empty prerelease"));
    }
    let mut prerelease = Vec::new();
    for identifier in prerelease_text.split('.') {
        validate_identifier(identifier)?;
        prerelease.push(identifier.to_owned());
    }
    let parsed = ReleaseVersion {
        major: parse_component(major)?,
        minor: parse_component(minor)?,
        patch: parse_component(patch)?,
        prerelease,
    };
    Ok(parsed)
}

impl fmt::Display for ReleaseVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.prerelease.is_empty() {
            write!(formatter, "-{}", self.prerelease.join("."))?;
        }
        Ok(())
    }
}

/// Compares two prerelease identifiers following semver precedence: both
/// numeric → numeric comparison; numeric < alphanumeric; both alphanumeric →
/// ASCII lexical comparison.
fn compare_identifiers(left: &str, right: &str) -> Ordering {
    let left_numeric = left.bytes().all(|byte| byte.is_ascii_digit());
    let right_numeric = right.bytes().all(|byte| byte.is_ascii_digit());
    match (left_numeric, right_numeric) {
        (true, true) => {
            // Both are digit strings without leading zeros, so length is a
            // faithful numeric order proxy; the fallback parse never fails.
            left.len().cmp(&right.len()).then_with(|| left.cmp(right))
        }
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => left.cmp(right),
    }
}

impl PartialOrd for ReleaseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReleaseVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| {
                // A release without prerelease outranks the same core version
                // with one (0.4.0-alpha.1 < 0.4.0).
                match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
                    (true, false) => Ordering::Greater,
                    (false, true) => Ordering::Less,
                    (true, true) | (false, false) => {
                        for (left, right) in self.prerelease.iter().zip(&other.prerelease) {
                            let ordering = compare_identifiers(left, right);
                            if ordering != Ordering::Equal {
                                return ordering;
                            }
                        }
                        // A shorter prerelease list that is a prefix of the
                        // other sorts first (alpha < alpha.1).
                        self.prerelease.len().cmp(&other.prerelease.len())
                    }
                }
            })
    }
}

impl Serialize for ReleaseVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ReleaseVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_constants)]
    use super::*;

    fn parse(text: &str) -> Option<ReleaseVersion> {
        text.parse().ok()
    }

    fn prerelease(identifiers: &[&str]) -> Vec<String> {
        identifiers.iter().map(|id| (*id).to_owned()).collect()
    }

    /// Plain and `v`-prefixed core versions parse to the same value.
    #[test]
    fn parses_plain_and_v_prefixed_versions() {
        assert_eq!(
            parse("0.3.0"),
            Some(ReleaseVersion::new(0, 3, 0, Vec::new()))
        );
        assert_eq!(
            parse("v0.3.0"),
            Some(ReleaseVersion::new(0, 3, 0, Vec::new()))
        );
        assert_eq!(
            parse("1.2.3"),
            Some(ReleaseVersion::new(1, 2, 3, Vec::new()))
        );
    }

    /// Prerelease identifiers parse and keep their exact spelling.
    #[test]
    fn parses_prerelease_versions() {
        assert_eq!(
            parse("0.3.0-alpha.1"),
            Some(ReleaseVersion::new(0, 3, 0, prerelease(&["alpha", "1"])))
        );
        assert_eq!(
            parse("v0.4.0-beta.2"),
            Some(ReleaseVersion::new(0, 4, 0, prerelease(&["beta", "2"])))
        );
    }

    /// Malformed input is rejected, never silently truncated.
    #[test]
    fn rejects_malformed_versions() {
        for malformed in [
            "",
            "v",
            "0.3",
            "0.3.0.1",
            "0.3.0-",
            "0.3.0-alpha..1",
            "0.3.0-alpha.01",
            "01.2.3",
            "0.3.0+build",
            "0.3.0 alpha",
            "a.b.c",
            "1.2.x",
            "0.3.0-alpha_1",
            "0.3.0.alpha.1",
        ] {
            assert!(
                parse(malformed).is_none(),
                "expected {malformed:?} to be rejected"
            );
        }
    }

    /// Display round-trips through the parser and never emits a `v` prefix.
    #[test]
    fn display_round_trips() {
        for text in ["0.3.0", "0.3.0-alpha.1", "0.4.0-beta.2"] {
            let Some(version) = parse(text) else {
                assert!(false, "must parse {text}");
                return;
            };
            assert_eq!(version.to_string(), text, "display must round-trip");
        }
        assert_eq!(
            parse("v0.3.0-alpha.1").map(|version| version.to_string()),
            Some("0.3.0-alpha.1".to_owned()),
            "Display must not emit the v prefix"
        );
    }

    /// A prerelease of the same core version sorts below the stable release.
    #[test]
    fn prerelease_orders_below_stable() {
        assert!(
            parse("0.4.0-alpha.1") < parse("0.4.0"),
            "0.4.0-alpha.1 must sort below 0.4.0"
        );
        assert!(parse("0.4.0") > parse("0.4.0-beta.9"));
    }

    /// Within one channel, numeric identifiers compare numerically.
    #[test]
    fn alpha_identifiers_compare_numerically() {
        assert!(parse("0.4.0-alpha.1") < parse("0.4.0-alpha.2"));
        assert!(parse("0.4.0-alpha.10") > parse("0.4.0-alpha.2"));
        assert!(parse("0.4.0-alpha.1") < parse("0.4.0-alpha.10"));
    }

    /// Alpha sorts below beta for equal core versions.
    #[test]
    fn alpha_orders_below_beta() {
        assert!(
            parse("0.4.0-alpha.9") < parse("0.4.0-beta.1"),
            "alpha must sort below beta"
        );
        assert!(parse("0.4.0-beta.1") < parse("0.4.0"));
    }

    /// Core-version differences dominate prerelease differences.
    #[test]
    fn core_version_dominates_prerelease() {
        assert!(parse("0.3.0") < parse("0.4.0-alpha.1"));
        assert!(parse("0.4.0-alpha.1") < parse("0.4.1-alpha.1"));
        assert!(parse("0.4.0-alpha.1") < parse("0.4.1"));
        assert!(parse("0.9.9") < parse("1.0.0-alpha.1"));
    }

    /// Alphanumeric and numeric identifiers follow semver precedence.
    #[test]
    fn mixed_identifier_kinds_compare_by_semver_rules() {
        assert!(parse("0.4.0-alpha.1") < parse("0.4.0-alpha.beta"));
        assert!(parse("0.4.0-alpha.beta") > parse("0.4.0-alpha.1"));
        assert!(parse("0.4.0-alpha.aa") < parse("0.4.0-alpha.ab"));
    }

    /// A shorter prerelease list that prefixes another sorts first.
    #[test]
    fn prefix_prerelease_sorts_first() {
        assert!(
            parse("0.4.0-alpha") < parse("0.4.0-alpha.1"),
            "a prefix prerelease must sort first"
        );
        assert!(parse("0.4.0-alpha.1.1") > parse("0.4.0-alpha.1"));
    }

    /// Channel-family classification for the fence.
    #[test]
    fn channel_classification() {
        assert_eq!(parse("0.3.0-alpha.1").map(|v| v.channel()), Some("alpha"));
        assert_eq!(parse("0.3.0-alpha").map(|v| v.channel()), Some("alpha"));
        assert_eq!(parse("0.3.0-beta.1").map(|v| v.channel()), Some("beta"));
        assert_eq!(parse("0.3.0").map(|v| v.channel()), Some("stable"));
        assert_eq!(
            parse("0.3.0-rc.1").map(|v| v.channel()),
            Some("stable"),
            "unknown prerelease families classify as stable"
        );
    }

    /// Versions serialize as their Display string and deserialize back.
    #[test]
    fn serde_round_trips_through_strings() {
        let version = ReleaseVersion::new(0, 3, 0, prerelease(&["alpha", "1"]));
        let serialized = match serde_json::to_string(&version) {
            Ok(serialized) => serialized,
            Err(error) => {
                assert!(serde_json::to_string(&version).is_ok(), "{error}");
                return;
            }
        };
        assert_eq!(serialized, "\"0.3.0-alpha.1\"");
        let parsed: ReleaseVersion = match serde_json::from_str(&serialized) {
            Ok(parsed) => parsed,
            Err(error) => {
                assert!(
                    serde_json::from_str::<ReleaseVersion>(&serialized).is_ok(),
                    "{error}"
                );
                return;
            }
        };
        assert_eq!(parsed, version);
        assert!(
            serde_json::from_str::<ReleaseVersion>("\"not-a-version\"").is_err(),
            "invalid versions must fail deserialization"
        );
    }

    /// Ordering is total and reflexive over a spread of versions.
    #[test]
    fn ordering_is_total_over_a_spread() {
        let versions = [
            "0.2.0-alpha.1",
            "0.2.0-alpha.2",
            "0.2.0-beta.1",
            "0.2.0",
            "0.3.0-alpha.1",
            "0.3.0",
            "0.4.0-alpha.1",
            "0.4.0",
            "1.0.0",
        ]
        .iter()
        .filter_map(|text| parse(text))
        .collect::<Vec<_>>();
        for left in &versions {
            for right in &versions {
                let ordering = left.cmp(right);
                if left == right {
                    assert_eq!(ordering, Ordering::Equal, "{left} vs {right}");
                } else {
                    assert_eq!(
                        ordering,
                        right.cmp(left).reverse(),
                        "ordering must be antisymmetric for {left} vs {right}"
                    );
                }
            }
        }
        let mut sorted = versions.clone();
        sorted.sort();
        assert_eq!(
            sorted.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [
                "0.2.0-alpha.1",
                "0.2.0-alpha.2",
                "0.2.0-beta.1",
                "0.2.0",
                "0.3.0-alpha.1",
                "0.3.0",
                "0.4.0-alpha.1",
                "0.4.0",
                "1.0.0",
            ]
        );
    }
}
