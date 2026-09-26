//! Process-level CLI tests for the `o3k` binary.
//!
//! Hermetic by construction: the assertions never depend on `/etc/o3k` or a
//! real installation existing. `doctor --json` must always emit a valid JSON
//! document on stdout regardless of the host state, exiting 0 (healthy) or
//! 1 (warning/unhealthy).
#![allow(clippy::panic)]

use std::process::Command;

/// Runs the binary and returns (exit code, stdout, stderr).
///
/// A failure to *execute* the binary is a harness defect, not product
/// behaviour, so it panics with the underlying error instead of reporting a
/// synthetic exit code that hides the cause. (`--version` and friends must
/// always be runnable; if they are not, the test has nothing to say about the
/// CLI.)
fn run(args: &[&str]) -> (i32, String, String) {
    let binary = env!("CARGO_BIN_EXE_o3k");
    match Command::new(binary).args(args).output() {
        Ok(output) => (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ),
        Err(error) => panic!("could not execute the o3k binary at {binary}: {error}"),
    }
}

/// `o3k --version` prints `o3k <version>` on stdout and exits 0.
#[test]
fn version_prints_version_and_exits_zero() {
    let (code, stdout, _stderr) = run(&["--version"]);
    assert_eq!(code, 0, "o3k --version must exit 0");
    assert_eq!(
        stdout.trim(),
        format!("o3k {}", env!("CARGO_PKG_VERSION")),
        "o3k --version must print the package version"
    );
}

/// `o3k` with no arguments prints usage on stderr and exits 2.
#[test]
fn no_arguments_exits_two_with_usage() {
    let (code, _stdout, stderr) = run(&[]);
    assert_eq!(code, 2, "o3k with no arguments must exit 2");
    assert!(
        stderr.contains("Usage") || stderr.contains("doctor"),
        "usage must mention available commands"
    );
}

/// `o3k --help` prints usage on stdout and exits 0.
#[test]
fn help_exits_zero() {
    let (code, stdout, _stderr) = run(&["--help"]);
    assert_eq!(code, 0, "o3k --help must exit 0");
    assert!(
        stdout.contains("doctor") || stdout.contains("Commands"),
        "help must mention available commands"
    );
}

/// `o3k help` behaves like `--help`.
#[test]
fn help_subcommand_exits_zero() {
    let (code, stdout, _stderr) = run(&["help"]);
    assert_eq!(code, 0, "o3k help must exit 0");
    assert!(stdout.contains("Usage"), "help must print usage");
}

/// `o3k doctor --help` prints subcommand help on stdout and exits 0.
#[test]
fn doctor_help_exits_zero() {
    let (code, stdout, _stderr) = run(&["doctor", "--help"]);
    assert_eq!(code, 0, "o3k doctor --help must exit 0");
    assert!(stdout.contains("doctor"), "doctor help must be printed");
}

/// Unknown commands are usage errors (exit 2).
#[test]
fn unknown_command_exits_two() {
    let (code, _stdout, stderr) = run(&["frobnicate"]);
    assert_eq!(code, 2, "unknown commands must exit 2");
    assert!(
        stderr.contains("unrecognized") || stderr.contains("error"),
        "stderr must name the error"
    );
}

/// `o3k doctor --json` always emits a JSON document on stdout and exits
/// 0 or 1, even when no /etc/o3k installation exists on this host.
#[test]
fn doctor_json_emits_contract_json_without_an_install() {
    let (code, stdout, _stderr) = run(&["doctor", "--json"]);
    assert!(
        code == 0 || code == 1,
        "doctor --json must exit 0 (healthy) or 1 (warning/unhealthy), got {code}"
    );
    let value: serde_json::Value = match serde_json::from_str(&stdout) {
        Ok(value) => value,
        Err(error) => {
            assert!(
                serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
                "doctor --json must emit valid JSON: {error}"
            );
            return;
        }
    };
    let object = match value.as_object() {
        Some(object) => object,
        None => {
            assert!(
                value.is_object(),
                "doctor --json output must be a JSON object"
            );
            return;
        }
    };
    for key in ["version", "overall_status", "timestamp", "checks"] {
        assert!(
            object.contains_key(key),
            "doctor --json output must contain {key}"
        );
    }
    let checks = match object.get("checks").and_then(serde_json::Value::as_array) {
        Some(checks) => checks,
        None => {
            assert!(
                object
                    .get("checks")
                    .is_some_and(serde_json::Value::is_array),
                "doctor --json checks must be an array"
            );
            return;
        }
    };
    assert_eq!(checks.len(), 36, "doctor must run exactly 36 checks");
}

/// `o3k doctor` (human output) exits 0 or 1 and ends with the OVERALL line.
#[test]
fn doctor_human_output_ends_with_overall() {
    let (code, stdout, _stderr) = run(&["doctor"]);
    assert!(
        code == 0 || code == 1,
        "doctor must exit 0 or 1, got {code}"
    );
    assert!(
        stdout.starts_with("O3K Doctor v"),
        "human output must start with the header"
    );
    assert!(
        stdout.trim_end().ends_with("HEALTHY")
            || stdout.trim_end().ends_with("WARNING")
            || stdout.trim_end().ends_with("UNHEALTHY"),
        "human output must end with the OVERALL verdict"
    );
}
