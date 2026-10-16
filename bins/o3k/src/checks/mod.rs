//! The 34 doctor checks, grouped by output category. Each check is a
//! `pub async fn check(ctx: &Context) -> Check`; internal errors are always
//! converted to a sanitized FAIL, never a panic.

pub mod cloud;
pub mod compute;
pub mod control;
pub mod database;
pub mod host;
pub mod identity;
pub mod libvirt;
pub mod network;
pub mod release;
pub mod security;
pub mod services;

use crate::context::{Context, sanitize_error};
use crate::output::{Category, Check, CheckStatus};

/// Converts an internal check error into a FAIL with a sanitized summary.
#[must_use]
pub fn internal_failure(
    id: &str,
    category: Category,
    what: &str,
    error: &str,
    actions: Vec<String>,
) -> Check {
    Check::new(
        id,
        category,
        CheckStatus::Fail,
        format!(
            "internal error while checking {what}: {}",
            sanitize_error(error)
        ),
    )
    .with_actions(actions)
}

/// Converts a failed read-only store query into a FAIL without copying the
/// backend error text, which can carry connection details or stored values.
#[must_use]
pub fn database_read_failure(
    id: &str,
    category: Category,
    what: &str,
    actions: Vec<String>,
) -> Check {
    Check::new(
        id,
        category,
        CheckStatus::Fail,
        format!("internal error while checking {what}: database read failed"),
    )
    .with_details(
        "the doctor's read-only database query failed; the backend error text is \
         withheld because it can contain connection details. Review the database.* \
         checks for the database path and permissions.",
    )
    .with_actions(actions)
}

/// Standard read-only actions for the control-plane daemon.
#[must_use]
pub fn o3kd_actions() -> Vec<String> {
    vec![
        "systemctl status o3kd".to_owned(),
        "journalctl -u o3kd -n 100".to_owned(),
    ]
}

/// Standard read-only actions for the compute agent.
#[must_use]
pub fn compute_actions() -> Vec<String> {
    vec![
        "systemctl status o3k-compute".to_owned(),
        "journalctl -u o3k-compute -n 100".to_owned(),
    ]
}

/// The stable libvirt domain name of an O3K server, mirroring
/// `o3k-libvirt::stable_domain_name`: `o3k-` plus the first 20 lowercase hex
/// characters of the SHA-256 of the server id string.
#[must_use]
pub fn stable_domain_name(server_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(server_id.as_bytes());
    let mut hex = String::with_capacity(40);
    for byte in digest.iter().take(10) {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("o3k-{hex}")
}

/// Whether a libvirt domain name follows the O3K managed naming pattern.
#[must_use]
pub fn is_o3k_domain_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("o3k-") else {
        return false;
    };
    suffix.len() == 20 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True when a context belongs to the installed libvirt profile.
#[must_use]
pub fn not_libvirt_profile(ctx: &Context) -> bool {
    !ctx.libvirt_profile
}

/// Builds the standard NOT_APPLICABLE check for the compute-agent profile.
#[must_use]
pub fn profile_not_applicable(id: &str, category: Category) -> Check {
    Check::new(
        id,
        category,
        CheckStatus::NotApplicable,
        "the compute agent is not part of this installation profile",
    )
}

#[cfg(test)]
mod database_read_redaction_tests {
    use crate::output::{CheckStatus, OverallStatus, Report};
    use crate::testutil::{FakeDb, FakeExec, FakeHttp, context_with};

    /// Every check that reads canonical rows must report a failed read without
    /// copying the backend error text, in both JSON and human output.
    #[tokio::test]
    async fn failed_row_reads_are_secret_safe_in_json_and_human_output() {
        let sentinel = "postgres://user:sentinel-secret@db.example/o3k: relation leaked";
        // Every canonical row read a check performs, failed one at a time, so
        // a later read in a check is reached after the earlier ones succeed.
        let reads: [(&str, &str); 9] = [
            ("compute.agent_epoch", "latest_epochs"),
            ("compute.agent_capabilities", "placement_providers"),
            ("compute.agent_capabilities", "placement_inventories"),
            ("compute.placement_consistent", "placement_providers"),
            ("compute.placement_consistent", "placement_inventories"),
            ("compute.placement_consistent", "live_allocation_resources"),
            ("cloud.testvm_status", "compute_instances"),
            ("network.ownership_records", "compute_instances"),
            ("libvirt.domains_consistent", "compute_instances"),
        ];
        let mut checks = Vec::new();
        for (id, read) in reads {
            let db = FakeDb {
                read_error: Some(sentinel.to_owned()),
                read_error_only: Some(read),
                ..FakeDb::healthy()
            };
            let ctx = context_with(FakeExec::healthy(), FakeHttp::healthy(), db, true, true);
            let check = match id {
                "compute.agent_epoch" => super::compute::check_agent_epoch(&ctx).await,
                "compute.agent_capabilities" => {
                    super::compute::check_agent_capabilities(&ctx).await
                }
                "compute.placement_consistent" => {
                    super::compute::check_placement_consistent(&ctx).await
                }
                "cloud.testvm_status" => super::cloud::check_testvm_status(&ctx).await,
                "network.ownership_records" => super::network::check_ownership_records(&ctx).await,
                _ => super::libvirt::check_domains_consistent(&ctx).await,
            };
            assert_eq!(check.id, id);
            assert_eq!(check.status, CheckStatus::Fail, "{id} / {read}");
            assert!(
                check.summary.contains("database read failed"),
                "{id} did not reach its {read} read: {}",
                check.summary
            );
            assert!(!check.recommended_actions.is_empty(), "{id} / {read}");
            checks.push(check);
        }

        let report = Report {
            version: "test".to_owned(),
            overall_status: OverallStatus::Unhealthy,
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            checks,
        };
        let json = serde_json::to_string(&report).unwrap_or_default();
        let human = report.render_human();
        assert!(!json.is_empty());
        for leaked in ["sentinel-secret", "postgres://", "relation leaked"] {
            assert!(!json.contains(leaked), "JSON output leaked {leaked}");
            assert!(!human.contains(leaked), "human output leaked {leaked}");
        }
    }
}
