//! Cloud/API checks: service discovery endpoints and the bootstrap
//! test-vm status.

use crate::checks::{database_read_failure, o3kd_actions};
use crate::context::Context;
use crate::output::{Category, Check, CheckStatus};

/// `cloud.api_discovery`: both `/v3` (Keystone) and `/placement` discovery
/// endpoints must answer 200.
pub async fn check_api_discovery(ctx: &Context) -> Check {
    let mut failures = Vec::new();
    let mut unreachable = false;
    for endpoint in ["/v3", "/placement"] {
        let url = format!("http://{}{}", ctx.listen_addr, endpoint);
        match ctx.http.get(&url).await {
            Ok(response) if response.status == 200 => {}
            Ok(response) => failures.push(format!("{endpoint}: HTTP {}", response.status)),
            Err(error) => {
                unreachable = true;
                failures.push(format!("{endpoint}: {error}"));
            }
        }
    }
    if failures.is_empty() {
        return Check::new(
            "cloud.api_discovery",
            Category::Cloud,
            CheckStatus::Pass,
            "service discovery endpoints answer",
        );
    }
    let status = if unreachable {
        CheckStatus::Fail
    } else {
        CheckStatus::Warn
    };
    Check::new(
        "cloud.api_discovery",
        Category::Cloud,
        status,
        if unreachable {
            "control plane API unreachable"
        } else {
            "service discovery endpoints answered unexpectedly"
        },
    )
    .with_details(failures.join("\n"))
    .with_actions(o3kd_actions())
}

/// `cloud.testvm_status`: bootstrap test-vm resources must all be ACTIVE.
/// States are listed, never names' credentials.
pub async fn check_testvm_status(ctx: &Context) -> Check {
    if ctx.is_postgres() || !ctx.exec.is_regular_file(&ctx.database_path()) {
        return Check::new(
            "cloud.testvm_status",
            Category::Cloud,
            CheckStatus::NotApplicable,
            "no bootstrap test-vm resources",
        );
    }
    let instances = match ctx.db.compute_instances(&ctx.database_path()).await {
        Ok(instances) => instances,
        Err(_) => {
            return database_read_failure(
                "cloud.testvm_status",
                Category::Cloud,
                "compute instances",
                o3kd_actions(),
            );
        }
    };
    let test_vms: Vec<&crate::db::InstanceRow> = instances
        .iter()
        .filter(|instance| instance.name.starts_with("test-vm"))
        .collect();
    if test_vms.is_empty() {
        return Check::new(
            "cloud.testvm_status",
            Category::Cloud,
            CheckStatus::NotApplicable,
            "no bootstrap test-vm resources",
        );
    }
    let active = test_vms
        .iter()
        .all(|instance| instance.observed_state.eq_ignore_ascii_case("active"));
    if active {
        return Check::new(
            "cloud.testvm_status",
            Category::Cloud,
            CheckStatus::Pass,
            format!("{} bootstrap test-vm resource(s) ACTIVE", test_vms.len()),
        );
    }
    let states: Vec<String> = test_vms
        .iter()
        .map(|instance| format!("{}: {}", instance.name, instance.observed_state))
        .collect();
    Check::new(
        "cloud.testvm_status",
        Category::Cloud,
        CheckStatus::Warn,
        "bootstrap test-vm resources are not all ACTIVE",
    )
    .with_details(states.join("\n"))
    .with_actions(vec![
        "openstack server list".to_owned(),
        "journalctl -u o3kd -n 100".to_owned(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeDb, FakeExec, FakeHttp, context_with};

    fn context(db: FakeDb) -> Context {
        context_with(FakeExec::healthy(), FakeHttp::healthy(), db, true, true)
    }

    #[tokio::test]
    async fn api_discovery_passes_when_both_endpoints_200() {
        let check = check_api_discovery(&context(FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[tokio::test]
    async fn api_discovery_fails_when_unreachable() {
        let mut http = FakeHttp::healthy();
        http.with(
            "GET http://127.0.0.1:8080/placement",
            Err("connection refused".to_owned()),
        );
        let ctx = context_with(FakeExec::healthy(), http, FakeDb::healthy(), true, true);
        let check = check_api_discovery(&ctx).await;
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[tokio::test]
    async fn testvm_status_passes_when_active() {
        let check = check_testvm_status(&context(FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[tokio::test]
    async fn testvm_status_warns_when_not_active() {
        let mut db = FakeDb::healthy();
        for instance in &mut db.instances {
            instance.observed_state = "building".to_owned();
        }
        let check = check_testvm_status(&context(db)).await;
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(
            check
                .details
                .as_deref()
                .is_some_and(|d| d.contains("building"))
        );
    }

    #[tokio::test]
    async fn testvm_status_not_applicable_without_test_vms() {
        let mut db = FakeDb::healthy();
        db.instances.clear();
        let check = check_testvm_status(&context(db)).await;
        assert_eq!(check.status, CheckStatus::NotApplicable);
    }
}
