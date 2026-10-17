//! Libvirt/KVM checks: identity separation, and consistency between
//! libvirt domains and durable compute instances.

use crate::checks::{
    compute_actions, database_read_failure, internal_failure, is_o3k_domain_name,
    not_libvirt_profile, profile_not_applicable, stable_domain_name,
};
use crate::context::Context;
use crate::output::{Category, Check, CheckStatus};
use std::collections::{BTreeMap, BTreeSet};

/// Observed server states that imply a libvirt domain exists on the host
/// (mirrors `o3k-domain::ServerState`). `deleting` is included because
/// deletion cannot be cancelled once started, so its domain must exist
/// until the delete converges.
const DOMAIN_REQUIRED_STATES: [&str; 7] = [
    "active",
    "error",
    "stopped",
    "stopping",
    "starting",
    "rebooting",
    "deleting",
];

/// `libvirt.compute_access`: the `o3k-compute` identity must be able to open
/// `qemu:///system` (verified through the exec seam as root).
pub async fn check_compute_access(ctx: &Context) -> Check {
    if ctx.is_kubernetes() {
        return Check::new(
            "libvirt.compute_access",
            Category::Libvirt,
            CheckStatus::NotApplicable,
            "local libvirt access check is not applicable for Kubernetes control plane; compute agents run on external hypervisors",
        );
    }
    if not_libvirt_profile(ctx) {
        return profile_not_applicable("libvirt.compute_access", Category::Libvirt);
    }
    if !ctx.is_root {
        return Check::new(
            "libvirt.compute_access",
            Category::Libvirt,
            CheckStatus::NotApplicable,
            "run with sudo to check identity separation",
        );
    }
    match ctx.exec.virsh_uri(Some("o3k-compute")).await {
        Ok(_) => Check::new(
            "libvirt.compute_access",
            Category::Libvirt,
            CheckStatus::Pass,
            "compute identity can access qemu:///system",
        ),
        Err(error) => Check::new(
            "libvirt.compute_access",
            Category::Libvirt,
            CheckStatus::Fail,
            format!("compute identity cannot access qemu:///system: {error}"),
        )
        .with_actions(vec![
            "id o3k-compute".to_owned(),
            "systemctl status libvirtd".to_owned(),
        ]),
    }
}

/// `libvirt.control_isolation`: the `o3k` control identity must be denied by
/// libvirt; success is a boundary breach.
pub async fn check_control_isolation(ctx: &Context) -> Check {
    if ctx.is_kubernetes() {
        return Check::new(
            "libvirt.control_isolation",
            Category::Libvirt,
            CheckStatus::Pass,
            "control plane has no libvirt socket access (container isolated)",
        );
    }
    if not_libvirt_profile(ctx) {
        return profile_not_applicable("libvirt.control_isolation", Category::Libvirt);
    }
    if !ctx.is_root {
        return Check::new(
            "libvirt.control_isolation",
            Category::Libvirt,
            CheckStatus::NotApplicable,
            "run with sudo to check identity separation",
        );
    }
    match ctx.exec.virsh_uri(Some("o3k")).await {
        Err(_) => Check::new(
            "libvirt.control_isolation",
            Category::Libvirt,
            CheckStatus::Pass,
            "control identity correctly denied",
        ),
        Ok(_) => Check::new(
            "libvirt.control_isolation",
            Category::Libvirt,
            CheckStatus::Fail,
            "control identity can access libvirt: boundary breach",
        )
        .with_actions(vec![
            "check /etc/polkit-1/rules.d/50-o3k-libvirt.rules".to_owned(),
            "journalctl -u libvirtd -n 100".to_owned(),
        ]),
    }
}

/// `libvirt.domains_consistent`: every live instance whose state implies a
/// running domain must have its `o3k-<sha256>` domain present; O3K-patterned
/// domains without a live instance are foreign same-name leftovers (WARN).
pub async fn check_domains_consistent(ctx: &Context) -> Check {
    if ctx.is_kubernetes() {
        return Check::new(
            "libvirt.domains_consistent",
            Category::Libvirt,
            CheckStatus::NotApplicable,
            "local domain consistency check is not applicable for Kubernetes control plane; hypervisor domains reside on external compute nodes",
        );
    }
    if not_libvirt_profile(ctx) {
        return profile_not_applicable("libvirt.domains_consistent", Category::Libvirt);
    }
    let instances = match ctx.db.compute_instances(&ctx.database_path()).await {
        Ok(instances) => instances,
        Err(_) => {
            return database_read_failure(
                "libvirt.domains_consistent",
                Category::Libvirt,
                "compute instances",
                compute_actions(),
            );
        }
    };
    let domains = match ctx.exec.virsh_list_names().await {
        Ok(domains) => domains,
        Err(error) => {
            return internal_failure(
                "libvirt.domains_consistent",
                Category::Libvirt,
                "libvirt domain listing",
                &error,
                vec!["virsh -c qemu:///system list --all --name".to_owned()],
            );
        }
    };
    let live_domains: BTreeSet<&str> = domains.iter().map(String::as_str).collect();
    let mut missing = Vec::new();
    let mut expected_by_domain: BTreeMap<String, bool> = BTreeMap::new();
    for instance in &instances {
        if instance.observed_state.eq_ignore_ascii_case("deleted") {
            continue;
        }
        let domain = stable_domain_name(&instance.id);
        expected_by_domain.insert(domain.clone(), true);
        if !DOMAIN_REQUIRED_STATES
            .iter()
            .any(|state| instance.observed_state.eq_ignore_ascii_case(state))
        {
            continue;
        }
        if !live_domains.contains(domain.as_str()) {
            missing.push(format!(
                "{} ({}) has no libvirt domain {}",
                instance.name, instance.id, domain
            ));
        }
    }
    let mut foreign = Vec::new();
    for domain in &domains {
        if !is_o3k_domain_name(domain) {
            // Foreign domains outside the O3K naming pattern are ignored.
            continue;
        }
        if !expected_by_domain
            .get(domain.as_str())
            .copied()
            .unwrap_or(false)
        {
            foreign.push(domain.clone());
        }
    }
    if missing.is_empty() && foreign.is_empty() {
        return Check::new(
            "libvirt.domains_consistent",
            Category::Libvirt,
            CheckStatus::Pass,
            "libvirt domains match the durable compute instances",
        );
    }
    let mut details = Vec::new();
    if !missing.is_empty() {
        details.push(format!("missing domains:\n{}", missing.join("\n")));
    }
    if !foreign.is_empty() {
        details.push(format!(
            "foreign same-name domains:\n{}",
            foreign.join("\n")
        ));
    }
    let status = if missing.is_empty() {
        CheckStatus::Warn
    } else {
        CheckStatus::Fail
    };
    let summary = if missing.is_empty() {
        "libvirt holds same-name domains with no live instance"
    } else {
        "libvirt domains are inconsistent with the durable compute instances"
    };
    Check::new(
        "libvirt.domains_consistent",
        Category::Libvirt,
        status,
        summary,
    )
    .with_details(details.join("\n"))
    .with_actions(vec![
        "virsh -c qemu:///system list --all --name".to_owned(),
        "journalctl -u o3k-compute -n 100".to_owned(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeDb, FakeExec, FakeHttp, context_with};

    fn context(exec: FakeExec, db: FakeDb, is_root: bool) -> Context {
        context_with(exec, FakeHttp::healthy(), db, true, is_root)
    }

    #[tokio::test]
    async fn compute_access_passes_for_compute_identity() {
        let check =
            check_compute_access(&context(FakeExec::healthy(), FakeDb::healthy(), true)).await;
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[tokio::test]
    async fn compute_access_fails_when_libvirt_unavailable() {
        let mut exec = FakeExec::healthy();
        exec.virsh_uri_results
            .insert("o3k-compute".to_owned(), Err("access denied".to_owned()));
        let check = check_compute_access(&context(exec, FakeDb::healthy(), true)).await;
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[tokio::test]
    async fn compute_access_not_applicable_without_root() {
        let check =
            check_compute_access(&context(FakeExec::healthy(), FakeDb::healthy(), false)).await;
        assert_eq!(check.status, CheckStatus::NotApplicable);
        assert!(check.summary.contains("sudo"));
    }

    #[tokio::test]
    async fn control_isolation_fails_when_control_can_access() {
        let mut exec = FakeExec::healthy();
        exec.virsh_uri_results
            .insert("o3k".to_owned(), Ok("qemu:///system".to_owned()));
        let check = check_control_isolation(&context(exec, FakeDb::healthy(), true)).await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("boundary breach"));
    }

    #[tokio::test]
    async fn domains_consistent_warns_on_foreign_same_name_domain() {
        let mut exec = FakeExec::healthy();
        if let Ok(domains) = exec.virsh_domains.as_mut() {
            domains.push("o3k-ffffffffffffffffffff".to_owned());
        }
        let check = check_domains_consistent(&context(exec, FakeDb::healthy(), true)).await;
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.summary.contains("same-name"));
    }

    #[tokio::test]
    async fn domains_consistent_fails_when_domain_missing() {
        let mut exec = FakeExec::healthy();
        if let Ok(domains) = exec.virsh_domains.as_mut() {
            domains.clear();
        }
        let check = check_domains_consistent(&context(exec, FakeDb::healthy(), true)).await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("inconsistent"));
    }

    #[tokio::test]
    async fn control_isolation_not_applicable_without_profile() {
        let ctx = context_with(
            FakeExec::healthy(),
            FakeHttp::healthy(),
            FakeDb::healthy(),
            false,
            true,
        );
        let check = check_control_isolation(&ctx).await;
        assert_eq!(check.status, CheckStatus::NotApplicable);
    }

    #[tokio::test]
    async fn domains_consistent_not_applicable_without_profile() {
        let ctx = context_with(
            FakeExec::healthy(),
            FakeHttp::healthy(),
            FakeDb::healthy(),
            false,
            true,
        );
        let check = check_domains_consistent(&ctx).await;
        assert_eq!(check.status, CheckStatus::NotApplicable);
    }
}
