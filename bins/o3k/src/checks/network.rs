//! Networking/DHCP checks against the host network state, the ownership
//! manifest, and the dnsmasq ownership records.
//!
//! The ownership manifest schema mirrors
//! `crates/o3k-network::NetworkOwnershipManifest`; the dnsmasq pidfile and
//! `.owner` identity mirror `crates/o3k-dhcp` (pidfile `<root>/dnsmasq-*.pid`
//! with the kernel start time recorded in `<pidfile>.owner`).

use crate::checks::{
    compute_actions, database_read_failure, internal_failure, not_libvirt_profile,
    profile_not_applicable,
};
use crate::context::Context;
use crate::output::{Category, Check, CheckStatus};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Ownership manifest as persisted by the host-network manager.
#[derive(Debug, Deserialize)]
struct OwnershipManifest {
    #[serde(default)]
    bridge: Option<BridgeOwnership>,
    #[serde(default)]
    taps: BTreeMap<String, TapOwnership>,
}

#[derive(Debug, Deserialize)]
struct BridgeOwnership {
    name: String,
    created_by_o3k: bool,
}

#[derive(Debug, Deserialize)]
struct TapOwnership {
    interface: String,
    instance_id: String,
}

/// Loads and parses the ownership manifest through the exec seam.
async fn load_manifest(ctx: &Context) -> Result<Option<OwnershipManifest>, String> {
    let path = ctx.ownership_path();
    if !ctx.exec.is_regular_file(&path) {
        return Ok(None);
    }
    let contents = ctx
        .exec
        .read_file(&path)
        .map_err(|error| format!("ownership manifest is unreadable: {error}"))?;
    serde_json::from_str(&contents)
        .map(Some)
        .map_err(|error| format!("ownership manifest is corrupt: {error}"))
}

/// `network.bridge_state`: the manifest's bridge must exist on the host.
pub async fn check_bridge_state(ctx: &Context) -> Check {
    if ctx.is_kubernetes() {
        return Check::new(
            "network.bridge_state",
            Category::Network,
            CheckStatus::NotApplicable,
            "host network bridge checks are not applicable for Kubernetes control plane; networking resides on external compute agents",
        );
    }
    if not_libvirt_profile(ctx) {
        return profile_not_applicable("network.bridge_state", Category::Network);
    }
    let manifest = match load_manifest(ctx).await {
        Ok(Some(manifest)) => manifest,
        Ok(None) => {
            return Check::new(
                "network.bridge_state",
                Category::Network,
                CheckStatus::NotApplicable,
                "no network ownership manifest",
            );
        }
        Err(error) => {
            return Check::new(
                "network.bridge_state",
                Category::Network,
                CheckStatus::Fail,
                error,
            )
            .with_actions(vec!["ls -l /var/lib/o3k/compute/network".to_owned()]);
        }
    };
    let Some(bridge) = manifest.bridge else {
        return Check::new(
            "network.bridge_state",
            Category::Network,
            CheckStatus::NotApplicable,
            "ownership manifest records no bridge",
        );
    };
    let links = match ctx.exec.ip_link_names().await {
        Ok(links) => links,
        Err(error) => {
            return internal_failure(
                "network.bridge_state",
                Category::Network,
                "the host link list",
                &error,
                vec!["ip -o link show".to_owned()],
            );
        }
    };
    if links.iter().any(|link| link == &bridge.name) {
        return Check::new(
            "network.bridge_state",
            Category::Network,
            CheckStatus::Pass,
            format!("owned bridge {} is present on the host", bridge.name),
        );
    }
    Check::new(
        "network.bridge_state",
        Category::Network,
        CheckStatus::Fail,
        format!("owned bridge {} missing on host", bridge.name),
    )
    .with_actions(vec![
        "ip -o link show".to_owned(),
        "journalctl -u o3k-compute -n 100".to_owned(),
    ])
}

/// `network.tap_state`: every recorded TAP must exist; O3K-prefixed host
/// interfaces without an ownership record are stale leftovers.
pub async fn check_tap_state(ctx: &Context) -> Check {
    if ctx.is_kubernetes() {
        return Check::new(
            "network.tap_state",
            Category::Network,
            CheckStatus::NotApplicable,
            "host TAP checks are not applicable for Kubernetes control plane; networking resides on external compute agents",
        );
    }
    if not_libvirt_profile(ctx) {
        return profile_not_applicable("network.tap_state", Category::Network);
    }
    let manifest = match load_manifest(ctx).await {
        Ok(Some(manifest)) => manifest,
        Ok(None) => {
            return Check::new(
                "network.tap_state",
                Category::Network,
                CheckStatus::NotApplicable,
                "no network ownership manifest",
            );
        }
        Err(error) => {
            return Check::new(
                "network.tap_state",
                Category::Network,
                CheckStatus::Fail,
                error,
            )
            .with_actions(vec!["ls -l /var/lib/o3k/compute/network".to_owned()]);
        }
    };
    let links = match ctx.exec.ip_link_names().await {
        Ok(links) => links,
        Err(error) => {
            return internal_failure(
                "network.tap_state",
                Category::Network,
                "the host link list",
                &error,
                vec!["ip -o link show".to_owned()],
            );
        }
    };
    let mut missing = Vec::new();
    for (key, tap) in &manifest.taps {
        let name = tap.interface.clone();
        if name.is_empty() {
            missing.push(key.clone());
            continue;
        }
        if !links.iter().any(|link| link == &name) {
            missing.push(name);
        }
    }
    let mut stale = Vec::new();
    for link in &links {
        if link.starts_with("o3ktap-") && !manifest.taps.contains_key(link) {
            stale.push(link.clone());
        }
    }
    if missing.is_empty() && stale.is_empty() {
        return Check::new(
            "network.tap_state",
            Category::Network,
            CheckStatus::Pass,
            "recorded TAP interfaces are present and no stale TAPs remain",
        );
    }
    let mut details = Vec::new();
    if !missing.is_empty() {
        details.push(format!("recorded TAP missing: {}", missing.join(", ")));
    }
    if !stale.is_empty() {
        details.push(format!("stale TAPs: {}", stale.join(", ")));
    }
    let status = if missing.is_empty() {
        CheckStatus::Warn
    } else {
        CheckStatus::Fail
    };
    let summary = if missing.is_empty() {
        "stale TAP on host with no ownership record"
    } else {
        "recorded TAP missing"
    };
    Check::new("network.tap_state", Category::Network, status, summary)
        .with_details(details.join("\n"))
        .with_actions(vec![
            "ip -o link show".to_owned(),
            "journalctl -u o3k-compute -n 100".to_owned(),
        ])
}

/// Parses a pidfile's numeric pid.
fn pidfile_pid(contents: &str) -> Option<u32> {
    contents.trim().parse::<u32>().ok()
}

/// `network.dhcp_state`: every `dnsmasq-*.pid` in the dhcp root must point
/// at a live process whose cmdline contains the dhcp root and whose kernel
/// start time matches the adjacent `.owner` record.
pub async fn check_dhcp_state(ctx: &Context) -> Check {
    if ctx.is_kubernetes() {
        return Check::new(
            "network.dhcp_state",
            Category::Network,
            CheckStatus::NotApplicable,
            "host DHCP checks are not applicable for Kubernetes control plane; networking resides on external compute agents",
        );
    }
    if not_libvirt_profile(ctx) {
        return profile_not_applicable("network.dhcp_state", Category::Network);
    }
    let entries = match ctx.exec.read_dir_names(&ctx.dhcp_root) {
        Ok(entries) => entries,
        Err(error) => {
            return internal_failure(
                "network.dhcp_state",
                Category::Network,
                "the dhcp root",
                &error,
                vec![format!("ls -l {}", ctx.dhcp_root.display())],
            );
        }
    };
    let pidfiles: Vec<String> = entries
        .iter()
        .filter(|name| name.starts_with("dnsmasq-") && name.ends_with(".pid"))
        .cloned()
        .collect();
    let mut dead = Vec::new();
    let mut mismatched = Vec::new();
    for pidfile in &pidfiles {
        let pid_path = ctx.dhcp_root.join(pidfile);
        let contents = match ctx.exec.read_file(&pid_path) {
            Ok(contents) => contents,
            Err(error) => {
                mismatched.push(format!("{pidfile} is unreadable: {error}"));
                continue;
            }
        };
        let Some(pid) = pidfile_pid(&contents) else {
            mismatched.push(format!("{pidfile} carries no pid"));
            continue;
        };
        if !ctx.exec.proc_alive(pid) {
            dead.push(pidfile.clone());
            continue;
        }
        let owner_path = format!("{}.owner", pid_path.display());
        let identity_path = Path::new(&owner_path);
        let expected = match ctx.exec.read_file(identity_path) {
            Ok(owner) => owner.trim().to_owned(),
            Err(_) => String::new(),
        };
        let cmdline_ok = ctx.exec.proc_cmdline(pid).is_some_and(|cmdline| {
            let root_text = ctx.dhcp_root.display().to_string();
            cmdline.contains(&root_text)
                || std::fs::canonicalize(&ctx.dhcp_root)
                    .is_ok_and(|canonical| cmdline.contains(canonical.to_string_lossy().as_ref()))
        });
        let starttime_ok = ctx
            .exec
            .proc_start_time_ticks(pid)
            .is_some_and(|ticks| !expected.is_empty() && ticks == expected);
        if !cmdline_ok || !starttime_ok {
            mismatched.push(pidfile.clone());
        }
    }
    if dead.is_empty() && mismatched.is_empty() && !pidfiles.is_empty() {
        return Check::new(
            "network.dhcp_state",
            Category::Network,
            CheckStatus::Pass,
            format!("{} owned dnsmasq process(es) verified", pidfiles.len()),
        );
    }
    let binding_count = dhcp_binding_count(ctx).await;
    if pidfiles.is_empty() {
        if binding_count > 0 {
            return Check::new(
                "network.dhcp_state",
                Category::Network,
                CheckStatus::Warn,
                "DHCP bindings exist but no dnsmasq is running",
            )
            .with_actions(vec![
                "journalctl -u o3k-compute -n 100".to_owned(),
                format!("ls -l {}", ctx.dhcp_root.display()),
            ]);
        }
        return Check::new(
            "network.dhcp_state",
            Category::Network,
            CheckStatus::NotApplicable,
            "no dnsmasq pidfiles and no DHCP bindings",
        );
    }
    let mut details = Vec::new();
    if !dead.is_empty() {
        details.push(format!("dead pidfiles: {}", dead.join(", ")));
    }
    if !mismatched.is_empty() {
        details.push(format!("identity mismatches: {}", mismatched.join(", ")));
    }
    let status = if dead.is_empty() {
        CheckStatus::Warn
    } else {
        CheckStatus::Fail
    };
    let summary = if dead.is_empty() {
        "dnsmasq process does not match ownership record"
    } else {
        "dead dnsmasq process with stale pidfile"
    };
    Check::new("network.dhcp_state", Category::Network, status, summary)
        .with_details(details.join("\n"))
        .with_actions(vec![
            format!("ls -l {}", ctx.dhcp_root.display()),
            "journalctl -u o3k-compute -n 100".to_owned(),
        ])
}

/// Counts the durable DHCP bindings in the dhcp state file.
async fn dhcp_binding_count(ctx: &Context) -> usize {
    let Ok(contents) = ctx.exec.read_file(&ctx.dhcp_state_path()) else {
        return 0;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return 0;
    };
    value
        .get("bindings")
        .and_then(serde_json::Value::as_object)
        .map(|bindings| bindings.len())
        .unwrap_or(0)
}

/// `network.ownership_records`: the manifest must be parseable, its taps
/// must reference live instances, and an adopted (not created) bridge is a
/// WARN.
pub async fn check_ownership_records(ctx: &Context) -> Check {
    if ctx.is_kubernetes() {
        return Check::new(
            "network.ownership_records",
            Category::Network,
            CheckStatus::NotApplicable,
            "host network ownership checks are not applicable for Kubernetes control plane",
        );
    }
    if not_libvirt_profile(ctx) {
        return profile_not_applicable("network.ownership_records", Category::Network);
    }
    let manifest = match load_manifest(ctx).await {
        Ok(Some(manifest)) => manifest,
        Ok(None) => {
            return Check::new(
                "network.ownership_records",
                Category::Network,
                CheckStatus::NotApplicable,
                "no network ownership manifest",
            );
        }
        Err(error) => {
            return Check::new(
                "network.ownership_records",
                Category::Network,
                CheckStatus::Fail,
                format!("network ownership manifest corrupt: {error}"),
            )
            .with_actions(vec!["ls -l /var/lib/o3k/compute/network".to_owned()]);
        }
    };
    let instances = match ctx.db.compute_instances(&ctx.database_path()).await {
        Ok(instances) => instances,
        Err(_) => {
            return database_read_failure(
                "network.ownership_records",
                Category::Network,
                "compute instances",
                compute_actions(),
            );
        }
    };
    let live_ids: std::collections::BTreeSet<&str> = instances
        .iter()
        .filter(|instance| !instance.observed_state.eq_ignore_ascii_case("deleted"))
        .map(|instance| instance.id.as_str())
        .collect();
    let mut stale_records = Vec::new();
    for (interface, tap) in &manifest.taps {
        if !live_ids.contains(tap.instance_id.as_str()) {
            stale_records.push(format!(
                "tap {interface} references deleted instance {}",
                tap.instance_id
            ));
        }
    }
    let ambiguous_bridge = manifest
        .bridge
        .as_ref()
        .is_some_and(|bridge| !bridge.created_by_o3k);
    if stale_records.is_empty() && !ambiguous_bridge {
        return Check::new(
            "network.ownership_records",
            Category::Network,
            CheckStatus::Pass,
            "network ownership records reference live instances only",
        );
    }
    let mut details = Vec::new();
    if !stale_records.is_empty() {
        details.push(stale_records.join("\n"));
    }
    if ambiguous_bridge {
        let name = manifest
            .bridge
            .as_ref()
            .map(|bridge| bridge.name.as_str())
            .unwrap_or("");
        details.push(format!(
            "bridge {name} is adopted (created_by_o3k=false) while the manifest declares ownership"
        ));
    }
    let status = if stale_records.is_empty() {
        CheckStatus::Warn
    } else {
        CheckStatus::Fail
    };
    let summary = if stale_records.is_empty() {
        "ambiguous foreign resource adoption"
    } else {
        "stale network ownership record for deleted instance"
    };
    Check::new(
        "network.ownership_records",
        Category::Network,
        status,
        summary,
    )
    .with_details(details.join("\n"))
    .with_actions(vec![
        "journalctl -u o3k-compute -n 100".to_owned(),
        format!("ls -l {}", ctx.network_root.display()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeDb, FakeExec, FakeHttp, context_with};

    fn context(exec: FakeExec, db: FakeDb) -> Context {
        context_with(exec, FakeHttp::healthy(), db, true, true)
    }

    #[tokio::test]
    async fn bridge_state_fails_when_bridge_missing() {
        let mut exec = FakeExec::healthy();
        exec.links.retain(|link| link != "o3k-br0");
        let check = check_bridge_state(&context(exec, FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("missing"));
    }

    #[tokio::test]
    async fn tap_state_warns_on_stale_tap() {
        let mut exec = FakeExec::healthy();
        exec.links.push("o3ktap-99999999".to_owned());
        let check = check_tap_state(&context(exec, FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.summary.contains("stale TAP"));
    }

    #[tokio::test]
    async fn tap_state_fails_when_recorded_tap_missing() {
        let mut exec = FakeExec::healthy();
        exec.links.retain(|link| link != "o3ktap-00000001");
        let check = check_tap_state(&context(exec, FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("missing"));
    }

    #[tokio::test]
    async fn dhcp_state_fails_on_dead_pidfile() {
        let mut exec = FakeExec::healthy();
        exec.procs
            .insert(123, (false, String::new(), "987".to_owned()));
        let check = check_dhcp_state(&context(exec, FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("dead dnsmasq"));
    }

    #[tokio::test]
    async fn dhcp_state_warns_on_mismatched_identity() {
        let mut exec = FakeExec::healthy();
        exec.procs.insert(
            123,
            (
                true,
                "/usr/sbin/dnsmasq --conf-file=/var/lib/o3k/compute/dhcp/dnsmasq.conf".to_owned(),
                "777".to_owned(),
            ),
        );
        let check = check_dhcp_state(&context(exec, FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.summary.contains("does not match"));
    }

    #[tokio::test]
    async fn dhcp_state_warns_on_bindings_without_dnsmasq() {
        let mut exec = FakeExec::healthy();
        exec.dir_listings.remove("/var/lib/o3k/compute/dhcp");
        exec.files.insert(
            "/var/lib/o3k/compute/dhcp/state.json".to_owned(),
            Ok("{\"config\": null, \"bindings\": {\"p1\": {\"port_id\": \"p1\"}}}".to_owned()),
        );
        let check = check_dhcp_state(&context(exec, FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.summary.contains("bindings exist"));
    }

    #[tokio::test]
    async fn ownership_records_fails_on_stale_instance() {
        let mut exec = FakeExec::healthy();
        exec.files.insert(
            "/var/lib/o3k/compute/network/ownership.json".to_owned(),
            Ok(
                "{\"bridge\": {\"name\": \"o3k-br0\", \"created_by_o3k\": true}, \
                 \"taps\": {\"o3ktap-00000001\": {\"interface\": \"o3ktap-00000001\", \"instance_id\": \"gone-1\"}}}"
                    .to_owned(),
            ),
        );
        let check = check_ownership_records(&context(exec, FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("stale network ownership"));
    }

    #[tokio::test]
    async fn ownership_records_warns_on_adopted_bridge() {
        let mut exec = FakeExec::healthy();
        exec.files.insert(
            "/var/lib/o3k/compute/network/ownership.json".to_owned(),
            Ok(
                "{\"bridge\": {\"name\": \"o3k-br0\", \"created_by_o3k\": false}, \
                 \"taps\": {\"o3ktap-00000001\": {\"interface\": \"o3ktap-00000001\", \"instance_id\": \"inst-1\"}}}"
                    .to_owned(),
            ),
        );
        let check = check_ownership_records(&context(exec, FakeDb::healthy())).await;
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.summary.contains("adoption"));
    }

    #[tokio::test]
    async fn bridge_state_not_applicable_without_profile() {
        let ctx = context_with(
            FakeExec::healthy(),
            FakeHttp::healthy(),
            FakeDb::healthy(),
            false,
            true,
        );
        let check = check_bridge_state(&ctx).await;
        assert_eq!(check.status, CheckStatus::NotApplicable);
    }

    #[tokio::test]
    async fn tap_state_not_applicable_without_profile() {
        let ctx = context_with(
            FakeExec::healthy(),
            FakeHttp::healthy(),
            FakeDb::healthy(),
            false,
            true,
        );
        let check = check_tap_state(&ctx).await;
        assert_eq!(check.status, CheckStatus::NotApplicable);
    }

    #[tokio::test]
    async fn dhcp_state_not_applicable_without_profile() {
        let ctx = context_with(
            FakeExec::healthy(),
            FakeHttp::healthy(),
            FakeDb::healthy(),
            false,
            true,
        );
        let check = check_dhcp_state(&ctx).await;
        assert_eq!(check.status, CheckStatus::NotApplicable);
    }

    #[tokio::test]
    async fn ownership_records_not_applicable_without_profile() {
        let ctx = context_with(
            FakeExec::healthy(),
            FakeHttp::healthy(),
            FakeDb::healthy(),
            false,
            true,
        );
        let check = check_ownership_records(&ctx).await;
        assert_eq!(check.status, CheckStatus::NotApplicable);
    }
}
