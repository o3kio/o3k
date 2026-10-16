//! Control-plane API checks against the loopback HTTP listener.

use crate::checks::o3kd_actions;
use crate::context::{Context, HttpResponse};
use crate::output::{Category, Check, CheckStatus};

/// `control.healthz`: the control plane liveness probe must answer 200 with
/// an "ok" body.
pub async fn check_healthz(ctx: &Context) -> Check {
    let url = format!("http://{}/healthz", ctx.listen_addr);
    let response = match ctx.http.get(&url).await {
        Ok(response) => response,
        Err(error) => {
            return Check::new(
                "control.healthz",
                Category::Control,
                CheckStatus::Fail,
                format!("control plane API unreachable: {error}"),
            )
            .with_actions(o3kd_actions());
        }
    };
    if response.status == 200 && response.body.contains("ok") {
        return Check::new(
            "control.healthz",
            Category::Control,
            CheckStatus::Pass,
            "control plane liveness probe answered",
        );
    }
    Check::new(
        "control.healthz",
        Category::Control,
        CheckStatus::Warn,
        format!("unexpected healthz response: HTTP {}", response.status),
    )
    .with_actions(vec![
        format!("curl -s {url}"),
        "systemctl status o3kd".to_owned(),
    ])
}

/// `control.readyz`: 200 with "ready" is healthy; 503 means o3kd's
/// readiness gate is down. In the libvirt profile that gate is the
/// compute-agent control plane (the authenticated registration listener),
/// not the agent's own presence — a stopped agent is reported by the
/// compute/service checks, while readyz stays healthy as long as the
/// control plane itself is serving.
pub async fn check_readyz(ctx: &Context) -> Check {
    let url = format!("http://{}/readyz", ctx.listen_addr);
    let response = match readyz_response(ctx).await {
        Ok(response) => response,
        Err(error) => {
            return Check::new(
                "control.readyz",
                Category::Control,
                CheckStatus::Fail,
                format!("control plane API unreachable: {error}"),
            )
            .with_actions(o3kd_actions());
        }
    };
    if response.status == 200 && response.body.contains("ready") {
        return Check::new(
            "control.readyz",
            Category::Control,
            CheckStatus::Pass,
            "control plane reports ready",
        );
    }
    if response.status == 503 {
        let summary = if ctx.libvirt_profile {
            "control plane not ready: compute-agent control plane down"
        } else {
            "control plane not ready: provider capability probe failed"
        };
        return Check::new(
            "control.readyz",
            Category::Control,
            CheckStatus::Fail,
            summary,
        )
        .with_actions(o3kd_actions());
    }
    Check::new(
        "control.readyz",
        Category::Control,
        CheckStatus::Warn,
        format!("unexpected readyz response: HTTP {}", response.status),
    )
    .with_actions(vec![
        format!("curl -s {url}"),
        "systemctl status o3kd".to_owned(),
    ])
}

/// Re-runs the readiness probe for other checks that branch on its result
/// (the response is small and loopback-local).
pub(crate) async fn readyz_response(ctx: &Context) -> Result<HttpResponse, String> {
    let url = format!("http://{}/readyz", ctx.listen_addr);
    ctx.http.get(&url).await
}

/// `controller.session`: checks that the controller session is active and valid.
pub async fn check_controller_session(ctx: &Context) -> Check {
    match ctx
        .db
        .active_controller_sessions(&ctx.database_path(), ctx.is_postgres(), ctx.database_url())
        .await
    {
        Ok(count) if count > 0 => Check::new(
            "controller.session",
            Category::Control,
            CheckStatus::Pass,
            format!("observed {count} active controller session(s) in coordination store"),
        ),
        Ok(_) => Check::new(
            "controller.session",
            Category::Control,
            CheckStatus::Fail,
            "coordination store has no active controller session",
        )
        .with_actions(o3kd_actions()),
        Err(_) => Check::new(
            "controller.session",
            Category::Control,
            CheckStatus::Fail,
            "controller session authority is unreadable",
        )
        .with_actions(o3kd_actions()),
    }
}

/// `controller.work_fencing`: checks that work leases and fencing tokens are active and coordinated.
pub async fn check_work_fencing(ctx: &Context) -> Check {
    match ctx
        .db
        .active_work_leases(&ctx.database_path(), ctx.is_postgres(), ctx.database_url())
        .await
    {
        Ok(leases)
            if leases
                .iter()
                .all(|lease| lease.fencing_token > 0 && lease.owner_session_active) =>
        {
            Check::new(
                "controller.work_fencing",
                Category::Control,
                CheckStatus::Pass,
                format!(
                    "observed {} active work lease(s) with fencing tokens",
                    leases.len()
                ),
            )
        }
        Ok(_) => Check::new(
            "controller.work_fencing",
            Category::Control,
            CheckStatus::Fail,
            "coordination store contains an invalid or orphaned work lease",
        )
        .with_actions(o3kd_actions()),
        Err(_) => Check::new(
            "controller.work_fencing",
            Category::Control,
            CheckStatus::Fail,
            "work fencing authority is unreadable",
        )
        .with_actions(o3kd_actions()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeDb, FakeExec, FakeHttp, context_with};

    fn context(http: FakeHttp) -> Context {
        context_with(FakeExec::healthy(), http, FakeDb::healthy(), true, true)
    }

    #[tokio::test]
    async fn healthz_passes_on_200_ok() {
        let check = check_healthz(&context(FakeHttp::healthy())).await;
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[tokio::test]
    async fn healthz_fails_when_unreachable() {
        let mut http = FakeHttp::healthy();
        http.with(
            "GET http://127.0.0.1:8080/healthz",
            Err("connection refused".to_owned()),
        );
        let check = check_healthz(&context(http)).await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("unreachable"));
    }

    #[tokio::test]
    async fn readyz_passes_on_200_ready() {
        let check = check_readyz(&context(FakeHttp::healthy())).await;
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[tokio::test]
    async fn readyz_fails_on_503() {
        let mut http = FakeHttp::healthy();
        http.with(
            "GET http://127.0.0.1:8080/readyz",
            Ok(HttpResponse {
                status: 503,
                headers: Vec::new(),
                body: "{\"status\":\"not_ready\"}".to_owned(),
            }),
        );
        let check = check_readyz(&context(http)).await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("not ready"));
    }

    #[tokio::test]
    async fn controller_session_fails_without_durable_active_session() {
        let mut db = FakeDb::healthy();
        db.active_sessions = Ok(0);
        let check = check_controller_session(&context_with(
            FakeExec::healthy(),
            FakeHttp::healthy(),
            db,
            true,
            true,
        ))
        .await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("no active"));
    }

    #[tokio::test]
    async fn work_fencing_fails_on_invalid_durable_token() {
        let mut db = FakeDb::healthy();
        db.work_leases = Ok(vec![crate::db::WorkLeaseRow {
            work_key: "operation-1".to_owned(),
            owner_controller_id: "controller-1".to_owned(),
            owner_controller_epoch: "epoch-1".to_owned(),
            fencing_token: 0,
            owner_session_active: true,
        }]);
        let check = check_work_fencing(&context_with(
            FakeExec::healthy(),
            FakeHttp::healthy(),
            db,
            true,
            true,
        ))
        .await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("invalid"));
    }

    #[tokio::test]
    async fn work_fencing_fails_on_orphaned_lease_owner() {
        let mut db = FakeDb::healthy();
        db.work_leases = Ok(vec![crate::db::WorkLeaseRow {
            work_key: "operation-1".to_owned(),
            owner_controller_id: "stale-controller".to_owned(),
            owner_controller_epoch: "old-epoch".to_owned(),
            fencing_token: 7,
            owner_session_active: false,
        }]);
        let check = check_work_fencing(&context_with(
            FakeExec::healthy(),
            FakeHttp::healthy(),
            db,
            true,
            true,
        ))
        .await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.summary.contains("orphaned"));
    }

    #[tokio::test]
    async fn coordination_errors_do_not_escape_into_json_or_human_output() {
        let sentinel = "postgres://doctor:secret@db.example.invalid/o3k";
        let mut db = FakeDb::healthy();
        db.active_sessions = Err(sentinel.to_owned());
        db.work_leases = Err(sentinel.to_owned());
        let ctx = context_with(FakeExec::healthy(), FakeHttp::healthy(), db, true, true);

        for check in [
            check_controller_session(&ctx).await,
            check_work_fencing(&ctx).await,
        ] {
            let serialized = serde_json::to_string(&check);
            assert!(serialized.is_ok(), "check serialization failed");
            let json = serialized.unwrap_or_default();
            assert!(!json.contains(sentinel));
            let report = crate::output::Report {
                version: "test".to_owned(),
                overall_status: crate::output::OverallStatus::Unhealthy,
                timestamp: "2026-01-01T00:00:00Z".to_owned(),
                checks: vec![check],
            };
            assert!(!report.render_human().contains(sentinel));
        }
    }
}
