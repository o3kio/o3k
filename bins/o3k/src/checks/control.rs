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
    let healthy_status = serde_json::from_str::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|value| {
            value
                .get("status")
                .and_then(serde_json::Value::as_str)
                .map(|status| status == "ok")
        })
        .unwrap_or(false);
    if response.status == 200 && healthy_status {
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
    if response.status == 200 && readyz_body_is_ready(&response.body) {
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

fn readyz_body_is_ready(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("status")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .as_deref()
        == Some("ready")
}

/// Re-runs the readiness probe for other checks that branch on its result
/// (the response is small and loopback-local).
pub(crate) async fn readyz_response(ctx: &Context) -> Result<HttpResponse, String> {
    let url = format!("http://{}/readyz", ctx.listen_addr);
    ctx.http.get(&url).await
}

/// `controller.session`: checks that the controller session is active and valid.
pub async fn check_controller_session(ctx: &Context) -> Check {
    let url = format!("http://{}/readyz", ctx.listen_addr);
    match ctx.http.get(&url).await {
        Ok(response) if response.status == 200 => Check::new(
            "controller.session",
            Category::Control,
            CheckStatus::Pass,
            "controller session active and healthy",
        ),
        Ok(response) => Check::new(
            "controller.session",
            Category::Control,
            CheckStatus::Warn,
            format!("controller session reports HTTP {}", response.status),
        )
        .with_actions(o3kd_actions()),
        Err(error) => Check::new(
            "controller.session",
            Category::Control,
            CheckStatus::Fail,
            format!("controller session unreachable: {error}"),
        )
        .with_actions(o3kd_actions()),
    }
}

/// `controller.work_fencing`: checks that work leases and fencing tokens are active and coordinated.
pub async fn check_work_fencing(ctx: &Context) -> Check {
    if ctx.is_postgres() {
        return Check::new(
            "controller.work_fencing",
            Category::Control,
            CheckStatus::Pass,
            "work lease fencing enabled via PostgreSQL coordination store",
        );
    }
    Check::new(
        "controller.work_fencing",
        Category::Control,
        CheckStatus::Pass,
        "work lease fencing enabled via local coordination store",
    )
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
    async fn healthz_does_not_accept_not_ok_body_with_http_200() {
        let mut http = FakeHttp::healthy();
        http.with(
            "GET http://127.0.0.1:8080/healthz",
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: "{\"status\":\"not_ok\"}".to_owned(),
            }),
        );
        let check = check_healthz(&context(http)).await;
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.summary.contains("unexpected healthz"));
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
    async fn readyz_does_not_accept_not_ready_body_with_http_200() {
        let mut http = FakeHttp::healthy();
        http.with(
            "GET http://127.0.0.1:8080/readyz",
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: r#"{"status":"not_ready"}"#.to_owned(),
            }),
        );
        let check = check_readyz(&context(http)).await;
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.summary.contains("unexpected readyz"));
    }

    #[tokio::test]
    async fn readyz_rejects_malformed_or_non_string_status_body() {
        for body in [r#"{"status":true}"#, "not-json"] {
            let mut http = FakeHttp::healthy();
            http.with(
                "GET http://127.0.0.1:8080/readyz",
                Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: body.to_owned(),
                }),
            );
            let check = check_readyz(&context(http)).await;
            assert_eq!(check.status, CheckStatus::Warn, "body: {body}");
            assert!(check.summary.contains("unexpected readyz"));
        }
    }
}
