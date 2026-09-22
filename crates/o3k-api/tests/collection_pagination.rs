//! Collection pagination (`limit` / `marker` / `*_links`) for the two OpenStack
//! collection families the accepted PP.4 Horizon journey exercises: Neutron
//! `GET /v2.0/networks` and Nova `GET /v2.1/{project_id}/servers` and
//! `/servers/detail`.
//!
//! The pinned unmodified Horizon client (`openstacksdk` 4.10.0) re-requests a
//! collection with `marker=<last id>` when it supplied a `limit` and the body
//! carries no next link; a conformant service answers that with an empty page.
//! These tests pin that behavior, the upstream-shaped `*_links` metadata, and
//! the bounded rejection/ignore rules around `limit` and `marker`.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use o3k_api::AppState;
use o3k_compute::ComputeService;
use o3k_identity::{BootstrapConfig, ExtraProjectSeed, Secret, TokenService};
use o3k_kernel::MemoryAuditSink;
use o3k_network::NetworkService;
use o3k_provider::FakeComputeProvider;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const PROJECT_A: &str = "eba29e2d-53de-461d-ae91-ede7402713cb";
const PROJECT_B: &str = "9f3c2b6e-5f2d-4b3a-9c8e-1a2b3c4d5e6f";
const USER_B: &str = "6b0f5a2e-8c4d-4a7e-9b1f-2d3e4f5a6b7c";
const FLAVOR_ID: &str = "00000000-0000-0000-0000-000000000001";
/// A UUID below every `Uuid::now_v7()` resource identity.
const MARKER_BELOW_ALL: &str = "00000000-0000-0000-0000-000000000000";
/// A UUID above every `Uuid::now_v7()` resource identity.
const MARKER_ABOVE_ALL: &str = "ffffffff-ffff-ffff-ffff-ffffffffffff";

struct Harness {
    app: axum::Router,
    token_a: String,
    token_b: String,
    root: std::path::PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

async fn build_harness() -> Result<Harness, Box<dyn std::error::Error>> {
    let store = Arc::new(o3k_store::testkit::open_memory().await?);
    o3k_identity::seed_identity_defaults(
        store.as_ref(),
        &BootstrapConfig {
            catalog_endpoint: "http://127.0.0.1:18090".to_owned(),
            bootstrap_password: Secret::new("password".to_owned()),
            cinder_password: None,
            cinder_endpoint: None,
            pbkdf2_iterations: 1_000,
            extra_projects: vec![ExtraProjectSeed {
                project_id: PROJECT_B.to_owned(),
                project_name: "tenant-b".to_owned(),
                user_id: USER_B.to_owned(),
                user_name: "tenant-b-user".to_owned(),
                password: Secret::new("tenant-b-password".to_owned()),
            }],
        },
    )
    .await?;

    let audit_sink = Arc::new(MemoryAuditSink::new());
    let compute = ComputeService::new_for_test(store.clone(), Arc::new(FakeComputeProvider::new()))
        .with_required_audit_publisher(audit_sink.clone());
    let identity = TokenService::load(
        store.clone(),
        Secret::new("a-secure-signing-key-with-at-least-32-bytes".to_owned()),
        Duration::from_secs(3600),
    )
    .await?;
    let root = std::env::temp_dir().join(format!("o3k-api-pagination-{}", uuid::Uuid::now_v7()));
    let network = NetworkService::open_for_test(&root, store)
        .await?
        .with_required_audit_publisher(audit_sink);

    let state = AppState::new()
        .with_identity(identity)
        .with_compute(compute)
        .with_network(network);
    state.set_ready(true);
    let app = o3k_api::router_with_state(state);

    let token_a = issue_token(&app, "admin", "password", "admin").await?;
    let token_b = issue_token(&app, "tenant-b-user", "tenant-b-password", "tenant-b").await?;
    Ok(Harness {
        app,
        token_a,
        token_b,
        root,
    })
}

async fn issue_token(
    app: &axum::Router,
    user: &str,
    password: &str,
    project: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = serde_json::json!({
        "auth": {
            "identity": {"methods": ["password"], "password": {"user": {"name": user, "password": password}}},
            "scope": {"project": {"name": project}}
        }
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v3/auth/tokens")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request)?))?,
        )
        .await?;
    Ok(response
        .headers()
        .get("x-subject-token")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing x-subject-token header")?
        .to_owned())
}

async fn get(
    app: &axum::Router,
    uri: &str,
    token: &str,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header("x-auth-token", token)
                .body(Body::empty())?,
        )
        .await?)
}

async fn json(response: axum::response::Response) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 64 * 1024).await?,
    )?)
}

async fn body_text(
    response: axum::response::Response,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(String::from_utf8(
        axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await?
            .to_vec(),
    )?)
}

fn ids(body: &Value, key: &str) -> Vec<String> {
    body[key]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["id"].as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The `rel: next` href of a paginated collection, if the page has one.
fn next_href(body: &Value, links_key: &str) -> Option<String> {
    body.get(links_key)
        .and_then(Value::as_array)?
        .iter()
        .find(|link| link["rel"] == "next")
        .and_then(|link| link["href"].as_str().map(ToOwned::to_owned))
}

/// Follows `rel: next` links from `first_uri`, collecting every id seen.
async fn collect_pages(
    app: &axum::Router,
    first_uri: &str,
    token: &str,
    collection_key: &str,
    links_key: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut seen = Vec::new();
    let mut uri = first_uri.to_owned();
    for _ in 0..64 {
        let response = get(app, &uri, token).await?;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let body = json(response).await?;
        seen.extend(ids(&body, collection_key));
        match next_href(&body, links_key) {
            Some(href) => uri = href,
            None => return Ok(seen),
        }
    }
    Err("pagination did not terminate".into())
}

async fn create_network(
    app: &axum::Router,
    token: &str,
    name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/networks")
                .header("x-auth-token", token)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"network": {"name": name}}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED, "create {name}");
    let body = json(response).await?;
    body["network"]["id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "missing network id".into())
}

async fn create_subnet(
    app: &axum::Router,
    token: &str,
    network_id: &str,
    cidr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2.0/subnets")
                .header("x-auth-token", token)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "subnet": {"network_id": network_id, "cidr": cidr, "ip_version": 4}
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED, "create subnet");
    Ok(())
}

async fn create_server(
    app: &axum::Router,
    token: &str,
    project: &str,
    name: &str,
    network_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v2.1/{project}/servers"))
                .header("x-auth-token", token)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "server": {
                            "name": name,
                            "image": {"id": "image-1"},
                            "flavor": {"id": FLAVOR_ID},
                            "networks": [{"uuid": network_id}]
                        }
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED, "create {name}");
    let body = json(response).await?;
    body["server"]["id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "missing server id".into())
}

/// Creates a network plus an admitted subnet so a Server can attach to it.
async fn create_server_network(
    app: &axum::Router,
    token: &str,
    name: &str,
    cidr: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let network_id = create_network(app, token, name).await?;
    create_subnet(app, token, &network_id, cidr).await?;
    Ok(network_id)
}

#[tokio::test]
async fn networks_empty_collection_with_limit_has_no_next_link()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = build_harness().await?;
    let response = get(&harness.app, "/v2.0/networks?limit=5", &harness.token_a).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await?;
    assert_eq!(body["networks"].as_array().map(Vec::len), Some(0), "{body}");
    assert!(next_href(&body, "networks_links").is_none(), "{body}");
    Ok(())
}

#[tokio::test]
async fn networks_single_resource_with_larger_limit_has_no_next_link()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = build_harness().await?;
    let id = create_network(&harness.app, &harness.token_a, "only").await?;
    let response = get(
        &harness.app,
        "/v2.0/networks?limit=21&sort_key=id&sort_dir=asc&shared=True",
        &harness.token_a,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await?;
    assert_eq!(ids(&body, "networks"), [id], "{body}");
    assert!(next_href(&body, "networks_links").is_none(), "{body}");
    Ok(())
}

#[tokio::test]
async fn networks_collection_below_page_limit_is_returned_without_next_link()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = build_harness().await?;
    let mut created = Vec::new();
    for name in ["a", "b", "c"] {
        created.push(create_network(&harness.app, &harness.token_a, name).await?);
    }
    let response = get(&harness.app, "/v2.0/networks?limit=10", &harness.token_a).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await?;
    let mut listed = ids(&body, "networks");
    listed.sort();
    created.sort();
    assert_eq!(listed, created, "{body}");
    assert!(next_href(&body, "networks_links").is_none(), "{body}");
    Ok(())
}

#[tokio::test]
async fn networks_pagination_traversal_visits_every_network_exactly_once()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = build_harness().await?;
    let mut created = Vec::new();
    for name in ["a", "b", "c", "d", "e"] {
        created.push(create_network(&harness.app, &harness.token_a, name).await?);
    }
    created.sort();

    for limit in [1, 2, 3] {
        let visited = collect_pages(
            &harness.app,
            &format!("/v2.0/networks?limit={limit}"),
            &harness.token_a,
            "networks",
            "networks_links",
        )
        .await?;
        let mut unique = visited.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            visited.len(),
            "limit {limit} repeated a network"
        );
        assert_eq!(unique, created, "limit {limit} missed or added a network");
    }
    Ok(())
}

#[tokio::test]
async fn horizon_pagination_ball_marker_follow_up_returns_empty_networks()
-> Result<(), Box<dyn std::error::Error>> {
    // The exact captured Horizon regression pair: the first request supplies
    // `limit=21`, so the SDK falls back to "pagination ball" and re-requests
    // the collection with `marker=<last id>`. A conformant answer is an empty
    // page, which is what stops the client's endless-pagination guard.
    let harness = build_harness().await?;
    let id = create_network(&harness.app, &harness.token_a, "captured").await?;

    let first = get(
        &harness.app,
        "/v2.0/networks?limit=21&sort_key=id&sort_dir=asc&shared=True",
        &harness.token_a,
    )
    .await?;
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = json(first).await?;
    let listed = ids(&first_body, "networks");
    assert_eq!(listed.len(), 1, "{first_body}");
    assert_eq!(listed[0], id, "{first_body}");

    let follow_up = get(
        &harness.app,
        &format!("/v2.0/networks?sort_key=id&sort_dir=asc&shared=True&marker={id}&limit=21"),
        &harness.token_a,
    )
    .await?;
    assert_eq!(follow_up.status(), StatusCode::OK);
    let follow_up_body = json(follow_up).await?;
    assert_eq!(
        follow_up_body["networks"].as_array().map(Vec::len),
        Some(0),
        "marker follow-up must terminate pagination: {follow_up_body}"
    );
    assert!(next_href(&follow_up_body, "networks_links").is_none());
    Ok(())
}

#[tokio::test]
async fn networks_without_limit_keep_the_unchanged_response_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = build_harness().await?;
    let id = create_network(&harness.app, &harness.token_a, "plain").await?;
    let response = get(&harness.app, "/v2.0/networks", &harness.token_a).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await?;
    assert_eq!(ids(&body, "networks"), [id], "{body}");
    assert!(
        body.get("networks_links").is_none(),
        "a non-paginating listing must not gain a link array: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn malformed_limit_and_marker_are_bounded_rejections()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = build_harness().await?;
    let cases: [&str; 7] = [
        "/v2.0/networks?limit=0",
        "/v2.0/networks?limit=-1",
        "/v2.0/networks?limit=not-a-number",
        "/v2.0/networks?marker=not-a-uuid",
        &format!("/v2.1/{PROJECT_A}/servers?limit=0"),
        &format!("/v2.1/{PROJECT_A}/servers?limit=not-a-number"),
        &format!("/v2.1/{PROJECT_A}/servers/detail?marker=not-a-uuid"),
    ];
    for uri in cases {
        let response = get(&harness.app, uri, &harness.token_a).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let text = body_text(response).await?;
        assert!(text.contains("Bad Request"), "{uri}: {text}");
    }

    // Neither a malformed marker nor a malformed limit may echo the value the
    // caller supplied.
    for (uri, raw) in [
        (
            "/v2.0/networks?marker=deadbeef-not-a-uuid",
            "deadbeef-not-a-uuid",
        ),
        ("/v2.0/networks?limit=not-a-number", "not-a-number"),
        (
            &format!("/v2.1/{PROJECT_A}/servers/detail?marker=deadbeef-not-a-uuid"),
            "deadbeef-not-a-uuid",
        ),
    ] {
        let response = get(&harness.app, uri, &harness.token_a).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let text = body_text(response).await?;
        assert!(!text.contains(raw), "{uri} echoed {raw:?}: {text}");
    }
    Ok(())
}

#[tokio::test]
async fn unknown_but_well_formed_marker_is_a_cursor_not_an_existence_oracle()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = build_harness().await?;
    let mut created = Vec::new();
    for name in ["a", "b", "c"] {
        created.push(create_network(&harness.app, &harness.token_a, name).await?);
    }
    created.sort();

    // Below every identity: the whole canonical order, exactly once.
    let below = get(
        &harness.app,
        &format!("/v2.0/networks?marker={MARKER_BELOW_ALL}&limit=10"),
        &harness.token_a,
    )
    .await?;
    assert_eq!(below.status(), StatusCode::OK);
    let below_body = json(below).await?;
    let mut listed = ids(&below_body, "networks");
    listed.sort();
    assert_eq!(listed, created, "{below_body}");

    // Above every identity: a normal empty page, never a 404 and never a
    // repeated page.
    let above = get(
        &harness.app,
        &format!("/v2.0/networks?marker={MARKER_ABOVE_ALL}&limit=10"),
        &harness.token_a,
    )
    .await?;
    assert_eq!(above.status(), StatusCode::OK);
    let above_body = json(above).await?;
    assert_eq!(
        above_body["networks"].as_array().map(Vec::len),
        Some(0),
        "{above_body}"
    );

    // A real marker is a strict cursor, and repeating it is stable.
    let first = created[0].clone();
    let cursor_uri = format!("/v2.0/networks?marker={first}&limit=10");
    let cursor = json(get(&harness.app, &cursor_uri, &harness.token_a).await?).await?;
    let repeated = json(get(&harness.app, &cursor_uri, &harness.token_a).await?).await?;
    assert_eq!(cursor, repeated, "cursor page is not stable");
    assert!(!ids(&cursor, "networks").contains(&first), "{cursor}");
    Ok(())
}

#[tokio::test]
async fn servers_detail_pagination_pages_and_terminates() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = build_harness().await?;
    let network_id =
        create_server_network(&harness.app, &harness.token_a, "net-a", "10.0.0.0/24").await?;
    let first = create_server(
        &harness.app,
        &harness.token_a,
        PROJECT_A,
        "one",
        &network_id,
    )
    .await?;
    let second = create_server(
        &harness.app,
        &harness.token_a,
        PROJECT_A,
        "two",
        &network_id,
    )
    .await?;

    let page = get(
        &harness.app,
        &format!("/v2.1/{PROJECT_A}/servers/detail?limit=1"),
        &harness.token_a,
    )
    .await?;
    assert_eq!(page.status(), StatusCode::OK);
    let page_body = json(page).await?;
    let page_ids = ids(&page_body, "servers");
    assert_eq!(page_ids.len(), 1, "{page_body}");
    let head = page_ids[0].clone();
    let next = next_href(&page_body, "servers_links").ok_or("missing next link")?;
    assert_eq!(
        next,
        format!("/v2.1/{PROJECT_A}/servers/detail?marker={head}&limit=1")
    );

    // The captured Nova-shaped follow-up: `limit=1` plus the marker of the last
    // resource on the page returns the remaining page.
    let remaining = json(
        get(
            &harness.app,
            &format!("/v2.1/{PROJECT_A}/servers/detail?limit=1&marker={head}"),
            &harness.token_a,
        )
        .await?,
    )
    .await?;
    let remaining_ids = ids(&remaining, "servers");
    assert_eq!(remaining_ids.len(), 1, "{remaining}");
    let tail_id = remaining_ids[0].clone();
    assert_ne!(tail_id, head, "the marker page re-served its own marker");

    // Following the last page's marker again terminates with an empty page.
    let tail = json(
        get(
            &harness.app,
            &format!("/v2.1/{PROJECT_A}/servers/detail?limit=1&marker={tail_id}"),
            &harness.token_a,
        )
        .await?,
    )
    .await?;
    assert_eq!(tail["servers"].as_array().map(Vec::len), Some(0), "{tail}");

    // Both servers were reachable exactly once across the traversal.
    let mut served = vec![head, tail_id];
    served.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(served, expected);
    Ok(())
}

#[tokio::test]
async fn servers_collection_pagination_traversal_is_stable_and_complete()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = build_harness().await?;
    let network_id =
        create_server_network(&harness.app, &harness.token_a, "net-a", "10.0.0.0/24").await?;
    let mut created = Vec::new();
    for name in ["one", "two", "three"] {
        created.push(
            create_server(&harness.app, &harness.token_a, PROJECT_A, name, &network_id).await?,
        );
    }
    created.sort();

    for verb in ["servers", "servers/detail"] {
        let visited = collect_pages(
            &harness.app,
            &format!("/v2.1/{PROJECT_A}/{verb}?limit=1"),
            &harness.token_a,
            "servers",
            "servers_links",
        )
        .await?;
        let mut unique = visited.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), visited.len(), "{verb} repeated a server");
        assert_eq!(unique, created, "{verb} missed or added a server");
    }

    // Without a limit the collection keeps its pre-existing shape.
    let plain = json(
        get(
            &harness.app,
            &format!("/v2.1/{PROJECT_A}/servers"),
            &harness.token_a,
        )
        .await?,
    )
    .await?;
    assert!(plain.get("servers_links").is_none(), "{plain}");
    assert_eq!(ids(&plain, "servers").len(), 3, "{plain}");
    Ok(())
}

#[tokio::test]
async fn server_collection_pagination_is_project_scoped() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = build_harness().await?;
    let network_a =
        create_server_network(&harness.app, &harness.token_a, "net-a", "10.0.0.0/24").await?;
    let network_b =
        create_server_network(&harness.app, &harness.token_b, "net-b", "10.1.0.0/24").await?;
    let server_a = create_server(
        &harness.app,
        &harness.token_a,
        PROJECT_A,
        "a-one",
        &network_a,
    )
    .await?;
    let server_b = create_server(
        &harness.app,
        &harness.token_b,
        PROJECT_B,
        "b-one",
        &network_b,
    )
    .await?;

    let visited = collect_pages(
        &harness.app,
        &format!("/v2.1/{PROJECT_B}/servers?limit=1"),
        &harness.token_b,
        "servers",
        "servers_links",
    )
    .await?;
    assert_eq!(visited.len(), 1, "{visited:?}");
    assert_eq!(visited[0], server_b, "{visited:?}");

    // A foreign project's cursor never reaches the other project's resources,
    // and a well-formed unknown marker is not an existence oracle.
    let foreign_cursor = json(
        get(
            &harness.app,
            &format!("/v2.1/{PROJECT_B}/servers?limit=1&marker={server_a}"),
            &harness.token_b,
        )
        .await?,
    )
    .await?;
    assert!(
        !ids(&foreign_cursor, "servers").contains(&server_a),
        "{foreign_cursor}"
    );

    // Network collections are project-scoped in exactly the same way.
    let network_b_only = collect_pages(
        &harness.app,
        "/v2.0/networks?limit=1",
        &harness.token_b,
        "networks",
        "networks_links",
    )
    .await?;
    assert_eq!(network_b_only, [network_b], "{network_b_only:?}");
    assert!(!network_b_only.contains(&network_a));
    Ok(())
}
