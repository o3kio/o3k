//! Gate A — Identity gate.
//!
//! Proves the identity surface required by the Cinder 28 attachment closure:
//!
//! 1. project-scoped password token issuance and public validation;
//! 2. token re-authentication (`methods: ["token"]`, used by Cinder's Nova
//!    client and keystone service_auth);
//! 3. service-role tokens: the Cinder service user's token carries the
//!    `service` role and is distinguishable from a regular user token;
//! 4. `X-Service-Token` on Cinder deletion: the outbound Cinder client sends a
//!    service-role token in `X-Service-Token` and the fake Cinder validates it
//!    through the public Identity API (`attachment_deletion_allowed`);
//! 5. negative cases: a DELETE without a valid service token is rejected with
//!    409, a bogus token is rejected, and public validation returns 404.
//!
//! Everything runs against the real O3K identity implementation over HTTP.

use axum::{
    body::Body,
    http::{Method, StatusCode},
};
use http_body_util::BodyExt;
use o3k_cinder::ComputeConnector;
use o3k_cinder::testkit;
use o3k_identity::AuthError;
use o3k_identity::testkit::test_service;
use serde_json::json;

mod common;
use common::{PROJECT, keystone_router, setup};

fn connector() -> ComputeConnector {
    ComputeConnector {
        host: "compute-gate-a".to_owned(),
        ip: "10.0.0.5".to_owned(),
        platform: "x86_64".to_owned(),
        os_type: "linux".to_owned(),
        multipath: false,
        initiator: Some("iqn.1993-08.org.debian:01:o3k-gate-a".to_owned()),
    }
}

fn roles_of(token_response: &o3k_identity::TokenResponse) -> Vec<String> {
    token_response
        .token
        .roles()
        .iter()
        .map(|role| role.name.clone())
        .collect()
}

#[tokio::test]
async fn password_authentication_issues_and_public_validation_succeeds()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = test_service("http://127.0.0.1:8080").await?;
    let (app, address) = keystone_router(identity).await?;
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(hyper_util::client::legacy::connect::HttpConnector::new());

    // Password authentication returns 201 with x-subject-token.
    let body = json!({"auth": {
        "identity": {"methods": ["password"], "password": {"user": {"name": "admin", "password": "password"}}},
        "scope": {"project": {"name": "admin"}}
    }}).to_string();
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("http://{address}/v3/auth/tokens"))
        .header("content-type", "application/json")
        .body(Body::from(body))?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let subject = resp
        .headers()
        .get("x-subject-token")
        .ok_or("missing x-subject-token")?
        .to_str()?
        .to_owned();

    // Public validation returns 200 with details and roles.
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(format!("http://{address}/v3/auth/tokens"))
        .header("x-subject-token", &subject)
        .header("x-auth-token", &subject)
        .body(Body::empty())?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = app;
    Ok(())
}

#[tokio::test]
async fn token_reauthentication_exchanges_a_valid_token() -> Result<(), Box<dyn std::error::Error>>
{
    let identity = test_service("http://127.0.0.1:8080").await?;
    let (_app, address) = keystone_router(identity.clone()).await?;
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(hyper_util::client::legacy::connect::HttpConnector::new());

    // Issue a password token, then exchange it with methods: ["token"].
    let body = json!({"auth": {
        "identity": {"methods": ["password"], "password": {"user": {"name": "admin", "password": "password"}}},
        "scope": {"project": {"name": "admin"}}
    }}).to_string();
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("http://{address}/v3/auth/tokens"))
        .header("content-type", "application/json")
        .body(Body::from(body))?;
    let resp = client.request(req).await?;
    let subject = resp
        .headers()
        .get("x-subject-token")
        .ok_or("missing x-subject-token")?
        .to_str()?
        .to_owned();

    // Token re-authentication body.
    let body = json!({"auth": {
        "identity": {"methods": ["token"], "token": {"id": subject}},
        "scope": {"project": {"name": "admin"}}
    }})
    .to_string();
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("http://{address}/v3/auth/tokens"))
        .header("content-type", "application/json")
        .body(Body::from(body))?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert!(resp.headers().get("x-subject-token").is_some());
    Ok(())
}

#[tokio::test]
async fn cinder_service_token_carries_the_service_role() -> Result<(), Box<dyn std::error::Error>> {
    let identity = test_service("http://127.0.0.1:8080").await?;
    let (token, _) = identity.issue(
        &o3k_identity::testkit::cinder_service_request("password"),
        std::time::SystemTime::now(),
    )?;
    let details = identity.verify_details(&token, std::time::SystemTime::now())?;
    let roles = roles_of(&details);
    assert!(
        roles.iter().any(|role| role == "service"),
        "cinder service token must carry the service role: {roles:?}"
    );

    // A regular user token must not be a service token.
    let (user_token, _) = identity.issue(
        &o3k_identity::testkit::admin_request("password"),
        std::time::SystemTime::now(),
    )?;
    let user_details = identity.verify_details(&user_token, std::time::SystemTime::now())?;
    let user_roles = roles_of(&user_details);
    assert!(
        !user_roles.iter().any(|role| role == "service"),
        "regular user token must not carry the service role: {user_roles:?}"
    );
    Ok(())
}

#[tokio::test]
async fn delete_sends_and_validates_x_service_token_through_public_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let (client, fake, _endpoint) = setup().await?;
    let volume = client.create_volume(PROJECT, 1, "gate-a-vol").await?;
    let attachment = client
        .create_attachment(
            PROJECT,
            &volume.id,
            Some("9dd22dc6-ea63-5bea-b994-f5a3796a3c59"),
        )
        .await?;
    client
        .update_attachment_connector(PROJECT, &attachment.id, &connector())
        .await?;
    assert_eq!(
        fake.last_delete_service_token_validated(),
        None,
        "no delete yet"
    );

    client.terminate_attachment(PROJECT, &attachment.id).await?;

    // The fake validated the X-Service-Token through the public Identity API.
    assert_eq!(
        fake.last_delete_service_token_validated(),
        Some(true),
        "terminate must send a service-role X-Service-Token validated by keystone"
    );
    client.delete_volume(PROJECT, &volume.id).await?;
    Ok(())
}

#[tokio::test]
async fn delete_without_service_token_is_rejected_with_conflict()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = test_service("http://127.0.0.1:8080").await?;
    let (_app, keystone_address) = keystone_router(identity.clone()).await?;
    let (fake, cinder_address) =
        testkit::start_fake_cinder(Some(format!("http://{keystone_address}"))).await?;
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(hyper_util::client::legacy::connect::HttpConnector::new());

    // A regular user token (no service role) validated by the router's service.
    let (user_token, _) = identity.issue(
        &o3k_identity::testkit::admin_request("password"),
        std::time::SystemTime::now(),
    )?;
    let _ = &fake;
    // Seed a volume and attachment directly on the fake so we can DELETE with a
    // user token and no service token.
    let body = serde_json::json!({"volume": {"size": 1, "name": "v"}});
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("http://{cinder_address}/v3/{PROJECT}/volumes"))
        .header("x-auth-token", &user_token)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(format!("http://{cinder_address}/v3/{PROJECT}/volumes"))
        .header("x-auth-token", &user_token)
        .body(Body::empty())?;
    let resp = client.request(req).await?;
    let value: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await?.to_bytes())?;
    let volume_id = value["volumes"][0]["id"]
        .as_str()
        .ok_or("volume id missing")?
        .to_owned();

    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("http://{cinder_address}/v3/{PROJECT}/attachments"))
        .header("x-auth-token", &user_token)
        .header("content-type", "application/json")
        .body(Body::from(json!({"attachment": {"volume_uuid": volume_id, "instance_uuid": "9dd22dc6-ea63-5bea-b994-f5a3796a3c59"}}).to_string()))?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let value: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await?.to_bytes())?;
    let attachment_id = value["attachment"]["id"]
        .as_str()
        .ok_or("attachment id missing")?
        .to_owned();

    // Make the attachment LIVE (instance + connection_info) with a connector
    // update so the delete guard applies.
    let req = axum::http::Request::builder()
        .method(Method::PUT)
        .uri(format!(
            "http://{cinder_address}/v3/{PROJECT}/attachments/{attachment_id}"
        ))
        .header("x-auth-token", &user_token)
        .header("content-type", "application/json")
        .body(Body::from(json!({"attachment": {"connector": {"host": "c", "ip": "10.0.0.5", "platform": "x86_64", "os_type": "linux", "multipath": false}}}).to_string()))?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);

    // DELETE without X-Service-Token must be rejected with 409 for a live
    // attachment, mirroring Cinder 28 attachment_deletion_allowed.
    let req = axum::http::Request::builder()
        .method(Method::DELETE)
        .uri(format!(
            "http://{cinder_address}/v3/{PROJECT}/attachments/{attachment_id}"
        ))
        .header("x-auth-token", &user_token)
        .body(Body::empty())?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    Ok(())
}

#[tokio::test]
async fn invalid_token_is_rejected_by_public_validation() -> Result<(), Box<dyn std::error::Error>>
{
    let identity = test_service("http://127.0.0.1:8080").await?;
    let (_app, address) = keystone_router(identity).await?;
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(hyper_util::client::legacy::connect::HttpConnector::new());
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(format!("http://{address}/v3/auth/tokens"))
        .header("x-subject-token", "not-a-real-token")
        .header("x-auth-token", "not-a-real-token")
        .body(Body::empty())?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn head_token_existence_check_validates_and_rejects() -> Result<(), Box<dyn std::error::Error>>
{
    // keystonemiddleware uses HEAD /v3/auth/tokens for cheap token existence.
    let identity = test_service("http://127.0.0.1:8080").await?;
    let (_app, address) = keystone_router(identity.clone()).await?;
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(hyper_util::client::legacy::connect::HttpConnector::new());

    let (token, _) = identity.issue(
        &o3k_identity::testkit::cinder_service_request("password"),
        std::time::SystemTime::now(),
    )?;
    let req = axum::http::Request::builder()
        .method(Method::HEAD)
        .uri(format!("http://{address}/v3/auth/tokens"))
        .header("x-subject-token", &token)
        .header("x-auth-token", &token)
        .body(Body::empty())?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);

    let req = axum::http::Request::builder()
        .method(Method::HEAD)
        .uri(format!("http://{address}/v3/auth/tokens"))
        .header("x-subject-token", "bogus")
        .header("x-auth-token", "bogus")
        .body(Body::empty())?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn wrong_service_password_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let identity = test_service("http://127.0.0.1:8080").await?;
    let result = identity.issue(
        &o3k_identity::testkit::cinder_service_request("wrong"),
        std::time::SystemTime::now(),
    );
    assert!(matches!(result, Err(AuthError::Unauthorized)));
    Ok(())
}
