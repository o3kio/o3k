//! P12-IAM.7 evidence against a real OIDC provider.
//!
//! The shell harness starts Keycloak and obtains real OAuth access tokens. This
//! test owns only the O3K side of the boundary: durable subject bindings,
//! authorization, native exchange, restart, and secret-safe failure checks.
#![allow(clippy::expect_used, clippy::panic)]

use o3k_native_api::auth::{NativeAuth, NativeFederatedCredentials, NativeTokenRequestV1};
use o3k_store::{FederatedBindingRecord, IdentityRepository, OperatorAssignmentRecord};
use std::{sync::Arc, time::Duration};

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}

fn federated_request(token: &str, project_id: Option<&str>, system: bool) -> NativeTokenRequestV1 {
    NativeTokenRequestV1 {
        auth: NativeAuth {
            method: "federated".to_owned(),
            password: None,
            token: None,
            project_id: project_id.map(str::to_owned),
            federated: Some(NativeFederatedCredentials {
                access_token: token.to_owned(),
                scope: system.then_some(o3k_native_api::auth::NativeFederatedScope::System),
            }),
        },
    }
}

async fn open_store() -> Result<o3k_store::unified::O3kStore, Box<dyn std::error::Error>> {
    if let Ok(url) = std::env::var("O3K_DATABASE_URL") {
        return Ok(o3k_store::unified::O3kStore::connect_postgres(&url).await?);
    }
    let path = std::env::var("O3K_P12_7_SQLITE_PATH")?;
    Ok(o3k_store::unified::O3kStore::connect_sqlite_file(path.as_ref()).await?)
}

async fn configure_store(
    store: &o3k_store::unified::O3kStore,
    issuer: &str,
    alice_subject: &str,
    bob_subject: &str,
    operator_subject: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    o3k_identity::seed_identity_defaults(
        store,
        &o3k_identity::BootstrapConfig {
            catalog_endpoint: "http://127.0.0.1:8080".to_owned(),
            bootstrap_password: o3k_identity::Secret::new(required("O3K_P12_7_BOOTSTRAP_SECRET")),
            cinder_password: None,
            cinder_endpoint: None,
            pbkdf2_iterations: 1_000,
            extra_projects: vec![
                o3k_identity::ExtraProjectSeed {
                    project_id: "project-a".to_owned(),
                    project_name: "project-a".to_owned(),
                    user_id: "user-a".to_owned(),
                    user_name: "alice".to_owned(),
                    password: o3k_identity::Secret::new(required("O3K_P12_7_BOOTSTRAP_SECRET")),
                },
                o3k_identity::ExtraProjectSeed {
                    project_id: "project-b".to_owned(),
                    project_name: "project-b".to_owned(),
                    user_id: "user-b".to_owned(),
                    user_name: "bob".to_owned(),
                    password: o3k_identity::Secret::new(required("O3K_P12_7_BOOTSTRAP_SECRET")),
                },
            ],
        },
    )
    .await?;
    let now = "2026-09-06T00:00:00Z".to_owned();
    for (id, subject, principal) in [
        ("p12-7-alice", alice_subject, "user-a"),
        ("p12-7-bob", bob_subject, "user-b"),
        ("p12-7-operator", operator_subject, "bootstrap-user"),
    ] {
        store
            .insert_federated_binding(&FederatedBindingRecord {
                id: id.to_owned(),
                trusted_issuer_id: "p12-7-keycloak".to_owned(),
                issuer: issuer.to_owned(),
                subject: subject.to_owned(),
                principal_id: principal.to_owned(),
                principal_type: "user".to_owned(),
                enabled: true,
                created_at: now.clone(),
                updated_at: now.clone(),
            })
            .await?;
    }
    store
        .insert_operator_assignment(&OperatorAssignmentRecord {
            id: "p12-7-operator-assignment".to_owned(),
            user_id: "bootstrap-user".to_owned(),
            profile: "operator-console".to_owned(),
            enabled: true,
            created_at: now.clone(),
            updated_at: now,
        })
        .await?;
    Ok(())
}

fn validator() -> Result<Arc<o3k_identity::oidc::OidcValidator>, Box<dyn std::error::Error>> {
    let issuer = url::Url::parse(&required("O3K_P12_7_ISSUER"))?;
    let discovery = url::Url::parse(&required("O3K_P12_7_DISCOVERY_URL"))?;
    let trusted = o3k_identity::oidc::TrustedIssuer {
        id: "p12-7-keycloak".to_owned(),
        issuer,
        audience: "o3k".to_owned(),
        algorithms: vec![jsonwebtoken::Algorithm::RS256],
        discovery_url: discovery,
        allow_insecure_local: true,
        timeout: Duration::from_secs(5),
        cache_ttl: Duration::from_secs(300),
        max_token_bytes: 16 * 1024,
        max_document_bytes: 512 * 1024,
        clock_skew: Duration::from_secs(30),
    };
    Ok(Arc::new(o3k_identity::oidc::OidcValidator::new(trusted)?))
}

#[tokio::test]
#[ignore = "requires the real Keycloak testbed started by tests/p12-iam-7-real-idp.sh"]
async fn p12_iam_7_real_federation_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = required("O3K_P12_7_ISSUER");
    let alice_token = required("O3K_P12_7_ALICE_TOKEN");
    let bob_token = required("O3K_P12_7_BOB_TOKEN");
    let operator_token = required("O3K_P12_7_OPERATOR_TOKEN");
    let unbound_token = required("O3K_P12_7_UNBOUND_TOKEN");
    let alice_subject = required("O3K_P12_7_ALICE_SUBJECT");
    let bob_subject = required("O3K_P12_7_BOB_SUBJECT");
    let operator_subject = required("O3K_P12_7_OPERATOR_SUBJECT");

    let store = Arc::new(open_store().await?);
    configure_store(
        store.as_ref(),
        &issuer,
        &alice_subject,
        &bob_subject,
        &operator_subject,
    )
    .await?;
    let identity = Arc::new(
        o3k_identity::TokenService::load(
            store.clone(),
            o3k_identity::Secret::new(
                "p12-7-real-evidence-signing-key-at-least-32-bytes".to_owned(),
            ),
            Duration::from_secs(900),
        )
        .await?,
    );
    let adapter = o3kd::native_adapters::TokenIssuerAdapter {
        service: identity.clone(),
        oidc_validator: Some(validator()?),
    };

    let (alice_native, _) = o3k_native_api::auth::TokenIssuer::issue_native(
        &adapter,
        &federated_request(&alice_token, Some("project-a"), false),
    )
    .await
    .map_err(|error| format!("Alice Project A exchange failed: {error:?}"))?;
    let alice_context = o3k_native_api::auth::TokenIssuer::auth_context(&adapter, &alice_native)
        .await
        .map_err(|error| format!("Alice native context failed: {error:?}"))?;
    assert_eq!(alice_context.effective_scope().id().as_str(), "project-a");
    assert!(!format!("{alice_context:?}").contains(&alice_token));

    assert!(
        o3k_native_api::auth::TokenIssuer::issue_native(
            &adapter,
            &federated_request(&alice_token, Some("project-b"), false),
        )
        .await
        .is_err()
    );
    assert!(
        o3k_native_api::auth::TokenIssuer::issue_native(
            &adapter,
            &federated_request(&bob_token, Some("project-a"), false),
        )
        .await
        .is_err()
    );

    let (operator_native, _) = o3k_native_api::auth::TokenIssuer::issue_native(
        &adapter,
        &federated_request(&operator_token, None, true),
    )
    .await
    .map_err(|error| format!("operator system exchange failed: {error:?}"))?;
    let operator_context =
        o3k_native_api::auth::TokenIssuer::auth_context(&adapter, &operator_native)
            .await
            .map_err(|error| format!("operator native context failed: {error:?}"))?;
    assert_eq!(
        operator_context.effective_scope().kind(),
        o3k_kernel::ScopeKind::System
    );
    assert!(
        o3k_native_api::auth::TokenIssuer::issue_native(
            &adapter,
            &federated_request(&alice_token, None, true),
        )
        .await
        .is_err()
    );
    // The IdP can authenticate an otherwise valid subject, but O3K's durable
    // binding is the authority boundary and the unknown subject is denied.
    assert!(
        o3k_native_api::auth::TokenIssuer::issue_native(
            &adapter,
            &federated_request(&unbound_token, Some("project-a"), false),
        )
        .await
        .is_err()
    );

    // Wrong issuer, audience, and signature all fail before durable scope
    // authorization. A temporarily unavailable JWKS endpoint also fails
    // closed and exposes no provider or credential material.
    let wrong_issuer = o3k_identity::oidc::TrustedIssuer {
        issuer: url::Url::parse("http://127.0.0.1:9/wrong")?,
        ..validator()?.issuer().clone()
    };
    assert!(
        o3k_identity::oidc::OidcValidator::new(wrong_issuer)?
            .validate(&alice_token)
            .await
            .is_err()
    );
    let wrong_audience = o3k_identity::oidc::TrustedIssuer {
        audience: "wrong-audience".to_owned(),
        ..validator()?.issuer().clone()
    };
    assert!(
        o3k_identity::oidc::OidcValidator::new(wrong_audience)?
            .validate(&alice_token)
            .await
            .is_err()
    );
    let mut invalid_signature = alice_token.clone().into_bytes();
    let last = invalid_signature.len() - 1;
    invalid_signature[last] = if invalid_signature[last] == b'A' {
        b'B'
    } else {
        b'A'
    };
    assert!(
        validator()?
            .validate(std::str::from_utf8(&invalid_signature)?)
            .await
            .is_err()
    );

    // Reconstruct the service from the same durable store. Bindings and the
    // operator assignment must survive the control-plane restart.
    drop(adapter);
    drop(identity);
    let reloaded = Arc::new(
        o3k_identity::TokenService::load(
            store.clone(),
            o3k_identity::Secret::new(
                "p12-7-real-evidence-signing-key-at-least-32-bytes".to_owned(),
            ),
            Duration::from_secs(900),
        )
        .await?,
    );
    let reloaded_adapter = o3kd::native_adapters::TokenIssuerAdapter {
        service: reloaded,
        oidc_validator: Some(validator()?),
    };
    assert!(
        o3k_native_api::auth::TokenIssuer::issue_native(
            &reloaded_adapter,
            &federated_request(&alice_token, Some("project-a"), false),
        )
        .await
        .is_ok()
    );
    // A durable binding alone is not operator authority: removing the
    // canonical operator-console assignment must deny a system exchange.
    store
        .set_operator_assignment_enabled("p12-7-operator-assignment", false)
        .await?;
    let assignment_removed = o3k_identity::TokenService::load(
        store.clone(),
        o3k_identity::Secret::new("p12-7-real-evidence-signing-key-at-least-32-bytes".to_owned()),
        Duration::from_secs(900),
    )
    .await?;
    let assignment_removed_adapter = o3kd::native_adapters::TokenIssuerAdapter {
        service: Arc::new(assignment_removed),
        oidc_validator: Some(validator()?),
    };
    assert!(
        o3k_native_api::auth::TokenIssuer::issue_native(
            &assignment_removed_adapter,
            &federated_request(&operator_token, None, true),
        )
        .await
        .is_err()
    );
    store
        .set_operator_assignment_enabled("p12-7-operator-assignment", true)
        .await?;
    store
        .set_federated_binding_enabled("p12-7-alice", false)
        .await?;
    let disabled_binding = o3k_identity::TokenService::load(
        store.clone(),
        o3k_identity::Secret::new("p12-7-real-evidence-signing-key-at-least-32-bytes".to_owned()),
        Duration::from_secs(900),
    )
    .await?;
    let disabled_adapter = o3kd::native_adapters::TokenIssuerAdapter {
        service: Arc::new(disabled_binding),
        oidc_validator: Some(validator()?),
    };
    assert!(
        o3k_native_api::auth::TokenIssuer::issue_native(
            &disabled_adapter,
            &federated_request(&alice_token, Some("project-a"), false),
        )
        .await
        .is_err()
    );
    store
        .set_federated_binding_enabled("p12-7-alice", true)
        .await?;
    println!("P12-IAM.7 real federation evidence: PASS");
    Ok(())
}
