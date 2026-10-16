use std::sync::{Arc, RwLock};

use o3k_kernel::{AuthContext, CloudProfile, ManifestRegistry};
use o3k_store::{
    AuditEventRecord, CloudProfileRecord, CompositionRepository, O3kStore, StoreError,
};

/// Production composition adapter. It persists only desired CloudProfile
/// state; manifests remain the observed runtime registry supplied by o3kd.
pub struct CloudProfileAdapter {
    pub store: Arc<O3kStore>,
    pub registry: Arc<RwLock<ManifestRegistry>>,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[async_trait::async_trait]
impl o3k_native_api::composition::CompositionReader for CloudProfileAdapter {
    async fn get(&self, id: &str) -> Result<Option<CloudProfile>, String> {
        self.store
            .get_cloud_profile(id)
            .await
            .map_err(|e| e.to_string())?
            .map(|r| r.profile().map_err(|e| e.to_string()))
            .transpose()
    }
    async fn put(
        &self,
        profile: CloudProfile,
        expected: Option<u64>,
        auth: &AuthContext,
    ) -> Result<CloudProfile, o3k_native_api::composition::CompositionWriteError> {
        use o3k_native_api::composition::CompositionWriteError as WriteError;

        profile.validate().map_err(|_| WriteError::BadRequest)?;
        // Both stores persist the generation as a signed 64-bit integer; a
        // larger client value is a bad request, not a store fault.
        if i64::try_from(profile.generation).is_err() {
            return Err(WriteError::BadRequest);
        }
        let record = CloudProfileRecord::from_profile(&profile, now())
            .map_err(|_| WriteError::BadRequest)?;
        let audit = AuditEventRecord {
            event_id: format!(
                "cloud-profile:{}:{}",
                profile.profile_id, profile.generation
            ),
            timestamp: now(),
            request_id: auth.request_id().to_owned(),
            audit_id: auth.audit_id().to_owned(),
            principal_id: auth.principal().id().to_string(),
            principal_kind: "user".to_owned(),
            effective_scope: auth.effective_scope().id().as_str().to_owned(),
            service: "composition".to_owned(),
            action: "composition:ManageCloudProfile".to_owned(),
            resource_type: Some("composition:cloud_profile".to_owned()),
            resource_id: Some(profile.profile_id.clone()),
            owner_scope: None,
            operation_id: None,
            outcome: "succeeded".to_owned(),
            reason_category: None,
        };
        self.store
            .upsert_cloud_profile_with_audit(&record, expected, &audit)
            .await
            .map_err(|error| match error {
                // A reused generation collides on the audit event id; that is
                // a client conflict, not a server fault.
                StoreError::StaleGeneration | StoreError::AuditEventConflict => {
                    WriteError::Conflict
                }
                StoreError::Database(_) | StoreError::Migration(_) => WriteError::NotAvailable,
                _ => WriteError::Internal,
            })?;
        Ok(profile)
    }
    async fn reconcile(
        &self,
        id: &str,
        _auth: &AuthContext,
    ) -> Result<o3k_native_api::composition::CloudProfileView, String> {
        let profile = self
            .get(id)
            .await?
            .ok_or_else(|| "profile not found".to_owned())?;
        let registry = self
            .registry
            .read()
            .map_err(|_| "registry unavailable".to_owned())?;
        let observation = profile.observe(&registry);
        Ok(o3k_native_api::composition::CloudProfileView {
            profile,
            consumable: Some(observation.consumable),
            drift: Some(observation.drifts),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use o3k_kernel::{
        AuthContext, OwnershipScope, Principal, PrincipalId, ScopeId, ScopeKind,
        ServiceOwnershipMode, ServiceSelection, UserPrincipal,
    };
    use o3k_native_api::{NativeApiState, auth, pagination, router};
    use o3k_store::AuditRepository;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tower::ServiceExt;

    struct TestIssuer(AuthContext);

    #[async_trait::async_trait]
    impl auth::TokenIssuer for TestIssuer {
        async fn issue_native(
            &self,
            _request: &auth::NativeTokenRequestV1,
        ) -> Result<(String, Value), o3k_native_api::error::ProblemDetails> {
            Err(o3k_native_api::error::ProblemDetails::unauthorized())
        }

        async fn auth_context(
            &self,
            token: &str,
        ) -> Result<AuthContext, o3k_native_api::error::ProblemDetails> {
            if token == "test-operator" {
                Ok(self.0.clone())
            } else {
                Err(o3k_native_api::error::ProblemDetails::unauthorized())
            }
        }
    }

    fn operator_context() -> AuthContext {
        AuthContext::new(
            Principal::User(UserPrincipal::new(
                PrincipalId::new_unchecked("operator-1"),
                "operator",
                None,
            )),
            OwnershipScope::new(
                ScopeId::new_unchecked("system"),
                ScopeKind::System,
                None,
                None,
            ),
            vec!["operator".to_owned()],
            1,
            2,
            "cloud-profile-test-audit",
            "cloud-profile-test-request",
            None,
        )
    }

    fn valid_profile() -> CloudProfile {
        CloudProfile {
            profile_id: "default".to_owned(),
            generation: 1,
            selected_services: vec![ServiceSelection {
                service_id: "compute".to_owned(),
                ownership: ServiceOwnershipMode::O3kImplemented,
                version_requirement: "*".to_owned(),
                dependencies: vec![],
                required_capabilities: vec![],
                locality: None,
                placement_requirement: None,
                config_refs: vec![],
            }],
            upgrade_order: vec![],
        }
    }

    async fn snapshot(store: &O3kStore) -> (CloudProfileRecord, Vec<o3k_store::AuditEventRecord>) {
        let profile = store
            .get_cloud_profile("default")
            .await
            .unwrap()
            .expect("seed profile");
        let audit = match store {
            O3kStore::Sqlite(sqlite) => {
                sqlite
                    .list_audit_events_page("system", None, 100)
                    .await
                    .unwrap()
                    .items
            }
            O3kStore::Postgres(_) => panic!("test uses the SQLite profile"),
        };
        (profile, audit)
    }

    fn cloud_profile_app(store: Arc<O3kStore>) -> axum::Router {
        let registry = Arc::new(RwLock::new(ManifestRegistry::new()));
        let state = NativeApiState::new(
            None,
            pagination::CursorConfig::default(),
            Some(Arc::new(TestIssuer(operator_context()))),
            None,
            None,
            None,
        )
        .unwrap()
        .with_authorizer(Arc::new(o3k_kernel::StaticAuthorizer::standard()))
        .with_composition_reader(Arc::new(CloudProfileAdapter { store, registry }));
        router(state)
    }

    async fn put_profile(
        app: &axum::Router,
        body: String,
        content_type: Option<&str>,
    ) -> axum::response::Response {
        let mut request = Request::builder()
            .method("PUT")
            .uri("/operator/cloud-profiles/default")
            .header("authorization", "Bearer test-operator")
            .header("x-request-id", "cloud-profile-test-request");
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        app.clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn rejected_cloud_profile_writes_preserve_profile_and_audit() {
        let store = Arc::new(O3kStore::connect_sqlite_memory().await.unwrap());
        let app = cloud_profile_app(store.clone());
        let send = |body: String| {
            let app = app.clone();
            async move { put_profile(&app, body, Some("application/json")).await }
        };

        let initial = json!({"profile": valid_profile(), "expected_generation": null});
        let response = send(initial.to_string()).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let baseline = snapshot(&store).await;

        let malformed = send("{ malformed INPUT-SECRET-MARKER".to_owned()).await;
        assert_eq!(malformed.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            malformed
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        let body = axum::body::to_bytes(malformed.into_body(), 4096)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("INPUT-SECRET-MARKER"));
        assert_eq!(snapshot(&store).await, baseline);

        let unknown_field = json!({
            "profile": valid_profile(),
            "expected_generation": 1,
            "unexpected": "INPUT-SECRET-MARKER"
        });
        let response = send(unknown_field.to_string()).await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("INPUT-SECRET-MARKER"));
        assert_eq!(snapshot(&store).await, baseline);

        let mut mismatched = valid_profile();
        mismatched.profile_id = "other-profile".to_owned();
        let response =
            send(json!({"profile": mismatched, "expected_generation": 1}).to_string()).await;
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let problem: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["request_id"], "cloud-profile-test-request");
        assert_eq!(snapshot(&store).await, baseline);

        let mut invalid = valid_profile();
        invalid.generation = 2;
        invalid.selected_services[0].config_refs = vec!["password=INPUT-SECRET-MARKER".into()];
        let response =
            send(json!({"profile": invalid, "expected_generation": 1}).to_string()).await;
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("INPUT-SECRET-MARKER"));
        let problem: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["request_id"], "cloud-profile-test-request");
        assert_eq!(snapshot(&store).await, baseline);

        let mut stale = valid_profile();
        stale.generation = 2;
        let response = send(json!({"profile": stale, "expected_generation": 0}).to_string()).await;
        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let problem: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["request_id"], "cloud-profile-test-request");
        assert_eq!(snapshot(&store).await, baseline);

        let response = put_profile(
            &app,
            json!({"profile": valid_profile(), "expected_generation": 1, "note": "INPUT-SECRET-MARKER"})
                .to_string(),
            None,
        )
        .await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("INPUT-SECRET-MARKER"));
        assert_eq!(snapshot(&store).await, baseline);

        let mut oversized = valid_profile();
        oversized.generation = u64::MAX;
        let response =
            send(json!({"profile": oversized, "expected_generation": 1}).to_string()).await;
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(snapshot(&store).await, baseline);

        // Re-sending the current generation passes the generation check but
        // reuses the audit event id: a client conflict, not a server fault.
        let response =
            send(json!({"profile": valid_profile(), "expected_generation": 1}).to_string()).await;
        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let problem: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["request_id"], "cloud-profile-test-request");
        assert_eq!(snapshot(&store).await, baseline);
    }

    #[tokio::test]
    async fn cloud_profile_write_reports_unavailable_store_as_503() {
        use sqlx::Connection as _;

        struct RemoveOnDrop(std::path::PathBuf);
        impl Drop for RemoveOnDrop {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let dir = std::env::temp_dir().join(format!("o3k-cloud-profile-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let _cleanup = RemoveOnDrop(dir.clone());
        let path = dir.join("store.sqlite");
        let store = Arc::new(O3kStore::connect_sqlite_file(&path).await.unwrap());
        let app = cloud_profile_app(store.clone());
        let initial = json!({"profile": valid_profile(), "expected_generation": null});
        let response = put_profile(&app, initial.to_string(), Some("application/json")).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Make the store fail with a database error on the next write.
        let mut external = sqlx::SqliteConnection::connect(&format!("sqlite://{}", path.display()))
            .await
            .unwrap();
        sqlx::query("DROP TABLE cloud_profiles")
            .execute(&mut external)
            .await
            .unwrap();
        external.close().await.unwrap();

        let mut next = valid_profile();
        next.generation = 2;
        let response = put_profile(
            &app,
            json!({"profile": next, "expected_generation": 1}).to_string(),
            Some("application/json"),
        )
        .await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let problem: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["request_id"], "cloud-profile-test-request");
        assert!(!String::from_utf8_lossy(&body).contains("cloud_profiles"));

        drop(app);
        drop(store);
    }
}
