use super::*;
use std::collections::BTreeMap;

use o3k_native_api::error::ProblemDetails;

/// Store-backed canonical operation visibility adapter. Historical operation
/// rows without P12.4 metadata fail closed rather than being reconstructed
/// with fabricated ownership or action fields.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod native_compute_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use o3k_domain::StorageCapabilities;
    use o3k_kernel::{
        ActionId, AuthContext, OwnershipScope, Principal, PrincipalId, ScopeId, UserPrincipal,
    };
    use o3k_native_api::auth::{NativeTokenRequestV1, TokenIssuer};
    use o3k_provider::{FailureInjection, FakeComputeProvider};
    use o3k_storage::{
        PreparedAttachment, StorageAttachmentObservation, StorageAttachmentRequest,
        StorageProvider, StorageProviderError, StorageSnapshotObservation, StorageSnapshotRequest,
        StorageVolumeObservation, StorageVolumeRequest,
    };
    use o3k_store::DurableStore;
    use o3k_store::StorageRepository;
    use o3k_store::{KeypairRepository, NetworkRepository};
    use std::sync::Arc;
    use tower::util::ServiceExt;
    use uuid::Uuid;

    struct TestIssuer;

    /// Minimal in-memory storage provider so the generic native volume create
    /// arm can run end to end; models observe-after-mutation without touching
    /// host storage.
    #[derive(Default)]
    struct FakeStorageProvider {
        volumes: std::sync::Mutex<BTreeMap<Uuid, StorageVolumeObservation>>,
    }

    #[async_trait::async_trait]
    impl StorageProvider for FakeStorageProvider {
        async fn capabilities(&self) -> Result<StorageCapabilities, StorageProviderError> {
            Ok(StorageCapabilities {
                create_volume: true,
                snapshots: false,
                attachment: false,
                capacity_bytes: 1 << 40,
                allocated_bytes: 0,
                allocation_unit_bytes: 4096,
            })
        }

        async fn create_volume(
            &self,
            request: &StorageVolumeRequest,
        ) -> Result<StorageVolumeObservation, StorageProviderError> {
            let observation = StorageVolumeObservation {
                provider_reference: o3k_domain::StorageProviderReference {
                    provider: "test".into(),
                    resource_id: format!("volume-{}", request.volume_id),
                },
                size_bytes: request.size_bytes,
                owned: true,
                available: true,
            };
            self.volumes
                .lock()
                .map_err(|_| StorageProviderError::CommandFailed)?
                .insert(request.volume_id.as_uuid(), observation.clone());
            Ok(observation)
        }

        async fn inspect_volume(
            &self,
            request: &StorageVolumeRequest,
        ) -> Result<StorageVolumeObservation, StorageProviderError> {
            self.volumes
                .lock()
                .map_err(|_| StorageProviderError::CommandFailed)?
                .get(&request.volume_id.as_uuid())
                .cloned()
                .ok_or(StorageProviderError::NotFound)
        }

        async fn delete_volume(
            &self,
            request: &StorageVolumeRequest,
        ) -> Result<(), StorageProviderError> {
            self.volumes
                .lock()
                .map_err(|_| StorageProviderError::CommandFailed)?
                .remove(&request.volume_id.as_uuid())
                .map(|_| ())
                .ok_or(StorageProviderError::NotFound)
        }

        async fn prepare_attachment(
            &self,
            request: &StorageAttachmentRequest,
        ) -> Result<PreparedAttachment, StorageProviderError> {
            PreparedAttachment::from_provider(
                o3k_domain::StorageProviderReference {
                    provider: "test".into(),
                    resource_id: format!("volume-{}", request.volume_id),
                },
                "/dev/test".into(),
                request.attachment_id,
                request.volume_id,
            )
        }

        async fn inspect_attachment(
            &self,
            request: &StorageAttachmentRequest,
        ) -> Result<StorageAttachmentObservation, StorageProviderError> {
            Ok(StorageAttachmentObservation {
                attachment_id: request.attachment_id,
                volume_id: request.volume_id,
                host_id: "test".into(),
                attached: false,
                provider_reference: o3k_domain::StorageProviderReference {
                    provider: "test".into(),
                    resource_id: format!("volume-{}", request.volume_id),
                },
            })
        }

        async fn terminate_attachment(
            &self,
            request: &StorageAttachmentRequest,
        ) -> Result<StorageAttachmentObservation, StorageProviderError> {
            self.inspect_attachment(request).await
        }

        async fn create_snapshot(
            &self,
            _request: &StorageSnapshotRequest,
        ) -> Result<StorageSnapshotObservation, StorageProviderError> {
            Err(StorageProviderError::InvalidRequest)
        }

        async fn delete_snapshot(
            &self,
            _request: &StorageSnapshotRequest,
        ) -> Result<(), StorageProviderError> {
            Err(StorageProviderError::InvalidRequest)
        }
    }

    fn context(project: &str) -> AuthContext {
        AuthContext::new(
            Principal::User(UserPrincipal::new(
                PrincipalId::new_unchecked(format!("user-{project}")),
                format!("user-{project}"),
                None,
            )),
            OwnershipScope::project(ScopeId::new_unchecked(project), None, None),
            vec!["member".into()],
            1,
            u64::MAX,
            "audit",
            "request",
            None,
        )
    }

    #[async_trait::async_trait]
    impl TokenIssuer for TestIssuer {
        async fn issue_native(
            &self,
            _request: &NativeTokenRequestV1,
        ) -> Result<(String, serde_json::Value), ProblemDetails> {
            Err(ProblemDetails::bad_request(
                "test issuer does not issue tokens",
            ))
        }

        async fn auth_context(&self, token: &str) -> Result<AuthContext, ProblemDetails> {
            token
                .strip_prefix("project-")
                .map(|project| context(&format!("project-{project}")))
                .ok_or_else(ProblemDetails::unauthorized)
        }
    }

    fn compute_manifest_registry() -> o3k_kernel::ManifestRegistry {
        use std::collections::HashMap;
        let mut reg = o3k_kernel::ManifestRegistry::new();
        let mut ops = HashMap::new();
        ops.insert(
            "create".to_owned(),
            ActionId::new_unchecked("compute", "CreateServer"),
        );
        ops.insert(
            "delete".to_owned(),
            ActionId::new_unchecked("compute", "DeleteServer"),
        );
        ops.insert(
            "list".to_owned(),
            ActionId::new_unchecked("compute", "ListServers"),
        );
        ops.insert(
            "show".to_owned(),
            ActionId::new_unchecked("compute", "ShowServer"),
        );
        ops.insert(
            "update".to_owned(),
            ActionId::new_unchecked("compute", "UpdateServer"),
        );
        ops.insert(
            "start".to_owned(),
            ActionId::new_unchecked("compute", "StartServer"),
        );
        ops.insert(
            "stop".to_owned(),
            ActionId::new_unchecked("compute", "StopServer"),
        );
        ops.insert(
            "reboot".to_owned(),
            ActionId::new_unchecked("compute", "RebootServer"),
        );
        let m = o3k_kernel::ServiceManifest {
            manifest_version: 1,
            service_id: "compute".to_owned(),
            namespace: "compute".to_owned(),
            service_version: "0.4.0".to_owned(),
            ownership: o3k_kernel::ServiceOwnership::O3kImplemented,
            resource_types: vec![o3k_kernel::RegisteredResourceType {
                resource_type: o3k_kernel::ResourceType::new_unchecked("compute", "server"),
                schema_version: "v1".to_owned(),
                collection: Some("servers".to_owned()),
                scope: o3k_kernel::ResourceScope::Tenant,
                operations: ops,
            }],
            actions: vec![
                "compute:ListServers".to_owned(),
                "compute:CreateServer".to_owned(),
                "compute:DeleteServer".to_owned(),
                "compute:ShowServer".to_owned(),
                "compute:UpdateServer".to_owned(),
                "compute:StartServer".to_owned(),
                "compute:StopServer".to_owned(),
                "compute:RebootServer".to_owned(),
            ],
            capabilities: vec![],
            dependencies: vec![],
            quota_dimensions: vec![],
            regions: vec![],
            availability_domains: vec![],
            controller: Some(o3k_kernel::ManifestController {
                mode: "in-process".to_owned(),
                protocol: "in-process".to_owned(),
                protocol_version: "1.0".to_owned(),
                service_principal: None,
            }),
            health: None,
        };
        let _ = reg.register(m);
        let _ = reg.register_controller(
            "compute",
            o3k_kernel::controller::ControllerSession {
                service_id: "compute".to_owned(),
                namespace: "compute".to_owned(),
                service_principal: o3k_kernel::ServicePrincipal::new(
                    o3k_kernel::PrincipalId::new_unchecked("test-controller"),
                    "test-controller",
                    "compute",
                ),
                session_id: uuid::Uuid::new_v4(),
                session_generation: 1,
                protocol_version: o3k_kernel::controller::ProtocolVersion::new(1, 0),
                manifest_digest: "test-digest".to_owned(),
                manifest_generation: 1,
                started_at: "2026-01-01T00:00:00Z".to_owned(),
            },
        );
        let _ = reg.activate_controller("compute");
        let mut network_ops = HashMap::new();
        network_ops.insert(
            "list".to_owned(),
            ActionId::new_unchecked("network", "ListNetworks"),
        );
        network_ops.insert(
            "show".to_owned(),
            ActionId::new_unchecked("network", "ReadNetwork"),
        );
        network_ops.insert(
            "create".to_owned(),
            ActionId::new_unchecked("network", "CreateNetwork"),
        );
        network_ops.insert(
            "delete".to_owned(),
            ActionId::new_unchecked("network", "DeleteNetwork"),
        );
        let network_manifest = o3k_kernel::ServiceManifest {
            manifest_version: 1,
            service_id: "network".to_owned(),
            namespace: "network".to_owned(),
            service_version: "0.4.0".to_owned(),
            ownership: o3k_kernel::ServiceOwnership::O3kImplemented,
            resource_types: vec![o3k_kernel::RegisteredResourceType {
                resource_type: o3k_kernel::ResourceType::new_unchecked("network", "network"),
                schema_version: "v1".to_owned(),
                collection: Some("networks".to_owned()),
                scope: o3k_kernel::ResourceScope::Tenant,
                operations: network_ops,
            }],
            actions: vec![
                "network:ListNetworks".to_owned(),
                "network:CreateNetwork".to_owned(),
                "network:ReadNetwork".to_owned(),
                "network:DeleteNetwork".to_owned(),
            ],
            capabilities: vec![],
            dependencies: vec![],
            quota_dimensions: vec![],
            regions: vec![],
            availability_domains: vec![],
            controller: Some(o3k_kernel::ManifestController {
                mode: "in-process".to_owned(),
                protocol: "in-process".to_owned(),
                protocol_version: "1.0".to_owned(),
                service_principal: None,
            }),
            health: None,
        };
        let _ = reg.register(network_manifest);
        let _ = reg.register_controller(
            "network",
            o3k_kernel::controller::ControllerSession {
                service_id: "network".to_owned(),
                namespace: "network".to_owned(),
                service_principal: o3k_kernel::ServicePrincipal::new(
                    o3k_kernel::PrincipalId::new_unchecked("test-network-controller"),
                    "test-network-controller",
                    "network",
                ),
                session_id: uuid::Uuid::new_v4(),
                session_generation: 1,
                protocol_version: o3k_kernel::controller::ProtocolVersion::new(1, 0),
                manifest_digest: "test-digest".to_owned(),
                manifest_generation: 1,
                started_at: "2026-01-01T00:00:00Z".to_owned(),
            },
        );
        let _ = reg.activate_controller("network");
        let mut volume_ops = HashMap::new();
        volume_ops.insert(
            "list".to_owned(),
            ActionId::new_unchecked("volume", "ListVolumes"),
        );
        volume_ops.insert(
            "show".to_owned(),
            ActionId::new_unchecked("volume", "ReadVolume"),
        );
        volume_ops.insert(
            "create".to_owned(),
            ActionId::new_unchecked("volume", "CreateVolume"),
        );
        volume_ops.insert(
            "delete".to_owned(),
            ActionId::new_unchecked("volume", "DeleteVolume"),
        );
        let volume_manifest = o3k_kernel::ServiceManifest {
            manifest_version: 1,
            service_id: "volume".to_owned(),
            namespace: "volume".to_owned(),
            service_version: "0.4.0".to_owned(),
            ownership: o3k_kernel::ServiceOwnership::O3kImplemented,
            resource_types: vec![o3k_kernel::RegisteredResourceType {
                resource_type: o3k_kernel::ResourceType::new_unchecked("volume", "volume"),
                schema_version: "v1".to_owned(),
                collection: Some("volumes".to_owned()),
                scope: o3k_kernel::ResourceScope::Tenant,
                operations: volume_ops,
            }],
            actions: vec![
                "volume:ListVolumes".to_owned(),
                "volume:CreateVolume".to_owned(),
                "volume:ReadVolume".to_owned(),
                "volume:DeleteVolume".to_owned(),
            ],
            capabilities: vec![],
            dependencies: vec![],
            quota_dimensions: vec![],
            regions: vec![],
            availability_domains: vec![],
            controller: Some(o3k_kernel::ManifestController {
                mode: "in-process".to_owned(),
                protocol: "in-process".to_owned(),
                protocol_version: "1.0".to_owned(),
                service_principal: None,
            }),
            health: None,
        };
        let _ = reg.register(volume_manifest);
        let _ = reg.register_controller(
            "volume",
            o3k_kernel::controller::ControllerSession {
                service_id: "volume".to_owned(),
                namespace: "volume".to_owned(),
                service_principal: o3k_kernel::ServicePrincipal::new(
                    o3k_kernel::PrincipalId::new_unchecked("test-volume-controller"),
                    "test-volume-controller",
                    "volume",
                ),
                session_id: uuid::Uuid::new_v4(),
                session_generation: 1,
                protocol_version: o3k_kernel::controller::ProtocolVersion::new(1, 0),
                manifest_digest: "test-digest".to_owned(),
                manifest_generation: 1,
                started_at: "2026-01-01T00:00:00Z".to_owned(),
            },
        );
        let _ = reg.activate_controller("volume");
        reg
    }

    async fn setup() -> (
        axum::Router,
        Arc<o3k_store::unified::O3kStore>,
        Arc<FakeComputeProvider>,
        Uuid,
    ) {
        let (router, store, provider, foreign_port, _) = setup_with_network().await;
        (router, store, provider, foreign_port)
    }

    async fn setup_with_network() -> (
        axum::Router,
        Arc<o3k_store::unified::O3kStore>,
        Arc<FakeComputeProvider>,
        Uuid,
        Arc<o3k_network::NetworkService>,
    ) {
        use axum::routing::get;
        use axum::{Router, extract::DefaultBodyLimit};
        use o3k_native_api::{operation, resource};

        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        let provider = Arc::new(FakeComputeProvider::new());
        let compute = Arc::new(o3k_compute::ComputeService::new_for_test(
            store.clone(),
            provider.clone(),
        ));
        let network_service = Arc::new(
            o3k_network::NetworkService::open_for_test(
                std::env::temp_dir().join(format!("o3k-native-test-{}", Uuid::new_v4())),
                store.clone(),
            )
            .await
            .expect("network service"),
        );
        let foreign_network = network_service
            .create_network_for_project("project-b", "foreign-network".to_owned())
            .await
            .expect("foreign network");
        network_service
            .create_subnet_for_project(
                "project-b",
                foreign_network.id,
                "foreign-subnet".to_owned(),
                "198.51.100.0/24".to_owned(),
                None,
                Some("198.51.100.10".parse().expect("pool start")),
                Some("198.51.100.200".parse().expect("pool end")),
            )
            .await
            .expect("foreign subnet");
        let foreign_port = network_service
            .create_port_for_project("project-b", foreign_network.id, "foreign-port".to_owned())
            .await
            .expect("foreign port")
            .id;

        let network_for_test = network_service.clone();
        let app = GenericResourceApplication {
            compute: compute.clone(),
            image: None,
            network_service,
            store: store.clone(),
            server: Arc::new(ServerReaderAdapter {
                service: compute.clone(),
            }),
            network: Arc::new(NetworkReaderAdapter {
                store: store.clone(),
                authorizer: Arc::new(o3k_kernel::StaticAuthorizer::empty()),
            }),
            external_controllers: Arc::new(BTreeMap::new()),
            public_allocator: None,
            public_address_workflow: None,
            network_external_realm_id: None,
            attachment_workflow: None,
            storage_provider: Some(Arc::new(FakeStorageProvider::default())),
            metering: None,
        };

        let native = o3k_native_api::NativeApiState::new(
            Some(compute_manifest_registry()),
            o3k_native_api::pagination::CursorConfig::new(
                b"test-only-native-cursor-key-at-least-32-bytes".to_vec(),
            )
            .expect("cursor key"),
            Some(Arc::new(TestIssuer)),
            Some(Arc::new(ServerReaderAdapter {
                service: compute.clone(),
            })),
            None,
            None,
        )
        .expect("native state")
        .with_operation_reader(Arc::new(OperationReaderAdapter {
            store: store.clone(),
        }))
        .with_resource_application(Arc::new(app))
        .with_authorizer(Arc::new(o3k_kernel::StaticAuthorizer::standard()));

        // Build a minimal router that only has generic resource routes and
        // the operation route — we deliberately omit the concrete
        // /compute/servers GET-only route so that POST to the generic
        // {namespace}/{collection} route resolves correctly.
        let router = Router::new()
            .route(
                "/{namespace}/{collection}",
                get(resource::list).post(resource::create),
            )
            .route(
                "/{namespace}/{collection}/{id}",
                get(resource::show)
                    .put(resource::update)
                    .delete(resource::delete),
            )
            .route(
                "/{namespace}/{collection}/{id}/actions/{action_name}",
                post(resource::action),
            )
            .route(
                "/{namespace}/{collection}/{id}/relationships",
                get(resource::relationships),
            )
            .route("/operations/{id}", get(operation::show_operation))
            .layer(DefaultBodyLimit::max(1_048_576))
            .with_state(native);

        (router, store, provider, foreign_port, network_for_test)
    }

    fn authed(path: &str, project: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header("authorization", format!("Bearer project-{project}"))
            .body(Body::empty())
            .expect("request")
    }

    fn authed_post(
        path: &str,
        project: &str,
        idempotency_key: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .uri(path)
            .method("POST")
            .header("authorization", format!("Bearer project-{project}"))
            .header("content-type", "application/json")
            .header("idempotency-key", idempotency_key)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .expect("request")
    }

    fn authed_put(
        path: &str,
        project: &str,
        idempotency_key: &str,
        generation: i64,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .uri(path)
            .method("PUT")
            .header("authorization", format!("Bearer project-{project}"))
            .header("content-type", "application/json")
            .header("idempotency-key", idempotency_key)
            .header("if-match", format!("generation-{generation}"))
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .expect("request")
    }

    fn authed_action(
        path: &str,
        project: &str,
        idempotency_key: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .uri(path)
            .method("POST")
            .header("authorization", format!("Bearer project-{project}"))
            .header("content-type", "application/json")
            .header("idempotency-key", idempotency_key)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .expect("request")
    }

    fn authed_delete(path: &str, project: &str, idempotency_key: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .method("DELETE")
            .header("authorization", format!("Bearer project-{project}"))
            .header("idempotency-key", idempotency_key)
            .body(Body::empty())
            .expect("request")
    }

    /// Helper: send a request through a cloned router and return (status, parsed JSON body).
    /// Panics if the body is not valid JSON.
    async fn exec(router: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = router.clone().oneshot(req).await.expect("request");
        let status = response.status();
        let body_bytes = &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(body_bytes).expect("json");
        (status, json)
    }

    // ── Tests ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn native_compute_create_and_read_operation() {
        let (router, _, _, _) = setup().await;
        let router = &router;
        let body = serde_json::json!({
            "spec": {
                "name": "test",
                "image_id": "image-a",
                "flavor_id": "00000000-0000-0000-0000-000000000001",
                "network_ids": ["net-a"]
            }
        });

        // POST create
        let (status, json) = exec(
            router,
            authed_post("/compute/servers", "a", "create-A", body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(json["complete"].as_bool().unwrap());
        let operation_id = json["operation_id"].as_str().unwrap().to_owned();
        let resource_id = json["resource_id"].as_str().unwrap().to_owned();

        // GET /operations/{id}
        let (status, op) = exec(router, authed(&format!("/operations/{operation_id}"), "a")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(op["id"], operation_id);
        assert_eq!(op["action"]["namespace"], "compute");
        assert_eq!(op["action"]["action"], "CreateServer");
        assert_eq!(op["resource_type"]["namespace"], "compute");
        assert_eq!(op["resource_type"]["name"], "server");
        assert_eq!(op["resource_id"], resource_id);
        assert_eq!(op["owner_scope"]["id"], "project-a");

        let update_body = serde_json::json!({"spec": {"name": "renamed"}});
        let (update_status, update) = exec(
            router,
            authed_put(
                &format!("/compute/servers/{resource_id}"),
                "a",
                "update-A",
                2,
                update_body.clone(),
            ),
        )
        .await;
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(update["resource_id"], resource_id);
        let operation_id = update["operation_id"].as_str().unwrap();

        let (replay_status, replay) = exec(
            router,
            authed_put(
                &format!("/compute/servers/{resource_id}"),
                "a",
                "update-A",
                2,
                update_body,
            ),
        )
        .await;
        assert_eq!(replay_status, StatusCode::OK);
        assert_eq!(replay["operation_id"], operation_id);

        let (conflict_status, _) = exec(
            router,
            authed_put(
                &format!("/compute/servers/{resource_id}"),
                "a",
                "update-A",
                2,
                serde_json::json!({"spec": {"name": "different"}}),
            ),
        )
        .await;
        assert_eq!(conflict_status, StatusCode::CONFLICT);

        let (stale_status, _) = exec(
            router,
            authed_put(
                &format!("/compute/servers/{resource_id}"),
                "a",
                "update-B",
                1,
                serde_json::json!({"spec": {"name": "stale"}}),
            ),
        )
        .await;
        assert_eq!(stale_status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn native_compute_canonical_network_resolves_one_deterministic_port() {
        let (router, store, provider, _, network) = setup_with_network().await;
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBJuQvak7YBzsbN71EyvJnDK8pODWM1Ox/3wO3tT8Adj o3k-test";
        let (key_type, fingerprint, public_key) =
            o3k_store::validate_public_key(public_key).expect("test key");
        store
            .insert_keypair(&o3k_store::KeypairRecord {
                id: Uuid::new_v5(&Uuid::NAMESPACE_URL, b"o3k:test-keypair"),
                user_id: "user-project-a".to_owned(),
                project_id: "project-a".to_owned(),
                name: "native-key".to_owned(),
                key_type,
                public_key: public_key.clone(),
                fingerprint,
                created_at: "1".to_owned(),
            })
            .await
            .expect("keypair");
        let canonical = network
            .create_network_for_project("project-a", "native-network".to_owned())
            .await
            .expect("canonical network");
        network
            .create_subnet_for_project(
                "project-a",
                canonical.id,
                "native-subnet".to_owned(),
                "192.0.2.0/29".to_owned(),
                None,
                Some("192.0.2.2".parse().unwrap()),
                Some("192.0.2.6".parse().unwrap()),
            )
            .await
            .expect("canonical subnet");
        let body = serde_json::json!({"spec": {
            "name": "native-network-vm",
            "image_id": "image-a",
            "flavor_id": "00000000-0000-0000-0000-000000000001",
            "network_ids": [canonical.id.to_string()],
            "key_name": "native-key"
        }});
        let before = network
            .list_ports_for_project("project-a")
            .await
            .unwrap()
            .len();
        let (status, first) = exec(
            &router,
            authed_post(
                "/compute/servers",
                "a",
                "native-network-create",
                body.clone(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(first["complete"].as_bool().unwrap());
        let first_resource = first["resource_id"].as_str().unwrap();
        let after_first = network.list_ports_for_project("project-a").await.unwrap();
        assert_eq!(after_first.len(), before + 1);
        assert_eq!(first_resource.len(), 36);
        let request = provider.last_create_request().expect("provider request");
        assert_eq!(request.key_name.as_deref(), Some("native-key"));
        assert_eq!(
            request
                .config_drive
                .as_ref()
                .map(|drive| drive.ssh_public_key.as_str()),
            Some(public_key.as_str())
        );

        let (status, replay) = exec(
            &router,
            authed_post("/compute/servers", "a", "native-network-create", body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(replay["resource_id"], first["resource_id"]);
        assert_eq!(
            network
                .list_ports_for_project("project-a")
                .await
                .unwrap()
                .len(),
            before + 1
        );
    }

    #[tokio::test]
    async fn native_compute_keypair_is_project_scoped_and_missing_key_fails_cleanly() {
        let (router, store, provider, _, _) = setup_with_network().await;
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBJuQvak7YBzsbN71EyvJnDK8pODWM1Ox/3wO3tT8Adj o3k-test";
        let (key_type, fingerprint, public_key) =
            o3k_store::validate_public_key(public_key).expect("test key");
        store
            .insert_keypair(&o3k_store::KeypairRecord {
                id: Uuid::new_v5(&Uuid::NAMESPACE_URL, b"o3k:scoped-keypair"),
                user_id: "user-project-a".to_owned(),
                project_id: "project-a".to_owned(),
                name: "scoped-key".to_owned(),
                key_type,
                public_key,
                fingerprint,
                created_at: "1".to_owned(),
            })
            .await
            .expect("keypair");
        let body = serde_json::json!({"spec": {
            "name": "scoped-key-server",
            "image_id": "image-a",
            "flavor_id": "00000000-0000-0000-0000-000000000001",
            "network_ids": ["net-a"],
            "key_name": "scoped-key"
        }});
        let (status, _) = exec(
            &router,
            authed_post("/compute/servers", "b", "foreign-key", body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(provider.instance_count(), 0);
        let (status, _) = exec(
            &router,
            authed_post("/compute/servers", "a", "missing-key", {
                let mut value = body;
                value["spec"]["key_name"] = serde_json::json!("missing");
                value
            }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(provider.instance_count(), 0);
    }

    #[tokio::test]
    async fn native_compute_failed_create_compensates_endpoint_and_keeps_canonical_error() {
        let (router, store, provider, _, network) = setup_with_network().await;
        provider
            .set_failure(FailureInjection::Terminal)
            .expect("failure injection");
        let canonical = network
            .create_network_for_project("project-a", "failed-native-network".to_owned())
            .await
            .expect("canonical network");
        network
            .create_subnet_for_project(
                "project-a",
                canonical.id,
                "failed-native-subnet".to_owned(),
                "192.0.2.0/29".to_owned(),
                None,
                Some("192.0.2.2".parse().unwrap()),
                Some("192.0.2.6".parse().unwrap()),
            )
            .await
            .expect("canonical subnet");
        let before = network
            .list_ports_for_project("project-a")
            .await
            .unwrap()
            .len();
        let body = serde_json::json!({"spec": {
            "name": "failed-native-vm",
            "image_id": "image-a",
            "flavor_id": "00000000-0000-0000-0000-000000000001",
            "network_ids": [canonical.id.to_string()]
        }});
        let (status, problem) = exec(
            &router,
            authed_post("/compute/servers", "a", "failed-native-create", body),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{problem}");
        assert_eq!(
            network
                .list_ports_for_project("project-a")
                .await
                .unwrap()
                .len(),
            before,
            "failed create must remove the endpoint it materialized"
        );

        let resources = store
            .list_resources("project-a", "compute_instance")
            .await
            .expect("compute resources");
        assert_eq!(
            resources.len(),
            1,
            "one canonical failed resource is retained"
        );
        assert!(resources[0].provider_id.is_none());
        let intent: serde_json::Value = serde_json::from_str(&resources[0].desired_state).unwrap();
        let operation_id = Uuid::parse_str(intent["operation_id"].as_str().unwrap()).unwrap();
        let operation = store.get_operation(operation_id).await.expect("operation");
        assert_eq!(
            resources[0].observed_state, "ERROR",
            "resources={resources:?} operation={operation:?}"
        );
        assert_eq!(operation.state, o3k_store::OperationState::Failed);
    }

    #[tokio::test]
    async fn native_compute_quota_exceeded_is_forbidden_without_provider_side_effect() {
        let (router, store, provider, _) = setup().await;
        let router = &router;
        use o3k_kernel::{LimitKey, LimitValue};
        use o3k_store::QuotaRepository;
        let scope_a = OwnershipScope::project(ScopeId::new_unchecked("project-a"), None, None);
        store
            .set_limit(
                &scope_a,
                &LimitKey::compute_servers(),
                LimitValue::Maximum(1),
            )
            .await
            .expect("quota limit");

        let spec = |name: &str| {
            serde_json::json!({
                "spec": {
                    "name": name,
                    "image_id": "image-a",
                    "flavor_id": "00000000-0000-0000-0000-000000000001",
                    "network_ids": ["net-a"]
                }
            })
        };
        let (status, json) = exec(
            router,
            authed_post("/compute/servers", "a", "quota-create-1", spec("one")),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");

        // Regression: the durable quota denial from the compute authority used
        // to surface as a 500 through the generic native route; it is a
        // caller-visible 403, and the provider must not observe the mutation.
        let (status, problem) = exec(
            router,
            authed_post("/compute/servers", "a", "quota-create-2", spec("two")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "quota denial must not map to an internal error: {problem}"
        );
        assert_eq!(provider.instance_count(), 1);
    }

    #[tokio::test]
    async fn native_network_quota_denial_is_forbidden_not_a_replay_conflict() {
        let (router, store, _, _) = setup().await;
        let router = &router;
        use o3k_kernel::{LimitKey, LimitValue};
        use o3k_store::QuotaRepository;
        let scope_a = OwnershipScope::project(ScopeId::new_unchecked("project-a"), None, None);
        store
            .set_limit(
                &scope_a,
                &LimitKey::network_networks(),
                LimitValue::Maximum(0),
            )
            .await
            .expect("quota limit");

        // Regression: the durable quota denial from the network authority was
        // swallowed by the replay probe and surfaced as a 409 conflict,
        // telling the tenant a non-retryable limit is retryable. It is a
        // caller-visible 403.
        let (status, problem) = exec(
            router,
            authed_post(
                "/network/networks",
                "a",
                "net-quota-1",
                serde_json::json!({"spec": {"name": "quota-net"}}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "network quota denial must map to 403, not a replay conflict: {problem}"
        );
    }

    #[tokio::test]
    async fn native_volume_create_replay_with_changed_semantics_conflicts() {
        let (router, store, _, _) = setup().await;
        let router = &router;
        let volume_spec = |size: u64, name: &str| {
            serde_json::json!({
                "spec": {
                    "name": name,
                    "size_bytes": size,
                    "volume_type": "lvm"
                }
            })
        };
        let (status, created) = exec(
            router,
            authed_post(
                "/volume/volumes",
                "a",
                "vol-key-1",
                volume_spec(1_073_741_824, "vol-a"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let volume_id = created["resource_id"]
            .as_str()
            .expect("volume id")
            .to_owned();

        // A same-key retry with identical semantics replays the durable
        // result.
        let (status, replayed) = exec(
            router,
            authed_post(
                "/volume/volumes",
                "a",
                "vol-key-1",
                volume_spec(1_073_741_824, "vol-a"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{replayed}");
        assert_eq!(replayed["resource_id"], volume_id, "{replayed}");

        // Regression: reusing the key with different semantics used to return
        // the original volume as if it were this request's result. Key reuse
        // with a changed body is an idempotency conflict.
        let (status, conflict) = exec(
            router,
            authed_post(
                "/volume/volumes",
                "a",
                "vol-key-1",
                volume_spec(2_147_483_648, "vol-a"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "same-key retry with changed semantics must conflict: {conflict}"
        );

        // The durable volume is untouched by the rejected key reuse.
        let volume_uuid = Uuid::parse_str(&volume_id).expect("volume uuid");
        let record = store
            .get_volume(volume_uuid)
            .await
            .expect("volume record")
            .expect("volume exists");
        assert_eq!(record.volume.size_bytes, 1_073_741_824);
    }

    #[tokio::test]
    async fn native_network_create_is_listed_and_deletable_through_generic_collection() {
        let (router, _, _, _) = setup().await;
        let router = &router;
        let body = serde_json::json!({"spec": {"name": "tenant-network"}});
        let (status, created) = exec(
            router,
            authed_post("/network/networks", "a", "net-create", body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let network_id = created["resource_id"]
            .as_str()
            .expect("network id")
            .to_owned();

        // Regression: the generic native collection must list a natively
        // created network. The durable resource-ledger row used to be written
        // only for migration envelopes, leaving native creates invisible to
        // the native list and undeletable through the generic delete route.
        let (status, listed) = exec(router, authed("/network/networks", "a")).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        let ids: Vec<&str> = listed["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["metadata"]["id"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            ids.contains(&network_id.as_str()),
            "native network missing from the generic collection: {listed}"
        );

        let delete_response = router
            .clone()
            .oneshot(authed_delete(
                &format!("/network/networks/{network_id}"),
                "a",
                "net-delete",
            ))
            .await
            .expect("delete request");
        assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn native_network_create_replay_returns_same_resource() {
        let (router, store, _, _) = setup().await;
        let router = &router;
        let body = serde_json::json!({"spec": {"name": "replay-network"}});
        let (status, first) = exec(
            router,
            authed_post("/network/networks", "a", "net-replay", body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{first}");
        let first_id = first["resource_id"]
            .as_str()
            .expect("network id")
            .to_owned();
        // The create response projects the public spec (name-only contract).
        assert_eq!(
            first["resource"]["spec"]["name"], "replay-network",
            "{first}"
        );

        let (status, replay) = exec(
            router,
            authed_post("/network/networks", "a", "net-replay", body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{replay}");
        assert_eq!(replay["resource_id"], first_id, "{replay}");

        // Exactly one canonical network and one ledger row exist for the
        // replayed create.
        let canonicals = store
            .list_canonical_networks("project-a")
            .await
            .expect("canonical networks");
        assert_eq!(
            canonicals
                .iter()
                .filter(|network| network.id.to_string() == first_id)
                .count(),
            1,
            "replay must not duplicate the canonical network: {canonicals:?}"
        );
        let (status, listed) = exec(router, authed("/network/networks", "a")).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        let occurrences = listed["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter(|item| item["metadata"]["id"].as_str() == Some(first_id.as_str()))
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(
            occurrences, 1,
            "replay must not duplicate the ledger row: {listed}"
        );

        // Show projects the public spec name for natively created networks.
        let (status, shown) = exec(
            router,
            authed(&format!("/network/networks/{first_id}"), "a"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{shown}");
        assert_eq!(shown["spec"]["name"], "replay-network", "{shown}");
    }

    #[tokio::test]
    async fn native_network_replay_with_changed_name_conflicts() {
        let (router, _, _, _) = setup().await;
        let router = &router;
        let first = serde_json::json!({"spec": {"name": "original-name"}});
        let (status, created) = exec(
            router,
            authed_post("/network/networks", "a", "net-rename", first),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        // Same key, different name: key reuse with changed semantics is a
        // conflict, not a silent replay of the original resource.
        let changed = serde_json::json!({"spec": {"name": "changed-name"}});
        let (status, conflict) = exec(
            router,
            authed_post("/network/networks", "a", "net-rename", changed),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    }

    #[tokio::test]
    async fn native_network_replay_after_delete_is_not_a_replay() {
        let (router, _, _, _) = setup().await;
        let router = &router;
        let body = serde_json::json!({"spec": {"name": "recreated-candidate"}});
        let (status, created) = exec(
            router,
            authed_post("/network/networks", "a", "net-delete-replay", body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let network_id = created["resource_id"]
            .as_str()
            .expect("network id")
            .to_owned();
        let delete_response = router
            .clone()
            .oneshot(authed_delete(
                &format!("/network/networks/{network_id}"),
                "a",
                "net-delete-replay-del",
            ))
            .await
            .expect("delete request");
        assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
        // A same-key retry after deletion must not treat the DELETED ledger
        // tombstone as a replay target: it fails closed (conflict) instead of
        // splitting fresh canonical authority from a stale ledger row.
        let (status, retried) = exec(
            router,
            authed_post("/network/networks", "a", "net-delete-replay", body),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "same-key retry after delete must fail closed: {retried}"
        );
    }

    #[tokio::test]
    async fn native_network_create_compensates_canonical_on_ledger_conflict() {
        let (router, store, _, _) = setup().await;
        let router = &router;
        // Pre-insert a ledger row with the exact id the create will derive
        // from its idempotency key, but under a different resource kind, so
        // the ledger insert fails after the canonical create has committed.
        let conflicting_id = Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            b"project-a:network:network:net-conflict",
        );
        store
            .insert_resource(&o3k_store::ResourceRecord {
                id: conflicting_id,
                kind: "compute_instance".to_owned(),
                project_id: "project-a".to_owned(),
                generation: 1,
                observed_generation: 1,
                desired_state: "{}".to_owned(),
                observed_state: "active".to_owned(),
                provider_id: None,
            })
            .await
            .expect("conflicting ledger row");
        let body = serde_json::json!({"spec": {"name": "orphan-candidate"}});
        let (status, failed) = exec(
            router,
            authed_post("/network/networks", "a", "net-conflict", body),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{failed}");

        // The canonical network created before the ledger failure must have
        // been compensated: it is not visible through the native surface
        // (without a ledger row it would previously have stayed visible to
        // show via the canonical fallback while being invisible to list and
        // undeletable — the orphan authority the fix removes).
        let (status, shown) = exec(
            router,
            authed(&format!("/network/networks/{conflicting_id}"), "a"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "compensated network must not remain visible: {shown}"
        );
        let canonicals = store
            .list_canonical_networks("project-a")
            .await
            .expect("canonical networks");
        assert!(
            canonicals
                .iter()
                .all(|network| network.id != conflicting_id),
            "compensated network must not remain canonical authority: {canonicals:?}"
        );
    }

    #[tokio::test]
    async fn native_network_show_conceals_deleted_resource() {
        let (router, _, _, _) = setup().await;
        let router = &router;
        let body = serde_json::json!({"spec": {"name": "doomed-network"}});
        let (status, created) = exec(
            router,
            authed_post("/network/networks", "a", "net-doomed", body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let network_id = created["resource_id"]
            .as_str()
            .expect("network id")
            .to_owned();
        let delete_response = router
            .clone()
            .oneshot(authed_delete(
                &format!("/network/networks/{network_id}"),
                "a",
                "net-doomed-delete",
            ))
            .await
            .expect("delete request");
        assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
        // Show is the live-resource view: a finalized network is concealed
        // (404) exactly like a deleted compute server, even though the
        // ledger keeps the tombstone for the collection projection.
        let (status, shown) = exec(
            router,
            authed(&format!("/network/networks/{network_id}"), "a"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "deleted network must be concealed from show: {shown}"
        );
    }

    #[tokio::test]
    async fn native_update_stale_if_match_leaves_no_pending_operation() {
        // The live generation is read from the durable ledger directly: this
        // minimal harness declares the legacy `compute:ShowServer` action,
        // which the standard authorizer does not register, so generic show
        // is not the generation source here.
        let (router, store, _, _) = setup().await;
        let router = &router;
        let body = serde_json::json!({
            "spec": {
                "name": "test",
                "image_id": "image-a",
                "flavor_id": "00000000-0000-0000-0000-000000000001",
                "network_ids": ["net-a"]
            }
        });
        let (status, created) = exec(
            router,
            authed_post("/compute/servers", "a", "create-stale-upd", body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let server_id = created["resource_id"]
            .as_str()
            .expect("server id")
            .to_owned();

        // Stale If-Match: 409, and — the actual regression — no durable
        // Pending operation or consumed idempotency reservation may be left
        // behind by a rejected precondition.
        let stale = authed_put(
            &format!("/compute/servers/{server_id}"),
            "a",
            "upd-stale",
            99_999,
            serde_json::json!({"spec": {"name": "renamed"}}),
        );
        let (status, rejected) = exec(router, stale).await;
        assert_eq!(status, StatusCode::CONFLICT, "{rejected}");
        let phantom_operation = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("compute:server:{server_id}:compute:UpdateServer:upd-stale").as_bytes(),
        );
        let (status, missing) = exec(
            router,
            authed(&format!("/operations/{phantom_operation}"), "a"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a stale precondition must not leave a durable operation: {missing}"
        );

        // Replaying the same rejected request with the same key must not be
        // accepted as a replay of a never-valid operation.
        let replay = authed_put(
            &format!("/compute/servers/{server_id}"),
            "a",
            "upd-stale",
            99_999,
            serde_json::json!({"spec": {"name": "renamed"}}),
        );
        let (status, replayed) = exec(router, replay).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a rejected update must not replay as accepted: {replayed}"
        );

        // The live generation still updates successfully afterwards.
        let server_uuid = Uuid::parse_str(&server_id).expect("server uuid");
        let ledger = store
            .get_resource(server_uuid)
            .await
            .expect("server ledger row");
        let live_generation = ledger.generation;
        let live = authed_put(
            &format!("/compute/servers/{server_id}"),
            "a",
            "upd-live",
            live_generation,
            serde_json::json!({"spec": {"name": "renamed-live"}}),
        );
        let (status, updated) = exec(router, live).await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        assert_eq!(updated["complete"], true, "{updated}");
        let updated_operation = updated["operation_id"]
            .as_str()
            .expect("update operation id")
            .to_owned();
        let ledger = store
            .get_resource(server_uuid)
            .await
            .expect("server ledger row");
        assert_eq!(
            ledger.generation,
            live_generation + 1,
            "update bumps the durable generation"
        );
        let desired: serde_json::Value =
            serde_json::from_str(&ledger.desired_state).expect("desired state");
        assert_eq!(desired["name"], "renamed-live", "{desired}");

        // True idempotent replay: a same-key retry of the ACCEPTED update
        // returns the durable result even though the generation has since
        // advanced — rejecting a client retry as stale would defeat
        // idempotency (the first call itself moved the generation).
        let replay_live = authed_put(
            &format!("/compute/servers/{server_id}"),
            "a",
            "upd-live",
            live_generation,
            serde_json::json!({"spec": {"name": "renamed-live"}}),
        );
        let (status, replayed) = exec(router, replay_live).await;
        assert_eq!(status, StatusCode::OK, "{replayed}");
        assert_eq!(replayed["operation_id"], updated_operation, "{replayed}");
        assert_eq!(replayed["complete"], true, "{replayed}");
    }

    #[tokio::test]
    async fn native_update_with_non_object_desired_state_fails_closed_without_panic() {
        // A durable ledger row whose desired_state is valid JSON but not an
        // object (corruption or a bad migration) must fail closed with a
        // clean conflict, not panic the request handler via serde_json's
        // IndexMut on a non-object value.
        let (router, store, _, _) = setup().await;
        let router = &router;
        let body = serde_json::json!({
            "spec": {
                "name": "test",
                "image_id": "image-a",
                "flavor_id": "00000000-0000-0000-0000-000000000001",
                "network_ids": ["net-a"]
            }
        });
        let (status, created) = exec(
            router,
            authed_post("/compute/servers", "a", "create-corrupt-desired", body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let server_id = created["resource_id"]
            .as_str()
            .expect("server id")
            .to_owned();
        let server_uuid = Uuid::parse_str(&server_id).expect("server uuid");
        let ledger = store
            .get_resource(server_uuid)
            .await
            .expect("server ledger row");
        store
            .update_resource(
                server_uuid,
                ledger.generation,
                "42",
                &ledger.observed_state,
                ledger.observed_generation,
                ledger.provider_id.as_deref(),
            )
            .await
            .expect("corrupt desired state");

        let (status, rejected) = exec(
            router,
            authed_put(
                &format!("/compute/servers/{server_id}"),
                "a",
                "upd-corrupt-desired",
                ledger.generation + 1,
                serde_json::json!({"spec": {"name": "renamed"}}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a non-object desired_state must fail closed, not panic: {rejected}"
        );
    }

    #[tokio::test]
    async fn native_compute_create_replay_equivalent() {
        let (router, _, provider, _) = setup().await;
        let router = &router;
        let body = serde_json::json!({
            "spec": {
                "name": "test",
                "image_id": "image-a",
                "flavor_id": "00000000-0000-0000-0000-000000000001",
                "network_ids": ["net-a"]
            }
        });

        // First create
        let (status, first) = exec(
            router,
            authed_post("/compute/servers", "a", "create-A", body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(first["complete"].as_bool().unwrap());

        // Replay with same key
        let (status, replay) = exec(
            router,
            authed_post("/compute/servers", "a", "create-A", body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(replay["operation_id"], first["operation_id"]);
        assert_eq!(replay["resource_id"], first["resource_id"]);
        assert_eq!(provider.instance_count(), 1);
    }

    #[tokio::test]
    async fn native_compute_declared_action_is_canonical_and_scoped() {
        let (router, _, _, _) = setup().await;
        let body = serde_json::json!({
            "spec": {
                "name": "action-test",
                "image_id": "image-a",
                "flavor_id": "00000000-0000-0000-0000-000000000001",
                "network_ids": ["net-a"]
            }
        });
        let (_, created) = exec(
            &router,
            authed_post("/compute/servers", "a", "action-create", body),
        )
        .await;
        let id = created["resource_id"].as_str().unwrap();
        let path = format!("/compute/servers/{id}/actions/StopServer");
        let request = serde_json::json!({"input": {}});
        let (status, first) = exec(
            &router,
            authed_action(&path, "a", "action-stop", request.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "action response: {first}");
        let operation_id = first["operation_id"].as_str().unwrap();
        assert_eq!(first["resource_id"], id);

        let (status, replay) = exec(
            &router,
            authed_action(&path, "a", "action-stop", request.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "action replay response: {replay}");
        assert_eq!(replay["operation_id"], operation_id);

        let (status, _) = exec(
            &router,
            authed_action(
                &path,
                "a",
                "action-stop",
                serde_json::json!({"input": {"reason": "different"}}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, _) = exec(&router, authed_action(&path, "b", "foreign", request)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let undeclared = format!("/compute/servers/{id}/actions/FlyServer");
        let (status, _) = exec(
            &router,
            authed_action(
                &undeclared,
                "a",
                "undeclared",
                serde_json::json!({"input": {}}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);

        let (status, _) = exec(
            &router,
            authed_action(&path, "a", "malformed", serde_json::json!({"input": []})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let oversized = format!("{}{}", "x".repeat(257), "");
        let (status, _) = exec(
            &router,
            authed_action(
                &path,
                "a",
                "oversized",
                serde_json::json!({"input": {"reason": oversized}}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn native_compute_create_changed_body_conflict() {
        let (router, _, provider, _) = setup().await;
        let router = &router;
        let body_a = serde_json::json!({
            "spec": {
                "name": "test-a",
                "image_id": "image-a",
                "flavor_id": "00000000-0000-0000-0000-000000000001",
                "network_ids": ["net-a"]
            }
        });
        let body_b = serde_json::json!({
            "spec": {
                "name": "test-b",
                "image_id": "image-b",
                "flavor_id": "00000000-0000-0000-0000-000000000002",
                "network_ids": ["net-b"]
            }
        });

        // First create
        let (status, _) = exec(
            router,
            authed_post("/compute/servers", "a", "create-A", body_a),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // Replay with DIFFERENT body → 409 Conflict
        let (status, _) = exec(
            router,
            authed_post("/compute/servers", "a", "create-A", body_b),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(provider.instance_count(), 1);
    }

    #[tokio::test]
    async fn native_compute_idempotency_isolated_between_owner_scopes() {
        let (router, store, provider, _) = setup().await;
        let body_a = serde_json::json!({"spec":{"name":"tenant-a","image_id":"image-a","flavor_id":"00000000-0000-0000-0000-000000000001","network_ids":["net-a"]}});
        let body_b = serde_json::json!({"spec":{"name":"tenant-b","image_id":"image-a","flavor_id":"00000000-0000-0000-0000-000000000001","network_ids":["net-a"]}});

        let (status_a, first_a) = exec(
            &router,
            authed_post("/compute/servers", "a", "shared-key", body_a.clone()),
        )
        .await;
        assert_eq!(status_a, StatusCode::CREATED);
        let (_, replay_a) = exec(
            &router,
            authed_post("/compute/servers", "a", "shared-key", body_a),
        )
        .await;
        assert_eq!(replay_a["resource_id"], first_a["resource_id"]);
        assert_eq!(replay_a["operation_id"], first_a["operation_id"]);

        let conflict_a = exec(&router, authed_post("/compute/servers", "a", "shared-key", serde_json::json!({"spec":{"name":"other-a","image_id":"image-b","flavor_id":"00000000-0000-0000-0000-000000000002","network_ids":["net-b"]}}))).await;
        assert_eq!(conflict_a.0, StatusCode::CONFLICT);

        let (status_b, first_b) = exec(
            &router,
            authed_post("/compute/servers", "b", "shared-key", body_b.clone()),
        )
        .await;
        assert_eq!(status_b, StatusCode::CREATED, "tenant B create: {first_b}");
        assert_ne!(first_b["resource_id"], first_a["resource_id"]);
        assert_ne!(first_b["operation_id"], first_a["operation_id"]);
        let b_resource = store
            .get_resource(uuid::Uuid::parse_str(first_b["resource_id"].as_str().unwrap()).unwrap())
            .await
            .expect("tenant B resource");
        assert_eq!(b_resource.project_id, "project-b");

        let (_, replay_b) = exec(
            &router,
            authed_post("/compute/servers", "b", "shared-key", body_b),
        )
        .await;
        assert_eq!(replay_b["resource_id"], first_b["resource_id"]);
        assert_eq!(replay_b["operation_id"], first_b["operation_id"]);
        let conflict_b = exec(&router, authed_post("/compute/servers", "b", "shared-key", serde_json::json!({"spec":{"name":"other-b","image_id":"image-b","flavor_id":"00000000-0000-0000-0000-000000000002","network_ids":["net-b"]}}))).await;
        assert_eq!(conflict_b.0, StatusCode::CONFLICT);

        assert_eq!(
            exec(
                &router,
                authed(
                    &format!(
                        "/compute/servers/{}",
                        first_a["resource_id"].as_str().unwrap()
                    ),
                    "b"
                )
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            exec(
                &router,
                authed(
                    &format!("/operations/{}", first_a["operation_id"].as_str().unwrap()),
                    "b"
                )
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(provider.instance_count(), 2);
    }

    #[tokio::test]
    async fn native_http_cursor_is_bound_to_owner_and_rejects_tampering() {
        let (router, _, provider, _) = setup().await;
        for (key, name) in [("page-a", "page-a"), ("page-b", "page-b")] {
            let (status, _) = exec(
                &router,
                authed_post(
                    "/compute/servers",
                    "a",
                    key,
                    serde_json::json!({"spec":{"name":name,"image_id":"image-a","flavor_id":"00000000-0000-0000-0000-000000000001","network_ids":["net-a"]}}),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }
        let (_, page_a) = exec(&router, authed("/compute/servers?limit=1", "a")).await;
        assert_eq!(page_a["items"][0]["kind"], "compute:server");
        let cursor_a = page_a["next_cursor"].as_str().expect("tenant A cursor");
        let (second_status, second_page) = exec(
            &router,
            authed(&format!("/compute/servers?limit=1&cursor={cursor_a}"), "a"),
        )
        .await;
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(second_page["items"].as_array().map(Vec::len), Some(1));
        let (cross_scope_status, _) = exec(
            &router,
            authed(&format!("/compute/servers?limit=1&cursor={cursor_a}"), "b"),
        )
        .await;
        assert_eq!(cross_scope_status, StatusCode::BAD_REQUEST);
        let (tampered_status, _) = exec(
            &router,
            authed(&format!("/compute/servers?limit=1&cursor={cursor_a}x"), "a"),
        )
        .await;
        assert_eq!(tampered_status, StatusCode::BAD_REQUEST);
        assert_eq!(provider.instance_count(), 2);
    }

    #[tokio::test]
    async fn native_http_cursor_continues_deterministically_after_anchor_deletion() {
        let (router, _, provider, _) = setup().await;
        for (key, name) in [("stale-a", "stale-a"), ("stale-b", "stale-b")] {
            let (status, _) = exec(
                &router,
                authed_post(
                    "/compute/servers",
                    "a",
                    key,
                    serde_json::json!({"spec":{"name":name,"image_id":"image-a","flavor_id":"00000000-0000-0000-0000-000000000001","network_ids":["net-a"]}}),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }
        let (_, first_page) = exec(&router, authed("/compute/servers?limit=1", "a")).await;
        let anchor_id = first_page["items"][0]["metadata"]["id"]
            .as_str()
            .expect("cursor anchor")
            .to_owned();
        let cursor = first_page["next_cursor"].as_str().expect("cursor");
        let delete_response = router
            .clone()
            .oneshot(authed_delete(
                &format!("/compute/servers/{anchor_id}"),
                "a",
                "stale-delete",
            ))
            .await
            .expect("delete response");
        assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
        let (status, page_after_delete) = exec(
            &router,
            authed(&format!("/compute/servers?limit=1&cursor={cursor}"), "a"),
        )
        .await;
        // Weak-consistency keyset pagination remains valid when the anchor is
        // deleted after the first page: the continuation predicate is based on
        // the immutable ordering key, not on anchor existence.
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page_after_delete["items"].as_array().map(Vec::len), Some(1));
        assert_eq!(provider.instance_count(), 1);
    }

    #[tokio::test]
    async fn native_http_oversized_body_is_rejected_before_provider_mutation() {
        let (router, _, provider, _) = setup().await;
        let mut body = vec![b' '; 1_048_577];
        body[0] = b'{';
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/compute/servers")
                    .header("authorization", "Bearer project-a")
                    .header("content-type", "application/json")
                    .header("idempotency-key", "oversized")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(provider.instance_count(), 0);
    }

    #[tokio::test]
    async fn native_http_route_shapes_fail_closed_without_descriptor_dispatch() {
        let (router, _, provider, _) = setup().await;
        for (method, uri) in [
            ("GET", "/future/servers"),
            ("GET", "/compute/servers/extra/path"),
            ("GET", "/compute/servers/%2Fambiguous"),
            ("POST", "/compute/servers/known-id"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("authorization", "Bearer project-a")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert!(
                matches!(
                    response.status(),
                    StatusCode::NOT_FOUND
                        | StatusCode::METHOD_NOT_ALLOWED
                        | StatusCode::BAD_REQUEST
                        | StatusCode::FORBIDDEN
                ),
                "unexpected status for {method} {uri}: {}",
                response.status()
            );
        }
        assert_eq!(provider.instance_count(), 0);
    }

    #[tokio::test]
    async fn native_compute_rejects_foreign_network_before_provider_mutation() {
        let (router, store, provider, foreign_port) = setup().await;
        let body = serde_json::json!({
            "spec": {
                "name": "cross-tenant-network",
                "image_id": "image-a",
                "flavor_id": "00000000-0000-0000-0000-000000000001",
                "network_ids": [foreign_port.to_string()]
            }
        });
        let (status, _) = exec(
            &router,
            authed_post("/compute/servers", "a", "foreign-network", body),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(provider.instance_count(), 0);
        assert!(
            store
                .list_resources("project-a", "compute:server")
                .await
                .expect("resource list")
                .is_empty()
        );
        // The setup-created foreign port is deliberately retained; the
        // rejected request has no path to mutate it or create a relationship.
    }

    #[tokio::test]
    async fn native_security_rejects_auth_namespace_and_cross_scope_access_before_mutation() {
        let (router, _, provider, _) = setup().await;
        let body = serde_json::json!({
            "spec": {
                "name": "security-test",
                "image_id": "image-a",
                "flavor_id": "00000000-0000-0000-0000-000000000001",
                "network_ids": ["net-a"]
            }
        });

        let missing = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/compute/servers")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let malformed = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/compute/servers")
                    .header("authorization", "Basic not-a-bearer")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED);

        let invalid = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/compute/servers")
                    .header("authorization", "Bearer invalid-token-is-not-used")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(provider.instance_count(), 0);
        let malformed_json = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/compute/servers")
                    .header("authorization", "Bearer project-a")
                    .header("content-type", "application/json")
                    .body(Body::from(br#"{"spec": malformed}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed_json.status(), StatusCode::BAD_REQUEST);
        assert_eq!(provider.instance_count(), 0);
        let (_, created) = exec(
            &router,
            authed_post("/compute/servers", "a", "isolated", body),
        )
        .await;
        let resource_id = created["resource_id"].as_str().unwrap();
        let operation_id = created["operation_id"].as_str().unwrap();

        let foreign_show = exec(
            &router,
            authed(&format!("/compute/servers/{resource_id}"), "b"),
        )
        .await;
        assert_eq!(foreign_show.0, StatusCode::FORBIDDEN);
        let foreign_operation =
            exec(&router, authed(&format!("/operations/{operation_id}"), "b")).await;
        assert_eq!(foreign_operation.0, StatusCode::NOT_FOUND);

        let unknown = exec(&router, authed("/unknown/servers", "a")).await;
        assert_eq!(unknown.0, StatusCode::NOT_FOUND);

        let cross_scope_replay = exec(
            &router,
            authed_post(
                "/compute/servers",
                "b",
                "isolated",
                serde_json::json!({"spec":{"name":"different"}}),
            ),
        )
        .await;
        assert_eq!(cross_scope_replay.0, StatusCode::BAD_REQUEST);
        assert_eq!(provider.instance_count(), 1);
    }

    #[tokio::test]
    async fn native_compute_delete_returns_operation() {
        let (router, _, provider, _) = setup().await;
        let router = &router;
        let body = serde_json::json!({
            "spec": {
                "name": "test",
                "image_id": "image-a",
                "flavor_id": "00000000-0000-0000-0000-000000000001",
                "network_ids": ["net-a"]
            }
        });

        // Create first
        let (status, json) = exec(
            router,
            authed_post("/compute/servers", "a", "create-A", body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let resource_id = json["resource_id"].as_str().unwrap().to_owned();

        // Set provider timeout so delete becomes async (202)
        provider
            .set_failure(FailureInjection::Timeout)
            .expect("set failure");

        // DELETE → 202 Accepted
        let (status, delete_json) = exec(
            router,
            authed_delete(&format!("/compute/servers/{resource_id}"), "a", "delete-A"),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let operation_id = delete_json["operation_id"].as_str().unwrap().to_owned();
        assert!(!delete_json["complete"].as_bool().unwrap());

        // GET /operations/{id} shows the delete
        let (status, op) = exec(router, authed(&format!("/operations/{operation_id}"), "a")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(op["id"], operation_id);
        assert_eq!(op["action"]["namespace"], "compute");
        assert_eq!(op["action"]["action"], "DeleteServer");
        assert_eq!(op["resource_id"], resource_id);
        assert_eq!(op["owner_scope"]["id"], "project-a");

        // Replay delete with same idempotency key — same operation
        let (status, replay) = exec(
            router,
            authed_delete(&format!("/compute/servers/{resource_id}"), "a", "delete-A"),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(replay["operation_id"], operation_id);
    }

    #[tokio::test]
    async fn native_compute_create_after_delete_same_key_fails() {
        let (router, _, provider, _) = setup().await;
        let router = &router;
        let body = serde_json::json!({
            "spec": {
                "name": "test",
                "image_id": "image-a",
                "flavor_id": "00000000-0000-0000-0000-000000000001",
                "network_ids": ["net-a"]
            }
        });

        // Create
        let (status, json) = exec(
            router,
            authed_post("/compute/servers", "a", "create-A", body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let resource_id = json["resource_id"].as_str().unwrap().to_owned();

        // Clear failure for synchronous delete
        provider
            .set_failure(FailureInjection::None)
            .expect("clear failure");

        // Delete (synchronous → 204 No Content)
        let response = router
            .clone()
            .oneshot(authed_delete(
                &format!("/compute/servers/{resource_id}"),
                "a",
                "delete-B",
            ))
            .await
            .expect("delete");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Create with SAME key — fail closed: the consumed idempotency key
        // cannot create a new resource, even after the original was deleted.
        let (status, _replay) = exec(
            router,
            authed_post("/compute/servers", "a", "create-A", body),
        )
        .await;
        // After deletion, the idempotency key is still bound to the original
        // create operation. Replaying returns the original resource (404 not
        // found is expected for a deleted resource — the system rejects the
        // request rather than silently creating a new resource with the same
        // key).
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn native_compute_create_after_delete_new_key_succeeds() {
        let (router, _, provider, _) = setup().await;
        let router = &router;
        let body = serde_json::json!({
            "spec": {
                "name": "test",
                "image_id": "image-a",
                "flavor_id": "00000000-0000-0000-0000-000000000001",
                "network_ids": ["net-a"]
            }
        });

        // Create
        let (status, json) = exec(
            router,
            authed_post("/compute/servers", "a", "create-A", body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let resource_id = json["resource_id"].as_str().unwrap().to_owned();

        // Clear failure for sync delete
        provider
            .set_failure(FailureInjection::None)
            .expect("clear failure");

        // Delete
        let response = router
            .clone()
            .oneshot(authed_delete(
                &format!("/compute/servers/{resource_id}"),
                "a",
                "delete-A",
            ))
            .await
            .expect("delete");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Create with NEW key — starts a new lifecycle
        let (status, recreate) = exec(
            router,
            authed_post("/compute/servers", "a", "create-B", body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_ne!(recreate["resource_id"].as_str().unwrap(), resource_id);
        assert!(recreate["complete"].as_bool().unwrap());
    }

    #[test]
    fn native_compute_manifest_exposes_no_generation_precondition_mutation() {
        let registry = compute_manifest_registry();
        let manifest = registry.get("compute").expect("compute manifest");
        let actions = manifest
            .actions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert!(
            actions
                .iter()
                .any(|action| action.ends_with(":CreateServer"))
        );
        assert!(
            actions
                .iter()
                .any(|action| action.ends_with(":DeleteServer"))
        );
        assert!(
            actions
                .iter()
                .any(|action| action.ends_with(":UpdateServer"))
        );
        assert!(
            !actions
                .iter()
                .any(|action| action.contains("CompareAndSet"))
        );
    }
}

/// Production-composition HTTP integration tests for the native IAM governance
/// surface: a real durable store, a real `TokenService`, and the canonical
/// `/operator/governance/...` router behind the standard authorizer.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod native_governance_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use o3k_identity::oidc::ValidatedExternalIdentity;
    use o3k_identity::{BootstrapConfig, ExtraProjectSeed, Secret, TokenService};
    use o3k_kernel::{
        AuthContext, OwnershipScope, Principal, PrincipalId, ScopeId, ScopeKind, StaticAuthorizer,
        UserPrincipal,
    };
    use o3k_native_api::auth::{NativeTokenRequestV1, TokenIssuer};
    use o3k_native_api::error::ProblemDetails;
    use o3k_native_api::pagination::CursorConfig;
    use o3k_store::{
        AuditRepository, FederatedBindingRecord, GovernanceRepository, IdentityRepository,
    };
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    const EXTRA_PROJECT: &str = "8d1f3c4a-5b6e-4f2a-9c3d-1e2f3a4b5c6d";
    const EXTRA_USER: &str = "a7c2e9d1-4f3b-4c8e-9d2a-3b4c5d6e7f8a";

    struct GovernanceIssuer;

    fn system_operator_context() -> AuthContext {
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
            u64::MAX,
            "audit-governance",
            "request-governance",
            None,
        )
    }

    /// A project-scoped caller that carries the `operator` role name must still
    /// never satisfy a system-scoped `governance:*` action.
    fn project_operator_context() -> AuthContext {
        AuthContext::new(
            Principal::User(UserPrincipal::new(
                PrincipalId::new_unchecked("project-operator"),
                "project-operator",
                None,
            )),
            OwnershipScope::new(
                ScopeId::new_unchecked("service-project"),
                ScopeKind::Project,
                None,
                None,
            ),
            vec!["operator".to_owned()],
            1,
            u64::MAX,
            "audit-governance",
            "request-governance",
            None,
        )
    }

    #[async_trait::async_trait]
    impl TokenIssuer for GovernanceIssuer {
        async fn issue_native(
            &self,
            _request: &NativeTokenRequestV1,
        ) -> Result<(String, serde_json::Value), ProblemDetails> {
            Err(ProblemDetails::bad_request(
                "test issuer does not issue tokens",
            ))
        }

        async fn auth_context(&self, token: &str) -> Result<AuthContext, ProblemDetails> {
            match token {
                "operator" => Ok(system_operator_context()),
                "project-operator" => Ok(project_operator_context()),
                _ => Err(ProblemDetails::unauthorized()),
            }
        }
    }

    struct GovernanceHarness {
        router: axum::Router,
        store: Arc<o3k_store::unified::O3kStore>,
        identity: Arc<TokenService>,
    }

    async fn setup_harness(federated_binding: bool) -> GovernanceHarness {
        let store = Arc::new(
            o3k_store::unified::O3kStore::connect_sqlite_memory()
                .await
                .expect("store"),
        );
        o3k_identity::seed_identity_defaults(
            store.as_ref(),
            &BootstrapConfig {
                catalog_endpoint: "http://127.0.0.1:18090".to_owned(),
                bootstrap_password: Secret::new("bootstrap-password".to_owned()),
                cinder_password: None,
                cinder_endpoint: None,
                pbkdf2_iterations: 1_000,
                extra_projects: vec![ExtraProjectSeed {
                    project_id: EXTRA_PROJECT.to_owned(),
                    project_name: "tenant-b".to_owned(),
                    user_id: EXTRA_USER.to_owned(),
                    user_name: "tenant-b-user".to_owned(),
                    password: Secret::new("tenant-b-password".to_owned()),
                }],
            },
        )
        .await
        .expect("seed identity defaults");

        if federated_binding {
            store
                .insert_federated_binding(&FederatedBindingRecord {
                    id: "governance-federated-binding".to_owned(),
                    trusted_issuer_id: "issuer-a".to_owned(),
                    issuer: "https://idp.example.test".to_owned(),
                    subject: "alice".to_owned(),
                    principal_id: "bootstrap-user".to_owned(),
                    principal_type: "user".to_owned(),
                    enabled: true,
                    created_at: "2026-09-06T00:00:00Z".to_owned(),
                    updated_at: "2026-09-06T00:00:00Z".to_owned(),
                })
                .await
                .expect("federated binding");
        }

        let identity = Arc::new(
            TokenService::load(
                store.clone(),
                Secret::new("a-secure-signing-key-with-at-least-32-bytes".to_owned()),
                Duration::from_secs(3600),
            )
            .await
            .expect("token service"),
        );

        let native = o3k_native_api::NativeApiState::new(
            None,
            CursorConfig::new(b"test-only-native-cursor-key-at-least-32-bytes".to_vec())
                .expect("cursor key"),
            Some(Arc::new(GovernanceIssuer)),
            None,
            None,
            None,
        )
        .expect("native state")
        .with_governance_reader(Arc::new(GovernanceReaderAdapter {
            store: store.clone(),
            identity: Some(identity.clone()),
        }))
        .with_authorizer(Arc::new(StaticAuthorizer::standard()));

        GovernanceHarness {
            router: o3k_native_api::router(native),
            store,
            identity,
        }
    }

    fn federated_identity() -> ValidatedExternalIdentity {
        ValidatedExternalIdentity {
            trusted_issuer_id: "issuer-a".to_owned(),
            issuer: "https://idp.example.test".to_owned(),
            subject: "alice".to_owned(),
            expires_at: u64::MAX,
        }
    }

    async fn project_id_by_name(store: &o3k_store::unified::O3kStore, name: &str) -> String {
        store
            .list_governance_projects_page(None, 100)
            .await
            .expect("projects")
            .items
            .into_iter()
            .find(|project| project.name == name)
            .unwrap_or_else(|| panic!("seeded project {name} missing"))
            .id
    }

    async fn principal_id_by_name(store: &o3k_store::unified::O3kStore, name: &str) -> String {
        store
            .list_governance_principals_page(None, 100)
            .await
            .expect("principals")
            .items
            .into_iter()
            .find(|principal| principal.name == name)
            .unwrap_or_else(|| panic!("seeded principal {name} missing"))
            .id
    }

    async fn role_id_by_name(store: &o3k_store::unified::O3kStore, name: &str) -> String {
        store
            .list_governance_roles_page(None, 100)
            .await
            .expect("roles")
            .items
            .into_iter()
            .find(|role| role.name == name)
            .unwrap_or_else(|| panic!("seeded role {name} missing"))
            .id
    }

    fn request(
        method: &str,
        uri: &str,
        token: &str,
        body: Option<&serde_json::Value>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"));
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(serde_json::to_vec(value).expect("json body"))
            }
            None => Body::empty(),
        };
        builder.body(body).expect("request")
    }

    async fn exec(router: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = router.clone().oneshot(req).await.expect("request");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json")
        };
        (status, json)
    }

    fn assert_no_password_hash(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                assert!(
                    !map.contains_key("password_hash"),
                    "governance DTO leaked password_hash: {value}"
                );
                for nested in map.values() {
                    assert_no_password_hash(nested);
                }
            }
            serde_json::Value::Array(items) => {
                for nested in items {
                    assert_no_password_hash(nested);
                }
            }
            _ => {}
        }
    }

    /// Successful assignment creates under the system operator are recorded
    /// under the actor's effective `system` scope.
    async fn managed_assignment_audit_events(
        store: &o3k_store::unified::O3kStore,
    ) -> Vec<o3k_store::AuditEventRecord> {
        let o3k_store::unified::O3kStore::Sqlite(sqlite) = store else {
            panic!("test harness is sqlite-backed");
        };
        sqlite
            .list_audit_events_page("system", None, 100)
            .await
            .expect("audit page")
            .items
            .into_iter()
            .filter(|event| {
                event.action == "governance:ManageAssignment" && event.outcome == "succeeded"
            })
            .collect()
    }

    #[tokio::test]
    async fn native_governance_operator_lifecycle_with_durable_audit() {
        let harness = setup_harness(false).await;
        let project_id = project_id_by_name(&harness.store, "service").await;
        let principal_id = principal_id_by_name(&harness.store, "admin").await;
        let role_id = role_id_by_name(&harness.store, "member").await;

        let (status, projects) = exec(
            &harness.router,
            request("GET", "/operator/governance/projects", "operator", None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !projects["items"].as_array().expect("items").is_empty(),
            "seeded projects must be visible: {projects}"
        );
        assert_no_password_hash(&projects);

        let (status, principals) = exec(
            &harness.router,
            request("GET", "/operator/governance/principals", "operator", None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_no_password_hash(&principals);
        for item in principals["items"].as_array().expect("items") {
            assert!(
                item["kind"].is_string(),
                "principal kind must be present: {item}"
            );
        }

        let body = serde_json::json!({
            "principal_id": principal_id,
            "project_id": project_id,
            "role_id": role_id,
        });
        let (status, created) = exec(
            &harness.router,
            request(
                "POST",
                "/operator/governance/assignments",
                "operator",
                Some(&body),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "assignment create: {created}");
        let id = created["id"].as_str().expect("assignment id").to_owned();

        // Replaying the identical request must converge on the same durable
        // assignment and create no duplicate authority.
        let (status, replay) = exec(
            &harness.router,
            request(
                "POST",
                "/operator/governance/assignments",
                "operator",
                Some(&body),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "assignment replay: {replay}");
        assert_eq!(replay["id"].as_str().expect("id"), id);
        assert_eq!(replay["principal_id"], created["principal_id"]);
        assert_eq!(replay["project_id"], created["project_id"]);
        assert_eq!(replay["role_id"], created["role_id"]);

        let uri = format!("/operator/governance/assignments?project_id={project_id}");
        let (status, list) = exec(&harness.router, request("GET", &uri, "operator", None)).await;
        assert_eq!(status, StatusCode::OK);
        let items = list["items"].as_array().expect("items");
        assert_eq!(
            items.len(),
            1,
            "expected exactly one assignment for the project: {list}"
        );
        assert_eq!(items[0]["id"].as_str().expect("id"), id);
        assert_eq!(
            items[0]["principal_id"].as_str().expect("principal"),
            principal_id
        );
        assert_eq!(items[0]["role_id"].as_str().expect("role"), role_id);

        let audit_events = managed_assignment_audit_events(&harness.store).await;
        assert_eq!(
            audit_events.len(),
            1,
            "replay must not create a second durable ManageAssignment audit event"
        );
        let event = &audit_events[0];
        assert_eq!(event.effective_scope, "system");
        let debug = format!("{event:?}");
        assert!(!debug.contains("password"), "audit leaked secret: {debug}");
        assert!(!debug.contains("secret"), "audit leaked secret: {debug}");
        assert!(
            !debug.contains("tenant-b-password"),
            "audit leaked secret: {debug}"
        );

        let uri = format!("/operator/governance/assignments/{id}");
        let (status, _) = exec(&harness.router, request("DELETE", &uri, "operator", None)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = exec(&harness.router, request("DELETE", &uri, "operator", None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn native_governance_rejects_privilege_escalation() {
        let harness = setup_harness(false).await;
        let project_id = project_id_by_name(&harness.store, "service").await;
        let principal_id = principal_id_by_name(&harness.store, "admin").await;
        let role_id = role_id_by_name(&harness.store, "member").await;

        let assignment_body = serde_json::json!({
            "principal_id": principal_id,
            "project_id": project_id,
            "role_id": role_id,
        });
        let operator_body = serde_json::json!({ "principal_id": principal_id });

        // A project-scoped caller carrying the `operator` role name is denied on
        // every governance route.
        for (method, uri, body) in [
            ("GET", "/operator/governance/projects", None),
            ("GET", "/operator/governance/assignments", None),
            (
                "POST",
                "/operator/governance/assignments",
                Some(&assignment_body),
            ),
            (
                "POST",
                "/operator/governance/operator-assignments",
                Some(&operator_body),
            ),
        ] {
            let (status, response) = exec(
                &harness.router,
                request(method, uri, "project-operator", body),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {response}");
        }

        // The system operator can create the durable operator assignment.
        let (status, created) = exec(
            &harness.router,
            request(
                "POST",
                "/operator/governance/operator-assignments",
                "operator",
                Some(&operator_body),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "operator assignment: {created}");
        let id = created["id"].as_str().expect("id").to_owned();
        assert_eq!(created["profile"], "operator-console");

        let (status, list) = exec(
            &harness.router,
            request(
                "GET",
                "/operator/governance/operator-assignments",
                "operator",
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            list["items"]
                .as_array()
                .expect("items")
                .iter()
                .any(|item| item["id"] == id),
            "created operator assignment must be listed: {list}"
        );

        let (status, replay) = exec(
            &harness.router,
            request(
                "POST",
                "/operator/governance/operator-assignments",
                "operator",
                Some(&operator_body),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "operator assignment replay: {replay}"
        );
        assert_eq!(replay["id"].as_str().expect("id"), id);

        let unknown_role = serde_json::json!({
            "principal_id": principal_id,
            "project_id": project_id,
            "role_id": "no-such-role",
        });
        let (status, _) = exec(
            &harness.router,
            request(
                "POST",
                "/operator/governance/assignments",
                "operator",
                Some(&unknown_role),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let unsupported_profile = serde_json::json!({
            "principal_id": principal_id,
            "profile": "root-console",
        });
        let (status, _) = exec(
            &harness.router,
            request(
                "POST",
                "/operator/governance/operator-assignments",
                "operator",
                Some(&unsupported_profile),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let uri = format!("/operator/governance/operator-assignments/{id}");
        let (status, _) = exec(&harness.router, request("DELETE", &uri, "operator", None)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn native_governance_grant_and_revoke_converge_in_identity_snapshot() {
        let harness = setup_harness(true).await;
        let principal_id = principal_id_by_name(&harness.store, "admin").await;
        assert_eq!(principal_id, "bootstrap-user");
        let role_id = role_id_by_name(&harness.store, "member").await;
        let identity = federated_identity();

        let before = harness
            .identity
            .discover_federated_scopes(&identity)
            .expect("scopes");
        assert!(
            before.iter().all(|scope| scope.id != EXTRA_PROJECT),
            "target project unexpectedly discoverable before grant: {before:?}"
        );

        let body = serde_json::json!({
            "principal_id": principal_id,
            "project_id": EXTRA_PROJECT,
            "role_id": role_id,
        });
        let (status, created) = exec(
            &harness.router,
            request(
                "POST",
                "/operator/governance/assignments",
                "operator",
                Some(&body),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "grant: {created}");
        let id = created["id"].as_str().expect("id").to_owned();

        // The HTTP mutation must have reloaded the shared identity snapshot:
        // the project is discoverable without a process restart.
        let after = harness
            .identity
            .discover_federated_scopes(&identity)
            .expect("scopes");
        assert!(
            after.iter().any(|scope| scope.id == EXTRA_PROJECT),
            "grant not visible in the identity snapshot: {after:?}"
        );

        let uri = format!("/operator/governance/assignments/{id}");
        let (status, _) = exec(&harness.router, request("DELETE", &uri, "operator", None)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let after_delete = harness
            .identity
            .discover_federated_scopes(&identity)
            .expect("scopes");
        assert!(
            after_delete.iter().all(|scope| scope.id != EXTRA_PROJECT),
            "revoke not visible in the identity snapshot: {after_delete:?}"
        );
    }
}
