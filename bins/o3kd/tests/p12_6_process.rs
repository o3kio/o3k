use ed25519_dalek::SigningKey;
use o3k_database_example::{ChildLifecycleActions, DatabaseControllerHandler, InstanceSpec};
use o3k_kernel::{ActionId, Controller, ManifestRegistry, OwnershipScope, ScopeId};
use o3k_kernel::{ActionPolicy, PrincipalKind};
use o3k_kernel::{LimitKey, LimitValue};
use o3k_native_api::auth::{NativeTokenRequestV1, TokenIssuer};
use o3k_native_api::error::ProblemDetails;
use o3k_provider::FakeComputeProvider;
use o3k_service_sdk::composition::{ChildResourceRequest, ServiceCompositionClient};
use o3k_service_sdk::{
    DelegationClaims, GrpcControllerAdapter, SignedDelegation,
    composition::{CompositionServiceAdapter, GrpcCompositionClient},
};
use o3k_store::{
    CanonicalOperationRecord, DurableStore, IdempotencyReservationRequest, O3kStore,
    OperationRecord, OperationState, ResourceRecord, ResourceRelationshipRecord,
};
use o3k_store::{NetworkRepository, QuotaRepository};
use std::{collections::HashMap, sync::Arc};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

struct ProcessTokenIssuer;

fn process_auth_context(project: &str) -> o3k_kernel::AuthContext {
    o3k_kernel::AuthContext::new(
        o3k_kernel::Principal::User(o3k_kernel::UserPrincipal::new(
            o3k_kernel::PrincipalId::new_unchecked(format!("user-{project}")),
            format!("user-{project}"),
            None,
        )),
        OwnershipScope::project(ScopeId::new_unchecked(project), None, None),
        vec!["member".into()],
        1,
        u64::MAX,
        "p12-6-http-audit",
        "p12-6-http-request",
        None,
    )
}

async fn await_bound_relationship(
    store: &O3kStore,
    parent: uuid::Uuid,
    slot: &str,
    expected_child_type: &str,
) -> Result<ResourceRelationshipRecord, Box<dyn std::error::Error + Send + Sync>> {
    let wait = async {
        loop {
            let record = store.get_relationship(parent, slot).await?;
            if record.state == "bound"
                && record.expected_child_resource_type == expected_child_type
                && record.child_resource_id.is_some()
                && record.child_operation_id.is_some()
            {
                return Ok::<_, o3k_store::StoreError>(record);
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), wait)
        .await
        .map_err(|_| format!("{slot} did not become durably bound before its dependent stage"))?
        .map_err(|error| format!("failed waiting for {slot} durable binding: {error:?}").into())
}

#[async_trait::async_trait]
impl TokenIssuer for ProcessTokenIssuer {
    async fn issue_native(
        &self,
        _request: &NativeTokenRequestV1,
    ) -> Result<(String, serde_json::Value), ProblemDetails> {
        Err(ProblemDetails::bad_request(
            "test issuer does not issue tokens",
        ))
    }

    async fn auth_context(&self, token: &str) -> Result<o3k_kernel::AuthContext, ProblemDetails> {
        token
            .strip_prefix("project-")
            .map(process_auth_context)
            .ok_or_else(ProblemDetails::unauthorized)
    }
}

fn fixture(name: &str) -> String {
    format!(
        "{}/../../crates/o3k-compute-agent/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn tls_server() -> Result<tonic::transport::ServerTlsConfig, Box<dyn std::error::Error>> {
    Ok(o3k_service_sdk::tls::server(
        fixture("ca.pem"),
        fixture("server-chain.pem"),
        fixture("server-key.pem"),
    )?)
}

fn tls_client() -> Result<tonic::transport::ClientTlsConfig, Box<dyn std::error::Error>> {
    Ok(o3k_service_sdk::tls::client(
        fixture("ca.pem"),
        fixture("agent-chain.pem"),
        fixture("agent-key.pem"),
        "o3k-control-plane",
    )?)
}

fn lifecycle() -> Result<ChildLifecycleActions, Box<dyn std::error::Error>> {
    Ok(ChildLifecycleActions {
        network_create: ActionId::new("network", "CreateNetwork")?,
        network_observe: ActionId::new("network", "ReadNetwork")?,
        network_delete: ActionId::new("network", "DeleteNetwork")?,
        volume_create: ActionId::new("volume", "CreateVolume")?,
        volume_observe: ActionId::new("volume", "ReadVolume")?,
        volume_delete: ActionId::new("volume", "DeleteVolume")?,
        compute_create: ActionId::new("compute", "CreateServer")?,
        compute_observe: ActionId::new("compute", "ReadServer")?,
        compute_delete: ActionId::new("compute", "DeleteServer")?,
    })
}

#[tokio::test]
async fn database_controller_and_composition_cross_real_mtls_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    let store_path =
        std::env::temp_dir().join(format!("o3k-p12-6-store-{}.sqlite", uuid::Uuid::new_v4()));
    let store = Arc::new(O3kStore::connect_sqlite_file(&store_path).await?);
    let compute = Arc::new(o3k_compute::ComputeService::new_for_test(
        store.clone(),
        Arc::new(FakeComputeProvider::new()),
    ));
    let network_service = Arc::new(
        o3k_network::NetworkService::open_for_test(
            std::env::temp_dir().join(format!("o3k-p12-6-{}", uuid::Uuid::new_v4())),
            store.clone(),
        )
        .await?,
    );
    let application: Arc<dyn o3k_native_api::resource::ResourceApplication> =
        Arc::new(o3kd::native_adapters::GenericResourceApplication {
            compute: compute.clone(),
            image: None,
            public_address_workflow: None,
            network_service: network_service.clone(),
            store: store.clone(),
            storage_provider: Some(Arc::new(
                o3k_storage::testkit::InMemoryStorageProvider::default(),
            )),
            server: Arc::new(o3kd::native_adapters::ServerReaderAdapter {
                service: compute.clone(),
            }),
            network: Arc::new(o3kd::native_adapters::NetworkReaderAdapter {
                store: store.clone(),
                authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
            }),
            external_controllers: Arc::new(Default::default()),
            public_allocator: None,
            network_external_realm_id: None,
            attachment_workflow: None,
            metering: None,
        });
    let mut manifests = ManifestRegistry::new();
    manifests.seed_core()?;
    manifests.register(o3k_database_example::manifest())?;
    let verification = SigningKey::from_bytes(&[9; 32]).verifying_key();
    let handler = o3kd::native_adapters::CompositionResourceHandler {
        application,
        store: store.clone(),
        manifests: Arc::new(manifests.clone()),
        delegation_keys: HashMap::from([(String::from("p12-6-test"), verification)]),
        dispatcher: o3k_native_api::resource::ResourceDispatcher::from_manifest_registry(
            &manifests,
        )
        .map_err(|error| format!("dispatcher: {error:?}"))?,
    };
    let composition_service = CompositionServiceAdapter::new(
        Arc::new(handler),
        "database-example",
        "database-controller",
    )
    .with_delegation_keys(
        "o3k-composition",
        HashMap::from([(String::from("p12-6-test"), verification)]),
    )
    .into_server();
    let composition_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let composition_address = composition_listener.local_addr()?;
    let composition_tls = tls_server()?;
    let composition_task = tokio::spawn(async move {
        let mut builder = Server::builder().tls_config(composition_tls)?;
        builder
            .add_service(composition_service)
            .serve_with_incoming(TcpListenerStream::new(composition_listener))
            .await
    });
    let composition_client = Arc::new(
        GrpcCompositionClient::connect(&format!("https://{composition_address}"), tls_client()?)
            .await?,
    );
    let controller_handler =
        DatabaseControllerHandler::new(composition_client.clone(), lifecycle()?);
    let controller_service = o3k_service_sdk::ServiceControllerServer::new(
        controller_handler,
        "database-example",
        "database",
        "p12-6-test-manifest",
        1,
    )
    .with_service_principal("database-controller")
    .with_delegation_recipient("o3k-composition")
    .with_delegation_keys(HashMap::from([(String::from("p12-6-test"), verification)]))
    .into_service();
    let controller_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let controller_address = controller_listener.local_addr()?;
    let controller_tls = tls_server()?;
    let controller_task = tokio::spawn(async move {
        let mut builder = Server::builder().tls_config(controller_tls)?;
        builder
            .add_service(controller_service)
            .serve_with_incoming(TcpListenerStream::new(controller_listener))
            .await
    });
    let controller = Arc::new(
        GrpcControllerAdapter::connect(
            &format!("https://{controller_address}"),
            tls_client()?,
            "database-example",
            "database",
            o3k_kernel::ServicePrincipal::new(
                o3k_kernel::PrincipalId::new_unchecked("database-controller"),
                "database-controller",
                "database",
            ),
            "p12-6-test-manifest",
            1,
        )
        .await?
        .with_delegation_signer("p12-6-test", SigningKey::from_bytes(&[9; 32])),
    );
    let api_application: Arc<dyn o3k_native_api::resource::ResourceApplication> =
        Arc::new(o3kd::native_adapters::GenericResourceApplication {
            compute: compute.clone(),
            image: None,
            public_address_workflow: None,
            network_service: network_service.clone(),
            store: store.clone(),
            storage_provider: Some(Arc::new(
                o3k_storage::testkit::InMemoryStorageProvider::default(),
            )),
            server: Arc::new(o3kd::native_adapters::ServerReaderAdapter {
                service: compute.clone(),
            }),
            network: Arc::new(o3kd::native_adapters::NetworkReaderAdapter {
                store: store.clone(),
                authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
            }),
            external_controllers: Arc::new(std::collections::BTreeMap::from([(
                "database-example".to_owned(),
                controller.clone(),
            )])),
            public_allocator: None,
            network_external_realm_id: None,
            attachment_workflow: None,
            metering: None,
        });
    manifests.register_controller("database-example", controller.session().clone())?;
    manifests.activate_controller("database-example")?;
    let mut api_authorizer = o3k_kernel::StaticAuthorizer::standard();
    for action_name in ["CreateInstance", "ReadInstance", "DeleteInstance"] {
        api_authorizer.register(ActionPolicy {
            action: ActionId::new("database", action_name)?,
            expected_resource_type: o3k_kernel::ResourceType::new("database", "instance")?,
            accepted_principals: vec![PrincipalKind::User, PrincipalKind::Service],
            require_ownership: true,
            required_roles: Vec::new(),
        });
    }
    let api_router = o3k_native_api::router(
        o3k_native_api::NativeApiState::new(
            Some(manifests.clone()),
            o3k_native_api::pagination::CursorConfig::default(),
            Some(Arc::new(ProcessTokenIssuer)),
            Some(Arc::new(o3kd::native_adapters::ServerReaderAdapter {
                service: compute.clone(),
            })),
            None,
            Some(Arc::new(o3kd::native_adapters::NetworkReaderAdapter {
                store: store.clone(),
                authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
            })),
        )?
        .with_resource_application(api_application.clone())
        .with_authorizer(Arc::new(api_authorizer)),
    );
    let http_create = axum::http::Request::builder()
        .method("POST")
        .uri("/database/instances")
        .header("authorization", "Bearer project-project-http")
        .header("content-type", "application/json")
        .header("idempotency-key", "http-create-1")
        .body(axum::body::Body::from(serde_json::to_vec(
            &serde_json::json!({
                "api_version": "o3k.io/v1",
                "kind": "database:instance",
                "spec": {"engine":"test-engine","version":"1","storage_gb":1}
            }),
        )?))?;
    let http_response = tower::ServiceExt::oneshot(api_router.clone(), http_create).await?;
    if !http_response.status().is_success() {
        let status = http_response.status();
        let body = axum::body::to_bytes(http_response.into_body(), 1_048_576).await?;
        return Err(format!(
            "HTTP create failed: {status} {}",
            String::from_utf8_lossy(&body)
        )
        .into());
    }
    let http_body = axum::body::to_bytes(http_response.into_body(), 1_048_576).await?;
    let http_json: serde_json::Value = serde_json::from_slice(&http_body)?;
    let http_id = http_json["resource_id"]
        .as_str()
        .ok_or_else(|| format!("HTTP create omitted resource id: {http_json}"))?
        .to_owned();
    let http_show = axum::http::Request::builder()
        .uri(format!("/database/instances/{http_id}"))
        .header("authorization", "Bearer project-project-http")
        .body(axum::body::Body::empty())?;
    let http_show_response = tower::ServiceExt::oneshot(api_router.clone(), http_show).await?;
    assert_eq!(http_show_response.status(), axum::http::StatusCode::OK);
    let http_delete = axum::http::Request::builder()
        .method("DELETE")
        .uri(format!("/database/instances/{http_id}"))
        .header("authorization", "Bearer project-project-http")
        .header("idempotency-key", "http-delete-1")
        .body(axum::body::Body::empty())?;
    let http_delete_response = tower::ServiceExt::oneshot(api_router, http_delete).await?;
    assert!(http_delete_response.status().is_success());

    let dispatcher =
        o3k_native_api::resource::ResourceDispatcher::from_manifest_registry(&manifests)
            .map_err(|error| format!("dispatcher: {error:?}"))?;
    let descriptor = dispatcher
        .resolve_resource_type(&o3k_kernel::ResourceType::new("database", "instance")?)
        .ok_or("database descriptor missing")?;
    let api_auth = o3k_kernel::AuthContext::new(
        o3k_kernel::Principal::User(o3k_kernel::UserPrincipal::new(
            o3k_kernel::PrincipalId::new("user-api")?,
            "user-api",
            None,
        )),
        OwnershipScope::project(ScopeId::new("project-api")?, None, None),
        Vec::new(),
        1,
        u64::MAX,
        "api-audit",
        uuid::Uuid::new_v4().to_string(),
        None,
    );
    let api_result = api_application
        .create(
            descriptor,
            &api_auth,
            o3k_native_api::resource::ValidatedCreateRequest {
                api_version: Some("o3k.io/v1".into()),
                kind: Some("database:instance".into()),
                spec: o3k_native_api::resource_contract::ValidatedSpec::from_external_contract(
                    serde_json::json!({"engine":"test-engine","version":"1","storage_gb":1}),
                ),
            },
            Some("api-create-1"),
        )
        .await
        .map_err(|error| format!("generic create: {error:?}"))?;
    let api_id = api_result
        .resource_id
        .clone()
        .ok_or("generic create omitted id")?;
    let replay = api_application
        .create(
            descriptor,
            &api_auth,
            o3k_native_api::resource::ValidatedCreateRequest {
                api_version: Some("o3k.io/v1".into()),
                kind: Some("database:instance".into()),
                spec: o3k_native_api::resource_contract::ValidatedSpec::from_external_contract(
                    serde_json::json!({"engine":"test-engine","version":"1","storage_gb":1}),
                ),
            },
            Some("api-create-1"),
        )
        .await
        .map_err(|error| format!("equivalent replay: {error:?}"))?;
    assert_eq!(replay.resource_id.as_deref(), Some(api_id.as_str()));
    let conflict = api_application
        .create(
            descriptor,
            &api_auth,
            o3k_native_api::resource::ValidatedCreateRequest {
                api_version: Some("o3k.io/v1".into()),
                kind: Some("database:instance".into()),
                spec: o3k_native_api::resource_contract::ValidatedSpec::from_external_contract(
                    serde_json::json!({"engine":"test-engine","version":"2","storage_gb":1}),
                ),
            },
            Some("api-create-1"),
        )
        .await;
    assert!(matches!(
        conflict,
        Err(o3k_native_api::resource::ResourceApplicationError::IdempotencyConflict)
    ));
    let api_show = api_application
        .show(descriptor, &api_auth, &api_id)
        .await
        .map_err(|error| format!("generic show: {error:?}"))?;
    assert!(api_show.get("status").is_some());
    let api_delete = api_application
        .delete(descriptor, &api_auth, &api_id, Some("api-delete-1"), None)
        .await
        .map_err(|error| format!("generic delete: {error:?}"))?;
    if !api_delete.complete {
        // A child mutation may be accepted without proving absence.  The
        // parent must remain recoverable rather than being reported deleted.
        let parent = store.get_resource(api_id.parse()?).await?;
        assert_ne!(parent.observed_state, "DELETED");
    }
    let quota_scope = OwnershipScope::project(ScopeId::new("project-quota")?, None, None);
    store
        .set_limit(
            &quota_scope,
            &LimitKey::compute_servers(),
            LimitValue::Maximum(0),
        )
        .await?;
    let quota_auth = o3k_kernel::AuthContext::new(
        o3k_kernel::Principal::User(o3k_kernel::UserPrincipal::new(
            o3k_kernel::PrincipalId::new("user-quota")?,
            "user-quota",
            None,
        )),
        quota_scope,
        Vec::new(),
        1,
        u64::MAX,
        "quota-audit",
        uuid::Uuid::new_v4().to_string(),
        None,
    );
    let quota_result = api_application
        .create(
            descriptor,
            &quota_auth,
            o3k_native_api::resource::ValidatedCreateRequest {
                api_version: Some("o3k.io/v1".into()),
                kind: Some("database:instance".into()),
                spec: o3k_native_api::resource_contract::ValidatedSpec::from_external_contract(
                    serde_json::json!({"engine":"test-engine","version":"1","storage_gb":1}),
                ),
            },
            Some("quota-create-1"),
        )
        .await
        .map_err(|error| format!("quota create: {error:?}"))?;
    assert!(!quota_result.complete);
    let quota_parent = quota_result
        .resource_id
        .as_deref()
        .ok_or("quota result omitted parent id")?
        .parse::<uuid::Uuid>()?;
    let quota_relationships = store.list_relationships(quota_parent).await?;
    assert!(quota_relationships.iter().all(|relationship| {
        relationship.expected_child_resource_type != "compute:server"
            || relationship.child_resource_id.is_none()
    }));
    let scope = OwnershipScope::project(ScopeId::new("project-a")?, None, None);
    let parent_id = uuid::Uuid::new_v4();
    let operation_id = uuid::Uuid::new_v4();
    let request_id = uuid::Uuid::new_v4();
    let resource_type = o3k_kernel::ResourceType::new("database", "instance")?;
    let resource = ResourceRecord {
        id: parent_id,
        kind: resource_type.to_string(),
        project_id: "project-a".into(),
        generation: 1,
        observed_generation: 0,
        desired_state: serde_json::to_string(&InstanceSpec {
            engine: "test-engine".into(),
            version: "1".into(),
            storage_gb: 1,
        })?,
        observed_state: "PROVISIONING".into(),
        provider_id: None,
    };
    let action = ActionId::new("database", "CreateInstance")?;
    let operation = OperationRecord {
        id: operation_id,
        resource_id: parent_id,
        kind: "lifecycle:create".into(),
        state: OperationState::Pending,
        provider_operation_id: None,
        error_category: None,
        error_message: None,
    };
    let canonical = CanonicalOperationRecord::from_kernel_operation(&o3k_kernel::Operation::new(
        operation_id,
        "database-example",
        action.clone(),
        "user-a",
        scope.clone(),
        resource_type.clone(),
        Some(o3k_kernel::ResourceId::new(parent_id.to_string())?),
        Some(request_id.to_string()),
    ))?;
    let identity = IdempotencyReservationRequest::from_semantics(
        "project-a",
        action.to_string(),
        "database-create-1",
        &resource_type.to_string(),
        Some(&parent_id.to_string()),
        &serde_json::from_str::<serde_json::Value>(&resource.desired_state)?,
        operation_id,
    )?;
    store
        .create_or_replay_canonical_resource_operation(
            &resource, &operation, &canonical, &identity, None,
        )
        .await?;
    let session = controller.session().clone();
    let context = o3k_kernel::OperationContext {
        request_id,
        operation_id,
        action,
        service_id: "database-example".into(),
        owner_scope: scope.clone(),
        session_id: session.session_id,
        session_generation: session.session_generation,
        deadline_unix_ms: chrono::Utc::now().timestamp_millis() as u64 + 60_000,
        replay_identity: "database-create-1".into(),
        audit_correlation: "p12-6-process".into(),
    };
    let resource_reference = o3k_kernel::ResourceReference {
        resource_type: o3k_kernel::ResourceType::new("database", "instance")?,
        resource_id: o3k_kernel::ResourceId::new(parent_id.to_string())?,
        generation: 1,
    };
    let delegation = controller.issue_parent_delegation(&context, "user-a", &resource_reference)?;

    // A correctly signed delegation for another owner scope must still fail
    // parent ownership validation before the generic composition service can
    // reserve a relationship or invoke a child application.
    let foreign_scope = OwnershipScope::project(ScopeId::new("project-foreign")?, None, None);
    let foreign_context = o3k_kernel::OperationContext {
        owner_scope: foreign_scope.clone(),
        audit_correlation: "p12-6-foreign-scope".into(),
        ..context.clone()
    };
    let foreign_delegation = controller.issue_parent_delegation(
        &foreign_context,
        "user-foreign",
        &resource_reference,
    )?;
    let foreign_credential = serde_json::to_vec(&SignedDelegation {
        claims: DelegationClaims {
            version: 1,
            credential_id: foreign_delegation.credential_id,
            issuer: "o3k-control-plane".into(),
            key_id: foreign_delegation.key_id.clone(),
            original_actor: foreign_delegation.original_actor.clone(),
            owner_scope: foreign_delegation.original_scope.to_string(),
            calling_service: foreign_delegation.calling_service.name().into(),
            recipient_service: foreign_delegation.recipient_service.name().into(),
            action: foreign_delegation.delegated_action.to_string(),
            resource_type: foreign_delegation.resource.resource_type.to_string(),
            resource_id: foreign_delegation.resource.resource_id.as_str().into(),
            request_id: foreign_delegation.request_id,
            operation_id: foreign_delegation.operation_id,
            session_id: foreign_delegation.session_id,
            session_generation: foreign_delegation.session_generation,
            issued_at_unix_ms: foreign_delegation.issued_at_unix_ms,
            expires_at_unix_ms: foreign_delegation.expires_at_unix_ms,
        },
        signature: foreign_delegation.signature.clone(),
    })?;
    let foreign_child = composition_client
        .create_child(ChildResourceRequest {
            parent: resource_reference.clone(),
            parent_operation_id: operation_id,
            child_operation_id: Some(uuid::Uuid::new_v4()),
            context: foreign_context,
            service_principal: "database-controller".into(),
            delegation: foreign_credential,
            child: None,
            action: ActionId::new("network", "CreateNetwork")?,
            resource_type: o3k_kernel::ResourceType::new("network", "network")?,
            owner_scope: foreign_scope,
            slot: "foreign-scope".into(),
            idempotency_key: "foreign-scope-child".into(),
            desired_spec: serde_json::json!({"name":"foreign"}),
        })
        .await;
    assert!(foreign_child.is_err());
    assert!(store.list_relationships(parent_id).await?.is_empty());

    // Two independent composition clients race the same real child mutation
    // over gRPC+mTLS. The relationship uniqueness and canonical child
    // idempotency layers, not a process-local mutex, decide the winner.
    let wire_delegation = serde_json::to_vec(&SignedDelegation {
        claims: DelegationClaims {
            version: 1,
            credential_id: delegation.credential_id,
            issuer: "o3k-control-plane".into(),
            key_id: delegation.key_id.clone(),
            original_actor: delegation.original_actor.clone(),
            owner_scope: delegation.original_scope.to_string(),
            calling_service: delegation.calling_service.name().into(),
            recipient_service: delegation.recipient_service.name().into(),
            action: delegation.delegated_action.to_string(),
            resource_type: delegation.resource.resource_type.to_string(),
            resource_id: delegation.resource.resource_id.as_str().into(),
            request_id: delegation.request_id,
            operation_id: delegation.operation_id,
            session_id: delegation.session_id,
            session_generation: delegation.session_generation,
            issued_at_unix_ms: delegation.issued_at_unix_ms,
            expires_at_unix_ms: delegation.expires_at_unix_ms,
        },
        signature: delegation.signature.clone(),
    })?;
    let child_request = ChildResourceRequest {
        parent: resource_reference.clone(),
        parent_operation_id: operation_id,
        child_operation_id: None,
        context: context.clone(),
        service_principal: "database-controller".into(),
        delegation: wire_delegation.clone(),
        child: None,
        action: ActionId::new("network", "CreateNetwork")?,
        resource_type: o3k_kernel::ResourceType::new("network", "network")?,
        owner_scope: scope.clone(),
        slot: "network-primary".into(),
        idempotency_key: format!("{operation_id}:network-primary"),
        desired_spec: serde_json::json!({"name": format!("database-network-{parent_id}")}),
    };

    // A real child resource owned by another tenant must not become
    // observable or adoptable merely because its canonical ID is supplied to
    // the composition boundary. This traverses the same authenticated mTLS
    // delegation path used by controller composition.
    let tenant_b_child = network_service
        .create_network_for_project("project-b", "tenant-b-network".into())
        .await?;
    let mut foreign_child_create = child_request.clone();
    foreign_child_create.child = Some(o3k_kernel::ResourceReference {
        resource_type: o3k_kernel::ResourceType::new("network", "network")?,
        resource_id: o3k_kernel::ResourceId::new(tenant_b_child.id.to_string())?,
        generation: 1,
    });
    foreign_child_create.slot = "foreign-child-create".into();
    assert!(
        composition_client
            .create_child(foreign_child_create)
            .await
            .is_err()
    );
    assert_eq!(
        network_service
            .get_network(
                &o3k_kernel::AuthContext::new(
                    o3k_kernel::Principal::User(o3k_kernel::UserPrincipal::new(
                        o3k_kernel::PrincipalId::new("user-b")?,
                        "user-b",
                        None,
                    )),
                    OwnershipScope::project(ScopeId::new("project-b")?, None, None),
                    Vec::new(),
                    1,
                    u64::MAX,
                    "foreign-child-check",
                    uuid::Uuid::new_v4().to_string(),
                    None,
                ),
                tenant_b_child.id,
            )
            .await?
            .id,
        tenant_b_child.id
    );
    assert!(store.list_relationships(parent_id).await?.is_empty());

    // Each binding is exercised independently through the real mTLS
    // composition boundary.  These requests use the otherwise valid signed
    // delegation, so a rejection cannot be attributed to malformed
    // credentials or a bypassed transport check.
    let mut wrong_action = child_request.clone();
    wrong_action.action = ActionId::new("network", "DeleteNetwork")?;
    assert!(composition_client.create_child(wrong_action).await.is_err());
    assert!(store.list_relationships(parent_id).await?.is_empty());

    let mut wrong_parent_operation = child_request.clone();
    wrong_parent_operation.parent_operation_id = uuid::Uuid::new_v4();
    assert!(
        composition_client
            .create_child(wrong_parent_operation)
            .await
            .is_err()
    );
    assert!(store.list_relationships(parent_id).await?.is_empty());

    let mut wrong_service_principal = child_request.clone();
    wrong_service_principal.service_principal = "other-service-controller".into();
    assert!(
        composition_client
            .create_child(wrong_service_principal)
            .await
            .is_err()
    );
    assert!(store.list_relationships(parent_id).await?.is_empty());

    // The composition endpoint must reject a cryptographically valid
    // delegation after its bounded lifetime, before reserving a child slot.
    let mut expired_wire: SignedDelegation = serde_json::from_slice(&wire_delegation)?;
    expired_wire.claims.expires_at_unix_ms =
        chrono::Utc::now().timestamp_millis().max(1) as u64 - 1;
    let expired_wire = serde_json::to_vec(&SignedDelegation::sign(
        expired_wire.claims,
        &SigningKey::from_bytes(&[9; 32]),
    )?)?;
    let mut expired_request = child_request.clone();
    expired_request.delegation = expired_wire;
    expired_request.slot = "expired-delegation".into();
    assert!(
        composition_client
            .create_child(expired_request)
            .await
            .is_err()
    );
    assert!(store.list_relationships(parent_id).await?.is_empty());

    // A delegation from the old controller epoch cannot be rebound to a new
    // session context, even when the request otherwise names the same parent.
    let mut stale_session_request = child_request.clone();
    stale_session_request.context.session_generation += 1;
    stale_session_request.slot = "stale-session".into();
    assert!(
        composition_client
            .create_child(stale_session_request)
            .await
            .is_err()
    );
    assert!(store.list_relationships(parent_id).await?.is_empty());

    // Build a second application object over the same durable store.  The
    // race below must exercise independent application state; two handlers
    // around one application would only prove transport concurrency.
    let independent_compute = Arc::new(o3k_compute::ComputeService::new_for_test(
        store.clone(),
        Arc::new(FakeComputeProvider::new()),
    ));
    let independent_network = Arc::new(
        o3k_network::NetworkService::open_for_test(
            std::env::temp_dir().join(format!("o3k-p12-6-independent-{}", uuid::Uuid::new_v4())),
            store.clone(),
        )
        .await?,
    );
    let independent_application: Arc<dyn o3k_native_api::resource::ResourceApplication> =
        Arc::new(o3kd::native_adapters::GenericResourceApplication {
            compute: independent_compute.clone(),
            image: None,
            public_address_workflow: None,
            network_service: independent_network,
            store: store.clone(),
            storage_provider: Some(Arc::new(
                o3k_storage::testkit::InMemoryStorageProvider::default(),
            )),
            server: Arc::new(o3kd::native_adapters::ServerReaderAdapter {
                service: independent_compute,
            }),
            network: Arc::new(o3kd::native_adapters::NetworkReaderAdapter {
                store: store.clone(),
                authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
            }),
            external_controllers: Arc::new(Default::default()),
            public_allocator: None,
            network_external_realm_id: None,
            attachment_workflow: None,
            metering: None,
        });
    let independent_dispatcher =
        o3k_native_api::resource::ResourceDispatcher::from_manifest_registry(&manifests)
            .map_err(|error| format!("independent dispatcher: {error:?}"))?;
    let independent_service = CompositionServiceAdapter::new(
        Arc::new(o3kd::native_adapters::CompositionResourceHandler {
            application: independent_application,
            store: store.clone(),
            manifests: Arc::new(manifests.clone()),
            delegation_keys: HashMap::from([(String::from("p12-6-test"), verification)]),
            dispatcher: independent_dispatcher,
        }),
        "database-example",
        "database-controller",
    )
    .with_delegation_keys(
        "o3k-composition",
        HashMap::from([(String::from("p12-6-test"), verification)]),
    )
    .into_server();
    let independent_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let independent_address = independent_listener.local_addr()?;
    let independent_tls = tls_server()?;
    let independent_task = tokio::spawn(async move {
        let mut builder = Server::builder().tls_config(independent_tls)?;
        builder
            .add_service(independent_service)
            .serve_with_incoming(TcpListenerStream::new(independent_listener))
            .await
    });
    let race_left = composition_client.clone();
    let race_right =
        GrpcCompositionClient::connect(&format!("https://{independent_address}"), tls_client()?)
            .await?;
    let (race_left_result, race_right_result) = tokio::join!(
        race_left.create_child(child_request.clone()),
        race_right.create_child(child_request),
    );
    let successful_results = [race_left_result, race_right_result]
        .into_iter()
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    assert!(!successful_results.is_empty());
    assert!(successful_results.windows(2).all(|results| {
        results[0].resource.resource_id == results[1].resource.resource_id
            && results[0].operation_id == results[1].operation_id
    }));
    assert_eq!(store.list_relationships(parent_id).await?.len(), 1);

    // The database workflow's network child is a canonical network, but a
    // native compute attachment requires an active bounded-flat realm.  Seed
    // that realm through the same Network authority before the controller
    // reaches its dependent compute slot.
    let network_id = store
        .get_relationship(parent_id, "network-primary")
        .await?
        .child_resource_id
        .ok_or("network child missing after composition race")?;
    network_service
        .create_subnet_for_project(
            "project-a",
            network_id,
            "database-subnet".into(),
            "192.0.2.0/24".into(),
            None,
            None,
            None,
        )
        .await?;

    let reconcile_request = o3k_kernel::ReconcileRequest {
        context,
        resource: o3k_kernel::ResourceSnapshot {
            reference: o3k_kernel::ResourceReference {
                resource_type,
                resource_id: o3k_kernel::ResourceId::new(parent_id.to_string())?,
                generation: 1,
            },
            desired_spec: serde_json::from_str(&resource.desired_state)?,
            known_status: None,
            owner_scope: scope.clone(),
        },
        delegation: Some(delegation),
    };
    // Two genuinely overlapping controller calls exercise both real gRPC
    // boundaries. Durable relationship uniqueness and canonical child
    // idempotency, rather than a process-local mutex, must converge them.
    let first_controller = controller.clone();
    let second_controller = controller.clone();
    let first_request = reconcile_request.clone();
    let second_request = reconcile_request.clone();
    let (first_outcome, second_outcome) = tokio::join!(
        first_controller.reconcile(first_request),
        second_controller.reconcile(second_request),
    );
    assert!(
        matches!(
            first_outcome,
            o3k_kernel::ReconcileOutcome::Succeeded { .. }
        ),
        "unexpected first outcome: {first_outcome:?}"
    );
    assert!(
        matches!(
            second_outcome,
            o3k_kernel::ReconcileOutcome::Succeeded { .. }
        ),
        "unexpected second outcome: {second_outcome:?}"
    );
    let relationships = store.list_relationships(parent_id).await?;
    assert_eq!(relationships.len(), 3);
    assert!(relationships.iter().all(|relationship| {
        relationship.state == "bound"
            && relationship.parent_resource_id == parent_id
            && relationship.owner_scope == "project-a"
            && relationship.child_resource_id.is_some()
    }));

    // Replace the controller session on the same production controller
    // endpoint. The old adapter still holds a valid signed delegation, but
    // its transport context must be fenced before the handler can reconcile.
    let stale_replay = reconcile_request.clone();
    let replacement = GrpcControllerAdapter::connect(
        &format!("https://{controller_address}"),
        tls_client()?,
        "database-example",
        "database",
        o3k_kernel::ServicePrincipal::new(
            o3k_kernel::PrincipalId::new_unchecked("database-controller"),
            "database-controller",
            "database",
        ),
        "p12-6-test-manifest",
        1,
    )
    .await?
    .with_delegation_signer("p12-6-test", SigningKey::from_bytes(&[9; 32]));
    assert_ne!(
        replacement.session().session_id,
        controller.session().session_id
    );
    let stale_outcome = controller.reconcile(stale_replay).await;
    assert!(matches!(
        stale_outcome,
        o3k_kernel::ReconcileOutcome::Unknown { .. }
    ));
    assert_eq!(store.list_relationships(parent_id).await?.len(), 3);

    // A delegation issued by the replacement session remains usable, proving
    // the rejection above is session fencing rather than generic breakage.
    let replacement_context = o3k_kernel::OperationContext {
        request_id: uuid::Uuid::new_v4(),
        session_id: replacement.session().session_id,
        session_generation: replacement.session().session_generation,
        replay_identity: "p12-6-session-replacement".into(),
        ..reconcile_request.context.clone()
    };
    let replacement_delegation = replacement.issue_parent_delegation(
        &replacement_context,
        "user-a",
        &reconcile_request.resource.reference,
    )?;
    let replacement_outcome = replacement
        .reconcile(o3k_kernel::ReconcileRequest {
            context: replacement_context,
            resource: reconcile_request.resource.clone(),
            delegation: Some(replacement_delegation),
        })
        .await;
    assert!(
        matches!(
            &replacement_outcome,
            o3k_kernel::ReconcileOutcome::Succeeded { .. }
        ),
        "replacement outcome: {replacement_outcome:?}"
    );
    controller_task.abort();
    let restarted_handler =
        DatabaseControllerHandler::new(composition_client.clone(), lifecycle()?);
    let restarted_service = o3k_service_sdk::ServiceControllerServer::new(
        restarted_handler,
        "database-example",
        "database",
        "p12-6-test-manifest",
        1,
    )
    .with_service_principal("database-controller")
    .with_delegation_recipient("o3k-composition")
    .with_delegation_keys(HashMap::from([("p12-6-test".to_owned(), verification)]))
    .into_service();
    let restarted_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let restarted_address = restarted_listener.local_addr()?;
    let restarted_tls = tls_server()?;
    let restarted_task = tokio::spawn(async move {
        let mut builder = Server::builder().tls_config(restarted_tls)?;
        builder
            .add_service(restarted_service)
            .serve_with_incoming(TcpListenerStream::new(restarted_listener))
            .await
    });
    let restarted_controller = Arc::new(
        GrpcControllerAdapter::connect(
            &format!("https://{restarted_address}"),
            tls_client()?,
            "database-example",
            "database",
            o3k_kernel::ServicePrincipal::new(
                o3k_kernel::PrincipalId::new_unchecked("database-controller"),
                "database-controller",
                "database",
            ),
            "p12-6-test-manifest",
            1,
        )
        .await?
        .with_delegation_signer("p12-6-test", SigningKey::from_bytes(&[9; 32])),
    );
    let restarted_session = restarted_controller.session().clone();
    let restarted_context = o3k_kernel::OperationContext {
        request_id,
        operation_id,
        action: ActionId::new("database", "CreateInstance")?,
        service_id: "database-example".into(),
        owner_scope: scope.clone(),
        session_id: restarted_session.session_id,
        session_generation: restarted_session.session_generation,
        deadline_unix_ms: chrono::Utc::now().timestamp_millis() as u64 + 60_000,
        replay_identity: "database-create-1".into(),
        audit_correlation: "p12-6-process-restart".into(),
    };
    let restarted_delegation = restarted_controller.issue_parent_delegation(
        &restarted_context,
        "user-a",
        &o3k_kernel::ResourceReference {
            resource_type: o3k_kernel::ResourceType::new("database", "instance")?,
            resource_id: o3k_kernel::ResourceId::new(parent_id.to_string())?,
            generation: 1,
        },
    )?;
    let restarted_outcome = restarted_controller
        .reconcile(o3k_kernel::ReconcileRequest {
            context: restarted_context,
            resource: o3k_kernel::ResourceSnapshot {
                reference: o3k_kernel::ResourceReference {
                    resource_type: o3k_kernel::ResourceType::new("database", "instance")?,
                    resource_id: o3k_kernel::ResourceId::new(parent_id.to_string())?,
                    generation: 1,
                },
                desired_spec: serde_json::from_str(&resource.desired_state)?,
                known_status: None,
                owner_scope: scope,
            },
            delegation: Some(restarted_delegation),
        })
        .await;
    assert!(matches!(
        restarted_outcome,
        o3k_kernel::ReconcileOutcome::Succeeded { .. }
    ));
    let after_restart = store.list_relationships(parent_id).await?;
    assert_eq!(after_restart.len(), 3);
    assert_eq!(
        after_restart
            .iter()
            .filter_map(|relationship| relationship.child_resource_id)
            .collect::<std::collections::BTreeSet<_>>(),
        relationships
            .iter()
            .filter_map(|relationship| relationship.child_resource_id)
            .collect::<std::collections::BTreeSet<_>>()
    );
    restarted_task.abort();
    composition_task.abort();
    independent_task.abort();
    let _ = std::fs::remove_file(store_path);
    Ok(())
}

#[tokio::test]
async fn unavailable_external_controller_and_composition_endpoints_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let composition = GrpcCompositionClient::connect("https://127.0.0.1:1", tls_client()?).await;
    assert!(composition.is_err());

    let controller = GrpcControllerAdapter::connect(
        "https://127.0.0.1:1",
        tls_client()?,
        "database-example",
        "database",
        o3k_kernel::ServicePrincipal::new(
            o3k_kernel::PrincipalId::new_unchecked("database-controller"),
            "database-controller",
            "database",
        ),
        "unavailable-test-manifest",
        1,
    )
    .await;
    assert!(controller.is_err());
    Ok(())
}

#[tokio::test]
async fn p12_6_relationship_recovery_reopens_store_and_serializes_process_race()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "o3k-p12-6-recovery-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let parent = uuid::Uuid::new_v4();
    let parent_operation = uuid::Uuid::new_v4();
    let child_operation = uuid::Uuid::new_v4();
    let record = ResourceRelationshipRecord {
        parent_resource_id: parent,
        parent_resource_type: "database:instance".into(),
        slot: "network-primary".into(),
        expected_child_resource_type: "network:network".into(),
        child_resource_id: None,
        ownership: "exclusive".into(),
        parent_operation_id: parent_operation,
        child_operation_id: Some(child_operation),
        owner_scope: "project:project-recovery".into(),
        state: "reserved".into(),
        fingerprint: "parent-slot-fingerprint".into(),
    };
    {
        let first = O3kStore::connect_sqlite_file(&path).await?;
        first
            .insert_resource(&ResourceRecord {
                id: parent,
                kind: "database:instance".into(),
                project_id: "project-recovery".into(),
                generation: 1,
                observed_generation: 0,
                desired_state: "{}".into(),
                observed_state: "PROVISIONING".into(),
                provider_id: None,
            })
            .await?;
        first.reserve_relationship(&record).await?;
        assert_eq!(first.list_relationships(parent).await?.len(), 1);
    }

    // Runtime A is gone: only the SQLite file remains. Runtime B must see the
    // unresolved intent and preserve its child operation identity instead of
    // treating the slot as empty.
    let reopened = O3kStore::connect_sqlite_file(&path).await?;
    let restored = reopened.list_relationships(parent).await?;
    assert_eq!(restored, vec![record.clone()]);
    drop(reopened);

    // Two independent store/application owners race the same reservation.
    // The database uniqueness constraint, not a process-local mutex, chooses
    // one durable slot and both equivalent attempts observe the same record.
    let left = O3kStore::connect_sqlite_file(&path).await?;
    let right = O3kStore::connect_sqlite_file(&path).await?;
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let left_barrier = barrier.clone();
    let right_barrier = barrier.clone();
    let left_record = record.clone();
    let right_record = record.clone();
    let left_task = tokio::spawn(async move {
        left_barrier.wait().await;
        left.reserve_relationship(&left_record).await
    });
    let right_task = tokio::spawn(async move {
        right_barrier.wait().await;
        right.reserve_relationship(&right_record).await
    });
    barrier.wait().await;
    let (left_result, right_result) = tokio::join!(left_task, right_task);
    assert_eq!(left_result??, record);
    assert_eq!(right_result??, record);

    let final_store = O3kStore::connect_sqlite_file(&path).await?;
    let final_relationships = final_store.list_relationships(parent).await?;
    assert_eq!(final_relationships.len(), 1);
    assert_eq!(
        final_relationships[0].child_operation_id,
        Some(child_operation)
    );
    drop(final_store);
    let _ = std::fs::remove_file(path);
    Ok(())
}

/// This is deliberately scoped as two runtime lifetimes.  The first helper
/// returns only durable identifiers; every application/store/registry/server
/// value is dropped before the second helper opens the SQLite file.
#[tokio::test]
async fn p12_6_reconstructs_two_independent_control_plane_runtimes()
-> Result<(), Box<dyn std::error::Error>> {
    let path =
        std::env::temp_dir().join(format!("o3k-p12-6-runtime-{}.sqlite", uuid::Uuid::new_v4()));
    let network_path = std::env::temp_dir().join(format!(
        "o3k-p12-6-runtime-network-{}",
        uuid::Uuid::new_v4()
    ));
    // The provider is an external execution fixture, not control-plane
    // state.  It survives the control-plane restart while every O3K
    // application/service object is rebuilt.
    let compute_provider = Arc::new(FakeComputeProvider::new());
    let parent = uuid::Uuid::new_v4();
    let parent_operation = uuid::Uuid::new_v4();
    let relationship = ResourceRelationshipRecord {
        parent_resource_id: parent,
        parent_resource_type: "database:instance".into(),
        slot: "network-primary".into(),
        expected_child_resource_type: "network:network".into(),
        child_resource_id: None,
        ownership: "exclusive".into(),
        parent_operation_id: parent_operation,
        child_operation_id: None,
        owner_scope: "project-runtime-recovery".into(),
        state: "bound".into(),
        fingerprint: "runtime-recovery-network".into(),
    };

    // Runtime A owns no state in this scope after the block exits.  The file
    // and static manifest fixture are the only inputs intentionally carried
    // to runtime B.
    let durable = {
        let store = Arc::new(O3kStore::connect_sqlite_file(&path).await?);
        let parent_type = o3k_kernel::ResourceType::new("database", "instance")?;
        let parent_action = ActionId::new("database", "CreateInstance")?;
        let parent_scope =
            OwnershipScope::project(ScopeId::new("project-runtime-recovery")?, None, None);
        let canonical =
            CanonicalOperationRecord::from_kernel_operation(&o3k_kernel::Operation::new(
                parent_operation,
                "database-example",
                parent_action.clone(),
                "user-runtime-recovery",
                parent_scope.clone(),
                parent_type.clone(),
                Some(o3k_kernel::ResourceId::new(parent.to_string())?),
                Some("runtime-recovery-request".into()),
            ))?;
        let operation = OperationRecord {
            id: parent_operation,
            resource_id: parent,
            kind: "lifecycle:create".into(),
            state: OperationState::Pending,
            provider_operation_id: None,
            error_category: None,
            error_message: None,
        };
        let identity = IdempotencyReservationRequest::from_semantics(
            "project-runtime-recovery",
            parent_action.to_string(),
            "runtime-recovery-create",
            &parent_type.to_string(),
            Some(&parent.to_string()),
            &serde_json::json!({"engine":"test-engine","version":"1","storage_gb":1}),
            parent_operation,
        )?;
        store
            .create_or_replay_canonical_resource_operation(
                &ResourceRecord {
                    id: parent,
                    kind: "database:instance".into(),
                    project_id: "project-runtime-recovery".into(),
                    generation: 1,
                    observed_generation: 0,
                    desired_state:
                        serde_json::json!({"engine":"test-engine","version":"1","storage_gb":1})
                            .to_string(),
                    observed_state: "PROVISIONING".into(),
                    provider_id: None,
                },
                &operation,
                &canonical,
                &identity,
                None,
            )
            .await?;
        store.reserve_relationship(&relationship).await?;
        for (slot, kind) in [
            ("volume-data", "volume:volume"),
            ("compute-primary", "compute:server"),
        ] {
            store
                .reserve_relationship(&ResourceRelationshipRecord {
                    parent_resource_id: parent,
                    parent_resource_type: "database:instance".into(),
                    slot: slot.into(),
                    expected_child_resource_type: kind.into(),
                    child_resource_id: None,
                    ownership: "exclusive".into(),
                    parent_operation_id: parent_operation,
                    child_operation_id: None,
                    owner_scope: "project-runtime-recovery".into(),
                    state: "reserved".into(),
                    fingerprint: format!("runtime-recovery-{slot}"),
                })
                .await?;
        }
        let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/o3k-database-example/service-manifest.json");
        let mut registry = ManifestRegistry::new();
        registry.seed_core()?;
        registry.register_json_file(manifest_path)?;
        let compute = Arc::new(o3k_compute::ComputeService::new_for_test(
            store.clone(),
            compute_provider.clone(),
        ));
        let network = Arc::new(
            o3k_network::NetworkService::open_for_test(network_path.clone(), store.clone()).await?,
        );
        let application: Arc<dyn o3k_native_api::resource::ResourceApplication> =
            Arc::new(o3kd::native_adapters::GenericResourceApplication {
                compute: compute.clone(),
                image: None,
                public_address_workflow: None,
                network_service: network.clone(),
                store: store.clone(),
                storage_provider: Some(Arc::new(
                    o3k_storage::testkit::InMemoryStorageProvider::default(),
                )),
                server: Arc::new(o3kd::native_adapters::ServerReaderAdapter {
                    service: compute.clone(),
                }),
                network: Arc::new(o3kd::native_adapters::NetworkReaderAdapter {
                    store: store.clone(),
                    authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
                }),
                external_controllers: Arc::new(Default::default()),
                public_allocator: None,
                network_external_realm_id: None,
                attachment_workflow: None,
                metering: None,
            });
        let dispatcher =
            o3k_native_api::resource::ResourceDispatcher::from_manifest_registry(&registry)
                .map_err(|error| format!("runtime A dispatcher: {error:?}"))?;
        let _composition_handler = o3kd::native_adapters::CompositionResourceHandler {
            application: application.clone(),
            store: store.clone(),
            manifests: Arc::new(registry.clone()),
            delegation_keys: HashMap::new(),
            dispatcher,
        };
        // Populate the durable fixture through the canonical generic
        // application before runtime A is destroyed.  Runtime B must later
        // observe these real child records, not merely reload synthetic
        // relationship IDs.
        let runtime_auth = process_auth_context("project-runtime-recovery");
        let runtime_dispatcher =
            o3k_native_api::resource::ResourceDispatcher::from_manifest_registry(&registry)
                .map_err(|error| format!("runtime A child dispatcher: {error:?}"))?;
        for (slot, kind, spec) in [
            (
                "network-primary",
                "network:network",
                serde_json::json!({"name": "runtime-recovery-network"}),
            ),
            (
                "volume-data",
                "volume:volume",
                serde_json::json!({"size_bytes": 1, "volume_type": "standard"}),
            ),
        ] {
            let (namespace, name) = kind
                .split_once(':')
                .ok_or_else(|| format!("invalid runtime child type {kind}"))?;
            let child_type = o3k_kernel::ResourceType::new(namespace, name)?;
            let child_descriptor = runtime_dispatcher
                .resolve_resource_type(&child_type)
                .ok_or_else(|| format!("missing runtime child descriptor {kind}"))?;
            let child = application
                .create(
                    child_descriptor,
                    &runtime_auth,
                    o3k_native_api::resource::ValidatedCreateRequest {
                        api_version: Some("o3k.io/v1".into()),
                        kind: Some(kind.into()),
                        spec: o3k_native_api::resource_contract::ValidatedSpec::from_external_contract(spec),
                    },
                    Some(&format!("runtime-recovery:{slot}")),
                )
                .await
                .map_err(|error| format!("runtime A child create {slot}: {error:?}"))?;
            let child_id = child
                .resource_id
                .ok_or_else(|| format!("runtime A child {slot} omitted resource"))?
                .parse()?;
            let child_operation_id = child.operation_id.parse()?;
            store
                .bind_relationship(parent, slot, child_id, child_operation_id)
                .await?;
        }
        // Force the simulated provider observations to become durable before
        // the control-plane teardown.  Runtime B must recover observable
        // canonical children, not merely relationship receipts.
        for record in store.list_relationships(parent).await? {
            let Some(child_id) = record.child_resource_id else {
                continue;
            };
            let (namespace, name) = record
                .expected_child_resource_type
                .split_once(':')
                .ok_or("invalid runtime child type")?;
            let child_type = o3k_kernel::ResourceType::new(namespace, name)?;
            let child_descriptor = runtime_dispatcher
                .resolve_resource_type(&child_type)
                .ok_or_else(|| format!("missing runtime observer descriptor {child_type}"))?;
            application
                .show(child_descriptor, &runtime_auth, &child_id.to_string())
                .await
                .map_err(|error| format!("runtime A child observe {}: {error:?}", record.slot))?;
        }
        let network_id = store
            .get_relationship(parent, "network-primary")
            .await?
            .child_resource_id
            .ok_or("runtime A network child missing")?;
        // Native compute resolves a canonical network UUID to an endpoint;
        // make the composition fixture attachable through the same canonical
        // network authority instead of relying on an opaque provider slot.
        network
            .create_subnet_for_project(
                "project-runtime-recovery",
                network_id,
                "runtime-recovery-subnet".into(),
                "192.0.2.0/24".into(),
                None,
                None,
                None,
            )
            .await?;
        let compute_type = o3k_kernel::ResourceType::new("compute", "server")?;
        let compute_descriptor = runtime_dispatcher
            .resolve_resource_type(&compute_type)
            .ok_or("missing runtime compute descriptor")?;
        let compute = application
            .create(
                compute_descriptor,
                &runtime_auth,
                o3k_native_api::resource::ValidatedCreateRequest {
                    api_version: Some("o3k.io/v1".into()),
                    kind: Some("compute:server".into()),
                    spec: o3k_native_api::resource_contract::ValidatedSpec::from_external_contract(
                        serde_json::json!({
                            "name": "runtime-recovery-compute",
                            "image_id": "image-1",
                            "flavor_id": uuid::Uuid::from_u128(1).to_string(),
                            "network_ids": [network_id.to_string()],
                            "key_name": null
                        }),
                    ),
                },
                Some("runtime-recovery:compute-primary"),
            )
            .await
            .map_err(|error| format!("runtime A child create compute-primary: {error:?}"))?;
        store
            .bind_relationship(
                parent,
                "compute-primary",
                compute
                    .resource_id
                    .ok_or("runtime A compute child omitted resource")?
                    .parse()?,
                compute.operation_id.parse()?,
            )
            .await?;
        let compute_id = store
            .get_relationship(parent, "compute-primary")
            .await?
            .child_resource_id
            .ok_or("runtime A compute child missing")?;
        application
            .show(
                runtime_dispatcher
                    .resolve_resource_type(&compute_type)
                    .ok_or("missing runtime compute observer descriptor")?,
                &runtime_auth,
                &compute_id.to_string(),
            )
            .await
            .map_err(|error| format!("runtime A child observe compute-primary: {error:?}"))?;
        let records = store.list_relationships(parent).await?;
        assert_eq!(records.len(), 3);
        (parent, parent_operation, records)
    };

    // Runtime A's store/application/registry/handler are all dropped above.
    // Runtime B uses new instances and reloads the external manifest through
    // ManifestRegistry rather than copying the prior registry.
    let store_b = Arc::new(O3kStore::connect_sqlite_file(&path).await?);
    let records_b = store_b.list_relationships(durable.0).await?;
    assert_eq!(records_b, durable.2);
    assert_eq!(records_b[0].parent_operation_id, durable.1);
    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/o3k-database-example/service-manifest.json");
    let mut registry_b = ManifestRegistry::new();
    registry_b.seed_core()?;
    registry_b.register_json_file(manifest_path)?;
    let session_a = o3k_kernel::ControllerSession {
        service_id: "database-example".into(),
        namespace: "database".into(),
        service_principal: o3k_kernel::ServicePrincipal::new(
            o3k_kernel::PrincipalId::new_unchecked("database-controller"),
            "database-controller",
            "database",
        ),
        session_id: uuid::Uuid::new_v4(),
        session_generation: 1,
        protocol_version: o3k_kernel::ProtocolVersion { major: 1, minor: 0 },
        manifest_digest: "p12-6-test-manifest".into(),
        manifest_generation: 1,
        started_at: chrono::Utc::now().to_rfc3339(),
    };
    let session_b = o3k_kernel::ControllerSession {
        session_id: uuid::Uuid::new_v4(),
        session_generation: 2,
        ..session_a.clone()
    };
    registry_b.register_controller("database-example", session_a.clone())?;
    registry_b.register_controller("database-example", session_b.clone())?;
    registry_b.activate_controller("database-example")?;
    assert_ne!(session_a.session_id, session_b.session_id);
    assert!(
        registry_b
            .register_controller("database-example", session_a.clone())
            .is_err()
    );
    let compute_b = Arc::new(o3k_compute::ComputeService::new_for_test(
        store_b.clone(),
        compute_provider,
    ));
    let network_b = Arc::new(
        o3k_network::NetworkService::open_for_test(network_path.clone(), store_b.clone()).await?,
    );
    let application_b: Arc<dyn o3k_native_api::resource::ResourceApplication> =
        Arc::new(o3kd::native_adapters::GenericResourceApplication {
            compute: compute_b.clone(),
            image: None,
            public_address_workflow: None,
            network_service: network_b,
            store: store_b.clone(),
            storage_provider: Some(Arc::new(
                o3k_storage::testkit::InMemoryStorageProvider::default(),
            )),
            server: Arc::new(o3kd::native_adapters::ServerReaderAdapter {
                service: compute_b.clone(),
            }),
            network: Arc::new(o3kd::native_adapters::NetworkReaderAdapter {
                store: store_b.clone(),
                authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
            }),
            external_controllers: Arc::new(Default::default()),
            public_allocator: None,
            network_external_realm_id: None,
            attachment_workflow: None,
            metering: None,
        });
    let dispatcher_b =
        o3k_native_api::resource::ResourceDispatcher::from_manifest_registry(&registry_b)
            .map_err(|error| format!("runtime B dispatcher: {error:?}"))?;
    let runtime_auth_b = process_auth_context("project-runtime-recovery");
    for record in &records_b {
        if let Some(child_id) = record.child_resource_id {
            let (namespace, name) = record
                .expected_child_resource_type
                .split_once(':')
                .ok_or("invalid runtime B child type")?;
            let child_type = o3k_kernel::ResourceType::new(namespace, name)?;
            let descriptor = dispatcher_b
                .resolve_resource_type(&child_type)
                .ok_or("missing runtime B child descriptor")?;
            application_b
                .show(descriptor, &runtime_auth_b, &child_id.to_string())
                .await
                .map_err(|error| {
                    format!("runtime B direct child observe {}: {error:?}", record.slot)
                })?;
        }
    }
    assert!(
        dispatcher_b
            .resolve_resource_type(&o3k_kernel::ResourceType::new("database", "instance")?)
            .is_some()
    );
    let verification = SigningKey::from_bytes(&[9; 32]).verifying_key();
    let composition_service_b = CompositionServiceAdapter::new(
        Arc::new(o3kd::native_adapters::CompositionResourceHandler {
            application: application_b.clone(),
            store: store_b.clone(),
            manifests: Arc::new(registry_b.clone()),
            delegation_keys: HashMap::from([(String::from("p12-6-test"), verification)]),
            dispatcher: dispatcher_b,
        }),
        "database-example",
        "database-controller",
    )
    .with_delegation_keys(
        "o3k-composition",
        HashMap::from([(String::from("p12-6-test"), verification)]),
    )
    .into_server();
    let composition_listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let composition_address_b = composition_listener_b.local_addr()?;
    let composition_tls_b = tls_server()?;
    let composition_task_b = tokio::spawn(async move {
        let mut builder = Server::builder().tls_config(composition_tls_b)?;
        builder
            .add_service(composition_service_b)
            .serve_with_incoming(TcpListenerStream::new(composition_listener_b))
            .await
    });
    let composition_client_b = Arc::new(
        GrpcCompositionClient::connect(&format!("https://{composition_address_b}"), tls_client()?)
            .await?,
    );
    let controller_service_b = o3k_service_sdk::ServiceControllerServer::new(
        DatabaseControllerHandler::new(composition_client_b, lifecycle()?),
        "database-example",
        "database",
        "p12-6-test-manifest",
        1,
    )
    .with_service_principal("database-controller")
    .with_delegation_recipient("o3k-composition")
    .with_delegation_keys(HashMap::from([("p12-6-test".to_owned(), verification)]))
    .into_service();
    let controller_listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let controller_address_b = controller_listener_b.local_addr()?;
    let controller_tls_b = tls_server()?;
    let controller_task_b = tokio::spawn(async move {
        let mut builder = Server::builder().tls_config(controller_tls_b)?;
        builder
            .add_service(controller_service_b)
            .serve_with_incoming(TcpListenerStream::new(controller_listener_b))
            .await
    });
    let controller_b = GrpcControllerAdapter::connect(
        &format!("https://{controller_address_b}"),
        tls_client()?,
        "database-example",
        "database",
        o3k_kernel::ServicePrincipal::new(
            o3k_kernel::PrincipalId::new_unchecked("database-controller"),
            "database-controller",
            "database",
        ),
        "p12-6-test-manifest",
        1,
    )
    .await?
    .with_delegation_signer("p12-6-test", SigningKey::from_bytes(&[9; 32]));
    assert_eq!(controller_b.session().service_id, "database-example");
    assert_eq!(controller_b.session().session_generation, 1);
    let recovered_scope =
        OwnershipScope::project(ScopeId::new("project-runtime-recovery")?, None, None);
    let recovered_resource_type = o3k_kernel::ResourceType::new("database", "instance")?;
    let recovered_reference = o3k_kernel::ResourceReference {
        resource_type: recovered_resource_type.clone(),
        resource_id: o3k_kernel::ResourceId::new(durable.0.to_string())?,
        generation: 1,
    };
    let recovered_context = o3k_kernel::OperationContext {
        request_id: uuid::Uuid::new_v4(),
        operation_id: durable.1,
        action: ActionId::new("database", "CreateInstance")?,
        service_id: "database-example".into(),
        owner_scope: recovered_scope.clone(),
        session_id: controller_b.session().session_id,
        session_generation: controller_b.session().session_generation,
        deadline_unix_ms: chrono::Utc::now().timestamp_millis() as u64 + 60_000,
        replay_identity: "runtime-recovery-create".into(),
        audit_correlation: "p12-6-runtime-recovery".into(),
    };
    let recovered_delegation = controller_b.issue_parent_delegation(
        &recovered_context,
        "user-runtime-recovery",
        &recovered_reference,
    )?;
    let recovered_outcome = controller_b
        .reconcile(o3k_kernel::ReconcileRequest {
            context: recovered_context,
            resource: o3k_kernel::ResourceSnapshot {
                reference: recovered_reference,
                desired_spec: serde_json::json!({
                    "engine": "test-engine",
                    "version": "1",
                    "storage_gb": 1
                }),
                known_status: None,
                owner_scope: recovered_scope,
            },
            delegation: Some(recovered_delegation),
        })
        .await;
    assert!(
        matches!(
            &recovered_outcome,
            o3k_kernel::ReconcileOutcome::Succeeded { .. }
        ),
        "recovered runtime outcome: {recovered_outcome:?}"
    );
    let parent_b = store_b.get_resource(durable.0).await?;
    assert_eq!(parent_b.id, durable.0);
    assert_eq!(parent_b.generation, 1);
    let records_after_reconcile = store_b.list_relationships(durable.0).await?;
    assert_eq!(records_after_reconcile, durable.2);
    assert!(records_after_reconcile.iter().all(|record| {
        record.child_resource_id.is_some()
            && record.child_operation_id.is_some()
            && record.state == "bound"
    }));
    drop(controller_b);
    controller_task_b.abort();
    composition_task_b.abort();
    drop(application_b);
    drop(store_b);
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(network_path);
    Ok(())
}

#[tokio::test]
async fn p12_6_independent_application_instances_converge_durable_slots()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = std::env::temp_dir().join(format!(
        "o3k-p12-6-app-race-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let parent = uuid::Uuid::new_v4();
    let record = ResourceRelationshipRecord {
        parent_resource_id: parent,
        parent_resource_type: "database:instance".into(),
        slot: "network-primary".into(),
        expected_child_resource_type: "network:network".into(),
        child_resource_id: None,
        ownership: "exclusive".into(),
        parent_operation_id: uuid::Uuid::new_v4(),
        child_operation_id: Some(uuid::Uuid::new_v4()),
        owner_scope: "project-independent-race".into(),
        state: "reserved".into(),
        fingerprint: "independent-application-race".into(),
    };
    let records = vec![
        record.clone(),
        ResourceRelationshipRecord {
            slot: "volume-data".into(),
            expected_child_resource_type: "volume:volume".into(),
            child_operation_id: Some(uuid::Uuid::new_v4()),
            fingerprint: "independent-application-volume".into(),
            ..record.clone()
        },
        ResourceRelationshipRecord {
            slot: "compute-primary".into(),
            expected_child_resource_type: "compute:server".into(),
            child_operation_id: Some(uuid::Uuid::new_v4()),
            fingerprint: "independent-application-compute".into(),
            ..record.clone()
        },
    ];
    let left_store = Arc::new(O3kStore::connect_sqlite_file(&path).await?);
    left_store
        .insert_resource(&ResourceRecord {
            id: parent,
            kind: "database:instance".into(),
            project_id: "project-independent-race".into(),
            generation: 1,
            observed_generation: 0,
            desired_state: "{}".into(),
            observed_state: "PROVISIONING".into(),
            provider_id: None,
        })
        .await?;
    let right_store = Arc::new(O3kStore::connect_sqlite_file(&path).await?);
    let shared_compute_provider = Arc::new(FakeComputeProvider::new());
    let left_compute = Arc::new(o3k_compute::ComputeService::new_for_test(
        left_store.clone(),
        shared_compute_provider.clone(),
    ));
    let right_compute = Arc::new(o3k_compute::ComputeService::new_for_test(
        right_store.clone(),
        shared_compute_provider,
    ));
    let left_network = Arc::new(
        o3k_network::NetworkService::open_for_test(
            std::env::temp_dir().join(format!("o3k-p12-6-app-left-{}", uuid::Uuid::new_v4())),
            left_store.clone(),
        )
        .await?,
    );
    let right_network = Arc::new(
        o3k_network::NetworkService::open_for_test(
            std::env::temp_dir().join(format!("o3k-p12-6-app-right-{}", uuid::Uuid::new_v4())),
            right_store.clone(),
        )
        .await?,
    );
    let left_application: Arc<dyn o3k_native_api::resource::ResourceApplication> =
        Arc::new(o3kd::native_adapters::GenericResourceApplication {
            compute: left_compute.clone(),
            image: None,
            public_address_workflow: None,
            network_service: left_network.clone(),
            store: left_store.clone(),
            storage_provider: Some(Arc::new(
                o3k_storage::testkit::InMemoryStorageProvider::default(),
            )),
            server: Arc::new(o3kd::native_adapters::ServerReaderAdapter {
                service: left_compute,
            }),
            network: Arc::new(o3kd::native_adapters::NetworkReaderAdapter {
                store: left_store.clone(),
                authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
            }),
            external_controllers: Arc::new(Default::default()),
            public_allocator: None,
            network_external_realm_id: None,
            attachment_workflow: None,
            metering: None,
        });
    let right_application: Arc<dyn o3k_native_api::resource::ResourceApplication> =
        Arc::new(o3kd::native_adapters::GenericResourceApplication {
            compute: right_compute.clone(),
            image: None,
            public_address_workflow: None,
            network_service: right_network.clone(),
            store: right_store.clone(),
            storage_provider: Some(Arc::new(
                o3k_storage::testkit::InMemoryStorageProvider::default(),
            )),
            server: Arc::new(o3kd::native_adapters::ServerReaderAdapter {
                service: right_compute,
            }),
            network: Arc::new(o3kd::native_adapters::NetworkReaderAdapter {
                store: right_store.clone(),
                authorizer: Arc::new(o3k_kernel::StaticAuthorizer::standard()),
            }),
            external_controllers: Arc::new(Default::default()),
            public_allocator: None,
            network_external_realm_id: None,
            attachment_workflow: None,
            metering: None,
        });
    let mut child_registry = ManifestRegistry::new();
    child_registry.seed_core()?;
    let child_dispatcher = Arc::new(
        o3k_native_api::resource::ResourceDispatcher::from_manifest_registry(&child_registry)
            .map_err(|error| format!("child dispatcher: {error:?}"))?,
    );
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let left_barrier = barrier.clone();
    let right_barrier = barrier.clone();
    let left_records = records.clone();
    let right_records = records.clone();
    let left_dispatcher = child_dispatcher.clone();
    let right_dispatcher = child_dispatcher;
    let left_task = tokio::spawn(async move {
        left_barrier.wait().await;
        for candidate in &left_records {
            if left_store.reserve_relationship(candidate).await.is_ok() {
                let current = left_store.get_relationship(parent, &candidate.slot).await?;
                if current.state == "bound" && current.child_resource_id.is_some() {
                    continue;
                }
                let (namespace, name) = candidate
                    .expected_child_resource_type
                    .split_once(':')
                    .ok_or("invalid child type")?;
                let child_type = o3k_kernel::ResourceType::new(namespace, name)?;
                let descriptor = left_dispatcher
                    .resolve_resource_type(&child_type)
                    .ok_or("missing child descriptor")?
                    .clone();
                let network_id = if candidate.slot == "compute-primary" {
                    await_bound_relationship(
                        &left_store,
                        parent,
                        "network-primary",
                        "network:network",
                    )
                    .await?
                    .child_resource_id
                    .ok_or("network-primary was bound without a child ID")?
                    .to_string()
                } else {
                    String::new()
                };
                if candidate.slot == "compute-primary" {
                    match left_network
                        .create_subnet_for_project(
                            "project-independent-race",
                            network_id.parse()?,
                            "independent-race-subnet".into(),
                            "192.0.2.0/24".into(),
                            None,
                            None,
                            None,
                        )
                        .await
                    {
                        Ok(_) | Err(o3k_network::NetworkError::Conflict) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                let spec = match candidate.slot.as_str() {
                    "network-primary" => serde_json::json!({"name": "independent-race-network"}),
                    "volume-data" => {
                        serde_json::json!({"size_bytes": 1, "volume_type": "standard"})
                    }
                    "compute-primary" => serde_json::json!({
                        "name": "independent-race-compute",
                        "image_id": "image-1",
                        "flavor_id": uuid::Uuid::from_u128(1),
                        "network_ids": [network_id],
                        "key_name": null
                    }),
                    _ => return Err("unknown child slot".into()),
                };
                let child_result = left_application
                    .create(
                        &descriptor,
                        &process_auth_context("project-independent-race"),
                        o3k_native_api::resource::ValidatedCreateRequest {
                            api_version: Some("o3k.io/v1".into()),
                            kind: Some(candidate.expected_child_resource_type.clone()),
                            spec: o3k_native_api::resource_contract::ValidatedSpec::from_external_contract(spec),
                        },
                        Some(&format!("independent-race:{}", candidate.slot)),
                    )
                    .await;
                let child = match child_result {
                    Ok(child) => child,
                    Err(o3k_native_api::resource::ResourceApplicationError::Conflict) => {
                        let _ = await_bound_relationship(
                            &left_store,
                            parent,
                            &candidate.slot,
                            &candidate.expected_child_resource_type,
                        )
                        .await?;
                        continue;
                    }
                    Err(error) => {
                        return Err(format!("child create {}: {error:?}", candidate.slot).into());
                    }
                };
                left_store
                    .bind_relationship(
                        parent,
                        &candidate.slot,
                        child.resource_id.ok_or("missing child id")?.parse()?,
                        child.operation_id.parse()?,
                    )
                    .await?;
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let right_task = tokio::spawn(async move {
        right_barrier.wait().await;
        for candidate in &right_records {
            // NetworkService's canonical lifecycle currently rejects a
            // duplicate name rather than returning an equivalent receipt.
            // Let the other independent application establish this slot,
            // then recover it from the durable relationship before continuing
            // with the remaining slots.  The relationship uniqueness race is
            // still exercised by both applications for every slot below.
            if candidate.slot == "network-primary" {
                let _ = right_store.reserve_relationship(candidate).await;
                let _ = await_bound_relationship(
                    &right_store,
                    parent,
                    "network-primary",
                    "network:network",
                )
                .await?;
                continue;
            }
            if right_store.reserve_relationship(candidate).await.is_ok() {
                let current = right_store
                    .get_relationship(parent, &candidate.slot)
                    .await?;
                if current.state == "bound" && current.child_resource_id.is_some() {
                    continue;
                }
                let (namespace, name) = candidate
                    .expected_child_resource_type
                    .split_once(':')
                    .ok_or("invalid child type")?;
                let child_type = o3k_kernel::ResourceType::new(namespace, name)?;
                let descriptor = right_dispatcher
                    .resolve_resource_type(&child_type)
                    .ok_or("missing child descriptor")?
                    .clone();
                let network_id = if candidate.slot == "compute-primary" {
                    await_bound_relationship(
                        &right_store,
                        parent,
                        "network-primary",
                        "network:network",
                    )
                    .await?
                    .child_resource_id
                    .ok_or("network-primary was bound without a child ID")?
                    .to_string()
                } else {
                    String::new()
                };
                if candidate.slot == "compute-primary" {
                    match right_network
                        .create_subnet_for_project(
                            "project-independent-race",
                            network_id.parse()?,
                            "independent-race-subnet".into(),
                            "192.0.2.0/24".into(),
                            None,
                            None,
                            None,
                        )
                        .await
                    {
                        Ok(_) | Err(o3k_network::NetworkError::Conflict) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                let spec = match candidate.slot.as_str() {
                    "network-primary" => serde_json::json!({"name": "independent-race-network"}),
                    "volume-data" => {
                        serde_json::json!({"size_bytes": 1, "volume_type": "standard"})
                    }
                    "compute-primary" => serde_json::json!({
                        "name": "independent-race-compute",
                        "image_id": "image-1",
                        "flavor_id": uuid::Uuid::from_u128(1),
                        "network_ids": [network_id],
                        "key_name": null
                    }),
                    _ => return Err("unknown child slot".into()),
                };
                let child_result = right_application
                    .create(
                        &descriptor,
                        &process_auth_context("project-independent-race"),
                        o3k_native_api::resource::ValidatedCreateRequest {
                            api_version: Some("o3k.io/v1".into()),
                            kind: Some(candidate.expected_child_resource_type.clone()),
                            spec: o3k_native_api::resource_contract::ValidatedSpec::from_external_contract(spec),
                        },
                        Some(&format!("independent-race:{}", candidate.slot)),
                    )
                    .await;
                let child = match child_result {
                    Ok(child) => child,
                    Err(o3k_native_api::resource::ResourceApplicationError::Conflict) => {
                        let _ = await_bound_relationship(
                            &right_store,
                            parent,
                            &candidate.slot,
                            &candidate.expected_child_resource_type,
                        )
                        .await?;
                        continue;
                    }
                    Err(error) => {
                        return Err(format!("child create {}: {error:?}", candidate.slot).into());
                    }
                };
                right_store
                    .bind_relationship(
                        parent,
                        &candidate.slot,
                        child.resource_id.ok_or("missing child id")?.parse()?,
                        child.operation_id.parse()?,
                    )
                    .await?;
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    barrier.wait().await;
    let (left, right) = tokio::join!(left_task, right_task);
    left??;
    right??;
    let final_store = O3kStore::connect_sqlite_file(&path).await?;
    let final_relationships = final_store.list_relationships(parent).await?;
    assert_eq!(final_relationships.len(), 3);
    assert_eq!(
        final_relationships
            .iter()
            .map(|relationship| relationship.slot.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        ["compute-primary", "network-primary", "volume-data"]
            .into_iter()
            .collect()
    );
    assert!(final_relationships.iter().all(|relationship| {
        relationship.child_resource_id.is_some()
            && relationship.child_operation_id.is_some()
            && relationship.state == "bound"
    }));
    assert_eq!(
        final_store
            .list_networks("project-independent-race")
            .await?
            .len(),
        1,
        "one canonical Network child per workflow"
    );
    assert_eq!(
        final_store
            .list_resources("project-independent-race", "volume")
            .await?
            .len(),
        1,
        "one canonical Volume child per workflow"
    );
    assert_eq!(
        final_store
            .list_resources("project-independent-race", "compute_instance")
            .await?
            .len(),
        1,
        "one canonical Compute child per workflow"
    );
    assert_eq!(
        final_relationships
            .iter()
            .filter_map(|relationship| relationship.child_operation_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3,
        "one stable child Operation per slot"
    );
    drop(final_store);
    let _ = std::fs::remove_file(path);
    Ok(())
}
