//! O3K Cloud Kernel: the foundational IAM, authorization, resource ownership,
//! service registry, and platform audit contracts shared across all first-class
//! O3K cloud services.
//!
//! Architectural invariants (ADR-0165, ADR-0166, SPEC-0020):
//! - Inward-facing core crate: must never depend on API, store, identity, provider,
//!   or framework crates.
//! - Canonical IAM & AuthContext: single authoritative `AuthContext` consumed by
//!   all application services.
//! - Service-neutral authorization: `Principal × Action × Resource × Context -> Allow/Deny`.
//! - Default-deny fail-closed policy model.
//! - Canonical runtime service authority with Keystone catalog projection.
//! - Canonical secret-safe audit events and bounded audit sink port.

pub mod action;
pub mod audit;
pub mod auth_context;
pub mod authorization;
pub mod building_block;
pub mod composition;
pub mod controller;
pub mod durable_audit;
pub mod envelope;
pub mod error;
pub mod location;
pub mod manifest;
pub mod metering;
pub mod operation;
pub mod principal;
pub mod quota;
pub mod registry;
pub mod resource;
pub mod scope;

pub use action::ActionId;
pub use audit::{
    AuditEvent, AuditOutcome, AuditSink, DurableAuditSink, DurableFnAuditSink, EventId,
    FnAuditSink, MemoryAuditSink, NoopAuditSink, RequiredAuditPublisher,
};
pub use auth_context::AuthContext;
pub use authorization::{
    ActionPolicy, AuthorizationDecision, AuthorizationRequest, Authorizer, DecisionReason,
    StaticAuthorizer,
};
pub use building_block::{
    BuildingBlock, BuildingBlockError, BuildingBlockState, DrainBlocker, DrainBlockerKind,
    MAX_BUILDING_BLOCK_REFS,
};
pub use composition::{
    CloudProfile, CloudProfileError, CompositionDrift, CompositionObservation, DriftKind,
    ServiceOwnershipMode, ServiceSelection,
};
pub use controller::{
    Controller, ControllerCapabilities, ControllerFailure, ControllerHealth,
    ControllerRegistration, ControllerSession, ControllerState, DelegationContext, DeleteRequest,
    FailureCategory, Observation, ObserveOutcome, ObserveRequest, OperationContext,
    ProtocolVersion, ReconcileOutcome, ReconcileRequest, RelationshipOwnership, ResourceReference,
    ResourceRelationship, ResourceSnapshot,
};
pub use durable_audit::{
    AuditQuery, DurableAuditPage, DurableAuditRepository, MAX_AUDIT_PAGE_SIZE,
};
pub use envelope::{ResourceEnvelope, ResourceMeta};
pub use error::KernelError;
pub use location::{
    AvailabilityDomain, BindingListCursor, BindingTarget, BindingTargetKind, FailureDomain,
    FailureDomainClass, LocationError, LocationRegistry, RegionDeclaration, TopologyBinding,
    TopologyError, TopologySnapshot, TopologyStore,
};
pub use manifest::{
    ControllerBinding, ControllerDescriptor, DependencyDescriptor, ManifestController,
    ManifestError, ManifestRegistry, NativeResourceMetaV1, NativeResourceV1, OpenStackApiSurface,
    OpenStackApiSurfaceV1, OpenStackCompatibilityProjection, OpenStackEndpointTemplate,
    OpenStackEndpointV1, OpenStackProjectionV1, QuotaDimension, QuotaDimensionDescriptor,
    RegisteredResourceType, ResourceScope, ResourceTypeDescriptor, ServiceDependency,
    ServiceHealth, ServiceLifecycleState, ServiceManifest, ServiceManifestV1,
};
pub use metering::{
    Clock, INGEST_BUCKET_WIDTH_MS, LifecycleMeteringObserver, MAX_USAGE_AGGREGATE_ROWS,
    MAX_USAGE_BUCKETS, MAX_USAGE_METERS, MAX_USAGE_RANGE_MS, MAX_USAGE_SERIES, METER_CATALOG,
    MeterAggregateRecord, MeterAggregation, MeterDefinition, MeterIntervalRecord, MeterObservation,
    MeterUnit, MeterUsage, MeterUsageReport, MeteringRepository, SystemClock, UsageBucket,
    UsageGranularity, UsageQuery, UsageStatus, bucket_contributions, format_quantity_millis,
    meter_definition,
};
pub use operation::{Operation, OperationState};
pub use principal::{Principal, PrincipalId, PrincipalKind, ServicePrincipal, UserPrincipal};
pub use quota::{
    LimitKey, LimitValue, QuotaDecision, Reservation, ReservationId, ReservationState,
    ResourceAmount, Usage,
};
pub use registry::{
    ApiSurface, EndpointTemplate, KernelRegistry, KeystoneCatalogEndpoint, KeystoneCatalogService,
    ServiceDescriptor, ServiceId, ServiceNamespace, ServiceOwnership,
};
pub use resource::{ResourceId, ResourceTarget, ResourceType};
pub use scope::{OwnershipScope, ScopeId, ScopeKind};

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user_context(user_id: &str, project_id: &str) -> AuthContext {
        let principal_id = PrincipalId::new_unchecked(user_id);
        let user = UserPrincipal::new(principal_id, "test-user", Some("default".to_string()));
        let scope_id = ScopeId::new_unchecked(project_id);
        let scope = OwnershipScope::project(
            scope_id,
            Some("test-project".to_string()),
            Some("default".to_string()),
        );
        AuthContext::new(
            Principal::User(user),
            scope,
            vec!["member".to_string(), "reader".to_string()],
            1700000000,
            1700003600,
            "audit-12345",
            "req-67890",
            None,
        )
    }

    fn test_service_context(service_id: &str, project_id: &str) -> AuthContext {
        let principal_id = PrincipalId::new_unchecked(service_id);
        let service = ServicePrincipal::new(principal_id, "cinder", "volumev3");
        let scope_id = ScopeId::new_unchecked(project_id);
        let scope = OwnershipScope::project(
            scope_id,
            Some("service-project".to_string()),
            Some("default".to_string()),
        );
        AuthContext::new(
            Principal::Service(service.clone()),
            scope,
            vec!["service".to_string(), "admin".to_string()],
            1700000000,
            1700003600,
            "audit-67890",
            "req-12345",
            Some(service),
        )
    }

    fn test_system_operator_context() -> AuthContext {
        let principal = UserPrincipal::new(PrincipalId::new_unchecked("usr-1"), "test-user", None);
        AuthContext::new(
            Principal::User(principal),
            OwnershipScope::new(
                ScopeId::new_unchecked("system"),
                ScopeKind::System,
                Some("System".to_owned()),
                None,
            ),
            vec!["operator".to_owned()],
            1700000000,
            1700003600,
            "audit-system",
            "req-system",
            None,
        )
    }

    #[test]
    fn authorizer_standard_allow_owner() -> Result<(), KernelError> {
        let auth = StaticAuthorizer::standard();
        let ctx = test_user_context("usr-1", "proj-1");
        let target = ResourceTarget::instance(
            ResourceType::new("compute", "server")?,
            ResourceId::new("srv-1")?,
            Some(ScopeId::new("proj-1")?),
        );
        let req = AuthorizationRequest {
            auth_context: &ctx,
            action: ActionId::new("compute", "ReadServer")?,
            resource_target: target,
        };
        let decision = auth.authorize(&req);
        assert!(decision.is_allowed());
        assert_eq!(decision.reason(), &DecisionReason::Allowed);
        Ok(())
    }

    #[test]
    fn operator_action_requires_system_user_scope_and_operator_role() -> Result<(), KernelError> {
        let auth = StaticAuthorizer::standard();
        let target = ResourceTarget::collection(
            ResourceType::new("operator", "profile")?,
            Some(ScopeId::new("system")?),
        );
        let system = test_system_operator_context();
        let request = AuthorizationRequest {
            auth_context: &system,
            action: ActionId::new("operator", "ReadProfile")?,
            resource_target: target.clone(),
        };
        assert!(auth.authorize(&request).is_allowed());

        let project = test_user_context("usr-1", "proj-1");
        let request = AuthorizationRequest {
            auth_context: &project,
            action: ActionId::new("operator", "ReadProfile")?,
            resource_target: target.clone(),
        };
        assert_eq!(
            auth.authorize(&request).reason(),
            &DecisionReason::ScopeMismatch
        );

        let service = test_service_context("svc-1", "system");
        let request = AuthorizationRequest {
            auth_context: &service,
            action: ActionId::new("operator", "ReadProfile")?,
            resource_target: target,
        };
        assert_eq!(
            auth.authorize(&request).reason(),
            &DecisionReason::UnsupportedPrincipal
        );
        Ok(())
    }

    fn test_system_user_context_without_operator_role() -> AuthContext {
        let principal = UserPrincipal::new(PrincipalId::new_unchecked("usr-2"), "plain-user", None);
        AuthContext::new(
            Principal::User(principal),
            OwnershipScope::new(
                ScopeId::new_unchecked("system"),
                ScopeKind::System,
                Some("System".to_owned()),
                None,
            ),
            vec![],
            1700000000,
            1700003600,
            "audit-plain",
            "req-plain",
            None,
        )
    }

    #[test]
    fn governance_actions_require_system_scope_and_operator_role() -> Result<(), KernelError> {
        let auth = StaticAuthorizer::standard();
        let target = ResourceTarget::collection(
            ResourceType::new("governance", "governance")?,
            Some(ScopeId::new("system")?),
        );
        let system = test_system_operator_context();

        for action in [
            ActionId::new("governance", "ReadGovernance")?,
            ActionId::new("governance", "ManageAssignment")?,
            ActionId::new("governance", "ManageOperatorAssignment")?,
        ] {
            let request = AuthorizationRequest {
                auth_context: &system,
                action: action.clone(),
                resource_target: target.clone(),
            };
            assert!(
                auth.authorize(&request).is_allowed(),
                "system operator must satisfy {action}"
            );

            // A project-scoped caller, even one with an `operator` role string
            // inside the project, must never satisfy a governance action.
            let mut project = test_user_context("usr-1", "proj-1");
            project = AuthContext::new(
                project.principal().clone(),
                project.effective_scope().clone(),
                vec!["operator".to_owned()],
                1700000000,
                1700003600,
                "audit-project",
                "req-project",
                None,
            );
            let request = AuthorizationRequest {
                auth_context: &project,
                action: action.clone(),
                resource_target: target.clone(),
            };
            assert_eq!(
                auth.authorize(&request).reason(),
                &DecisionReason::ScopeMismatch,
                "project scope must not satisfy {action}"
            );

            // System scope without the durable operator role is unauthorized.
            let no_role = test_system_user_context_without_operator_role();
            let request = AuthorizationRequest {
                auth_context: &no_role,
                action: action.clone(),
                resource_target: target.clone(),
            };
            assert_eq!(
                auth.authorize(&request).reason(),
                &DecisionReason::UnauthorizedRole,
                "system scope without operator role must not satisfy {action}"
            );

            let service = test_service_context("svc-1", "system");
            let request = AuthorizationRequest {
                auth_context: &service,
                action,
                resource_target: target.clone(),
            };
            assert_eq!(
                auth.authorize(&request).reason(),
                &DecisionReason::UnsupportedPrincipal
            );
        }
        Ok(())
    }

    #[test]
    fn governance_capabilities_expose_canonical_policies() -> Result<(), KernelError> {
        let auth = StaticAuthorizer::standard();
        let capabilities = auth.capabilities();
        assert!(!capabilities.is_empty());
        let expected_resource_type = ResourceType::new("governance", "governance")?;
        for action in [
            "ReadGovernance",
            "ManageAssignment",
            "ManageOperatorAssignment",
        ] {
            let expected = ActionId::new_unchecked("governance", action);
            let mut matched = false;
            for policy in &capabilities {
                if policy.action == expected {
                    matched = true;
                    assert_eq!(policy.expected_resource_type, expected_resource_type);
                    assert_eq!(policy.required_roles, vec!["operator".to_owned()]);
                }
            }
            assert!(matched, "missing capability for governance:{action}");
        }
        Ok(())
    }

    #[test]
    fn governance_namespace_is_system_gated_for_any_action() -> Result<(), KernelError> {
        let mut auth = StaticAuthorizer::standard();
        // Register a hypothetical future governance action that only declares
        // the operator role, to prove the namespace scope gate cannot be
        // accidentally omitted from new governance actions.
        auth.register(ActionPolicy {
            action: ActionId::new("governance", "FutureAdminAction")?,
            expected_resource_type: ResourceType::new("governance", "governance")?,
            accepted_principals: vec![PrincipalKind::User],
            require_ownership: false,
            required_roles: vec!["operator".to_owned()],
        });
        let target = ResourceTarget::collection(
            ResourceType::new("governance", "governance")?,
            Some(ScopeId::new("system")?),
        );
        // A project-scoped caller with an `operator` role string is denied.
        let mut project = test_user_context("usr-1", "proj-1");
        project = AuthContext::new(
            project.principal().clone(),
            project.effective_scope().clone(),
            vec!["operator".to_owned()],
            1700000000,
            1700003600,
            "audit-future",
            "req-future",
            None,
        );
        let request = AuthorizationRequest {
            auth_context: &project,
            action: ActionId::new("governance", "FutureAdminAction")?,
            resource_target: target.clone(),
        };
        assert_eq!(
            auth.authorize(&request).reason(),
            &DecisionReason::ScopeMismatch
        );
        // A system-scoped operator is allowed.
        let system = test_system_operator_context();
        let request = AuthorizationRequest {
            auth_context: &system,
            action: ActionId::new("governance", "FutureAdminAction")?,
            resource_target: target,
        };
        assert!(auth.authorize(&request).is_allowed());
        Ok(())
    }

    #[test]
    fn topology_read_is_open_to_any_authenticated_principal() -> Result<(), KernelError> {
        let auth = StaticAuthorizer::standard();
        let target =
            ResourceTarget::collection(ResourceType::new("topology", "failure_domain")?, None);
        // A plain project-scoped tenant token satisfies the read action.
        let project = test_user_context("usr-1", "proj-1");
        let request = AuthorizationRequest {
            auth_context: &project,
            action: ActionId::new("topology", "ReadTopology")?,
            resource_target: target.clone(),
        };
        assert!(auth.authorize(&request).is_allowed());
        // So does a service principal.
        let service = test_service_context("svc-1", "proj-1");
        let request = AuthorizationRequest {
            auth_context: &service,
            action: ActionId::new("topology", "ReadTopology")?,
            resource_target: target,
        };
        assert!(auth.authorize(&request).is_allowed());
        Ok(())
    }

    #[test]
    fn topology_manage_requires_system_scope_and_operator_role() -> Result<(), KernelError> {
        let auth = StaticAuthorizer::standard();
        let target =
            ResourceTarget::collection(ResourceType::new("topology", "failure_domain")?, None);
        let system = test_system_operator_context();
        let request = AuthorizationRequest {
            auth_context: &system,
            action: ActionId::new("topology", "ManageTopology")?,
            resource_target: target.clone(),
        };
        assert!(auth.authorize(&request).is_allowed());

        // A project-scoped caller with an `operator` role string must never
        // satisfy topology administration.
        let mut project = test_user_context("usr-1", "proj-1");
        project = AuthContext::new(
            project.principal().clone(),
            project.effective_scope().clone(),
            vec!["operator".to_owned()],
            1700000000,
            1700003600,
            "audit-topology-project",
            "req-topology-project",
            None,
        );
        let request = AuthorizationRequest {
            auth_context: &project,
            action: ActionId::new("topology", "ManageTopology")?,
            resource_target: target.clone(),
        };
        assert_eq!(
            auth.authorize(&request).reason(),
            &DecisionReason::ScopeMismatch
        );

        // System scope without the durable operator role is unauthorized.
        let no_role = test_system_user_context_without_operator_role();
        let request = AuthorizationRequest {
            auth_context: &no_role,
            action: ActionId::new("topology", "ManageTopology")?,
            resource_target: target.clone(),
        };
        assert_eq!(
            auth.authorize(&request).reason(),
            &DecisionReason::ScopeMismatch
        );
        Ok(())
    }

    #[test]
    fn topology_namespace_is_system_gated_for_future_mutation_actions() -> Result<(), KernelError> {
        let mut auth = StaticAuthorizer::standard();
        // Register a hypothetical future topology mutation action that only
        // declares the operator role, to prove the namespace scope gate cannot
        // be accidentally omitted from new topology mutation actions.
        auth.register(ActionPolicy {
            action: ActionId::new("topology", "FutureManageAction")?,
            expected_resource_type: ResourceType::new("topology", "failure_domain")?,
            accepted_principals: vec![PrincipalKind::User],
            require_ownership: false,
            required_roles: vec!["operator".to_owned()],
        });
        let target =
            ResourceTarget::collection(ResourceType::new("topology", "failure_domain")?, None);
        // A project-scoped caller with an `operator` role string is denied.
        let mut project = test_user_context("usr-1", "proj-1");
        project = AuthContext::new(
            project.principal().clone(),
            project.effective_scope().clone(),
            vec!["operator".to_owned()],
            1700000000,
            1700003600,
            "audit-topology-future",
            "req-topology-future",
            None,
        );
        let request = AuthorizationRequest {
            auth_context: &project,
            action: ActionId::new("topology", "FutureManageAction")?,
            resource_target: target.clone(),
        };
        assert_eq!(
            auth.authorize(&request).reason(),
            &DecisionReason::ScopeMismatch
        );
        // A system-scoped operator is allowed.
        let system = test_system_operator_context();
        let request = AuthorizationRequest {
            auth_context: &system,
            action: ActionId::new("topology", "FutureManageAction")?,
            resource_target: target,
        };
        assert!(auth.authorize(&request).is_allowed());
        Ok(())
    }

    #[test]
    fn authorizer_standard_deny_cross_project() -> Result<(), KernelError> {
        let auth = StaticAuthorizer::standard();
        let ctx = test_user_context("usr-1", "proj-1");
        let target = ResourceTarget::instance(
            ResourceType::new("compute", "server")?,
            ResourceId::new("srv-1")?,
            Some(ScopeId::new("proj-2")?),
        );
        let req = AuthorizationRequest {
            auth_context: &ctx,
            action: ActionId::new("compute", "ReadServer")?,
            resource_target: target,
        };
        let decision = auth.authorize(&req);
        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), &DecisionReason::ScopeMismatch);
        Ok(())
    }

    #[test]
    fn authorizer_deny_unknown_action() -> Result<(), KernelError> {
        let auth = StaticAuthorizer::standard();
        let ctx = test_user_context("usr-1", "proj-1");
        let target = ResourceTarget::collection(
            ResourceType::new("compute", "server")?,
            Some(ScopeId::new("proj-1")?),
        );
        let req = AuthorizationRequest {
            auth_context: &ctx,
            action: ActionId::new("compute", "NonExistentAction")?,
            resource_target: target,
        };
        let decision = auth.authorize(&req);
        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), &DecisionReason::UnknownAction);
        Ok(())
    }

    #[test]
    fn authorizer_deny_unknown_resource_type() -> Result<(), KernelError> {
        let auth = StaticAuthorizer::standard();
        let ctx = test_user_context("usr-1", "proj-1");
        let target = ResourceTarget::collection(
            ResourceType::new("database", "instance")?,
            Some(ScopeId::new("proj-1")?),
        );
        let req = AuthorizationRequest {
            auth_context: &ctx,
            action: ActionId::new("compute", "CreateServer")?,
            resource_target: target,
        };
        let decision = auth.authorize(&req);
        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), &DecisionReason::UnknownResourceType);
        Ok(())
    }

    #[test]
    fn authorizer_deny_unsupported_principal() -> Result<(), KernelError> {
        let mut auth = StaticAuthorizer::empty();
        auth.register(ActionPolicy {
            action: ActionId::new("compute", "AdminAction")?,
            expected_resource_type: ResourceType::new("compute", "server")?,
            accepted_principals: vec![PrincipalKind::Service],
            require_ownership: false,
            required_roles: vec![],
        });

        let user_ctx = test_user_context("usr-1", "proj-1");
        let target = ResourceTarget::collection(ResourceType::new("compute", "server")?, None);
        let req = AuthorizationRequest {
            auth_context: &user_ctx,
            action: ActionId::new("compute", "AdminAction")?,
            resource_target: target,
        };
        let decision = auth.authorize(&req);
        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), &DecisionReason::UnsupportedPrincipal);
        Ok(())
    }

    #[test]
    fn auth_context_contains_no_raw_tokens_or_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let ctx = test_user_context("usr-1", "proj-1");
        let serialized = serde_json::to_string(&ctx)?;
        assert!(!serialized.contains("token_id"));
        assert!(!serialized.contains("x-auth-token"));
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("secret"));
        Ok(())
    }

    #[test]
    fn registry_standard_contains_expected_services() -> Result<(), KernelError> {
        let reg =
            KernelRegistry::standard("http://127.0.0.1:18080", Some("http://127.0.0.1:18776"));
        assert!(reg.service_by_id(&ServiceId::new("identity")?).is_some());
        assert!(reg.service_by_id(&ServiceId::new("image")?).is_some());
        assert!(reg.service_by_id(&ServiceId::new("network")?).is_some());
        assert!(reg.service_by_id(&ServiceId::new("compute")?).is_some());
        assert!(reg.service_by_id(&ServiceId::new("placement")?).is_some());
        assert!(reg.service_by_id(&ServiceId::new("cinder")?).is_some());

        let cinder = reg
            .service_by_id(&ServiceId::new("cinder")?)
            .ok_or_else(|| KernelError::InvalidServiceId("missing cinder service".to_owned()))?;
        assert_eq!(cinder.ownership, ServiceOwnership::ExternalHosted);

        let compute = reg
            .service_by_id(&ServiceId::new("compute")?)
            .ok_or_else(|| KernelError::InvalidServiceId("missing compute service".to_owned()))?;
        assert_eq!(compute.ownership, ServiceOwnership::O3kImplemented);

        Ok(())
    }

    #[test]
    fn registry_keystone_catalog_projection() -> Result<(), KernelError> {
        let reg =
            KernelRegistry::standard("http://127.0.0.1:18080", Some("http://127.0.0.1:18776"));
        let catalog = reg.project_keystone_catalog("project-abc");

        assert_eq!(catalog.len(), 6);
        let service_types: Vec<&str> = catalog.iter().map(|s| s.service_type.as_str()).collect();
        assert_eq!(
            service_types,
            vec![
                "compute",
                "identity",
                "image",
                "network",
                "placement",
                "volumev3"
            ]
        );

        let compute_entry = catalog
            .iter()
            .find(|s| s.service_type == "compute")
            .ok_or_else(|| {
                KernelError::InvalidServiceId("missing compute in catalog".to_owned())
            })?;
        let compute_pub = compute_entry
            .endpoints
            .iter()
            .find(|e| e.interface == "public")
            .ok_or_else(|| {
                KernelError::InvalidServiceId("missing public compute endpoint".to_owned())
            })?;
        assert_eq!(compute_pub.url, "http://127.0.0.1:18080/v2.1/project-abc");

        let image_entry = catalog
            .iter()
            .find(|s| s.service_type == "image")
            .ok_or_else(|| KernelError::InvalidServiceId("missing image in catalog".to_owned()))?;
        let image_pub = image_entry
            .endpoints
            .iter()
            .find(|e| e.interface == "public")
            .ok_or_else(|| {
                KernelError::InvalidServiceId("missing public image endpoint".to_owned())
            })?;
        assert_eq!(image_pub.url, "http://127.0.0.1:18080/");

        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn bound_registry_catalog_follows_canonical_readiness() {
        let mut manifests = ManifestRegistry::new();
        manifests.seed_core().expect("core manifests");
        manifests
            .register_external_service("database", "database", ServiceLifecycleState::Ready)
            .expect("database identity");
        manifests
            .register_projection(OpenStackCompatibilityProjection {
                service_id: "database".to_owned(),
                service_type: "database".to_owned(),
                service_name: Some("database".to_owned()),
                enabled: true,
                api_surfaces: vec![],
                endpoints: vec![OpenStackEndpointTemplate {
                    interface: "public".to_owned(),
                    region: "RegionOne".to_owned(),
                    url_template: "http://127.0.0.1:18080/database/{project_id}".to_owned(),
                    enabled: true,
                }],
                capabilities: vec![],
                evidence_profile: None,
            })
            .expect("database projection");
        let template = KernelRegistry::standard("http://127.0.0.1:18080", None);
        template
            .register_projections_into(&mut manifests)
            .expect("linked projections");
        manifests
            .register_in_process_controller("identity", true, None)
            .expect("identity ready");
        manifests
            .register_in_process_controller("compute", false, Some("provider unavailable".into()))
            .expect("compute not ready");
        let shared = std::sync::Arc::new(std::sync::RwLock::new(manifests));
        let facade = template.with_canonical_registry(shared);
        let catalog = facade.project_keystone_catalog("project-abc");
        assert!(catalog.iter().any(|service| service.id == "identity"));
        assert!(!catalog.iter().any(|service| service.id == "compute"));
        assert!(catalog.iter().any(|service| service.id == "database"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn configured_but_unavailable_external_cinder_is_not_advertised() {
        let mut manifests = ManifestRegistry::new();
        manifests
            .register_external_service("cinder", "cinder", ServiceLifecycleState::NotReady)
            .expect("cinder identity");
        manifests
            .register_projection(OpenStackCompatibilityProjection {
                service_id: "cinder".to_owned(),
                service_type: "volumev3".to_owned(),
                service_name: Some("cinder".to_owned()),
                enabled: true,
                api_surfaces: vec![],
                endpoints: vec![OpenStackEndpointTemplate {
                    interface: "public".to_owned(),
                    region: "RegionOne".to_owned(),
                    url_template: "http://127.0.0.1:18776/v3/{project_id}".to_owned(),
                    enabled: true,
                }],
                capabilities: vec![],
                evidence_profile: None,
            })
            .expect("cinder projection");
        let shared = std::sync::Arc::new(std::sync::RwLock::new(manifests));
        let facade = KernelRegistry::standard("http://127.0.0.1:18080", None)
            .with_canonical_registry(shared);
        let catalog = facade.project_keystone_catalog("project-abc");
        assert!(
            !catalog
                .iter()
                .any(|service| service.service_type == "volumev3")
        );
    }

    #[test]
    fn audit_event_lifecycle_and_sink() -> Result<(), Box<dyn std::error::Error>> {
        let sink = MemoryAuditSink::new();
        let ctx = test_user_context("usr-1", "proj-1");

        let event = AuditEvent::from_auth(
            &ctx,
            ServiceNamespace::new("compute")?,
            ActionId::new("compute", "CreateServer")?,
            AuditOutcome::Succeeded,
        )
        .with_resource(
            ResourceType::new("compute", "server")?,
            Some(ResourceId::new("srv-uuid-1")?),
            Some(ctx.effective_scope().clone()),
        )
        .with_decision(AuthorizationDecision::Allow)
        .with_operation(uuid::Uuid::now_v7());

        sink.record(&event);

        let recorded = sink.events();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].action.to_string(), "compute:CreateServer");
        assert_eq!(recorded[0].outcome, AuditOutcome::Succeeded);
        assert_eq!(recorded[0].request_id, "req-67890");
        assert_eq!(recorded[0].audit_id, "audit-12345");
        assert_eq!(recorded[0].principal_id.to_string(), "usr-1");

        // Verify secret redaction: serialization must never contain raw passwords/keys/tokens
        let json = serde_json::to_string(&recorded[0])?;
        assert!(!json.contains("password"));
        assert!(!json.contains("token"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("chap"));

        // Service principal test
        let svc_ctx = test_service_context("cinder-svc", "proj-1");
        assert_eq!(svc_ctx.principal().kind(), PrincipalKind::Service);
        assert_eq!(
            svc_ctx.service_principal().map(|s| s.name()),
            Some("cinder")
        );

        Ok(())
    }
}
