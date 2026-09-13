use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    action::ActionId,
    auth_context::AuthContext,
    principal::PrincipalKind,
    resource::{ResourceTarget, ResourceType},
    scope::ScopeKind,
};

/// Authorization request presented to the Cloud Kernel authorizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest<'a> {
    pub auth_context: &'a AuthContext,
    pub action: ActionId,
    pub resource_target: ResourceTarget,
}

/// Stable reason for authorization decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReason {
    Allowed,
    UnknownAction,
    UnknownResourceType,
    ScopeMismatch,
    MissingOwnership,
    UnsupportedPrincipal,
    UnauthorizedRole,
    ExpiredContext,
}

/// The result of evaluating an authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum AuthorizationDecision {
    Allow,
    Deny { reason: DecisionReason },
}

impl AuthorizationDecision {
    /// Helper to check if the decision is `Allow`.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns the decision reason.
    #[must_use]
    pub fn reason(&self) -> &DecisionReason {
        match self {
            Self::Allow => &DecisionReason::Allowed,
            Self::Deny { reason } => reason,
        }
    }
}

/// Service-neutral authorization port.
pub trait Authorizer: Send + Sync {
    /// Evaluates an authorization request and returns a decision.
    fn authorize(&self, request: &AuthorizationRequest<'_>) -> AuthorizationDecision;

    /// Returns the canonical action policies known to this authorizer.
    ///
    /// System/operator governance clients use this to reason about
    /// authorization without inferring permissions from role display names.
    /// Authorizers that do not expose a static inventory return an empty list.
    fn capabilities(&self) -> Vec<ActionPolicy> {
        Vec::new()
    }
}

/// Static policy definition for an action in the authorization inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPolicy {
    pub action: ActionId,
    pub expected_resource_type: ResourceType,
    pub accepted_principals: Vec<PrincipalKind>,
    pub require_ownership: bool,
    pub required_roles: Vec<String>,
}

/// Default Cloud Kernel static authorizer implementing fail-closed policy evaluation.
#[derive(Debug, Clone)]
pub struct StaticAuthorizer {
    policies: HashMap<ActionId, ActionPolicy>,
}

impl Default for StaticAuthorizer {
    fn default() -> Self {
        Self::standard()
    }
}

impl StaticAuthorizer {
    /// Creates an authorizer with the standard built-in TestLab action inventory.
    #[must_use]
    pub fn standard() -> Self {
        let mut authorizer = Self {
            policies: HashMap::new(),
        };
        authorizer.register_standard_actions();
        authorizer
    }

    /// Creates an empty static authorizer (will deny all actions until policies are added).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    /// Registers a policy for an action.
    pub fn register(&mut self, policy: ActionPolicy) {
        self.policies.insert(policy.action.clone(), policy);
    }

    fn register_standard_actions(&mut self) {
        // Standard action inventory helper
        let mut reg = |ns: &str, act: &str, res_ns: &str, res_name: &str, require_owner: bool| {
            if let (Ok(action), Ok(expected_resource_type)) =
                (ActionId::new(ns, act), ResourceType::new(res_ns, res_name))
            {
                self.policies.insert(
                    action.clone(),
                    ActionPolicy {
                        action,
                        expected_resource_type,
                        accepted_principals: vec![PrincipalKind::User, PrincipalKind::Service],
                        require_ownership: require_owner,
                        required_roles: vec![],
                    },
                );
            }
        };

        // Identity
        reg("identity", "IssueToken", "identity", "token", false);
        reg("identity", "ValidateToken", "identity", "token", false);
        reg("identity", "RevokeToken", "identity", "token", false);

        // Native quota projection: tenant reads are owner-scoped; administration
        // is a distinct system/operator action and never inferred from routes.
        reg("quota", "ReadQuota", "quota", "quota", true);
        reg("quota", "ManageQuota", "quota", "quota", false);

        // Native topology authority (P15.1, ADR-0184/SPEC-0047): reads are
        // open to any authenticated principal; administration is a distinct
        // system/operator action, gated to System scope below exactly like
        // quota:ManageQuota.
        reg(
            "topology",
            "ReadTopology",
            "topology",
            "failure_domain",
            false,
        );
        reg(
            "topology",
            "ManageTopology",
            "topology",
            "failure_domain",
            false,
        );

        // Cloud Kernel operation visibility is explicitly permissioned; the
        // reader still applies durable owner-scope concealment below this
        // policy check.
        reg(
            "operation",
            "ReadOperation",
            "operation",
            "operation",
            false,
        );

        // Declarative CloudProfile composition is a system-scoped operator
        // concern; observed manifests and Catalog remain separate authorities.
        reg(
            "composition",
            "ReadCloudProfile",
            "composition",
            "cloud_profile",
            false,
        );
        reg(
            "composition",
            "ManageCloudProfile",
            "composition",
            "cloud_profile",
            false,
        );

        // Image
        reg("image", "ListImages", "image", "image", true);
        reg("image", "CreateImage", "image", "image", true);
        reg("image", "ReadImage", "image", "image", true);
        reg("image", "DeleteImage", "image", "image", true);
        reg("image", "UploadImage", "image", "image", true);
        reg("image", "DownloadImage", "image", "image", true);

        // Network
        reg("network", "ListNetworks", "network", "network", true);
        reg("network", "CreateNetwork", "network", "network", true);
        reg("network", "ReadNetwork", "network", "network", true);
        reg("network", "UpdateNetwork", "network", "network", true);
        reg("network", "DeleteNetwork", "network", "network", true);
        reg("network", "ListSubnets", "network", "subnet", true);
        reg("network", "CreateSubnet", "network", "subnet", true);
        reg("network", "ReadSubnet", "network", "subnet", true);
        reg("network", "UpdateSubnet", "network", "subnet", true);
        reg("network", "DeleteSubnet", "network", "subnet", true);
        reg("network", "ListPorts", "network", "port", true);
        reg("network", "CreatePort", "network", "port", true);
        reg("network", "ReadPort", "network", "port", true);
        reg("network", "DeletePort", "network", "port", true);
        reg(
            "network",
            "ListSecurityGroups",
            "network",
            "security_group",
            true,
        );
        reg(
            "network",
            "ReadSecurityGroup",
            "network",
            "security_group",
            true,
        );
        reg(
            "network",
            "CreateSecurityGroup",
            "network",
            "security_group",
            true,
        );
        reg(
            "network",
            "DeleteSecurityGroup",
            "network",
            "security_group",
            true,
        );
        reg(
            "network",
            "ListSecurityGroupRules",
            "network",
            "security_group_rule",
            true,
        );
        reg(
            "network",
            "ReadSecurityGroupRule",
            "network",
            "security_group_rule",
            true,
        );
        reg(
            "network",
            "CreateSecurityGroupRule",
            "network",
            "security_group_rule",
            true,
        );
        reg(
            "network",
            "DeleteSecurityGroupRule",
            "network",
            "security_group_rule",
            true,
        );
        reg("network", "ListRouters", "network", "router", true);
        reg("network", "ReadRouter", "network", "router", true);
        reg("network", "CreateRouter", "network", "router", true);
        reg("network", "DeleteRouter", "network", "router", true);
        reg(
            "network",
            "ListRouterInterfaces",
            "network",
            "router_interface",
            true,
        );
        reg(
            "network",
            "ReadRouterInterface",
            "network",
            "router_interface",
            true,
        );
        reg(
            "network",
            "CreateRouterInterface",
            "network",
            "router_interface",
            true,
        );
        reg(
            "network",
            "DeleteRouterInterface",
            "network",
            "router_interface",
            true,
        );
        // Public addresses are the native projection of the bounded routed
        // fabric allocator. Keep their authorization distinct from address
        // realms and endpoints so ownership is checked on the allocation.
        reg(
            "network",
            "ListAddressAllocations",
            "network",
            "floating_ip",
            true,
        );
        reg(
            "network",
            "ReadAddressAllocation",
            "network",
            "floating_ip",
            true,
        );
        reg("network", "AllocateAddress", "network", "floating_ip", true);
        reg("network", "ReleaseAddress", "network", "floating_ip", true);
        reg("network", "ListExtensions", "network", "extension", false);

        // Compute
        reg("compute", "ListFlavors", "compute", "flavor", true);
        reg("compute", "CreateFlavor", "compute", "flavor", true);
        reg("compute", "ReadFlavor", "compute", "flavor", true);
        reg("compute", "DeleteFlavor", "compute", "flavor", true);
        reg("compute", "ListKeypairs", "compute", "keypair", true);
        reg("compute", "ImportKeypair", "compute", "keypair", true);
        reg("compute", "ReadKeypair", "compute", "keypair", true);
        reg("compute", "DeleteKeypair", "compute", "keypair", true);
        reg("compute", "ListServers", "compute", "server", true);
        reg("compute", "CreateServer", "compute", "server", true);
        reg("compute", "ReadServer", "compute", "server", true);
        reg("compute", "UpdateServer", "compute", "server", true);
        reg("compute", "DeleteServer", "compute", "server", true);
        reg("compute", "StopServer", "compute", "server", true);
        reg("compute", "StartServer", "compute", "server", true);
        reg("compute", "RebootServer", "compute", "server", true);
        reg("compute", "ReadConsole", "compute", "server", true);

        // Volume
        reg(
            "volume",
            "ListVolumeAttachments",
            "volume",
            "volume_attachment",
            true,
        );
        reg(
            "volume",
            "AttachVolume",
            "volume",
            "volume_attachment",
            true,
        );
        reg(
            "volume",
            "ReadVolumeAttachment",
            "volume",
            "volume_attachment",
            true,
        );
        reg(
            "volume",
            "DetachVolume",
            "volume",
            "volume_attachment",
            true,
        );
        // P12.2 — Native volume read actions
        reg("volume", "ListVolumes", "volume", "volume", true);
        reg("volume", "CreateVolume", "volume", "volume", true);
        reg("volume", "ReadVolume", "volume", "volume", true);
        reg("volume", "DeleteVolume", "volume", "volume", true);
        // P12.2 — Native network read actions (canonical O3K resources)
        reg(
            "network",
            "ListAddressRealms",
            "network",
            "address_realm",
            true,
        );
        reg(
            "network",
            "ReadAddressRealm",
            "network",
            "address_realm",
            true,
        );
        reg(
            "network",
            "CreateAddressRealm",
            "network",
            "address_realm",
            true,
        );
        reg(
            "network",
            "DeleteAddressRealm",
            "network",
            "address_realm",
            true,
        );
        reg(
            "network",
            "ListAddressPools",
            "network",
            "address_pool",
            true,
        );
        reg(
            "network",
            "CreateAddressPool",
            "network",
            "address_pool",
            true,
        );
        reg(
            "network",
            "ReadAddressPool",
            "network",
            "address_pool",
            true,
        );
        reg(
            "network",
            "DeleteAddressPool",
            "network",
            "address_pool",
            true,
        );
        reg("network", "ListEndpoints", "network", "endpoint", true);
        reg("network", "CreateEndpoint", "network", "endpoint", true);
        reg("network", "ReadEndpoint", "network", "endpoint", true);
        reg("network", "DeleteEndpoint", "network", "endpoint", true);

        // Native IAM governance administration is explicit system/operator
        // authority over canonical O3K IAM state. It is never inferred from a
        // tenant role name, route shape, or IdP claim, and ordinary project
        // scope must never satisfy these actions.
        let mut reg_system = |act: &str| {
            if let (Ok(action), Ok(expected_resource_type)) = (
                ActionId::new("governance", act),
                ResourceType::new("governance", "governance"),
            ) {
                self.policies.insert(
                    action.clone(),
                    ActionPolicy {
                        action,
                        expected_resource_type,
                        accepted_principals: vec![PrincipalKind::User],
                        require_ownership: false,
                        required_roles: vec!["operator".to_owned()],
                    },
                );
            }
        };
        reg_system("ReadGovernance");
        reg_system("ManageAssignment");
        reg_system("ManageOperatorAssignment");

        if let (Ok(action), Ok(expected_resource_type)) = (
            ActionId::new("operator", "ReadProfile"),
            ResourceType::new("operator", "profile"),
        ) {
            self.policies.insert(
                action.clone(),
                ActionPolicy {
                    action,
                    expected_resource_type,
                    accepted_principals: vec![PrincipalKind::User],
                    require_ownership: false,
                    required_roles: vec!["operator".to_owned()],
                },
            );
        }

        // Native Operator diagnostics (#903) is a bounded, read-only
        // projection of canonical service/provider/capacity authority. It is
        // explicit durable system/operator authority: never inferred from a
        // tenant role name, route shape or IdP claim, and ordinary project
        // scope must never satisfy it.
        if let (Ok(action), Ok(expected_resource_type)) = (
            ActionId::new("operator", "ReadDiagnostics"),
            ResourceType::new("operator", "diagnostics"),
        ) {
            self.policies.insert(
                action.clone(),
                ActionPolicy {
                    action,
                    expected_resource_type,
                    accepted_principals: vec![PrincipalKind::User],
                    require_ownership: false,
                    required_roles: vec!["operator".to_owned()],
                },
            );
        }

        // Native metering (#904) exposes the canonical meter catalog and
        // bounded usage for one scope. Definitions are public, secret-free
        // metadata and are readable by any authenticated user, so they carry
        // no ownership requirement and no scope gate.
        if let (Ok(action), Ok(expected_resource_type)) = (
            ActionId::new("metering", "ReadDefinitions"),
            ResourceType::new("metering", "definitions"),
        ) {
            self.policies.insert(
                action.clone(),
                ActionPolicy {
                    action,
                    expected_resource_type,
                    accepted_principals: vec![PrincipalKind::User],
                    require_ownership: false,
                    required_roles: vec![],
                },
            );
        }

        // Usage is owner-scoped: a caller always reads the effective scope
        // carried by its own `AuthContext`, never a scope taken from request
        // JSON. `require_ownership` is meaningful here because the handler
        // always authorizes this action against the caller's own scope.
        if let (Ok(action), Ok(expected_resource_type)) = (
            ActionId::new("metering", "ReadUsage"),
            ResourceType::new("metering", "usage"),
        ) {
            self.policies.insert(
                action.clone(),
                ActionPolicy {
                    action,
                    expected_resource_type,
                    accepted_principals: vec![PrincipalKind::User],
                    require_ownership: true,
                    required_roles: vec![],
                },
            );
        }

        // Cross-scope usage reads are a distinct durable system/operator
        // capability, discoverable in the action inventory rather than
        // expressed ad-hoc by the handler. It is never inferred from a tenant
        // role name, and the system-scope gate below (like `operator` actions)
        // ensures a project-scoped caller cannot satisfy it even with an
        // `operator` role string.
        if let (Ok(action), Ok(expected_resource_type)) = (
            ActionId::new("metering", "ReadUsageAll"),
            ResourceType::new("metering", "usage"),
        ) {
            self.policies.insert(
                action.clone(),
                ActionPolicy {
                    action,
                    expected_resource_type,
                    accepted_principals: vec![PrincipalKind::User],
                    require_ownership: false,
                    required_roles: vec!["operator".to_owned()],
                },
            );
        }
    }
}

impl Authorizer for StaticAuthorizer {
    fn authorize(&self, request: &AuthorizationRequest<'_>) -> AuthorizationDecision {
        // 1. Look up policy for the requested action
        let Some(policy) = self.policies.get(&request.action) else {
            return AuthorizationDecision::Deny {
                reason: DecisionReason::UnknownAction,
            };
        };

        // 2. Validate resource type matches policy
        if request.resource_target.resource_type() != &policy.expected_resource_type {
            return AuthorizationDecision::Deny {
                reason: DecisionReason::UnknownResourceType,
            };
        }

        // 3. Validate principal kind is supported
        let principal_kind = request.auth_context.principal().kind();
        if !policy.accepted_principals.contains(&principal_kind) {
            return AuthorizationDecision::Deny {
                reason: DecisionReason::UnsupportedPrincipal,
            };
        }

        if request.action == ActionId::new_unchecked("operator", "ReadProfile")
            && request.auth_context.effective_scope().kind() != ScopeKind::System
        {
            return AuthorizationDecision::Deny {
                reason: DecisionReason::ScopeMismatch,
            };
        }

        // Operator diagnostics is system-scoped by construction. A tenant or
        // project-scoped caller carrying an `operator` role name must never
        // satisfy it; only durable System authority plus the required
        // operator role can (the role is checked in step 5).
        if request.action == ActionId::new_unchecked("operator", "ReadDiagnostics")
            && request.auth_context.effective_scope().kind() != ScopeKind::System
        {
            return AuthorizationDecision::Deny {
                reason: DecisionReason::ScopeMismatch,
            };
        }

        // Cross-scope metering reads (`metering:ReadUsageAll`) are system-scoped
        // by construction, exactly like the `operator` actions: a tenant or
        // project-scoped caller carrying an `operator` role name must never
        // satisfy one. Only durable System scope plus the required operator role
        // can (the role is checked in step 5). Owner-scoped `metering:ReadUsage`
        // has no gate here because its ownership check against the caller's own
        // effective scope is honest and sufficient.
        if request.action == ActionId::new_unchecked("metering", "ReadUsageAll")
            && request.auth_context.effective_scope().kind() != ScopeKind::System
        {
            return AuthorizationDecision::Deny {
                reason: DecisionReason::ScopeMismatch,
            };
        }

        if request.action == ActionId::new_unchecked("quota", "ManageQuota")
            && (request.auth_context.effective_scope().kind() != ScopeKind::System
                || !request.auth_context.has_role("operator"))
        {
            return AuthorizationDecision::Deny {
                reason: DecisionReason::ScopeMismatch,
            };
        }

        // Canonical topology administration is durable system/operator
        // authority, exactly like quota:ManageQuota: project/tenant scope must
        // never satisfy it, even with an `operator` role string.
        if request.action == ActionId::new_unchecked("topology", "ManageTopology")
            && (request.auth_context.effective_scope().kind() != ScopeKind::System
                || !request.auth_context.has_role("operator"))
        {
            return AuthorizationDecision::Deny {
                reason: DecisionReason::ScopeMismatch,
            };
        }

        // The `topology` namespace is reserved for canonical location-topology
        // administration. Topology *reads* (`topology:ReadTopology`) are open
        // to any authenticated principal, but every mutation action requires
        // System scope. Gating the namespace (rather than a literal action
        // list) means a newly registered topology mutation action cannot
        // accidentally omit this check; the operator-role requirement stays
        // explicit per action via `required_roles`.
        if request.action.namespace() == "topology"
            && request.action != ActionId::new_unchecked("topology", "ReadTopology")
            && request.auth_context.effective_scope().kind() != ScopeKind::System
        {
            return AuthorizationDecision::Deny {
                reason: DecisionReason::ScopeMismatch,
            };
        }

        if request.action.namespace() == "composition"
            && (request.auth_context.effective_scope().kind() != ScopeKind::System
                || (request.action == ActionId::new_unchecked("composition", "ManageCloudProfile")
                    && !request.auth_context.has_role("operator")))
        {
            return AuthorizationDecision::Deny {
                reason: DecisionReason::ScopeMismatch,
            };
        }

        // The `governance` namespace is reserved for system/operator
        // administration over canonical O3K IAM authority. Every action in it
        // requires System scope; a tenant or project-scoped caller must never
        // satisfy one even if it holds an `operator` role string inside a
        // project. Gating by namespace (rather than a literal action list)
        // means a newly registered governance action cannot accidentally omit
        // this check.
        if request.action.namespace() == "governance"
            && request.auth_context.effective_scope().kind() != ScopeKind::System
        {
            return AuthorizationDecision::Deny {
                reason: DecisionReason::ScopeMismatch,
            };
        }

        // 4. Validate ownership if required
        if policy.require_ownership
            && !(request.action == ActionId::new_unchecked("quota", "ReadQuota")
                && request.auth_context.effective_scope().kind() == ScopeKind::System
                && request.auth_context.has_role("operator"))
        {
            let caller_scope_id = request.auth_context.effective_scope().id();
            match request.resource_target.owner_scope() {
                Some(target_scope) => {
                    if target_scope != caller_scope_id {
                        return AuthorizationDecision::Deny {
                            reason: DecisionReason::ScopeMismatch,
                        };
                    }
                }
                None => {
                    return AuthorizationDecision::Deny {
                        reason: DecisionReason::MissingOwnership,
                    };
                }
            }
        }

        // 5. Validate required roles if any
        for required_role in &policy.required_roles {
            if !request.auth_context.has_role(required_role) {
                return AuthorizationDecision::Deny {
                    reason: DecisionReason::UnauthorizedRole,
                };
            }
        }

        AuthorizationDecision::Allow
    }

    fn capabilities(&self) -> Vec<ActionPolicy> {
        let mut policies: Vec<ActionPolicy> = self.policies.values().cloned().collect();
        policies.sort_by_key(|policy| policy.action.as_str());
        policies
    }
}
