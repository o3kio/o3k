# SPEC-0020 — O3K IAM, Keystone compatibility, catalog, and authorization context

Status: Accepted

Primary compatibility reference: OpenStack 2026.1 Gazpacho

Backward compatibility reference: OpenStack 2025.2 Flamingo where declared

Related decisions:

- [ADR-0165](../adr/ADR-0165-o3k-cloud-operating-system-and-cloud-kernel.md)
- [ADR-0166](../adr/ADR-0166-o3k-iam-and-keystone-compatibility-boundary.md)
- [SPEC-0004](SPEC-0004-keystone-bootstrap.md)

## Purpose

This specification defines the accepted identity and authorization contract for
O3K's current OpenStack-compatible profiles while preserving the architecture
required by the O3K Cloud Kernel.

The current implementation may expose a deliberately small Keystone-compatible
surface. That compatibility surface must map into one service-neutral O3K IAM
model rather than becoming the permanent internal model of every O3K service.

This specification therefore has two layers:

1. **O3K IAM contract** — canonical principal, scope, action, resource,
   authorization context, service identity, ownership, audit, and policy
   semantics consumed by O3K services;
2. **Keystone compatibility contract** — mapping from the selected Keystone API
   profile into the O3K IAM contract and back into OpenStack-compatible
   responses/catalogs.

Implementation breadth may lag this specification. Unsupported behavior must
fail closed and must not be advertised.

## Canonical O3K IAM concepts

### Principal

A principal is the authenticated actor represented by a stable typed identity.

The first implementation requires:

- user principal;
- service principal.

Future workload/automation principal types require an accepted profile before
being exposed.

A principal ID is not a display name and is never inferred from one.

### Ownership/security scope

An O3K-owned resource is associated with a stable ownership/security scope.

The current OpenStack-compatible TestLab maps this to project scope.

The canonical type must not assume that every future O3K service will always be
project-only. It therefore distinguishes:

- stable scope ID;
- scope type/profile;
- optional parent/grouping relationship;
- compatibility projection metadata.

A later tenancy ADR may introduce organization/account/workspace concepts. This
specification does not define them.

### Resource

Authorization-relevant resources have at least:

```text
resource_id
resource_type
owner_scope_id
service_namespace
region_id? / availability_domain?
authorization_attributes?
```

Display names, provider-native IDs, filesystem paths, and OpenStack JSON
envelopes are not authorization identities.

### Action

Every protected operation maps to one stable O3K action identifier.

Examples for current domains may include:

```text
identity:IssueToken
image:UploadImage
compute:CreateServer
compute:DeleteServer
network:CreatePort
capacity:Allocate
volume:AttachVolume
```

Exact action inventories are versioned with the selected service profile.

The first implementation may use a bounded static policy table, but handlers
must not invent ad hoc permission semantics that cannot be represented by the
common action/resource contract.

### Authorization context

All protocol adapters convert validated credentials into one immutable internal
context equivalent to:

```text
AuthContext
  principal_id
  principal_type
  effective_scope_id
  compatibility_scope?
  role_or_policy_inputs
  authentication_methods
  issued_at
  expires_at
  audit_id
  parent_audit_id?
  service_principal?
  delegated_actor?
  request_id
  assurance_attributes?
```

Requirements:

- raw credentials and token values are excluded;
- IDs are typed domain values, not arbitrary handler strings;
- expiry and effective scope are validated once before application dispatch;
- every service consumes the same context type;
- service modules do not parse Keystone token wire formats independently;
- original actor and service principal are both preserved for delegated work;
- the context is safe to propagate through operation/audit metadata after
  secret-bearing credential material has been discarded.

## Authorization decision contract

A protected operation is authorized through:

```text
Principal × Action × Resource × Context -> Allow | Deny
```

The policy input includes, where applicable:

- principal identity/class;
- effective ownership/security scope;
- action;
- resource type and resource ID;
- target resource owner scope;
- service principal/delegation identity;
- region/availability attributes;
- bounded action-specific condition attributes.

Default behavior is deny.

Authorization happens before:

- provider mutation;
- secret-bearing external-service calls;
- disclosure of another tenant's resource details;
- idempotency responses that could reveal cross-tenant existence.

A resource record that lacks required ownership metadata is invalid for a
tenant-scoped operation and fails closed.

## Current OpenStack/Keystone compatibility resources

The declared Keystone-compatible profile may expose:

- domain;
- project;
- user;
- group;
- role;
- role assignment;
- service;
- endpoint;
- region;
- token record or verifiable token identity;
- revocation record where revocation is enabled.

These are compatibility resources. They map to canonical IAM concepts and do
not require future O3K-native services to use Keystone vocabulary internally.

### Compatibility mapping

At minimum:

```text
Keystone user
  -> O3K user principal

Keystone project
  -> O3K ownership/security scope projection

Keystone domain
  -> compatibility hierarchy/projection

Keystone role/assignment
  -> policy input / compatibility role data

Keystone token
  -> authenticated credential producing AuthContext

Keystone service/endpoint
  -> OpenStack projection of the O3K service registry

Keystone catalog
  -> compatibility view containing only selected verified service endpoints
```

The mapping is deterministic and covered by compatibility tests.

## Bootstrap TestLab profile

The TestLab bootstrap profile may retain the current deterministic compatibility
records:

```text
domain ID:  default
domain name: Default
user ID:    bootstrap-user
user name:  admin
project ID: eba29e2d-53de-461d-ae91-ede7402713cb
project name: admin
role ID:    member
role name:  member
```

The duplicate user/project display name is intentional evidence that names and
IDs are different concepts.

The bootstrap profile must not expose the password or signing key.

Replacing bootstrap storage/authentication later must not change the internal
`AuthContext` or authorization request contract.

## Authentication request subset

The first OpenStack-compatible alpha supports the frozen compatibility subset,
including:

- `POST /v3/auth/tokens`;
- the selected `password` identity method;
- project scope by supported ID or explicitly supported unambiguous name form;
- `X-Subject-Token` response behavior;
- issue/expiry timestamps required by the compatibility contract;
- generic non-enumerating authentication failures.

Unsupported authentication methods fail with the selected
Keystone-compatible error envelope and are not silently ignored.

Bounded unscoped authentication and `GET /v3/auth/projects` are part of the
same subset (see SPEC-0004). An unscoped token has no effective scope, so
`AuthContext` construction fails closed for it: unscoped tokens authenticate a
subject for client project discovery only and never authorize an operation.
`GET /v3/auth/projects` returns only the caller's durable role-assignment
projects and is not project administration.

## Credential/token requirements

A token or server-side credential record binds enough information to construct
the canonical `AuthContext`, including:

- safe token ID/digest;
- principal/user ID;
- effective project/scope ID;
- role/policy inputs needed by the compatibility response;
- authentication method;
- issue/expiry timestamps;
- audit ID;
- optional parent audit ID;
- optional service principal;
- format/version identifier.

The alpha credential may remain opaque.

Validation fails closed for:

- invalid signature or missing record;
- expiry;
- revocation where enabled;
- malformed version;
- missing required scope;
- disabled principal/project compatibility record;
- impossible role assignment;
- unacceptable bounded clock skew.

Responses must not disclose whether a user, project, role, or secret exists.

## Service identity and delegation

A service principal includes at least:

```text
service_principal_id
service_namespace/type
effective service permissions
authenticated channel/credential identity
issue/expiry where credential based
audit identity
```

For work performed on behalf of a user, the effective context contains both:

1. the original user principal and ownership scope;
2. the authenticated calling service principal.

Examples include compute resolving image content, realizing a network port,
reserving capacity, or orchestrating a volume attachment.

The service principal does not replace the original user/scope and does not
automatically grant administrator access.

In-process calls may pass the typed context directly.

Any future process/network boundary requires an authenticated service channel
and explicit delegation contract.

## Policy contract for the current alpha

The alpha may use a bounded static policy table.

Each protected operation declares:

- O3K action ID;
- required credential/authentication state;
- required compatibility scope;
- accepted policy/role inputs;
- target resource type;
- whether resource ownership must equal effective scope;
- whether a service principal is required;
- whether administrative/system access is supported;
- whether the operation is public discovery.

An endpoint without an explicit policy declaration cannot be registered as a
protected operation.

OpenStack policy names may be recorded as compatibility metadata, but the
canonical policy key is the O3K action/resource contract.

## O3K service registry

The Cloud Kernel service registry is the canonical service-discovery model.

The minimal internal registration supports:

- stable service ID;
- service namespace/type;
- ownership mode (`o3k-implemented`, `external-hosted`, or another accepted
  explicit mode);
- enabled state;
- supported API surface/version metadata;
- regions;
- endpoints;
- resource/action namespaces;
- bounded capabilities;
- evidence/claim state where needed to prevent advertisement beyond proof.

Dynamic registration is not required by the first alpha.

## Keystone service catalog projection

The Keystone-compatible catalog exposes only the fields required by the
selected OpenStack contract:

- stable service ID;
- service type/name;
- endpoint ID;
- interface;
- region ID;
- enabled state;
- URL;
- discoverable version root.

Expected compatibility service types by milestone include:

- `identity`;
- `image`;
- `compute`;
- `network`;
- `placement`;
- `volumev3` only when its selected profile passes required gates.

Catalog URLs come from validated configuration, not untrusted request headers.

A service known to the internal registry but unsupported by the selected
OpenStack profile is omitted from the Keystone catalog.

## Discovery behavior

The declared OpenStack profile keeps consistent discovery for:

- identity root;
- `/v3`;
- advertised service roots;
- implemented version/microversion windows;
- endpoint URLs in the catalog.

Contradictory discovery/catalog information is a compatibility failure.

An O3K-native discovery/service-registry API requires a separate public
contract and is not implied by this spec.

## Persistence and restart

IAM compatibility state and canonical identity metadata must support:

- deterministic migrations;
- uniqueness and foreign-key constraints where applicable;
- restart without changing stable IDs;
- credential verification across restart when configured keys/records are
  retained;
- fail-closed corrupted-state handling;
- explicit migration of compatibility records without changing canonical
  principal/scope identity silently.

## Audit and redaction

Authorization/audit events contain enough canonical identity to answer:

```text
who
attempted what
against which resource
in which scope
through which service
with what decision
under which request/operation
```

At minimum, where applicable:

- request ID;
- audit ID;
- principal ID;
- effective scope ID;
- service principal;
- O3K action ID;
- target resource type/ID;
- allow/deny result;
- bounded reason category;
- operation ID.

Audit data excludes:

- password;
- raw token;
- signing key;
- private certificate/key material;
- unbounded request bodies;
- user-data;
- backend connection secrets.

## Required tests

### Canonical IAM/domain

- ID/name distinction;
- principal typing;
- stable ownership scope;
- resource owner required for protected tenant resources;
- action/resource mapping;
- default deny;
- cross-scope denial before provider dispatch;
- malformed/missing ownership fails closed.

### Authentication compatibility

- successful project-scoped password flow;
- supported project-name resolution;
- invalid-password redaction;
- expired/invalid credential;
- disabled user/project compatibility record;
- clock-skew boundaries;
- restart verification.

### Authorization

- same-scope allowed path;
- wrong-scope denial;
- role/policy reduction;
- endpoint without policy declaration fails closed;
- URL project/path mismatch;
- user plus service-principal dual context;
- service principal cannot broaden user scope implicitly;
- no cross-tenant existence disclosure through idempotency;
- audit propagation.

### Service registry/catalog

- only enabled/verified compatibility services advertised;
- stable service/endpoint/region IDs;
- URL configuration validation;
- resource/action metadata retained internally without corrupting Keystone
  catalog shape;
- omission of `volumev3` before the selected Cinder profile is ready;
- OpenStack CLI discovery without contradictory versions.

## Explicit non-goals for the first implementation

- complete Keystone administration API;
- generic dynamic IAM policy language;
- AWS-compatible IAM syntax;
- organization/account hierarchy as a public contract;
- federation;
- OAuth/OIDC compatibility unless separately selected;
- application credentials;
- trusts;
- online key rotation without an accepted design;
- system-scoped administration unless selected by a later profile;
- public O3K-native service-registry API;
- making this Cloud Kernel refactor a prerequisite for `v0.2.0-alpha.1`.
