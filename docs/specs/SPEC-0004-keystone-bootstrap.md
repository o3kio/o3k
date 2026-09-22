# SPEC-0004 — Keystone v3 bootstrap token flow

Status: Implemented subset

Normative trust model: [SPEC-0020](SPEC-0020-keystone-trust-catalog-and-auth-context.md)

## Decision

O3K supports `POST /v3/auth/tokens` with exactly one `password` identity method
in the TestLab bootstrap profile, for both a project scope and an unscoped
request. An unscoped request is one with no `scope` member, the `"unscoped"`
keyword, or an object without a `project`; any other scope shape is a bounded
rejection. Bootstrap credentials are configured explicitly with
`O3K_BOOTSTRAP_PASSWORD` and `O3K_TOKEN_SIGNING_KEY`; the signing key is
separate and must be at least 32 bytes. The route is unavailable until both are
configured.

An unscoped token authenticates the subject user only. It carries no project,
roles, or catalog, requires no role assignment, and is rejected with 401 by
every operation that requires a normalized `AuthContext` (OpenStack
compatibility routes and native `/o3k/v1` routes alike).

`GET /v3/auth/projects` supports client project discovery: it accepts an
unscoped or project-scoped token and returns only the enabled projects the
subject may scope into according to its durable role assignments. A subject
with no assignment receives an empty list. It is not project administration and
exposes no pagination, links, or write operations.

The token is an opaque URL-safe HMAC-SHA256 authenticated value containing the
user, optional project scope, issue time, expiry, and random token ID. It is not
a general JWT compatibility promise. Tokens expire after one hour in this alpha
profile and remain verifiable across restart when the same key is retained.

This spec defines only the implemented bootstrap subset. Durable identity
resources, service identity, authorization context, catalog policy, and future
expansion are governed by SPEC-0020 and ADR-0166 (superseding ADR-0161).

## Bootstrap records

```text
user ID:      bootstrap-user
user name:    admin
project ID:   eba29e2d-53de-461d-ae91-ede7402713cb
project name: admin
domain ID:    default
domain name:  Default
role ID/name: member
```

Project and user names are not internal IDs. In particular, the project name
`admin` must never be used where the durable project ID
`eba29e2d-53de-461d-ae91-ede7402713cb` is required by stores, authorization
checks, operations, provider commands, or runner probes.

The durable project ID is a fixed lowercase UUID. External OpenStack services
route project-scoped URLs through a hex-only `project_id` validation regex
(for example Cinder's `[DEFAULT] project_id_regex`, default `[0-9a-f\-]+`),
so a non-hex slug is unrouteable to a real external service (protected run
30993341589: `POST /v3/bootstrap-project/volumes` returned 404 from real
Cinder 28.0.0). The ID was amended from the former slug `bootstrap-project`
to keep O3K-issued tokens addressable by external services under test.

## Catalog

The bootstrap catalog advertises only implemented and enabled service
profiles:

- identity (`/v3`);
- image (`/v2`);
- network (`/v2.0`);
- compute (`/v2.1`);
- Placement only when its public profile is implemented and enabled.

The catalog must not advertise `volumev3` until the Cinder-compatible baseline,
policy, and contract tests pass. Planned services are omitted rather than
represented by placeholder endpoints.

Catalog URLs are derived from validated configuration. Authentication failures
use a generic 401 message and never echo credentials, names, raw tokens,
signing material, or internal errors.

## Authorization context

A successful bootstrap authentication produces the same normalized internal
`AuthContext` required by SPEC-0020. Service modules consume the durable user
and project IDs, roles, expiry, audit identity, and request identity from that
context. They do not parse or reinterpret the raw token independently.

## Evidence

The in-process API tests cover:

- successful issuance;
- `X-Subject-Token`;
- project scope;
- unscoped issuance (omitted `scope` and the `"unscoped"` keyword) with no
  `project`, `roles`, or `catalog` in the response body;
- rejection of a valid unscoped token by a project-scoped OpenStack
  compatibility route and by a native `/o3k/v1` route;
- bounded rejection of unsupported scope shapes and identity methods;
- `GET /v3/auth/projects` returning only the caller's role-assignment projects;
- project ID/name distinction;
- invalid password redaction;
- response shape;
- catalog omission for unsupported services.

Identity unit tests cover signing, verification, expiry, invalid credentials,
and restart behavior. Process-level and OpenStack CLI evidence remains part of
the declared TestLab compatibility and full-cloud gates.
