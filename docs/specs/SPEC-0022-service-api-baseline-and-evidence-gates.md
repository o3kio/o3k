# SPEC-0022 — Service API baseline and evidence gates

Status: Proposed

Primary OpenStack reference: 2026.1 Gazpacho

Backward reference: 2025.2 Flamingo where explicitly listed

Related decisions and specifications:

- [ADR-0160](../adr/ADR-0160-service-topology-and-execution-boundaries.md)
- [ADR-0162](../adr/ADR-0162-contract-first-staged-runner-validation.md)
- [ADR-0163](../adr/ADR-0163-product-profiles-and-deployment-posture.md)
- [SPEC-0024](SPEC-0024-product-profiles-and-claims.md)

## Purpose

O3K implements declared OpenStack-compatible profiles, not entire upstream
services. This specification defines how an API profile is frozen, implemented,
tested, advertised, and released within an O3K product profile.

The baseline prevents:

- discovering fundamental API requirements one endpoint at a time on a
  privileged runner;
- delaying all integration until undefined complete OpenStack parity;
- presenting an external-hosted service as an O3K implementation;
- promoting behavior verified in one product profile into another;
- advertising database, footprint, edge, metadata, or microversion claims that
  exceed executable evidence.

## Product-profile binding

Every compatibility record belongs to one or more product profiles from
`compatibility/product-profiles.yaml`:

- `openstack-service-testbed`;
- `native-rust-testlab`;
- `small-edge-cloud`;
- later explicitly accepted profiles.

The same HTTP operation may have different dependencies and evidence in
different profiles. For example, `volumev3` may identify an `external-hosted`
Cinder endpoint in the service-testbed profile while later identifying an
`o3k-implemented` native Cinder profile. These claims must never be conflated.

## Compatibility record

Every advertised operation has a machine-readable record containing:

- product profile ID;
- service type and ownership mode (`o3k-implemented` or `external-hosted`);
- operation ID;
- HTTP method and canonical path;
- upstream reference release and service API;
- upstream reference maximum where relevant;
- O3K advertised, implemented, and verified version or microversion windows;
- auth scope and policy ID;
- required request headers, parameters, and body fields;
- response headers, status code, body fields, and error envelopes;
- supported and explicitly unsupported fields;
- idempotency behavior;
- domain state transition;
- cross-service dependencies;
- provider or external-service capability requirement;
- database and execution-profile requirements;
- official public reference;
- public client/SDK/Tempest evidence;
- portable, process, component, full-profile, and release evidence IDs;
- known deviations and release claim.

A route without this record is unsupported. A record without executable
evidence is specified or implemented, not verified.

## Evidence states

Each operation and workflow records independent states:

```text
missing
specified
implemented
portable-contract-verified
process-verified
component-real-host-verified
full-profile-verified
release-claimed
```

A later state requires all earlier applicable states. `skipped`, `ready`, unit-
test-only, fake-provider-only, or documentation-only results cannot be promoted
to real-host verification.

## Native ephemeral-root TestLab baseline

The first native TestLab profile is intentionally bounded.

### Identity / Keystone-compatible

Required behavior:

- version discovery;
- project-scoped password authentication;
- unscoped password authentication: the password identity method with the
  `scope` member omitted, with the `"unscoped"` keyword, or with a scope object
  that carries no `project`. An unscoped token proves identity only. It carries
  no project, roles or catalog, never implies system or domain scope, and is
  never silently mapped to the bootstrap admin project. It is rejected with 401
  by every operation that requires a normalized project-scoped `AuthContext`.
  This is required by the bounded Horizon login bootstrap: the unmodified
  external client authenticates unscoped, discovers the projects it may scope
  into, and only then re-authenticates with the selected project scope;
- available-scope discovery for the authenticated subject:
  `GET /v3/auth/projects` and `GET /v3/users/{user_id}/projects` return, for the
  caller's own durable identity, the enabled projects in an enabled domain where
  the durable role assignments grant at least one role. Both are the same
  bounded capability addressed by identity and by user ID, and neither is
  project or user administration: no write operations, no pagination, no
  listing of another subject's scopes;
- `X-Subject-Token` issuance;
- token expiry and verification;
- catalog for enabled profile services;
- project ID/path consistency;
- durable ID/name separation;
- generic auth failure and redaction.

The hosted-service profile additionally requires service users, services,
regions, endpoints, and public token validation as defined in SPEC-0020 and
SPEC-0023.

### Image / Glance-compatible

Required operations:

- create image metadata;
- upload content;
- list, show, authenticated download, and delete.

Required behavior:

- size, checksum, and format validation;
- queued/saving/active or documented equivalent transitions;
- immutable active content in the profile;
- project visibility;
- missing/inactive-image rejection before compute dispatch;
- no host path exposure.

### Network / Neutron-compatible

Required operations:

- create/list/show/delete network;
- create/list/show/delete subnet;
- create/list/show/delete port.

Required behavior:

- flat provider-network profile;
- IPv4 subnet, gateway, pool, and DNS validation;
- stable MAC and fixed-IP ownership;
- dependency and port-binding intent;
- selected host, conflict detection, and complete cleanup.

Not included:

- routers;
- floating IPs;
- security groups;
- VLAN/VXLAN tenant networks;
- OVS/OVN compatibility.

### Placement-compatible

Required operations or equivalent declared behavior:

- resource-provider registration and discovery;
- VCPU, MEMORY_MB, and DISK_GB inventory;
- usage and available capacity;
- generation-protected inventory update;
- scheduler candidate selection;
- allocation create/show/delete;
- capacity and generation conflict responses.

Public Placement parity is advertised only for operations listed in the
manifest.

### Compute / Nova-compatible

Required operations:

- flavor create/list/detail/show/delete;
- keypair import/list/show/delete;
- server create/list/detail/show/delete;
- server stop/start/hard reboot;
- console-log retrieval;
- version discovery and the selected verified microversion window.

Required create validation:

- token/project path;
- active image;
- immutable flavor snapshot;
- owned keypair where requested;
- valid network/port dependencies;
- Placement capacity;
- idempotency identity;
- provider capability.

Required lifecycle behavior:

- public state derives from accepted observations;
- timeout becomes unknown outcome;
- duplicate delivery does not create a second resource;
- delete compensates dependencies and is idempotent;
- console output is real, bounded, authorized, and path-safe;
- restart preserves resource identity.

Not included:

- resize, rebuild, rescue, live migration, evacuation;
- server groups, NUMA, PCI passthrough;
- full Nova extension parity.

### Guest metadata

The first native alpha uses config-drive/cloud-init only. Metadata HTTP is
unsupported and unadvertised until a separate security/networking profile and
real guest-isolation evidence exist.

### Native volume / Cinder-compatible

The first ephemeral-root profile does not require or advertise native Cinder.

A later O3K-owned persistent-volume profile freezes its own operations,
including selected volume types, volumes, attachments, Nova attach/detach,
backend capabilities, `StorageProvider`, and real storage evidence.

No boot-from-volume claim is made until separately specified and verified.

## OpenStack service-testbed baseline

A hosted-service profile freezes only the satellite operations required by the
selected real OpenStack service.

For external Cinder, the profile includes the selected:

- service-user authentication;
- public Identity token validation;
- services, regions, endpoints, and dynamic catalog behavior;
- Glance image access;
- Nova volume-attachment operations;
- typed outbound Cinder attachment sequence;
- optional Neutron or Placement operations required by the selected test.

The external Cinder endpoint uses `ownership_mode: external-hosted`. It retains
its own database, message bus, processes, backend, migrations, upgrades, and
health. See SPEC-0023.

## Small edge-cloud baseline

The edge profile reuses only operations verified for its declared topology and
adds profile-specific requirements for:

- approximately 10–20 hypervisors;
- multi-host inventory, scheduling, allocations, and host binding;
- enrollment, epochs, heartbeat, reconnect, and resync;
- failure-safe retry and fencing;
- backup, restore, upgrade, rollback, and diagnostics;
- selected network and storage execution;
- database, policy, quota, performance, and availability limits.

An operation verified in a single-node TestLab is not automatically edge-
verified.

## Service module definition of complete

A logical O3K service module is ready for integration only when:

1. the product and API profiles are frozen;
2. HTTP contracts and discovery are generated or validated;
3. domain invariants are tested;
4. migrations and store conformance pass;
5. policy fails closed;
6. dependencies and compensation are executable;
7. a stateful provider or external-service fake covers required outcomes;
8. process-level public client tests pass;
9. compatibility inventory and deviations are current.

This does not require every upstream endpoint.

## Portable profile gates

Before privileged integration, the selected public workflow passes against real
O3K HTTP APIs, stores, identity, scheduler, operations, and reconciler with only
execution or external services faked.

Native TestLab example:

```text
discover
-> authenticate
-> image lifecycle
-> network/subnet/port
-> flavor/keypair
-> server create and observed state
-> console and actions
-> delete
-> restart/replay and cleanup
```

External-service testbed example:

```text
create service project/user/roles
-> register external-hosted endpoint
-> service-user authentication
-> public token validation
-> selected satellite APIs
-> external service workflow
-> failure compensation and cleanup
```

Every persisted phase receives failure, duplicate, timeout, restart, project-
isolation, and compensation testing.

## Component and full-profile gates

### Compute component

- exact source and host capabilities;
- real image transfer and digest;
- `qemu-img` and backing-chain evidence;
- config-drive attachment and guest consumption;
- deterministic owned libvirt XML;
- bounded `virsh list --all` diagnostic evidence;
- lifecycle, console, restart, and complete cleanup;
- no foreign-domain change.

### Network component

- selected port, MAC, fixed IP, subnet, and host;
- owned TAP and bridge membership;
- DHCP or equivalent binding evidence;
- guest or namespace connectivity;
- restart reconciliation and cleanup;
- no foreign-link change.

### Native storage component

Required only for the native persistent-volume profile:

- backend capability;
- real volume lifecycle;
- attachment preparation and teardown;
- secret-safe evidence;
- restart reconciliation;
- no foreign-volume change.

### External-service component

Required for a hosted service:

- selected external version and dependencies;
- service-user auth and public token validation;
- catalog discovery;
- selected public workflow;
- exact O3K/external failure boundary;
- redaction and cleanup across explicitly managed test resources.

### Full native profile

```text
Keystone
-> Glance
-> Neutron
-> Placement
-> Nova
-> o3k-compute/libvirt
-> guest boot, console, restart, delete, cleanup
```

### Full edge profile

Adds supported host count, multi-host scheduling, fencing, backup/restore,
upgrade, failure, database, policy, network, storage, and operational evidence.

All full-profile workflows use public APIs and standard clients. Direct database
repair or unadvertised operator shortcuts are forbidden.

## Diagnostic mode

Protected workflows may support an opt-in trusted diagnostic mode that records
the exact source SHA, pauses for a bounded interval, exposes redacted owned-
resource inspection commands, and always performs ownership-checked cleanup.

Diagnostic mode is not passing evidence by itself.

## Baseline change control

A baseline change requires:

- issue and rationale;
- product profile;
- official public source;
- compatibility and product-profile manifest update;
- spec/contract change;
- portable tests before implementation completion;
- deviation and release-impact assessment;
- human review for public API, auth, persistent state, privileged execution,
  external-service trust, database, or product claims.

LLM agents must not expand a profile because an adjacent endpoint appears easy.

## Release claims

Release documentation names:

- product profile;
- O3K-implemented and external-hosted services;
- primary reference release;
- per-service versions and verified microversions;
- verified and portable-only operations;
- database support state;
- metadata mechanism;
- footprint measurement state;
- known deviations and unsupported integrations;
- component and full-profile evidence IDs.

Invalid standalone claims include:

- “O3K supports Gazpacho.”
- “O3K implements Cinder” when only external Cinder is hosted.
- “O3K runs in 50 MB” without a profile-specific measurement.
- “PostgreSQL is supported for production” without an adapter and conformance.
- “O3K connects to OpenStack” without a defined integration profile.
