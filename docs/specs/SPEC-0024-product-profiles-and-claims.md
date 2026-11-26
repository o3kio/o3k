# SPEC-0024 — Product profiles and claims

Status: Accepted; profile and release-maturity claims amended by owner-directed ADR-0191 and SPEC-0052

Related decisions and specifications:

- [ADR-0163](../adr/ADR-0163-product-profiles-and-deployment-posture.md)
- [ADR-0165](../adr/ADR-0165-o3k-cloud-operating-system-and-cloud-kernel.md)
- [ADR-0166](../adr/ADR-0166-o3k-iam-and-keystone-compatibility-boundary.md)
- [ADR-0182](../adr/ADR-0182-edge-to-datacenter-building-block-cloud-os.md)
- [ADR-0191](../adr/ADR-0191-owner-directed-early-access-adoption-and-installation-trust.md)
- [SPEC-0052](SPEC-0052-early-access-profile-and-acceptance.md)
- [SPEC-0020](SPEC-0020-keystone-trust-catalog-and-auth-context.md)
- [SPEC-0022](SPEC-0022-service-api-baseline-and-evidence-gates.md)
- [SPEC-0023](SPEC-0023-external-cinder-service-under-test.md)
- [SPEC-0039](SPEC-0039-edge-to-datacenter-building-block-cloud.md)
- [Machine-readable product profiles](../../compatibility/product-profiles.yaml)

## Purpose

This specification defines the deployment/evidence profiles through which the
single O3K Cloud OS product is verified and released.

A profile controls dependencies, supported compatibility surfaces, execution
boundaries, database posture, footprint accounting, and release claims.

A feature or measurement from one profile must not be silently promoted to
another.

The profiles do **not** define separate internal cloud architectures. O3K's
canonical architecture is the Cloud Kernel in ADR-0165. ADR-0182/SPEC-0039 add
the scale-continuity rule: edge, cage, private-cloud and future datacenter-scale
profiles are evidence rungs of the same Cloud Operating System rather than
separate products that require replatforming.

## Product identity versus profile identity

The product identity is:

> O3K — a lightweight, open, Rust-native Cloud Operating System with OpenStack
> compatibility and pluggable infrastructure execution, intended to use the
> same cloud authority and product contracts from edge to datacenter.

Current release wording must still identify actual maturity, for example:

> O3K v0.2.0-alpha.1 is a Rust-native OpenStack-compatible libvirt TestLab
> alpha.

The owner-directed release target is `v0.4.1 — Early Access`, governed by
ADR-0191 and SPEC-0052. This is a separate bounded deployment/evidence profile:
Ubuntu 24.04 LTS, one active controller, PostgreSQL 16, KVM/libvirt, initially
one to three hypervisors. It is not supported for customer deployment until its
exact-artifact acceptance gate passes and the owner records GO. This profile
does not imply GA, full production certification, HA, automatic evacuation,
live migration, enterprise SLA, general DR, arbitrary host-count support, or
full OpenStack parity. The existing `v0.4.0` artifact remains immutable and
test-use-only.

"Cloud Operating System" and "edge to datacenter" describe architecture/
direction. They are not evidence for production readiness, HA, full OpenStack
parity, database support, service breadth, arbitrary host counts, or datacenter
scale.

## Profile A — OpenStack service testbed

### User outcome

A developer or CI system can run a selected real OpenStack service against O3K
without installing a complete DevStack/full OpenStack control plane.

The first declared hosted-service scenario is external Cinder.

### O3K responsibilities

Depending on the selected hosted service, O3K may provide declared subsets of:

- O3K IAM exposed through the selected Keystone-compatible authentication,
  token validation, service identity, catalog, region, and endpoint surface;
- Glance-compatible image operations;
- Nova-compatible compute/attachment operations;
- Neutron-compatible network/port behavior;
- Placement-compatible capacity behavior;
- Cloud Kernel operations, audit identity, and ownership state required by the
  selected workflow;
- fake, simulated, or real infrastructure execution appropriate to the test.

### External service responsibilities

The hosted service retains its own:

- service/API implementation;
- supported database and migrations;
- message bus where required;
- scheduler/workers/service processes;
- backend dependencies;
- upgrades, health, and operational ownership.

Catalog registration uses an explicit external-hosted ownership mode.

It must not imply that O3K implements the external service.

### Acceptance

The profile is accepted only when:

- selected external service version is pinned;
- required O3K compatibility operations are frozen;
- service authentication and public token validation pass;
- endpoint discovery passes;
- selected client/Tempest-compatible workflow passes;
- failure boundaries identify O3K versus external-service ownership;
- secrets/connection information are redacted;
- cleanup covers O3K-owned and explicitly managed test resources.

## Profile B — Native O3K Cloud / TestLab

### User outcome

O3K owns the selected Cloud Kernel and cloud-service state and exposes declared
OpenStack-compatible behavior through standard clients.

The internal service domains are O3K domains. OpenStack service names describe
compatibility adapters.

### Current native service direction

The current IaaS roadmap contains:

- O3K IAM with Keystone compatibility;
- O3K Image with Glance compatibility;
- O3K Compute with Nova compatibility;
- O3K Network with Neutron compatibility;
- O3K Capacity/Placement with Placement compatibility;
- O3K Volume with Cinder compatibility.

Future O3K services may exist without a one-to-one historical OpenStack service.
Those services require explicit API/product/evidence profiles before support is
claimed.

### First native milestone

The first real-cloud milestone remains an ephemeral-root libvirt TestLab:

```text
authenticate through Keystone compatibility
-> upload image
-> create network/subnet/port
-> create flavor/keypair
-> allocate compute capacity
-> create and boot server
-> inspect console/lifecycle
-> restart and reconcile
-> delete and prove cleanup
```

Native persistent volumes are later and do not block this guest.

### Cloud Kernel maturity

The TestLab may use a deliberately smaller Cloud Kernel implementation than a
future production cloud.

A release must identify which shared primitives are actually implemented and
verified, including at least:

- IAM/AuthContext subset;
- authorization policy subset;
- resource ownership;
- operations/reconciliation;
- service/catalog registration;
- quota/limit support if claimed;
- audit/event behavior if claimed.

Architecture intent alone does not promote a kernel primitive to supported
status.

## Profile C — Small edge cloud

### User outcome

An operator can run O3K as a lightweight multi-host Cloud OS for approximately
10–20 hypervisors in the initial edge profile.

This profile is the first bounded real multi-host scale rung in the end-to-end
model from ADR-0182/SPEC-0039. It is **not** the product's architectural maximum
and does not prove larger private-cloud or datacenter-scale operation.

Target host-execution topology:

```text
o3kd
  -> o3k-compute
  -> future o3k-network
  -> future o3k-storage
```

Logical execution-provider contracts are required before process extraction.
Future larger profiles may use different internal controller/database/fabric or
scheduler topology while preserving the same O3K cloud authority, IAM, resource,
API, operation, service-catalog and automation model.

### Required edge capabilities

An edge release claim requires evidence for:

- multi-host inventory and scheduling;
- capacity allocations;
- host enrollment, identity, epoch fencing, heartbeat, reconnect, and resync;
- no duplicate mutation after retry/restart/network interruption;
- host-local compute and declared network/storage ownership;
- project/security-scope isolation and authorization;
- quotas/limits where claimed;
- upgrades, backup/restore, diagnostics, rollback;
- resource/latency budgets;
- failure/cleanup behavior across supported host count;
- database profile appropriate to claimed concurrency/availability.

## Future larger private/datacenter scale profiles

Larger O3K profiles are governed by ADR-0182/SPEC-0039.

They are not new product identities. They SHALL preserve the same canonical
cloud model while publishing their own exact evidence for:

- real host count and failure-domain topology;
- control-plane/controller topology;
- database topology;
- scheduler/cell/partition behavior where used;
- fabric/network topology;
- storage topology;
- supported service catalog;
- performance and reconciliation budgets;
- host/block churn and capacity exhaustion;
- rolling upgrade/rollback and failure recovery;
- independent cleanup and foreign-state verification.

Simulation may supplement but does not replace real-host scale evidence.

## Service catalog composition across profiles

Physical scale and service breadth are orthogonal.

A small edge profile may intentionally expose only a minimal native O3K IaaS
catalog, while a cage or datacenter profile may add more capabilities. Conversely,
a specialized edge site may add a service that a larger general-purpose cloud
does not need.

The service catalog SHALL distinguish O3K-native from external-hosted ownership.
Upstream OpenStack services such as Octavia, Designate or Barbican may be added
only through exact versioned dependency-contract discovery and real conformance
evidence as specified by SPEC-0038. OpenStack API presence alone is not proof
that an upstream service is supported.

## Future delegated/federated cloud profiles

An existing cloud control plane is not equivalent to an O3K execution provider.

The following require separate decisions/profiles:

- host an external service in the O3K compatibility catalog;
- trust external identity;
- register O3K endpoints into another identity/catalog system;
- consume another cloud's compute/network/storage/image services;
- federate principals/scopes;
- map resources across clouds;
- delegate lifecycle ownership to an existing OpenStack/vSphere/Proxmox/
  KubeVirt/public-cloud control plane.

No generic "runs on any cloud" or "connects to every OpenStack cloud" claim is
permitted.

## Database profiles

### SQLite

SQLite is the currently supported default for minimal TestLab/portable profiles.

Support requires:

- foreign keys;
- bounded busy timeout;
- reviewed WAL/synchronous policy;
- deterministic migrations;
- concurrent API/reconciler tests;
- crash/restart tests;
- documented backup/restore/checkpoint/filesystem requirements.

A single-controller edge profile may use SQLite only within measured published
limits.

### PostgreSQL

PostgreSQL is the supported production-oriented persistence backend for O3K
(verified against PostgreSQL 16).

SQLite remains the supported default for TestLab and single-controller profiles.

Support is backed by:

- `PostgresStore` implementing all repository ports;
- unified store-conformance suite running identical tests against SQLite and PostgreSQL;
- PostgreSQL migrations matching the initial Cloud Kernel schema;
- transaction and concurrency invariants (fencing, quota advisory locking, error normalization);
- standard backup/restore (`pg_dump` / `psql`);
- process outage and recovery validation;
- portable TestLab and real libvirt gate execution.

Note: PostgreSQL support in P5 is for fresh PostgreSQL deployments. Automatic
SQLite -> PostgreSQL database migration is NOT yet supported. HA / multi-controller
claims remain planned for subsequent milestones (P6+).

## Footprint claims

The minimal O3K control plane targets approximately 50 MB steady-state memory.

Every footprint artifact records:

- exact product/deployment profile;
- included O3K processes;
- excluded/report-separately external processes;
- binary/bundle size separately from RSS;
- source commit/toolchain/build/features;
- host/kernel/filesystem/virtualization context;
- idle/workload phase;
- measurement duration/method.

External Cinder, RabbitMQ, PostgreSQL, libvirt, QEMU guests, Ceph, LVM, and
other external dependencies are not hidden inside an O3K-only number.

## Machine-readable profile registry

`compatibility/product-profiles.yaml` records:

- profile ID/maturity;
- user outcome;
- O3K-owned capabilities;
- external-hosted services;
- database posture;
- execution boundaries;
- compatibility/evidence dependencies;
- release-claim state;
- footprint-claim state.

## Claim states

Claims use independent states:

```text
planned
specified
implemented
portable-verified
component-real-host-verified
full-profile-verified
release-claimed
```

OpenStack compatibility, Cloud Kernel primitives, database, footprint,
metadata, edge scale, larger private/datacenter scale, external service
integration, Kubernetes control-plane deployment, and future native services are
tracked independently.

## Kubernetes control-plane deployment claims

Kubernetes control-plane deployment is an independent claim family governed by
[ADR-0167](../adr/ADR-0167-kubernetes-native-control-plane-deployment.md) and
the `kubernetes_control_plane` rule in `compatibility/product-profiles.yaml`:

- single-controller OCI image + Helm packaging evidence precedes any broader
  claim;
- an HA Kubernetes claim additionally requires the PostgreSQL adapter with
  conformance evidence, durable multi-controller work ownership/fencing, and
  rolling-update, pod-loss, node-drain, and database-failover evidence;
- pod-local filesystem state is never authoritative for recoverable cloud
  state;
- "O3K is Kubernetes-native" without that evidence is an invalid standalone
  claim.

## Required product wording

Valid architectural/product wording:

> O3K is a lightweight, open, Rust-native Cloud Operating System. It preserves
> selected OpenStack compatibility while using its own Cloud Kernel and typed
> infrastructure execution providers, with one product model intended to scale
> from edge to datacenter through capability-bearing building blocks.

Valid current-release wording:

> O3K v0.2.0-alpha.1 is a Rust-native OpenStack-compatible libvirt TestLab
> alpha.

Invalid standalone claims without qualifying evidence include:

- "O3K supports all of OpenStack 2026.1."
- "O3K is production ready."
- "O3K replaces Cinder" when only external Cinder is hosted.
- "O3K runs in 50 MB."
- "PostgreSQL is supported for production."
- "O3K connects to any OpenStack cloud."
- "O3K supports thousands of hosts."
- "O3K creates a production cloud in seconds."
- "Any OpenStack service works automatically with O3K."
- "O3K supports AWS-like databases/AI/Kubernetes" merely because the Cloud
  Kernel is designed to enable future services.

## Release-gate requirements

Every release identifies:

- included deployment/evidence profile(s);
- O3K-implemented versus external-hosted capabilities;
- implemented Cloud Kernel primitives;
- database support state;
- exact OpenStack compatibility operations/microversions;
- component/full-profile evidence;
- footprint measurement or explicit absence;
- exact tested scale where a scale claim is made;
- known limitations and unsupported integrations.
