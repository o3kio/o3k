# Project Charter

## Purpose

O3K is a lightweight, open, Rust-native **Cloud Operating System**.

Its long-term architecture is deliberately different from a historical
OpenStack reimplementation:

- OpenStack APIs remain first-class compatibility contracts;
- the O3K Cloud Kernel is the canonical internal platform;
- O3K IAM is the canonical identity/authorization model;
- first-class cloud services share common resource, policy, quota, operation,
  audit, event, and service-registry primitives;
- infrastructure execution is pluggable through typed provider boundaries;
- existing external clouds use explicit delegated/federated authority models,
  not the same abstraction as libvirt or Ceph.

O3K is intended to become a next-generation OpenStack in the architectural
sense: preserve useful OpenStack ecosystem compatibility while rebuilding the
cloud control plane around cleaner shared primitives and lower operational
complexity.

This is a product/architecture direction, not a claim of current production
maturity or complete OpenStack parity.

The normative Cloud OS decision is
[ADR-0165](adr/ADR-0165-o3k-cloud-operating-system-and-cloud-kernel.md).

## Current release reality

O3K is pursuing an owner-directed **Early Access** baseline for Ubuntu 24.04,
one active controller, PostgreSQL 16, KVM/libvirt, and one to three
hypervisors. The candidate profile is for development, test, and selected
replaceable non-critical semi-production workloads. Customer deployment is
not authorized until the SPEC-0052 bounded evidence gate passes on an exact
authenticated release artifact and the owner approves publication.

The target is `v0.4.1`, titled **O3K v0.4.1 — Early Access**, subject to
repository versioning and protected release workflow. This is not GA or full
production certification. No HA, automatic evacuation, live migration,
enterprise SLA, general disaster-recovery, or broad OpenStack parity claim is
made. PP.5, PP.6, and PP.7 are no longer mandatory predecessors for this
objective; their remaining requirements are transferred to future milestones
without changing any evidence state. The accepted owner decision is ADR-0191;
the profile and gate are SPEC-0052.

The immutable `v0.4.0` artifact remains test-use-only and retains its pinned
C1 authority. It is not an Early Access release and must not be retagged or
replaced.

## Product promises

O3K will:

- expose only specified, implemented, evidence-backed compatibility behavior;
- keep OpenStack protocol models separate from the canonical O3K domain;
- make identity/authorization a shared Cloud Kernel concern rather than
  service-specific plumbing;
- give every first-class O3K service one common resource ownership and
  authorization model;
- keep desired state, operations, scheduling, compensation, and reconciliation
  under O3K authority for O3K-owned resources;
- separate cloud authority from bounded host/provider execution;
- recover safely from interruption, duplicate delivery, stale observations, and
  unknown outcomes;
- use standard QEMU/KVM through libvirt as the first primary real compute
  execution backend;
- retain CellHV and future infrastructure implementations behind typed
  capability/provider contracts;
- add network/storage process boundaries only when privilege, locality, scaling,
  or failure isolation justifies them;
- make future cloud services materially cheaper to add by reusing IAM,
  authorization, ownership, quotas/limits, operations, audit/events, and service
  registration;
- keep external service and delegated-cloud authority explicit;
- remain operable by small infrastructure teams;
- publish source-bound evidence for compatibility, recovery, security,
  performance, footprint, and cleanup claims.

## O3K Cloud Kernel

The shared Cloud Kernel provides stable platform contracts for:

- principals and service identity;
- authentication context;
- authorization;
- resource identity and ownership/security scope;
- service registry/capability discovery;
- quotas and limits;
- durable operations;
- audit and events;
- regions and availability domains;
- compensation and reconciliation;
- shared failure/evidence identity.

Metering/billing, secrets, richer organization/account hierarchy, and other
platform-wide services may be added by later accepted decisions.

They are not implied to be implemented today.

## OpenStack compatibility

OpenStack remains strategically important.

The compatibility direction is:

```text
Keystone  -> O3K IAM adapter
Glance    -> O3K Image adapter
Nova      -> O3K Compute adapter
Neutron   -> O3K Network adapter
Placement -> O3K Capacity/Placement adapter
Cinder    -> O3K Volume adapter
```

The OpenStack client ecosystem—CLI, SDKs, Terraform, service integrations, and
operator knowledge—should continue to work for declared compatibility profiles.

Endpoint count or nominal support for an entire OpenStack release is not progress
by itself.

## Deployment/evidence profiles

O3K has one product identity with three primary profiles.

### 1. OpenStack service testbed

A real OpenStack service such as Cinder runs independently while O3K supplies
the selected compatibility APIs and Cloud Kernel state required by the test
workflow.

The hosted service keeps its own database, message bus, processes, backend,
migrations, upgrades, and operational ownership.

O3K must never present an external-hosted service as O3K-implemented.

### 2. Native O3K Cloud / TestLab

O3K owns the selected Cloud Kernel and service-domain state.

The first native milestone is an ephemeral-root QEMU/KVM TestLab through the
selected Keystone/Glance/Neutron/Placement/Nova compatibility workflow.

Native persistent volumes follow later.

### 3. Small edge cloud

O3K grows into a lightweight multi-host Cloud OS targeting approximately
10–20 hypervisors in the initial edge profile.

Multi-host scheduling, fencing, restart, database, network, storage, upgrade,
backup/restore, security, and operational claims require profile-specific
evidence.

The normative profile/claim rules are
[ADR-0163](adr/ADR-0163-product-profiles-and-deployment-posture.md) and
[SPEC-0024](specs/SPEC-0024-product-profiles-and-claims.md).

### 4. Kubernetes-native control-plane deployment

Kubernetes is a first-class deployment target for the O3K control plane
([ADR-0167](adr/ADR-0167-kubernetes-native-control-plane-deployment.md)), not a
Cloud Kernel dependency and not the tenant-resource database. Single-controller
OCI/Helm packaging precedes any HA claim; HA additionally requires PostgreSQL,
durable work ownership/fencing, and failure evidence.

## Infrastructure authority

For O3K-owned resources:

```text
user intent
-> O3K Cloud Kernel
-> O3K scheduling/orchestration
-> typed execution contract
-> infrastructure provider
-> observation
-> O3K reconciliation
```

The provider does not invent O3K public identities, authorize tenants, or
rewrite O3K desired state.

An existing external cloud is different. It already has its own scheduler,
policy, quotas, resource identity, and lifecycle authority. Such systems require
a separately accepted delegated/federated connector model.

## Primary users

1. infrastructure operators building small private/edge clouds;
2. OpenStack developers and CI systems needing a lightweight surrounding
   control plane;
3. SDK/Terraform/storage/network/identity teams running reproducible integration
   scenarios;
4. future O3K service developers who need a shared cloud platform rather than
   per-service IAM/orchestration plumbing;
5. MSPs/SMEs evaluating a smaller open private-cloud operating model.

## First release outcome

A user can install the native TestLab profile on one supported Linux node and:

- authenticate using the selected OpenStack-compatible identity flow;
- upload an image;
- create the selected network/subnet/port resources;
- create flavor/keypair;
- allocate compute capacity;
- boot a real QEMU/KVM guest through `o3k-compute`;
- inspect lifecycle/console state;
- restart `o3kd`, `o3k-compute`, and libvirt;
- reconcile without duplication;
- delete and prove complete O3K-owned cleanup;
- leave foreign state unchanged.

The first alpha uses config-drive/cloud-init for guest metadata.

The external-Cinder testbed may progress in parallel but does not replace or
block this release unless a later accepted decision changes the gate.

## Database posture

- SQLite is the currently supported default for minimal TestLab/portable
  profiles.
- SQLite support includes explicit concurrency/WAL/crash/migration/
  backup-restore/filesystem constraints.
- PostgreSQL is the intended production-oriented profile.
- PostgreSQL is not currently a supported production claim until its adapter and
  evidence gates pass.

## Footprint posture

The minimal O3K control plane targets approximately 50 MB steady-state memory.

This is a measured target, not a blanket guarantee.

Every footprint claim names the exact profile, processes, build, host, workload,
measurement method, and excluded external dependencies.

## Development model

O3K uses a contract-first evidence ladder:

```text
ADR/SPEC/contract
-> domain/store/policy/provider tests
-> portable simulated cloud
-> process/public-client tests
-> execution component gates
-> full-profile/hosted-service runner
-> failure/restart matrix
-> release gate
```

The protected runner verifies integration. It is not the requirements-discovery
loop for random endpoint growth.

## Governance

- Apache-2.0 source code;
- public issues, ADRs, specs, contracts, tests, compatibility manifests, and
  evidence;
- issue-driven changes;
- human approval for architecture, IAM/security, public contracts, persistence,
  privileged execution, destructive cleanup, and release decisions;
- LLM agents may research/implement/review but do not replace human product or
  security approval;
- accepted ADRs are authoritative and superseded decisions remain historical;
- product vision never overrides executable release evidence.

## Success measures

Long-term success includes:

- time from clean host to first useful cloud resource;
- time/effort to add a new first-class O3K cloud service;
- percentage of new services using shared IAM/authorization/resource/operation
  contracts without service-local reimplementation;
- deterministic restart/recovery/cleanup;
- zero foreign-resource mutation in acceptance tests;
- compatible OpenStack client journeys for declared profiles;
- measured per-profile CPU/memory/startup/lifecycle footprint;
- successful small edge-cloud pilots;
- clear diagnosis of failures at Cloud Kernel, service, execution, or
  external-hosted boundaries.

## Explicit non-goals for the bootstrap and first alpha

- complete OpenStack API parity;
- implementing every Keystone/Nova/Neutron/Cinder endpoint;
- implementing the full future Cloud Kernel before the first libvirt alpha;
- managed database, Kubernetes, AI, serverless, or other future service breadth
  merely to justify the Cloud OS name;
- immediate organization/account hierarchy;
- broad federation or unspecified cross-cloud interoperability;
- production SLA/HA/PostgreSQL/fixed-footprint claims without evidence;
- support for every hypervisor/network/storage backend;
- one daemon/crate per historical OpenStack service;
- a generic provider abstraction that treats an existing cloud control plane as
  equivalent to libvirt;
- direct source compatibility or mechanical translation from another O3K
  implementation.

Normative ownership is listed in
[`docs/NORMATIVE_SOURCES.md`](NORMATIVE_SOURCES.md).
