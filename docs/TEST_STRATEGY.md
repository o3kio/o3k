# Test Strategy

## Goals

Tests provide evidence for compatibility, authorization, state safety,
provider behavior, compensation, recovery, and user workflows. Test count and
coverage percentage are secondary to meaningful behavioral evidence.

The strategy follows an evidence ladder. Expensive privileged tests verify
already specified contracts; they are not the primary mechanism for discovering
missing endpoint requirements.

## Linux guest targets for future qualification

New and future Linux guest qualification uses Debian 13 and Ubuntu 24.04.
Do not provision Debian 12 for new test runs. Preserve existing Debian 12
results as historical evidence without relabeling them or treating them as
Debian 13 evidence. This test-target decision does not itself establish or
remove an installed-platform support claim; those claims remain tied to their
accepted product profile and profile-specific evidence.

## Evidence ladder

```text
spec/schema validation
-> domain/store/migration tests
-> API and policy contract tests
-> provider conformance with stateful fakes
-> portable simulated cloud
-> process-level client tests
-> component real-host gates
-> full-cloud real-host gate
-> failure/restart matrix
-> release gate
```

Every release-critical issue records implementation, portable evidence,
component evidence, full-cloud evidence, and remaining acceptance separately.

## Test layers

### 1. Specification and generated-contract validation

Validate:

- ADR/SPEC/contract links and status;
- service API compatibility manifest;
- OpenAPI and JSON Schema;
- protobuf compatibility;
- generated fixtures and stale-generation checks;
- requirement-to-test traceability;
- unsupported and unadvertised operations.

A route that is not present in the declared profile is unsupported regardless
of implementation presence.

### 2. Domain tests

Fast tests for:

- typed ID/name separation;
- resource validation and ownership;
- lifecycle transition tables;
- quota and authorization decisions;
- idempotency and operation-state rules;
- compensation phase ordering;
- serialization-independent invariants.

Prefer table-driven, property, and state-machine tests.

### 3. Protocol and public API contract tests

For every supported OpenStack operation:

- discovery, request headers, query, path, and JSON validation;
- API version, microversion, and extension behavior;
- status code and response body;
- error envelope;
- token, project, role, and service-identity policy;
- advertised catalog endpoint;
- supported and explicitly unsupported fields;
- restart-stable behavior where required.

Run black-box tests against an in-process router and a real server process.
Use standard OpenStack clients where practical.

### 4. Store and migration tests

The same behavioral suite runs against every store adapter. Required cases:

- migration from every supported previous schema;
- transaction rollback;
- uniqueness and foreign keys;
- concurrent generation conflict;
- restart;
- corrupted/partial state;
- immutable dependency snapshots;
- operation and compensation persistence;
- token and authorization-context persistence boundaries.

### 5. Provider conformance tests

Compute, network, and storage providers each pass a common domain-specific
suite plus shared protocol cases.

#### Shared cases

- capability reporting;
- mTLS identity and agent-epoch fencing;
- command identity and payload-fingerprint conflict;
- create/read/delete idempotency;
- timeout with unknown outcome;
- duplicate command;
- partial completion;
- stale observation and stale generation;
- provider unavailable and reconnect;
- bounded redacted errors;
- ownership ambiguity and foreign-state protection;
- cleanup after failure.

#### Compute cases

- image/config-drive identity;
- create/inspect/start/stop/reboot/delete;
- console bounds and authorization;
- restart discovery;
- no duplicate domain or artifact leak.

#### Network cases

- realize/inspect/remove port binding;
- deterministic MAC/fixed-IP identity;
- TAP/bridge/DHCP reconciliation;
- no duplicate link/lease;
- cleanup and foreign-link protection.

#### Storage cases

- create/inspect/delete volume;
- prepare/terminate attachment;
- secret-safe connection information;
- no duplicate backend resource;
- cleanup and foreign-volume protection.

### 6. Reconciliation and compensation tests

Use deterministic clocks and stateful fakes to test:

- restart after intent persistence;
- restart after external success but before persistence;
- restart after compensation begins;
- bounded retry/backoff;
- terminal failure;
- unknown outcome and observe-before-retry;
- orphan detection;
- reverse-order compensation;
- retained Placement allocation during unknown outcome;
- no duplicate external resource creation;
- stale epoch, stale sequence, and provider-reference conflict.

### 7. Portable simulated-cloud integration

Run the complete public workflow with real:

- Keystone-compatible auth and catalog;
- OpenStack HTTP APIs;
- durable stores and migrations;
- policy and project isolation;
- scheduler and Placement allocations;
- operation journal and reconciler;
- cross-service dependency and compensation logic.

Only provider execution is replaced by deterministic stateful compute, network,
and storage fakes.

Required workflow:

```text
discover -> token -> image -> network/subnet/port
-> flavor/keypair -> server -> console -> stop/start/reboot
-> optional volume/attachment profile -> delete -> restart -> cleanup
```

Inject failure after every durable workflow phase. Test timeout, unknown
outcome, duplicate delivery, cross-project access, insufficient capacity,
stale observations, restart, compensation, and complete cleanup.

This gate must pass before the corresponding full-cloud runner is used as a
release verifier.

### 8. Process-level tests

Start real `o3kd` and provider-agent processes with temporary owned state.
Verify:

- startup and readiness ordering;
- service discovery and OpenStack CLI behavior;
- registration, heartbeat, administrative state, and reconnect;
- process restart with durable identity and journal replay;
- no secret leakage in logs or artifacts;
- source-bound machine-readable evidence.

### 9. Component real-host gates

#### Compute gate

```text
image -> authenticated transfer -> base/overlay -> config-drive
-> libvirt XML/domain -> console -> lifecycle -> cleanup
```

Evidence includes `virsh list --all`, owned domain XML, QEMU state, backing
chain, console, agent journal, restart, and cleanup. A protected bounded
diagnostic hold may preserve the domain before cleanup.

#### Network gate

```text
port intent -> TAP -> bridge -> DHCP/binding -> connectivity
-> restart -> cleanup
```

Evidence includes link ownership, bridge membership, MAC/fixed IP, lease or
binding, connectivity, restart, and foreign-link preservation.

#### Storage gate

Required for the persistent-volume profile:

```text
volume intent -> backend resource -> attachment preparation
-> attach/detach -> delete -> cleanup
```

Evidence excludes raw secret connection information.

### 10. Full-cloud real-host gate

The ephemeral-root alpha runs:

```text
install -> discover -> token -> image -> network -> flavor/keypair
-> Placement -> server -> guest boot -> console
-> o3kd/o3k-compute/libvirt restart -> lifecycle -> delete -> reset
```

Use standard public OpenStack APIs only. The profile must prove real
libvirt/KVM execution through `o3k-compute`, minimum network realization, guest
metadata, and complete cleanup.

Cinder is added only to the later persistent-volume full-cloud profile after
its portable and storage-component gates pass.

### 11. Failure and restart matrix

Required real-host scenarios include:

- control-plane crash before and after dispatch;
- compute/network/storage agent crash before and after mutation;
- libvirt or backend restart;
- network interruption;
- timeout after accepted mutation;
- duplicate delivery;
- artifact corruption and checksum mismatch;
- qemu-img/config-drive/TAP/DHCP/backend failure;
- disk or capacity exhaustion;
- repeated delete and partial cleanup.

No scenario may produce a duplicate resource or modify foreign state.

### 12. Compatibility matrix

Every supported operation links to its executable tests and records:

- specified fields and microversion;
- portable result;
- component result where applicable;
- full-cloud result;
- known deviations;
- release claim.

## Diagnostic mode

Protected component and full-cloud workflows may expose an opt-in diagnostic
hold point that:

- runs only on a trusted manual workflow;
- is source-bound and time-bounded;
- pauses before destructive cleanup;
- shows only O3K-owned host resources;
- uploads redacted evidence;
- always invokes ownership-checked cleanup on timeout or cancellation.

Diagnostic mode never changes a failed result into passing evidence.

## Security testing

- authn/authz and service-token negative cases;
- tenant isolation and project ID/name confusion;
- service catalog omission for unsupported services;
- secret redaction;
- malformed and oversized input;
- path, symlink, XML, object-key, and artifact safety;
- agent certificate/epoch fencing;
- minimum capabilities and non-root execution;
- foreign-resource preservation;
- dependency, advisory, license, SBOM, and provenance checks;
- unsafe/native boundary tests when introduced.

## CI gates

### Fast PR gate

- actionlint and workflow validation;
- formatting;
- cargo check;
- Clippy with warnings denied;
- governed nextest PR profile with zero retries;
- doctests;
- affected contract, migration, fixture, shell, and Python tests;
- generated-file drift.

### Deep portable gate

- full workspace tests;
- portable simulated cloud;
- process/restart tests;
- compatibility target tests;
- coverage as a diagnostic signal;
- selected Miri/fuzz/property tests;
- cargo-deny, cargo-audit, SBOM, and provenance.

### Protected component gates

Run only for changes affecting their actual host execution boundaries.

### Full-cloud and release gates

Run after required portable and component evidence passes. A skipped runner is
not a pass. Release evidence must be source-bound, redacted, retained, and
machine-readable.
