# SPEC-0021 — Cross-service workflows and compensation

Status: Proposed

Related decisions:

- [ADR-0160](../adr/ADR-0160-service-topology-and-execution-boundaries.md)
- [ADR-0166](../adr/ADR-0166-o3k-iam-and-keystone-compatibility-boundary.md) (supersedes ADR-0161)
- [execution boundary contract](../../contracts/execution-boundaries.md)

## Purpose

This specification defines how O3K coordinates identity, image, compute,
network, placement, and volume behavior without treating database transactions
as substitutes for provider-side recovery.

The workflows apply whether the logical services execute inside `o3kd` or are
later separated. Every external mutation has a durable operation identity,
explicit ownership, an observable outcome, and a compensation rule.

## Common workflow rules

### Authorization

- validate one normalized `AuthContext` before resource lookup or mutation;
- preserve the user/project context and service identity through internal calls;
- reject project path mismatch, disabled resources, and missing policy before
  provider dispatch;
- use durable IDs internally; names are resolved only at supported public
  boundaries.

### Intent and operation persistence

Before an external side effect, persist:

- resource ID and project ownership;
- immutable request snapshot;
- desired state;
- operation ID;
- idempotency identity;
- dependency IDs;
- selected host or backend when selected;
- current workflow phase;
- compensation state.

### External execution

- dispatch typed commands only;
- include operation, resource, agent/backend, generation, deadline, and
  idempotency identity;
- accept provider success only with a matching observation;
- classify timeout or connection loss after dispatch as unknown outcome;
- observe before repeating a mutation;
- reject stale agent epochs, stale generations, conflicting provider IDs, and
  mismatched resources.

### Compensation

- compensation executes in reverse dependency order;
- compensation is itself durable and idempotent;
- a compensation timeout is an unknown outcome, not proof of absence;
- allocations and ownership are retained while an external resource may still
  exist;
- foreign resources are never adopted or removed implicitly;
- a server lifecycle releases only the endpoints it created. Ownership is decided
  from durable endpoint identity (the reserved server-owned name of the
  addressed project), never from a reference in the server intent: an endpoint
  the caller created and the server merely attaches is preserved, a foreign
  project's endpoint is never removed, and an already-absent endpoint is
  idempotent success;
- endpoint release follows that endpoint's terminal unbind, because the binding
  teardown plan reads the durable endpoint it has to remove, and it is driven by
  the terminal outcome of the server operation rather than by the request that
  happened to observe it, so a non-blocking (accepted) delete converges on the
  same durable state as a synchronous one.

## Server create workflow

### Preconditions

The request requires:

- valid project-scoped `AuthContext`;
- supported Nova request and microversion;
- active image visible to the project;
- immutable flavor snapshot;
- owned keypair where requested;
- valid network/subnet/port dependencies;
- enabled compute host inventory sufficient for the allocation;
- no conflicting idempotency record.

### Normal phases

```text
VALIDATED
-> SERVER_INTENT_PERSISTED
-> PLACEMENT_ALLOCATED
-> PORTS_RESERVED_OR_CREATED
-> IMAGE_ACCESS_AUTHORIZED
-> COMPUTE_COMMAND_DISPATCHED
-> COMPUTE_ARTIFACTS_REALIZED
-> NETWORK_BINDING_REALIZED
-> DOMAIN_DEFINED
-> DOMAIN_STARTED
-> GUEST_OBSERVED
-> ACTIVE
```

The first implementation may combine adjacent phases, but evidence and
recovery must still identify the completed boundary.

### Responsibilities

#### Keystone-compatible identity

- validates user/project scope and policy;
- supplies audit and request identity;
- authenticates service identity for internal work.

#### Glance-compatible image service

- authorizes image visibility;
- supplies immutable content identity, size, checksum, and format;
- returns content through an authenticated bounded interface;
- does not supply arbitrary host paths to Nova or agents.

#### Nova-compatible compute service

- owns server intent and public state;
- snapshots flavor, image, keypair, and requested network dependencies;
- requests Placement allocation;
- coordinates port binding intent;
- dispatches compute execution;
- projects observed state into Nova-compatible status.

#### Placement-compatible service

- selects and allocates VCPU, MEMORY_MB, and DISK_GB resources;
- uses generation-protected inventory and allocation updates;
- retains allocation during unknown provider outcome;
- releases allocation exactly once after proven terminal failure or deletion.

#### Neutron-compatible network service

- owns network, subnet, port, MAC, and fixed-IP intent;
- creates or reserves ports before compute dispatch;
- records binding host and binding state;
- receives execution observation from the network provider;
- does not infer guest connectivity from Nova ACTIVE alone.

#### Compute provider

- realizes the image and config-drive;
- constructs a deterministic owned domain;
- attaches the network interfaces described by typed bindings;
- starts, stops, reboots, inspects, and deletes the domain;
- reports observations without becoming authoritative for project policy.

#### Network provider

- realizes TAP, bridge, DHCP, routing, and policy state assigned to it;
- reports binding and connectivity observations;
- cleans only O3K-owned resources.

### ACTIVE criteria

Nova may report ACTIVE only when the selected profile's required observations
are satisfied. For the first libvirt TestLab profile:

- the owned libvirt domain exists and is running;
- the root artifact and config-drive are attached;
- expected port/MAC binding is present;
- no terminal operation error is pending.

Guest boot, DHCP lease, cloud-init consumption, and console marker are separate
acceptance evidence. The profile may choose whether they gate ACTIVE, but the
choice must be explicit and must not be misrepresented in release claims.

### Failure and compensation

#### Before compute dispatch

Compensate synchronously where possible:

1. release created/reserved ports;
2. release Placement allocation;
3. mark server ERROR or remove unaccepted intent according to the public
   contract.

#### After compute dispatch with known terminal failure

1. inspect for any provider resource;
2. delete proven owned compute resource;
3. remove network execution state;
4. release or delete ports;
5. release Placement allocation;
6. record terminal server error and evidence.

#### Unknown outcome

- retain server intent, provider command identity, ports, and allocation;
- mark the operation unknown/reconciling;
- observe the selected provider before any create retry;
- adopt only a resource carrying the exact O3K ownership identity;
- never create a second domain because the first response was lost.

## Server lifecycle actions

### Inspect

- reads durable server/host binding;
- dispatches a typed read-only provider command;
- verifies project and resource identity before dispatch;
- does not create a provider resource when missing;
- updates observed state only from accepted current observations.

### Stop and start

- persist desired state and operation before dispatch;
- repeated requests use deterministic operation/idempotency behavior;
- Nova state reflects observed provider state;
- timeout retains unknown outcome until inspected.

### Hard reboot

- uses one durable operation identity;
- preserves server, ports, disks, and allocation;
- does not implement reboot as delete/recreate;
- verifies the same provider resource remains owned by the server.

### Delete

```text
DELETE_REQUESTED
-> DOMAIN_STOPPED_OR_ABSENT
-> DOMAIN_UNDEFINED_OR_ABSENT
-> NETWORK_EXECUTION_REMOVED
-> PORTS_RELEASED_OR_DELETED
-> ARTIFACTS_REMOVED
-> ALLOCATION_RELEASED
-> DELETED
```

Delete is idempotent. A missing owned provider resource is acceptable only
after identity-safe observation. Foreign or ambiguous resources cause a
fail-closed terminal or operator-visible condition.

## Volume create workflow

Cinder-compatible volume work is a separate milestone and does not block the
first ephemeral-root guest.

### Normal phases

```text
VALIDATED
-> VOLUME_INTENT_PERSISTED
-> BACKEND_SELECTED
-> STORAGE_COMMAND_DISPATCHED
-> BACKEND_RESOURCE_OBSERVED
-> AVAILABLE
```

The storage provider returns an opaque provider reference and capabilities. The
control plane owns project, volume type, size, status, attachment state, and
public error behavior.

## Volume attachment workflow

### Preconditions

- valid dual user/service authorization context;
- volume AVAILABLE and owned or shared according to policy;
- server owned by the project and in a valid state;
- backend and compute host support a compatible attachment mode;
- no conflicting attachment exists.

### Normal phases

```text
ATTACHMENT_RESERVED
-> STORAGE_PREPARED
-> CONNECTION_INFO_AVAILABLE
-> COMPUTE_ATTACH_DISPATCHED
-> DEVICE_OBSERVED
-> ATTACHED
```

Connection information is secret-bearing operational data. It is bounded,
redacted, encrypted or protected at rest where required, and never returned to
unauthorized callers or uploaded as general CI evidence.

### Compensation

If compute attach fails terminally:

1. prove whether the device is attached;
2. detach if attached and owned;
3. terminate storage-side connection preparation;
4. return the volume to AVAILABLE when safe;
5. preserve an ERROR attachment state when outcome remains unknown.

## Cross-service restart behavior

After `o3kd` restart:

- persisted workflow phases are loaded;
- incomplete operations are not blindly replayed;
- allocations, ports, attachments, and provider commands are inspected;
- service authorization and project ownership are revalidated for operator or
  user-triggered actions;
- automatic reconciliation uses the persisted original project and service
  context, not a fabricated bootstrap admin request.

After execution-agent restart:

- in-flight local journal entries become unknown outcome unless a terminal
  result was durably recorded;
- committed artifacts and ownership manifests are rediscovered;
- the agent reconnects with a new fenced epoch;
- terminal results may be replayed idempotently;
- stale observations from earlier epochs are rejected.

## Required portable tests

- complete fake-provider server lifecycle through public APIs;
- failure at every phase with reverse compensation;
- timeout after accepted mutation;
- duplicate request and duplicate provider command;
- `o3kd` restart at every persisted phase;
- agent restart with accepted/running/terminal journal state;
- stale observation and agent epoch;
- provider-reference conflict;
- insufficient Placement capacity before dispatch;
- port conflict and fixed-IP conflict;
- cross-project and service-identity denial;
- volume create and attachment fake workflows when Cinder baseline is enabled.

## Required real-host evidence

### Compute component

- actual image/base/overlay chain;
- actual libvirt XML and running domain;
- console and lifecycle actions;
- same resource identity across supported restarts;
- complete compute-owned cleanup.

### Network component

- actual TAP/bridge/DHCP state;
- expected MAC/fixed-IP binding;
- observed connectivity evidence;
- complete network-owned cleanup.

### Storage component

- actual backend volume;
- attachment preparation and cleanup;
- no secret connection information in artifacts;
- complete storage-owned cleanup.

### Full cloud

- standard OpenStack CLI only;
- service catalog discovery;
- real guest and required observations;
- restart/reconciliation matrix;
- no owned-resource leak;
- unchanged foreign state.
