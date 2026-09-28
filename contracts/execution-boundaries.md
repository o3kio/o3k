# O3K execution-boundary contract

Status: Proposed

Related decisions:

- [ADR-0160](../docs/adr/ADR-0160-service-topology-and-execution-boundaries.md)
- [ADR-0166](../docs/adr/ADR-0166-o3k-iam-and-keystone-compatibility-boundary.md) (supersedes ADR-0161)
- [ADR-0168](../docs/adr/ADR-0168-o3k-routed-fabric-and-network-execution.md)
- [ADR-0169](../docs/adr/ADR-0169-native-persistent-storage-and-o3k-storage-boundary.md)
- [ADR-0170](../docs/adr/ADR-0170-namespaced-routed-edge-fabric.md) (Accepted)
- [SPEC-0021](../docs/specs/SPEC-0021-cross-service-workflows-and-compensation.md)
- [SPEC-0028](../docs/specs/SPEC-0028-namespaced-routed-edge-fabric-v1.md) (Accepted)
- [P11 edge-fabric contract](edge-fabric-v1.md) (Accepted)
- [ADR-0186](../docs/adr/ADR-0186-stretched-l2-edge-fabric-vxlan-her.md) (Accepted)
- [SPEC-0049](../docs/specs/SPEC-0049-stretched-l2-edge-fabric-v3.md) (Accepted)
- [P11 stretched-L2 contract](edge-fabric-stretched-l2.md) (Accepted)

## Purpose

This document defines the public architectural contract between `o3kd` and the
host-local execution capabilities represented by:

- `o3k-compute`;
- `o3k-network`;
- `o3k-storage`.

The current protobuf schema may implement only a subset. New wire fields or
actions must preserve these authority, identity, security, retry, and evidence
rules.

Accepted P11 fabric additions remain bounded by the active P11 authority
ADR-0186/SPEC-0049 and the evidence gates; historical ADR-0170/0171 and
SPEC-0028/0029 details remain applicable only where the successor explicitly
retains them. Acceptance does not itself establish runtime or product claims.

## Authority boundary

### `o3kd` is authoritative for

- user, project, service, and policy identity;
- public OpenStack/O3K resource IDs and representations;
- desired state;
- immutable request snapshots;
- operation identity and workflow phase;
- scheduling and Placement allocation;
- endpoint-to-host placement and derived multi-host fabric intent;
- retry, compensation, and reconciliation decisions;
- compatibility behavior and public errors.

### Execution agents are authoritative only for

- their current capabilities and health;
- provider-native resource IDs;
- whether an owned provider resource exists;
- provider-native observed state;
- bounded local artifact and host-resource state;
- redacted provider failure classification.

An agent cannot authorize a project, select a tenant, allocate control-plane
capacity, choose a new workload/endpoint host, or create a new public O3K
resource identity.

## Common command envelope

Every mutating or inspecting command includes:

```text
protocol_version
command_id
operation_id
idempotency_key
resource_id
resource_generation
project_id or opaque authorization binding
target_agent_id
target_agent_epoch
deadline
trace_id / request_id
action
canonical_payload_fingerprint
```

A profile may add another bounded generation/fence such as the P11 host-fabric
generation, but it cannot weaken the common identities above.

Requirements:

- identities are bounded typed values;
- `command_id` is deterministic where replay is required;
- the payload fingerprint is derived from canonical typed content;
- a command is accepted only by the selected current agent epoch;
- deadline expiry prevents new mutation but does not erase a previously
  accepted outcome;
- the agent persists acceptance before external mutation;
- the same identity with different payload is a conflict;
- a duplicate equivalent command replays durable status rather than mutating
  again.

Raw user tokens, passwords, private keys, service credentials, WireGuard private
keys, and unrestricted provider payloads are forbidden in the envelope.

## Common response and event types

The protocol distinguishes:

- registration result;
- heartbeat and administrative-state acknowledgement;
- command accepted;
- operation update;
- observation;
- artifact acknowledgement/status;
- resync request;
- typed protocol error.

Command acceptance is not resource success. Operation completion is not
accepted unless its identity and generation match the durable operation.

## Observation contract

An observation includes:

```text
agent_id
agent_epoch
resource_id
provider_resource_id
operation_id
resource_generation
observation_sequence
observed_at
operation_state
resource_state
error_category
redacted_message
optional bounded typed evidence
```

Requirements:

- sequence is monotonic within an agent epoch;
- stale epochs and stale generations are rejected;
- provider-resource identity cannot change silently;
- unknown outcome is preserved until observation resolves it;
- observations cannot create an unknown control-plane resource;
- observations cannot change project ownership or endpoint placement;
- console or diagnostic bytes are bounded and separately authorized;
- provider paths are never returned as public API fields;
- secret-bearing storage connection data and private fabric key material never
  enter ordinary observations/evidence.

## Capability contract

Capabilities are typed, versioned, and bounded. They include only facts needed
for scheduling or compatibility decisions.

### Compute examples

- architecture;
- vCPU and memory capacity;
- local disk capacity;
- supported machine, firmware, disk, console, and lifecycle features;
- artifact-transfer support;
- config-drive support;
- libvirt/QEMU versions where safe to report.

### Network examples

- flat, routed, VLAN, VXLAN, bridge, OVS, or OVN modes;
- IPv4/IPv6 and DHCP support;
- MTU bounds;
- routing, NAT, and policy features;
- local/regional L2-adjacency scope;
- overlapping-address-realm support;
- route/neighbor/fabric realization capability;
- encrypted-host-transport capability;
- supported port-binding modes.

A P11 fabric capability describes bounded behavior, not raw WireGuard
configuration or a private key.

### Storage examples

- backend type;
- capacity and allocation unit;
- volume, snapshot, clone, encryption, and attachment capabilities;
- supported connection modes;
- attachment/placement scope;
- backend availability zone or failure domain.

A capability is not support evidence until the conformance suite and required
real-host gate pass.

## Compute actions

The first compute contract may include:

- create instance;
- inspect instance;
- start instance;
- stop instance;
- hard reboot instance;
- delete instance;
- read bounded console output;
- query committed artifact status;
- reconcile owned resources.

A create command references immutable, already-authorized inputs:

- server ID and project binding;
- flavor snapshot;
- image content identity, digest, size, and format;
- config-drive identity and digest;
- typed network attachments;
- expected ownership metadata;
- resource limits and deadline.

It must not contain a control-plane filesystem path.

Compute-owned state includes only O3K-owned:

- domain metadata and provider ID;
- image/base references and instance overlay;
- config-drive;
- console artifact;
- compute-local journal and manifests.

## Network actions

The network contract is logically independent from compute. ADR-0168 activates
`o3k-network` as the bounded node-local network executor; it remains subordinate
to control-plane desired state and scheduling authority.

The network contract may include:

- realize/inspect/remove endpoint or port binding;
- configure/reconcile DHCP state;
- realize/inspect/reconcile semantic node network plans;
- realize/inspect/reconcile routing, NAT, public-address and policy state for
  activated profiles;
- inspect connectivity evidence;
- reconcile owned links, leases, routes, policy and neighbor state.

A binding command references:

- network/AddressRealm, subnet and port/endpoint IDs;
- project binding;
- selected host;
- MAC;
- fixed IP;
- CIDR, gateway, allocation context, DNS, and MTU as required;
- provider-network identity;
- security-policy reference when the selected profile supports it.

Network-owned state includes only proven O3K-owned:

- TAP or equivalent interface;
- realm bridge/OVS/OVN binding record selected by the activated provider;
- DHCP host/lease/config fragment;
- routing/NAT/policy state in supported profiles;
- provider-owned namespace/veth/neighbor/fabric state in supported profiles;
- network-local journal and manifests.

The network executor cannot allocate a different public fixed IP or MAC, change
AddressRealm/project ownership, or select a different endpoint host without an
accepted control-plane operation.

### Historical P11 v1/v2 namespaced routed-fabric actions

The following semantic actions document the historical routed/Geneve provider
surface from ADR-0170/SPEC-0028 and ADR-0171/SPEC-0029. They remain relevant
only to retained v1/v2 implementations; new v3 work follows the section below.

- realize/inspect/remove one host-local AddressRealm L2 island;
- realize/inspect/remove one routed AddressRealm namespace attachment;
- apply/inspect endpoint anti-spoofing and local bridge policy;
- publish/withdraw current remote proxy-neighbor entries from a control-plane
  derived realm endpoint directory;
- publish/withdraw current endpoint-location routes, normally IPv4 `/32`;
- realize/inspect one host fabric identity and encrypted transport;
- reconcile current fabric peer/public-key/route state;
- perform bounded neighbor convergence after accepted endpoint placement change.

The exact wire action names may differ. The semantic authority may not.

A P11 realm/fabric command references typed accepted state such as:

```text
realm_id / project binding
endpoint_id / endpoint generation
fixed IP / canonical endpoint MAC
selected endpoint host / placement generation
current realm endpoint directory generation
current target host fabric public identity/generation
semantic policy generation
MTU capability/selection
```

It must not carry raw `ip`/`bridge`/`nft`/`wg` command text as canonical
application intent.

### Historical P11 v1/v2 neighbor and fabric invariants

- same-host/same-realm endpoints may use normal ARP and actual endpoint MACs;
- local bridge forwarding must remain subject to accepted endpoint anti-spoofing
  and NetworkPolicy;
- remote same-realm ARP is answered locally only for a current accepted remote
  endpoint and uses the deterministic AddressRealm proxy MAC;
- remote endpoint actual MACs are not presented as cross-host L2 reachability;
- ARP/Ethernet broadcast is not flooded across the P11 host fabric;
- remote endpoint routes follow current accepted endpoint placement rather than
  assigning a tenant subnet permanently to a host;
- one shared host fabric serves multiple realms; one WireGuard interface/key per
  tenant is not the P11 authority model;
- fabric forwarding is default-deny and route presence alone does not authorize
  cross-realm traffic;
- P11 v1 rejects overlapping active prefixes across the shared routed fabric;
- WireGuard provides transport encryption/authentication only; AddressRealm and
  NetworkPolicy remain the tenant isolation/authorization authority;
- WireGuard private keys remain host-local and are never protocol payload or
  ordinary evidence.

See `contracts/edge-fabric-v1.md` and the historical v2 realm-overlay contract
for those providers. They do not override the active v3 contract.

### P11 v3 stretched-L2 actions and invariants

Under ADR-0186/SPEC-0049, the network executor additionally supports semantic
actions equivalent to:

- realize/inspect/remove one per-realm VXLAN binding and learning attachment;
- publish/withdraw the bounded head-end-replication flood list derived from the
  accepted realm endpoint directory;
- reconcile current enrolled WireGuard peers and realm VTEP transport identity;
- inspect/reconcile VNI-to-realm bindings, source-host authentication, and
  generation fences;
- apply/inspect mandatory local TAP/bridge source-MAC, source-IP, ARP-sender,
  and NetworkPolicy enforcement;
- rebuild provider FDB cache after restart without treating it as placement
  authority.

V3 commands reference the same typed canonical identity and generation fields
listed above, plus the current realm VNI/binding generation and flood-list
generation. They never carry raw provider commands or accept a tenant-supplied
VNI, VTEP, MAC, or transport identity.

V3 invariants are:

- each active realm has exactly one current VXLAN binding per host;
- HER targets only enrolled peers currently hosting endpoints in that realm;
- unknown/stale VNI, VTEP, source-host, placement, or generation fails closed;
- actual endpoint MACs may cross hosts, while anti-spoof and NetworkPolicy are
  enforced before guest delivery;
- WireGuard authenticates/encrypts host transport only and never carries tenant
  endpoint prefixes in AllowedIPs;
- provider learning/FDB state is cache, not placement authority, and foreign
  VXLAN/FDB/WireGuard state is never adopted or deleted.

## Storage actions

The storage contract is activated by the persistent-volume profile.

The first storage contract may include:

- create volume;
- inspect volume;
- delete volume;
- prepare attachment;
- terminate attachment;
- create/delete snapshot where declared;
- reconcile owned backend resources.

A volume command references:

- volume ID and project binding;
- immutable size and volume-type snapshot;
- selected backend and availability/failure domain;
- encryption reference when supported;
- attachment identity and selected compute host where applicable.

Storage-owned state includes only O3K-owned:

- backend volume/provider ID;
- attachment/session preparation;
- backend-local journal and ownership metadata.

Connection information is treated as secret-bearing operational data. It is
never logged or uploaded as ordinary CI evidence and is returned only through a
bounded authenticated path.

P11 scheduling consumes storage placement/attachment scope but does not transfer
storage placement authority into the network or compute executor.

## Artifact transfer

Artifact transfer uses:

- deterministic transfer ID;
- command, operation, resource, and agent identity;
- artifact kind;
- immutable artifact ID;
- byte length;
- digest;
- bounded chunk size/count;
- expiry;
- accepted/receiving/committed/rejected state.

Requirements:

- bytes are authenticated and digest-verified;
- partial content is never trusted as committed;
- publication is atomic;
- expired offers cannot begin new transfer;
- committed artifacts required for cleanup remain identifiable after the
  original offer expires;
- symlinks, special files, path traversal, and user-selected host paths are
  rejected;
- cleanup is ownership-checked and reference-aware.

## Error model

Errors use stable categories rather than unbounded provider text:

- invalid request;
- authorization binding failure;
- unsupported capability;
- conflict;
- not found;
- capacity exhausted;
- transient unavailable;
- timeout;
- unknown outcome;
- terminal provider failure;
- ownership ambiguity;
- internal protocol failure.

The redacted message is bounded and contains no secret, raw command, provider
connection information, private key, arbitrary XML, or filesystem path unless a
separately protected operator artifact explicitly allows a safe relative
identifier.

## Security and privilege rules

- all network connections use mutually authenticated transport;
- certificate identity binds to the agent ID;
- old agent epochs are fenced;
- each agent runs with the minimum documented account/privileges required for
  its activated actions;
- compute, network, storage and P11 fabric privilege sets are reviewed
  independently;
- an agent rejects commands outside its activated capability domain;
- foreign resources are never mutated or deleted;
- ambiguous ownership fails closed;
- destructive cleanup requires deterministic ownership evidence;
- host private fabric keys remain local and are excluded from control-plane
  state/protocol/log/audit/evidence;
- control-plane or fabric disconnection never proves an old VM/storage writer is
  stopped; duplicate execution requires an independently accepted fencing proof.

## Reconnect and replay

On connection loss:

- the agent remains alive unless a local fatal error or shutdown occurs;
- readiness becomes false while disconnected;
- reconnect uses bounded exponential backoff;
- a new epoch is registered;
- accepted/running local journal entries become unknown outcome unless a
  terminal result was durably recorded;
- terminal results and artifact status may be replayed idempotently;
- the control plane observes before redispatching mutation.

For P11, fabric/public-key generation is reconciled in addition to agent epoch.
A stale fabric generation cannot regain route/endpoint authority merely because
its old WireGuard interface/peer state remains in the kernel.

On control-plane restart:

- agent connections re-register;
- control-plane operations are loaded before reconciliation;
- no new provider identity is invented;
- stale observations are rejected;
- selected host/backend and allocations remain durable;
- accepted P11 endpoint directory/fabric plans are republished/reconciled before
  dependent guests are treated as network ready.

## Conformance suites

Every provider implementation passes a shared suite appropriate to its domain.

### Common

- registration and capability validation;
- mTLS identity and epoch fencing;
- command identity/fingerprint conflict;
- duplicate replay;
- timeout and unknown outcome;
- restart and reconnect;
- stale observation;
- bounded errors and secret redaction;
- ownership and foreign-state protection.

### Compute

- create/inspect/lifecycle/delete;
- image/config-drive identity;
- console bounds;
- no duplicate domain;
- cleanup and restart discovery.

### Network

- realize/inspect/remove binding;
- deterministic MAC/IP identity;
- DHCP/binding reconciliation;
- routing/NAT/policy realization where activated;
- no duplicate link/lease/provider state;
- cleanup and foreign-link protection.

### P11 fabric extension (only after acceptance)

- local same-realm ARP resolves actual local endpoint MAC;
- remote same-realm ARP resolves deterministic realm proxy MAC;
- no cross-host ARP broadcast dependency;
- local bridge and cross-host routed policy allow/deny;
- MAC/IP/ARP anti-spoofing;
- endpoint-directory generation/fingerprint replay;
- endpoint `/32` route placement/withdrawal;
- WireGuard public identity/generation fencing;
- WireGuard private-key redaction/locality;
- MTU boundary;
- peer/underlay interruption and recovery;
- endpoint local/remote neighbor convergence;
- netns/bridge/veth/neighbor/route/peer cleanup and foreign-state preservation.

### Storage

- create/inspect/delete volume;
- attachment preparation/termination;
- secret-safe connection data;
- no duplicate backend volume;
- cleanup and foreign-volume protection.

## Versioning

- protocol major changes require an ADR and incompatible-version rejection;
- additive optional fields require explicit default and downgrade semantics;
- action behavior changes require contract fixtures and compatibility review;
- independent agent releases declare supported protocol ranges;
- a process split cannot change OpenStack public behavior without a separate
  public-contract decision;
- P11 endpoint-directory/fabric-plan versions must reject incompatible semantics
  rather than silently guessing provider behavior.
