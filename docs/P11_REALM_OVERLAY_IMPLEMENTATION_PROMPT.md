# P11 historical implementation prompt — AddressRealm-encapsulated Edge Fabric v2

**Superseded by ADR-0186/SPEC-0049.** This document records the historical v2
Geneve implementation plan and must not be used for new privileged work. Use
the accepted v3 sources (`docs/adr/ADR-0186-stretched-l2-edge-fabric-vxlan-her.md`,
`docs/specs/SPEC-0049-stretched-l2-edge-fabric-v3.md`, and
`contracts/edge-fabric-stretched-l2.md`) for the VXLAN/HER migration. Existing
v2 evidence remains historical and does not establish a v3 runtime claim.

Repository: `o3kio/o3k`

---

## Mission

**Complete P11 — O3K AddressRealm-encapsulated Edge Fabric v2.**

Starting from current GitHub `main`, evolve the already-proven O3K compute, P9
routed networking, P10 persistent storage, and the portable P11 planning slice
merged in PR #703 into a real small multi-hypervisor cloud where independent
customers may safely use identical private CIDRs across different hypervisors.

The final architecture must preserve the O3K authority/fencing/ownership model
and must not recreate Neutron/OVN as O3K's internal control plane.

The central invariant is:

> **An endpoint address is `(AddressRealm, IP)`, not bare IP. Geneve carries
> AddressRealm identity across hosts. WireGuard authenticates/encrypts host
> transport only. NetworkPolicy authorizes traffic.**

## Mandatory first step — inspect before coding

Before modifying runtime code:

1. inspect the exact current `main` commit;
2. inspect all open P11 issues/PRs and do not create duplicates;
3. read `AGENTS.md` and repository-local instructions;
4. read `docs/NORMATIVE_SOURCES.md`;
5. read ADR-0160, ADR-0165, ADR-0168, ADR-0169, ADR-0170, **ADR-0171**;
6. read SPEC-0021, SPEC-0024, SPEC-0026, SPEC-0027, SPEC-0028, **SPEC-0029**;
7. read `contracts/execution-boundaries.md`, `contracts/edge-fabric-v1.md`, and
   **`contracts/edge-fabric-realm-overlay.md`**;
8. inspect PR #703 and the current `o3k-domain` P11 types before changing them;
9. inspect current P9 `o3k-network` process/provider/policy/public-address code;
10. inspect current scheduler/Placement/agent administrative-state behavior;
11. inspect P10 LVM/RBD placement/attachment contracts and evidence;
12. inspect current compatibility/product-profile claims before modifying them.

If ADR-0171 or SPEC-0029 is not `Accepted`, **stop runtime implementation**.
Implementation may proceed in bounded, reviewable slices after the accepted
architecture gate; the full P11 claim remains gated by the real-host evidence
requirements below.

If ADR-0171/SPEC-0029 become accepted, verify repository governance has also
made the supersession relationship explicit. Do not silently combine conflicting
rules from ADR-0170 and ADR-0171.

## Product outcome

P11 v2 is complete only when O3K operates a real multi-hypervisor cloud where:

```text
Project A / AddressRealm A
  10.0.0.0/24
  A1 = 10.0.0.10 on host-01
  A2 = 10.0.0.20 on host-02

Project B / AddressRealm B
  10.0.0.0/24
  B1 = 10.0.0.10 on host-03
  B2 = 10.0.0.20 on host-02
```

and:

- A1 reaches A2 only according to realm-A policy;
- B1 reaches B2 only according to realm-B policy;
- A traffic never reaches B simply because the inner destination IP matches;
- B traffic never reaches A simply because the inner destination IP matches;
- same-host/same-realm VMs retain normal ARP/local L2 behavior;
- remote same-realm ARP is answered locally from O3K's endpoint directory;
- no tenant ARP broadcast is required across hypervisors;
- Geneve carries realm identity;
- WireGuard carries authenticated encrypted host transport;
- P9 egress/FIP/policy remains correct with overlapping private IPs;
- P10 LVM/RBD placement remains correct;
- drain/restart/partition/replay/fencing converge safely;
- cleanup produces zero owned leaks and zero foreign mutations.

## Frozen canonical architecture

### Canonical O3K state remains provider-independent

Do not put Linux/Geneve/WireGuard implementation details into tenant resources.

Canonical concepts include:

```text
AddressRealm
NetworkIntent
Endpoint / port identity
Project ownership
Fixed IP / canonical endpoint MAC
NetworkPolicy
Route/Gateway/PublicAddress intent
Server placement
Volume/VolumeAttachment/Snapshot
Operation / generation / audit identity
```

Provider/native concepts include:

```text
Linux netns name
bridge/veth/TAP name
Geneve interface/tunnel name
Geneve VNI
provider tunnel MAC/FDB/neighbor state
WireGuard interface/peer configuration
WireGuard private key
fabric transport IP allocation
nftables handles
raw kernel routes
```

Never make provider-native names/IDs public tenant identity.

### Endpoint identity is realm-scoped

Every cross-host planner/executor lookup must behave as if keyed by:

```text
(realm_id, fixed_ip)
```

Bare tenant IP must never select a remote realm or endpoint.

Accept:

```text
(realm-A, 10.0.0.20)
(realm-B, 10.0.0.20)
```

Reject duplicate `10.0.0.20` inside one active AddressRealm unless a later
accepted semantic explicitly permits it.

## Preserve and adapt merged PR #703

PR #703 is not discarded.

Reuse:

- `EndpointLocation` semantics;
- one `RealmEndpointDirectory` per AddressRealm;
- local destination -> actual endpoint MAC;
- remote destination -> deterministic realm proxy MAC;
- endpoint/placement generation fencing;
- host fabric public identity concept;
- fail-closed deterministic planning.

Before privileged successor implementation, revise the planner/domain so:

1. cross-host endpoint-route identity explicitly contains `realm_id`;
2. no global lookup map is keyed by tenant IP alone;
3. host fabric identity includes/derives a **unique provider fabric transport
   address**;
4. WireGuard planning does **not** use tenant endpoint `/32`s as peer
   `AllowedIPs`;
5. a typed/durable `RealmEncapsulationBinding` or equivalent maps realm to the
   selected provider segment/VNI;
6. overlap is allowed only when the selected provider advertises the accepted
   overlapping-realm/realm-encapsulation capability;
7. duplicate CIDR/IP across different realms is tested and accepted;
8. duplicate endpoint IP inside one realm remains fail-closed;
9. all old non-overlap-specific tests/guards are either retained for providers
   that lack overlap capability or updated for the successor profile.

Do not weaken P9's default non-overlap provider merely because P11 v2 adds an
overlap-capable provider.

## Realm-to-Geneve provider mapping

Add a durable provider mapping with semantics equivalent to:

```text
RealmEncapsulationBinding {
    fabric_domain_id
    realm_id
    provider_kind = geneve
    vni
    binding_generation
    state
}
```

Exact type names may differ.

Mandatory behavior:

- tenant cannot provide raw VNI;
- VNI allocation occurs only after canonical realm/fabric authorization;
- active VNI unique within fabric domain;
- one current realm has one current binding in that fabric domain;
- equivalent replay returns same VNI;
- same identity/generation with different mapping is conflict;
- VNI collision with another realm fails before kernel mutation;
- stale binding generation is rejected;
- deletion is ownership/generation checked;
- VNI is not reused until previous owned state is independently proven absent;
- foreign Geneve/VNI state is never adopted by name/number alone.

Treat VNI as provider mapping, not Cloud Kernel resource identity.

## Local VM-facing topology

Retain one host-visible VM bridge per active AddressRealm to preserve the proven
libvirt/TAP attachment model.

Conceptually:

```text
host namespace

VM-A TAP ----\
              +--- br-realm-R --- realm-uplink
VM-B TAP ----/                         |
                                         v
                                  realm-R netns
```

Different AddressRealms never share a VM-facing bridge, even if CIDRs are
identical.

Kernel names are provider mappings and never ownership proof.

## Same-host ARP and policy

For local endpoints in the same AddressRealm:

- ordinary ARP is allowed;
- destination endpoint replies with actual canonical MAC;
- local bridge forwarding is allowed when policy permits;
- TAP/bridge anti-spoofing and canonical NetworkPolicy remain mandatory.

At minimum reject endpoint attempts to spoof:

```text
source MAC
source IPv4
ARP sender MAC
ARP sender IPv4
realm/project binding
endpoint generation/placement
```

Do not rely only on routed nftables rules because local bridge traffic can
bypass a router.

Compile one canonical NetworkPolicy generation to every required local/routed/
encapsulation enforcement point. No separate policy authority is permitted.

## Distributed endpoint directory and remote ARP

Do not flood tenant ARP across hypervisors.

For ARP inside realm R:

```text
if (R, destination IP) is current local endpoint:
    actual local endpoint answers
else if (R, destination IP) is current remote endpoint:
    local o3k-network answers with realm-R deterministic proxy MAC
else:
    no synthetic reply
```

Directory authority comes only from accepted durable endpoint/placement state.
Never learn current endpoint authority from:

```text
ARP traffic
bridge FDB
Geneve source MAC
WireGuard peer traffic
kernel route presence
```

Guests remain unmodified and learn ARP naturally.

## Cross-host realm encapsulation

### Core rule

Geneve is used to carry the cross-host AddressRealm discriminator for known
unicast tenant traffic.

The packet path is:

```text
VM-A
  |
local realm bridge
  |
realm-A netns
  |
lookup (realm-A, destination IP)
  |
accepted target host
  |
Geneve encapsulate with realm-A VNI
  |
shared WireGuard host transport
  |
remote Geneve VNI validation/demux
  |
remote realm-A execution context
  |
validate current local destination endpoint
  |
VM-A2
```

A customer-B packet may use the exact same inner source/destination IPs but has a
different realm/VNI and must enter only realm-B.

### No regional flood plane

Do not implement Geneve as a generic flooding Ethernet cloud merely because the
kernel tunnel is Ethernet-like.

P11 v2 must work without:

- cross-host ARP flood;
- broadcast flood;
- unknown-unicast flood;
- multicast flood;
- MAC learning as endpoint placement authority.

Remote host selection comes from O3K accepted placement.

## Linux Geneve realization

Before building the full privileged provider, create a focused Linux prototype
that proves the exact chosen Geneve topology on the selected kernel/iproute2
profile.

The prototype must prove:

1. two realms can use the same inner CIDR;
2. the same inner destination IP can be delivered to different realm contexts
   based only on accepted VNI/realm mapping;
3. no unscoped tenant-IP route in a shared namespace can cross the realms;
4. wrong/unknown VNI does not enter another realm;
5. tunnel cleanup is deterministic;
6. MTU can be measured and bounded.

For the approximately 10–20-host target, prefer the simplest static,
debuggable Linux realization. A bounded per-realm/per-remote-host Geneve tunnel
fanout is acceptable if it is reliable and operationally reasonable.

Do not introduce OVS, OVN, EVPN, BGP, or custom eBPF to optimize multiplexing
without a new architecture decision.

If static Geneve object growth is already excessive at the declared P11 target,
stop and report evidence instead of silently changing architecture.

## Shared WireGuard host transport

Use one shared WireGuard host transport per compute host, not one WireGuard
interface/key per tenant.

Each host has a unique provider transport identity equivalent to:

```text
host_id
wireguard_public_key
underlay_endpoint
fabric_transport_ip
fabric_generation
provider_version
underlay_mtu/fabric_mtu
```

The private WireGuard key:

- is generated host-locally;
- never enters canonical O3K tenant state;
- never enters normal PostgreSQL/SQLite public resource rows;
- never enters public APIs;
- never enters audit/events/logs/evidence;
- is destroyed only under exact provider ownership rules.

### Critical successor rule: no tenant prefixes in WireGuard AllowedIPs

With overlapping realms, these cannot be shared WireGuard routes:

```text
10.0.0.20/32 -> host-02
10.0.0.20/32 -> host-03
```

Therefore WireGuard peer routing/source validation uses only unique provider host
transport addresses/prefixes.

Conceptually:

```text
host-02 peer AllowedIPs -> host-02 fabric transport IP
host-03 peer AllowedIPs -> host-03 fabric transport IP
```

Tenant addresses remain inside Geneve realm encapsulation and must never select a
WireGuard peer directly.

WireGuard provides host authentication/encryption only.

## Geneve egress validation

Before encapsulation require all of:

- current local source endpoint;
- source endpoint belongs to ingress AddressRealm;
- source MAC/IP matches canonical binding;
- endpoint/placement generation current;
- destination lookup scoped to ingress realm;
- destination endpoint current or explicit canonical gateway/route intent;
- accepted target host current;
- target host fabric generation current;
- realm/VNI binding current;
- NetworkPolicy permits flow.

Then encapsulate known unicast to the accepted target host transport address.

## Geneve ingress validation

After WireGuard authenticates/decrypts host transport, require all of:

- source host current;
- VNI maps to exactly one current realm;
- source host may source the inner endpoint in that realm;
- inner source endpoint/placement generation current;
- destination lookup performed inside the VNI-selected realm;
- destination endpoint current and local to this host;
- destination endpoint generation current;
- NetworkPolicy permits flow.

Wrong/unknown/stale VNI must fail closed.

**Inner destination IP match alone must never deliver a packet.**

## Realm-aware public/FIP/NAT behavior

P9 north/south semantics stay canonical, but every private endpoint lookup must
include canonical endpoint/realm identity.

Mandatory overlap test:

```text
realm-A endpoint 10.0.0.10 has public/FIP binding
realm-B endpoint 10.0.0.10 has no such binding
```

External traffic must reach only realm-A's canonical endpoint.

No shared root/NAT rule may treat bare private `10.0.0.10` as sufficient
ownership identity.

## MTU

Derive the tenant MTU from the actual selected path:

```text
tenant packet
+ Geneve
+ WireGuard
+ outer underlay headers/options
```

Do not hard-code a universal MTU without proving it for the selected underlay.

Propagate selected MTU through existing guest configuration/DHCP.

Full-profile evidence must include:

- near-boundary packet success;
- explicit oversize/PMTU behavior;
- restart/reconciliation preserving MTU;
- no silent black hole at the advertised supported MTU.

## Scheduling and storage

Reuse existing authenticated host inventory, Placement, scheduler,
administrative state, work leases, fencing, agent epochs and reconciliation.

Placement filters on:

```text
current agent identity/epoch
Enabled administrative state
compute capacity/capability
realm/Geneve provider readiness
WireGuard host-transport readiness
accepted failure/availability constraints
P10 storage placement capability
```

Host-local LVM:

- workload must remain on owning eligible host;
- wrong-host placement fails before mutation.

Ceph RBD:

- prove serial cross-host attach;
- previous writer must cleanly detach/terminate or be independently fenced;
- no simultaneous single-writer multi-attach.

## Drain and unreachable-host semantics

Drain:

- blocks new placement immediately;
- existing workloads continue;
- resident workloads/attachments/local storage become explicit blockers;
- no hidden migration requirement.

Unreachable host:

- means unknown, not powered off;
- no blind duplicate workload recreation;
- no RBD writer activation elsewhere solely from heartbeat expiry;
- require clean ownership release or separately accepted fencing proof.

## Reuse existing replay/fencing semantics

Every P11 v2 mutation must preserve:

```text
durable desired/provider mapping before external mutation
deterministic command/idempotency identity
controller work/fencing ownership
current target agent epoch
endpoint/placement generation
realm-binding generation
host-fabric generation
persisted command acceptance before mutation
equivalent replay returns durable outcome
conflicting fingerprint fails closed
timeout after possible mutation = unknown outcome
observe before retry
foreign/ambiguous state never adopted/deleted
```

This applies to namespace/bridge/veth/Geneve/VNI/neighbor/route/policy/WireGuard
state.

## Suggested bounded implementation sequence

Do not create duplicate issues. Reuse current P11 work where applicable.

A reasonable sequence after architecture acceptance is:

1. governance supersession + contract fixtures;
2. adapt PR #703 planner/domain to realm-aware routes and host transport IP;
3. durable realm->Geneve VNI provider mapping + conformance tests;
4. focused Linux Geneve overlapping-CIDR prototype;
5. realm bridge/netns lifecycle and local anti-spoof/policy integration;
6. remote endpoint directory/proxy ARP integration;
7. shared WireGuard host transport using only provider transport addresses;
8. Geneve known-unicast encapsulation/decapsulation with VNI validation;
9. overlap-safe P9 FIP/egress/NAT integration;
10. MTU/path evidence;
11. placement/drain/LVM/RBD integration;
12. restart/replay/partition/failure matrix;
13. three-hypervisor overlapping-realm gate;
14. target-count operational/concurrency evidence;
15. exact cleanup/foreign-state inventory and human final review.

Do not collapse all slices into one uncontrolled PR.

## Mandatory portable tests

Before privileged multi-host evidence, add tests proving:

- same CIDR in realm A and realm B accepted;
- same endpoint IP in realm A and realm B accepted;
- duplicate endpoint IP inside one realm rejected;
- realm-scoped remote route identity;
- no global tenant-IP-only remote route key;
- provider VNI allocation uniqueness;
- VNI replay stability;
- VNI collision conflict;
- stale VNI generation rejection;
- host fabric transport IP uniqueness;
- tenant endpoint prefixes absent from WireGuard transport plan;
- wrong/unknown VNI ingress rejection;
- wrong source-host/realm endpoint rejection;
- stale endpoint/placement/fabric generations rejected;
- private WireGuard key cannot enter public identity/evidence types.

## Mandatory real multi-host gate

Use at least three genuinely independent KVM/libvirt hosts unless a later
accepted SPEC strengthens this requirement.

Use two independent projects with the same CIDR:

```text
Project A / Realm A: 10.0.0.0/24
  A1 10.0.0.10 host-01
  A2 10.0.0.20 host-02

Project B / Realm B: 10.0.0.0/24
  B1 10.0.0.10 host-03
  B2 10.0.0.20 host-02
```

Prove all of:

### Neighbor behavior

- local same-realm endpoint resolves to actual MAC;
- remote same-realm endpoint resolves locally to correct realm proxy MAC;
- ARP is not flooded to remote hypervisors;
- identical remote IP in another realm does not affect resolution.

### Encapsulation/isolation

- realm A uses its accepted VNI;
- realm B uses a different accepted VNI;
- A1 -> A2 succeeds when allowed;
- B1 -> B2 succeeds when allowed;
- A1 cannot reach B2 despite identical destination IP;
- B1 cannot reach A2 despite identical destination IP;
- wrong VNI packet is dropped;
- unknown VNI packet is dropped;
- stale VNI generation is dropped/rejected;
- spoofed source host/endpoint is dropped.

### Transport

- Geneve transport traverses WireGuard host fabric;
- underlay does not expose cleartext tenant workload IP packets for the tested
  path;
- WireGuard peers use provider fabric transport addresses rather than tenant
  endpoint CIDRs.

### Policy/public networking

- local and cross-host allow/deny policy proven in both overlapping realms;
- FIP/public binding to one `10.0.0.10` reaches only the correct canonical realm
  endpoint;
- unauthorized cross-realm traffic remains denied.

### MTU

- near-boundary traffic succeeds;
- no supported-size black hole;
- path recovers after restart/peer disruption.

### Storage

- LVM wrong-host placement rejected;
- RBD payload/checksum written on host A;
- clean detach;
- serial attach on host B;
- exact checksum verified;
- no simultaneous writer.

### Lifecycle/failure

- drain/undrain;
- controller restart/takeover as applicable;
- network-agent restart;
- compute/storage-agent restart where applicable;
- WireGuard peer interruption/recovery;
- partial Geneve realization recovery;
- endpoint cold relocation and neighbor convergence;
- host/controller partition without blind evacuation.

## Mandatory cleanup counters

Final independently generated evidence must include at least:

```text
duplicate compute resources = 0
duplicate network resources = 0
duplicate storage resources = 0
duplicate active realm/VNI bindings = 0
stale fenced mutations accepted = 0
unfenced duplicate workloads = 0
cross-realm overlapping-IP misdelivery = 0
owned compute leaks = 0
owned network leaks = 0
owned storage leaks = 0
owned realm bridge/netns/veth leaks = 0
owned proxy-neighbor/route/policy leaks = 0
owned Geneve/VNI/tunnel leaks = 0
owned WireGuard/fabric leaks = 0
foreign compute mutations = 0
foreign network mutations = 0
foreign storage mutations = 0
foreign fabric mutations = 0
```

Do not include private WireGuard key bytes or secret storage connection data in
ordinary evidence.

## Explicit non-goals

Do not expand P11 v2 into:

- arbitrary regional L2 adjacency;
- cross-host broadcast/multicast/unknown-unicast flooding;
- VXLAN/EVPN;
- OVN/OVS;
- custom eBPF dataplane;
- internal BGP;
- STUN/TURN/relay/rendezvous;
- live migration;
- blind automatic evacuation;
- storage migration;
- multi-attach;
- SR-IOV/DPDK;
- multi-region;
- P12 native API/CLI;
- Terraform/UI/ecosystem work.

## Completion rule

Do not declare P11 complete because namespaces, Geneve devices, WireGuard peers,
routes, or VNI mappings exist.

P11 v2 is complete only when the accepted SPEC-0029 full real-host gate proves
**two independent overlapping AddressRealms across multiple hypervisors with
zero cross-realm misdelivery**, together with policy, public/FIP, storage,
restart/failure, MTU, cleanup, and foreign-state evidence.
