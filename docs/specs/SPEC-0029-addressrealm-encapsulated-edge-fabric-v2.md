# SPEC-0029 — AddressRealm-encapsulated Edge Fabric v2

Status: Accepted

Superseded-by: SPEC-0049

Decision-accepted: 2026-08-20
Human-approval: requester acceptance recorded in issue #705 comment 5349129789

Related decision: [ADR-0171](../adr/ADR-0171-addressrealm-encapsulated-edge-fabric.md)
Related issue: [#705](https://github.com/o3kio/o3k/issues/705)
Related contract: [P11 realm-overlay fabric](../../contracts/edge-fabric-realm-overlay.md)

Related normative sources:

- [ADR-0160](../adr/ADR-0160-service-topology-and-execution-boundaries.md)
- [ADR-0165](../adr/ADR-0165-o3k-cloud-operating-system-and-cloud-kernel.md)
- [ADR-0168](../adr/ADR-0168-o3k-routed-fabric-and-network-execution.md)
- [ADR-0169](../adr/ADR-0169-native-persistent-storage-and-o3k-storage-boundary.md)
- [ADR-0170](../adr/ADR-0170-namespaced-routed-edge-fabric.md)
- [SPEC-0021](SPEC-0021-cross-service-workflows-and-compensation.md)
- [SPEC-0024](SPEC-0024-product-profiles-and-claims.md)
- [SPEC-0026](SPEC-0026-o3k-routed-fabric-v1.md)
- [SPEC-0027](SPEC-0027-native-persistent-storage-v1.md)
- [SPEC-0028](SPEC-0028-namespaced-routed-edge-fabric-v1.md)
- [execution-boundary contract](../../contracts/execution-boundaries.md)

## Purpose and governance gate

This accepted spec replaces the cross-host non-overlap assumption in accepted
SPEC-0028 with a realm-encapsulated P11 provider that supports overlapping
customer CIDRs across hypervisors while retaining the existing O3K authority,
neighbor-directory, policy, scheduling, storage, failure, and evidence model.

ADR-0171 and this SPEC were the P11 v2 architecture authority and are now
superseded for new fabric implementation by ADR-0186/SPEC-0049. The historical
Geneve realization remains subject to the implementation, safety, and real-host
evidence gates recorded here; it does not establish a v3 VXLAN/HER claim.

PR #703 is an already-merged portable semantic slice and remains reusable only
where its types/behavior do not depend on global tenant-IP uniqueness.

## Product outcome

After this successor is accepted and fully implemented, two independent tenants
may create identical private address space and use it across different compute
hosts without cross-tenant ambiguity.

Example required supported state:

```text
Project A / AddressRealm A
  subnet: 10.0.0.0/24
  VM A1: 10.0.0.10 on host-01
  VM A2: 10.0.0.20 on host-02

Project B / AddressRealm B
  subnet: 10.0.0.0/24
  VM B1: 10.0.0.10 on host-03
  VM B2: 10.0.0.20 on host-02
```

Required behavior:

- A1 reaches A2 when policy permits;
- B1 reaches B2 when policy permits;
- A traffic never reaches B merely because the inner IP is the same;
- B traffic never reaches A merely because the inner IP is the same;
- local ARP behavior remains natural;
- remote ARP is answered locally from O3K's accepted endpoint directory;
- no tenant ARP broadcast is required across the host fabric;
- Geneve carries the realm discriminator;
- WireGuard authenticates/encrypts only host transport;
- policy, public/FIP, storage placement, drain, restart, and cleanup remain
  correct.

## Profile capability

The successor reference profile is:

```text
IP family                              IPv4
same-host L2 adjacency                 supported per AddressRealm
cross-host tenant connectivity         realm-encapsulated routed unicast
cross-host ARP broadcast               unsupported/not required
cross-host unknown-unicast flooding    unsupported/not required
arbitrary regional L2                  unsupported
overlapping AddressRealm CIDRs         supported
realm encapsulation                    Geneve reference provider
host transport encryption              WireGuard reference provider
central network/gateway node           not required
live migration                         unsupported
blind failure evacuation               forbidden
```

This profile does not advertise broader Neutron compatibility solely because
Geneve exists internally.

## Canonical identity model

### Tenant endpoint key

Within P11 v2, fabric planning treats endpoint addressing as realm-scoped:

```text
EndpointAddressKey {
    realm_id
    ip
}
```

The exact Rust type name may differ, but bare IP must never be the sole lookup key
for cross-host endpoint routing or delivery.

### Canonical state remains provider-independent

Canonical resources continue to include semantic O3K identity such as:

- AddressRealm / NetworkIntent;
- endpoint / port ID;
- project ownership;
- fixed IP and canonical MAC;
- NetworkPolicy;
- server placement;
- public/floating-address binding;
- Volume / VolumeAttachment / Snapshot;
- durable operation, audit, quota, and generation identity.

Canonical tenant/public resources must not contain:

```text
Geneve device name
Geneve remote command
VNI as tenant identity
WireGuard private key
WireGuard peer command
Linux bridge/netns/veth names
nftables handles
raw FDB/neighbor entries
provider tunnel MAC
provider route-table number
```

## Provider mapping: realm encapsulation

The control plane/provider mapping layer must persist a collision-free mapping
with semantics equivalent to:

```text
RealmEncapsulationBinding {
    fabric_domain_id
    realm_id
    encapsulation_kind = geneve
    vni
    binding_generation
    state
}
```

### Required invariants

- binding identity is derived from accepted O3K realm/fabric state;
- VNI is not tenant supplied;
- VNI is valid for the selected provider;
- active VNI uniqueness is enforced within one fabric domain;
- duplicate equivalent allocation/replay returns the same mapping;
- same realm/binding generation with a different VNI is conflict;
- same VNI bound to a different active realm is conflict;
- stale binding generation cannot overwrite a newer binding;
- deletion/withdrawal is ownership checked;
- ambiguous observed Geneve/VNI state fails closed.

VNI reuse after realm deletion is permitted only after the old mapping and all
owned tunnel state are proven absent according to the provider's reconciliation
contract.

## Host fabric transport identity

Each participating host has a bounded public fabric identity with semantics at
least:

```text
FabricHostTransportIdentity {
    host_id
    public_key
    underlay_endpoint
    fabric_transport_ip
    provider_version
    fabric_generation
    underlay_mtu
    fabric_mtu
}
```

`fabric_transport_ip` is provider/operator infrastructure addressing, not a
tenant address.

Requirements:

- unique among active hosts in one fabric domain;
- never allocated by a tenant;
- generation-bound;
- current host enrollment/identity only;
- safe to distribute through authenticated control-plane state;
- private WireGuard key is not representable in this type.

## WireGuard contract change from SPEC-0028

The successor reference provider must not use tenant endpoint prefixes as shared
WireGuard `AllowedIPs`.

Instead, WireGuard routes only current host-fabric transport addresses/prefixes.
For a simple 10–20-host reference profile this normally means one exact remote
fabric transport address per peer.

This is mandatory because different realms may contain identical tenant `/32`s.
WireGuard is not the realm discriminator.

Private keys:

- are generated/stored host-locally;
- are never persisted in canonical tenant/control-plane state;
- are never uploaded in ordinary evidence;
- are fenced by current host fabric generation.

## Local AddressRealm realization

The accepted local topology is preserved.

For each active realm/host:

```text
host namespace

VM TAP A ----\
              +-- realm bridge -- realm uplink
VM TAP B ----/                      |
                                   v
                            realm network namespace
```

The realm namespace owns routed realm behavior. Provider names are not ownership
proof.

### Same-host ARP

For two current same-realm local endpoints:

- ordinary guest ARP is allowed;
- destination VM may answer with its actual canonical MAC;
- local L2 forwarding may occur;
- endpoint anti-spoofing and NetworkPolicy must still be enforced on the
  TAP/bridge path.

Different AddressRealms never share the same VM-facing realm bridge just because
addresses overlap.

## Realm endpoint directory

The existing PR #703 `RealmEndpointDirectory` concept remains valid but must be
realm-scoped everywhere it is consumed.

Required entry semantics:

```text
EndpointLocation {
    endpoint_id
    project_id
    realm_id
    fixed_ip
    canonical_mac
    selected_host
    endpoint_generation
    placement_generation
}
```

Within one realm:

- duplicate endpoint ID is invalid;
- duplicate fixed IP is invalid;
- duplicate endpoint MAC is invalid where the current domain requires it.

Across different realms:

- identical fixed IP is valid;
- identical subnet/CIDR is valid;
- directory construction must not reject overlap solely because another realm
  uses the same prefix.

## Remote neighbor behavior

No tenant ARP flood crosses hypervisors.

For a guest ARP request inside realm R:

```text
if (R, destination IP) is current local endpoint:
    actual endpoint answers
else if (R, destination IP) is current remote endpoint:
    local o3k-network answers with R's deterministic proxy MAC
else:
    no synthetic reply
```

The guest does not need to understand Geneve, WireGuard, VNI, host placement, or
remote MAC.

A remote endpoint's actual MAC is not exposed as proof of regional Ethernet
adjacency.

## Remote route/encapsulation plan

The portable planner must emit a realm-aware semantic destination equivalent to:

```text
RealmFabricEndpointRoute {
    realm_id
    endpoint_id
    destination_ip
    target_host
    endpoint_generation
    placement_generation
    realm_binding_generation
    target_fabric_generation
}
```

The exact type may extend or replace PR #703 `FabricEndpointRoute`.

The route is not identified by destination IP alone.

The provider resolves:

```text
realm_id -> current Geneve binding/VNI
target_host -> current host fabric transport IP
```

and then realizes the selected kernel tunnel/route state.

## Geneve datapath semantics

### Egress

For traffic from a local endpoint to a remote endpoint in the same realm:

1. validate local endpoint identity/realm/source IP/MAC;
2. apply canonical egress/local-routed policy;
3. look up destination by `(realm_id, destination IP)`;
4. validate accepted target host and generations;
5. obtain current realm Geneve binding/VNI;
6. encapsulate known unicast inner traffic with that realm VNI;
7. send Geneve transport toward the target host fabric transport IP through the
   shared WireGuard host fabric.

### Ingress

After WireGuard authenticates/decrypts a packet from a host:

1. Geneve VNI must map to exactly one current AddressRealm;
2. source host must be current and permitted for the source endpoint/realm;
3. inner source endpoint must be accepted on that source host;
4. inner destination lookup occurs inside the VNI-selected realm context;
5. destination endpoint must be current and local on the receiving host;
6. policy must permit the flow;
7. only then is the packet delivered toward the guest.

No packet may be delivered based solely on a matching inner destination IP.

## Linux realization constraints

The reference implementation must use kernel-native Linux primitives and must
first prove its exact Geneve topology with a focused provider prototype/conformance
test.

The spec intentionally does not require one exact interface fanout strategy,
because Linux Geneve may be realized with static unicast devices or externally
controlled metadata mode depending on the selected kernel/iproute2 profile.

However, the first production implementation must prefer the simplest
understandable option for the 10–20-host target. A static bounded
per-realm/per-peer realization is acceptable if it is more reliable and easier
to reconcile than metadata-mode multiplexing.

It must not introduce OVS, OVN, EVPN, BGP, or custom eBPF as an implementation
shortcut without a separate accepted architecture decision.

## No cross-host flood requirement

Geneve in this profile is not authority for an Ethernet learning plane.

Full-profile behavior must work without:

- ARP flood to remote hosts;
- broadcast replication to every host participating in a realm;
- unknown-unicast flood;
- learning a destination host from packet source MAC;
- treating bridge FDB as canonical placement.

Current endpoint placement provides the remote host explicitly.

## Policy and spoofing

One canonical NetworkPolicy generation may compile to:

- local TAP/bridge enforcement;
- realm routed enforcement;
- encapsulation egress validation;
- decapsulation ingress validation.

The provider must validate source endpoint identity before encapsulation and
again validate realm/source-host binding on decapsulation.

At minimum reject:

- spoofed source MAC;
- spoofed source IPv4;
- spoofed ARP sender IP/MAC;
- source endpoint not local to current host;
- wrong realm/VNI;
- wrong/stale source host fabric generation;
- destination endpoint in another realm even when the IP matches;
- stale endpoint/placement/binding generation.

Fail-open partial policy transitions are forbidden.

## Public/floating IP and egress

P9 semantics remain canonical. Provider realization must use canonical endpoint
identity plus realm, not bare private IP, when two realms reuse an address.

Required evidence includes two overlapping realms with the same private IP where
only the endpoint owning the tested public/FIP binding receives the external
traffic.

A root/shared NAT table must not ambiguously key tenant ownership by private IP
alone.

## MTU

The provider path includes at least:

```text
tenant packet
+ Geneve encapsulation
+ WireGuard encapsulation
+ underlay headers
```

The implementation must derive or configure a safe tenant MTU for the exact
underlay family/options and propagate it through the existing guest network
configuration/DHCP path.

Required evidence:

- near-boundary allowed packet succeeds;
- oversize/PMTU behavior is explicit and does not silently black-hole supported
  traffic;
- MTU remains correct after restart/reconciliation;
- no canonical tenant identity depends on the raw provider MTU number.

## Scheduling and storage integration

ADR-0171 does not change placement authority.

New placement still requires:

- current agent identity/epoch;
- `Enabled` administrative state;
- compute capacity/capability;
- P11 realm/fabric readiness;
- selected realm encapsulation provider capability;
- storage placement/attachment constraints.

Host-local LVM remains host-local.

Shared Ceph RBD may be attached serially on another eligible host only after a
clean previous detach/termination or stronger accepted fencing proof.

No backend-name branching should replace typed placement capability.

## Drain and host failure

Drain semantics from SPEC-0028 remain:

- no new placement on Draining host;
- existing workloads continue;
- blockers are explicit;
- no live migration requirement.

Unreachable host semantics remain fail-closed:

- unreachability is not proof of power-off;
- do not start a duplicate VM elsewhere;
- do not activate a second single-writer RBD attachment merely from heartbeat
  expiry;
- require clean release or accepted fencing proof.

## Migration from merged PR #703

Before privileged successor implementation:

1. retain `EndpointLocation` and realm-scoped endpoint directory behavior;
2. retain deterministic realm proxy-MAC neighbor behavior;
3. update/replace `FabricEndpointRoute` so realm scope is explicit;
4. add a typed host fabric transport IP to the public fabric identity/provider
   planning model;
5. add provider mapping/plan types for realm encapsulation binding/VNI;
6. stop generating tenant endpoint prefixes as WireGuard peer `AllowedIPs`;
7. remove global prefix-overlap rejection only behind the proven
   `OverlappingAddressRealms` + realm-encapsulation capability;
8. add planner tests where two different realms contain the same CIDR and same
   endpoint IPs;
9. keep duplicate IP rejection inside one realm.

Do not rewrite unrelated P9/P10 semantics.

## Provider conformance requirements

Before real-host promotion, portable/provider tests must cover:

- valid realm-to-VNI allocation;
- duplicate allocation replay;
- VNI collision conflict;
- stale binding generation rejection;
- VNI lookup only within current fabric domain;
- VNI deletion/reuse ownership fence;
- same CIDR in two realms accepted;
- same IP in two realms accepted;
- same IP twice in one realm rejected;
- remote route key includes realm;
- host fabric transport address uniqueness;
- WireGuard plan contains provider transport IPs, not tenant endpoint IPs;
- wrong VNI ingress drop;
- unknown VNI ingress drop;
- wrong source-host/realm binding drop;
- destination IP in wrong realm drop;
- equivalent replay/unknown-outcome/reconcile behavior;
- foreign Geneve device/VNI protection.

## Real functional gate

Use at least three independent KVM/libvirt compute hosts unless a later accepted
SPEC strengthens the requirement.

The core overlapping-address scenario is mandatory:

```text
Realm A / Project A: 10.0.0.0/24
 A1 10.0.0.10 host-01
 A2 10.0.0.20 host-02

Realm B / Project B: 10.0.0.0/24
 B1 10.0.0.10 host-03
 B2 10.0.0.20 host-02
```

Prove:

1. A1 ARPs for A2 and receives realm-A proxy MAC locally;
2. B1 ARPs for B2 and receives realm-B proxy MAC locally;
3. A1 -> A2 allowed flow succeeds;
4. B1 -> B2 allowed flow succeeds;
5. A1 never reaches B2 at the same inner destination IP;
6. B1 never reaches A2 at the same inner destination IP;
7. wrong VNI/realm mapping is rejected;
8. stale VNI generation is rejected;
9. source-host spoof/wrong endpoint placement is rejected;
10. tenant ARP is not flooded across hypervisors;
11. WireGuard underlay shows protected host transport rather than cleartext
    tenant workload packets;
12. P9 policy allow/deny works independently in both realms;
13. public/FIP binding to one overlapping private IP reaches only the canonical
    bound realm/endpoint;
14. MTU-boundary traffic works;
15. restart/reconnect/reconciliation preserves VNI and endpoint ownership;
16. cleanup independently verifies zero owned fabric leaks and zero foreign
    mutations.

## Storage multi-host gate

Retain P11 storage evidence:

- LVM-backed workload rejected on non-owning host before mutation;
- RBD-backed volume attached to VM on host A;
- guest writes random payload/checksum;
- clean detach/termination;
- serial attach to eligible VM on host B;
- checksum exactly matches;
- no simultaneous single-writer attachment.

## Failure matrix

At minimum cover:

1. duplicate endpoint-directory publication;
2. conflicting directory fingerprint;
3. duplicate realm/VNI binding allocation;
4. realm/VNI collision attempt;
5. stale realm-binding generation;
6. stale controller fence;
7. stale network-agent epoch;
8. stale fabric host generation;
9. stale WireGuard key/public identity generation;
10. partial Geneve interface/tunnel realization;
11. partial realm-to-fabric attachment realization;
12. partial policy realization;
13. interruption after Geneve mutation before acknowledgement;
14. WireGuard peer interruption and recovery;
15. controller restart with overlapping active realms;
16. network-agent restart with overlapping active realms;
17. host graceful restart;
18. host/controller partition;
19. endpoint cold relocation across hosts;
20. realm deletion during tunnel cleanup;
21. VNI reuse attempt before old state proven absent;
22. wrong/unknown VNI packet injection;
23. wrong source-host inner endpoint injection;
24. FIP/egress with overlapping private IPs;
25. full cleanup interruption and resume.

Every scenario must converge to a known state or explicit operator-visible
unknown/blocked state. Silent ambiguity is a failure.

## Scale/operational evidence

Separately exercise approximately the roadmap target host count for:

- host registration/heartbeats;
- fabric transport identity publication;
- overlapping realm directory fanout;
- realm/VNI mapping fanout;
- tunnel plan generation;
- scheduling filtering;
- drain state;
- reconnect/reconciliation concurrency.

Simulated agents may supplement concurrency tests but do not expand the real
hypervisor support claim.

Track tunnel/VNI/kernel-object growth explicitly. If the simple static Linux
Geneve realization becomes operationally excessive even at the claimed P11
host/realm count, stop and obtain architecture review before replacing it with a
more complex metadata/OVN/eBPF control plane.

## Cleanup/evidence counters

Final evidence must independently report at least:

```text
duplicate compute resources = 0
duplicate network resources = 0
duplicate storage resources = 0
duplicate active realm/VNI bindings = 0
stale fenced mutations accepted = 0
unfenced duplicate workloads = 0
owned compute leaks = 0
owned network leaks = 0
owned storage leaks = 0
owned realm-netns/bridge/veth leaks = 0
owned Geneve/VNI/tunnel leaks = 0
owned WireGuard/fabric leaks = 0
owned neighbor/route/policy leaks = 0
foreign compute mutations = 0
foreign network mutations = 0
foreign storage mutations = 0
foreign fabric mutations = 0
cross-realm overlapping-IP misdelivery = 0
```

Private WireGuard key material and secret storage connection data are forbidden
from ordinary evidence.

## Explicit non-goals

P11 v2 does not require:

- arbitrary regional L2 adjacency;
- cross-host ARP/broadcast/multicast flooding;
- VXLAN or EVPN;
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

## Definition of done

P11 v2 is complete only when:

> O3K runs the exact claimed real multi-hypervisor topology; different projects
> can reuse identical tenant CIDRs across hosts; AddressRealm/VNI identity
> prevents ambiguous delivery; same-host ARP/local L2 and remote proxy-ARP work;
> Geneve carries realm identity without cross-host flooding; WireGuard protects
> only host transport; NetworkPolicy and public/FIP behavior remain correct;
> LVM/RBD placement remains safe; drain/restart/partition/replay/fencing
> scenarios converge; and independent cleanup proves zero owned leaks, zero
> foreign mutations, and zero cross-realm overlapping-IP misdelivery.

Architecture acceptance alone does not satisfy this gate.
