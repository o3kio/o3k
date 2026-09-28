# SPEC-0049 — Stretched-L2 Edge Fabric v3

Status: Accepted

Decision-accepted: 2026-09-28
Human-approval: requester acceptance recorded in the introducing pull request, 2026-09-28
Supersedes: SPEC-0029

Related decision: [ADR-0186](../adr/ADR-0186-stretched-l2-edge-fabric-vxlan-her.md)
Related contract: [P11 stretched-L2 fabric](../../contracts/edge-fabric-stretched-l2.md)
Aligned external decision: CHV
[ADR-021](https://github.com/kubedoio/chv/blob/main/docs/specs/adr/021-stretched-l2-vxlan-her-wireguard-fabric.md)
(kubedoio/chv#270)

Related normative sources:

- [ADR-0160](../adr/ADR-0160-service-topology-and-execution-boundaries.md)
- [ADR-0165](../adr/ADR-0165-o3k-cloud-operating-system-and-cloud-kernel.md)
- [ADR-0168](../adr/ADR-0168-o3k-routed-fabric-and-network-execution.md)
- [ADR-0170](../adr/ADR-0170-namespaced-routed-edge-fabric.md)
- [ADR-0171](../adr/ADR-0171-addressrealm-encapsulated-edge-fabric.md) (superseded)
- [ADR-0172](../adr/ADR-0172-configurable-edge-fabric-transport-ports.md)
- [ADR-0176](../adr/ADR-0176-canonical-network-and-addressrealm-lifecycle-separation.md)
- [SPEC-0024](SPEC-0024-product-profiles-and-claims.md)
- [SPEC-0026](SPEC-0026-o3k-routed-fabric-v1.md)
- [SPEC-0028](SPEC-0028-namespaced-routed-edge-fabric-v1.md)
- [SPEC-0029](SPEC-0029-addressrealm-encapsulated-edge-fabric-v2.md) (superseded)
- [SPEC-0033](SPEC-0033-canonical-network-addressrealm-lifecycle-v1.md)
- [execution-boundary contract](../../contracts/execution-boundaries.md)

## Purpose and governance gate

This accepted spec replaces the P11 v2 cross-host dataplane semantics of
accepted SPEC-0029 with a **stretched-L2 fabric**: each `AddressRealm` is one
literal Ethernet broadcast domain (one VLAN) across all enrolled hypervisors,
carried as per-realm kernel VXLAN with head-end replication inside the existing
shared WireGuard host fabric.

Everything not named below is retained from SPEC-0029 unchanged: the
AddressRealm identity model, overlapping tenant CIDRs across realms, the
`(realm_id, fixed_ip)` endpoint key, the realm endpoint directory as placement
authority, the VNI binding registry semantics, the WireGuard host-transport
contract, canonical NetworkPolicy, public/FIP semantics, scheduling, storage,
drain, failure, and the ADR-0168 execution discipline.

ADR-0186 and this SPEC are the active P11 v3 architecture authority. Privileged
VXLAN realization remains subject to the implementation, safety, and real-host
evidence gates in this document and the successor contract.

## Product outcome

After this successor is accepted and fully implemented, one AddressRealm behaves
as a single switched LAN across hypervisors, including distant locations behind
untrusted networks, while two independent tenants may still create identical
private address space without cross-tenant ambiguity.

Required supported state:

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

- A1 ARPs for A2 and receives **A2's actual canonical MAC** (cross-host);
- A1 reaches A2 by unicast ICMP when policy permits;
- B1 ARPs for B2 and receives **B2's actual canonical MAC** (cross-host);
- A traffic never reaches B and B traffic never reaches A, including when inner
  IPs are identical;
- DHCP discovery broadcast from A1 is answered by the realm-A DHCP authority
  regardless of which host it runs on;
- local (same-host) and remote (cross-host) ARP/ping behavior are
  indistinguishable to the guest;
- VXLAN carries the realm discriminator; WireGuard authenticates/encrypts only
  host transport;
- policy, public/FIP, storage placement, drain, restart, and cleanup remain
  correct.

## Profile capability

The successor reference profile is:

```text
IP family                              IPv4
same-host L2 adjacency                 supported per AddressRealm
cross-host L2 adjacency                supported per AddressRealm (stretched VLAN)
cross-host ARP broadcast               supported via bounded head-end replication
cross-host unknown-unicast flooding    supported via bounded head-end replication
cross-host multicast L2                delivered as broadcast (no IGMP snooping)
arbitrary regional L2 beyond enrolled hosts  unsupported
overlapping AddressRealm CIDRs         supported
realm encapsulation                    kernel VXLAN reference provider
host transport encryption              WireGuard reference provider
central network/gateway node           not required
live migration                         unsupported
blind failure evacuation               forbidden
```

This profile does not advertise broader Neutron compatibility solely because
VXLAN exists internally.

## Canonical identity model

Unchanged from SPEC-0029, including the prohibition on canonical tenant/public
resources containing provider state. The provider-state vocabulary is updated:

```text
VXLAN device name
VXLAN remote/flood command
VNI as tenant identity
WireGuard private key
WireGuard peer command
Linux bridge/netns/veth names
nftables handles
raw FDB/neighbor entries
provider route-table number
```

Bare IP must never be the sole lookup key for cross-host endpoint routing or
delivery.

## Provider mapping: realm encapsulation

The control-plane/provider mapping layer must persist a collision-free mapping
with semantics equivalent to:

```text
RealmEncapsulationBinding {
    fabric_domain_id
    realm_id
    encapsulation_kind = vxlan
    vni
    binding_generation
    state
}
```

### Required invariants

All SPEC-0029 binding invariants are retained verbatim (identity derivation,
no tenant-supplied VNI, provider validity, active uniqueness per fabric domain,
idempotent replay, conflict on same-generation-different-VNI and
same-VNI-different-active-realm, stale-generation rejection, ownership-checked
deletion, fail-closed ambiguous observed state).

VNI reuse after realm deletion is permitted only after the old mapping and all
owned tunnel state (VXLAN devices, FDB entries, learned MAC state) are proven
absent according to the provider's reconciliation contract.

## Host fabric transport identity

Unchanged from SPEC-0029 (`FabricHostTransportIdentity` with `host_id`,
`public_key`, `underlay_endpoint`, `fabric_transport_ip`, `provider_version`,
`fabric_generation`, `underlay_mtu`, `fabric_mtu`). The WireGuard contract is
unchanged: AllowedIPs carry only host fabric transport addresses, never tenant
endpoint prefixes; private keys stay host-local and out of canonical state.

ADR-0172 port policy is retained for WireGuard. The Geneve destination-port
surface is retired with the Geneve datapath; VXLAN uses the standard UDP/4789
destination port inside the WireGuard tunnel and is not exposed on the physical
underlay.

## Local AddressRealm realization

The accepted local topology is preserved (realm bridge with VM TAPs, realm
network namespace owning routed realm behavior, provider names are not ownership
proof), extended with the realm's fabric attachment:

```text
host namespace

VM TAP A ----\
              +-- realm bridge ---- realm network namespace
VM TAP B ----/        |
                      +-- fabric attachment (learning) --> VXLAN (realm VNI)
```

The VXLAN device terminates where fabric transport routing lives (the shared
fabric namespace or an equivalent provider attachment). The spec intentionally
does not require one exact interface fanout strategy, but the first production
implementation must prefer the simplest understandable option for the 10–20-host
target, and must satisfy:

- exactly **one VXLAN device per active realm per host** (not per remote host);
- VXLAN `id` = the realm's current binding VNI, standard destination port 4789;
- the device is a learning bridge port of the realm's L2 island
  (`nolearning` must not be used);
- MTU per the MTU section below.

It must not introduce OVS, OVN, EVPN, BGP, or custom eBPF as an implementation
shortcut without a separate accepted architecture decision.

## Same-host and cross-host neighbor behavior

The SPEC-0029 remote-neighbor proxy contract is **removed**. There is no realm
proxy MAC in the v3 dataplane.

For a guest ARP request inside realm R:

```text
if (R, destination IP) is a current endpoint of R on any enrolled host:
    the destination endpoint answers with its actual canonical MAC
    (locally via the bridge, remotely via head-end replication)
else:
    no synthetic reply
```

The guest does not need to understand VXLAN, WireGuard, VNI, host placement, or
remote MACs. A remote endpoint's actual MAC **is** exposed across the fabric:
this is the intended stretched-VLAN semantics, and intra-realm broadcast
visibility is that of a real VLAN.

## Bounded head-end replication contract

This section replaces the SPEC-0029 "No cross-host flood requirement".

For each active realm/host, the provider must realize a flood list equivalent
to:

```text
for each peer host P currently hosting >= 1 current endpoint of realm R:
    bridge fdb replace 00:00:00:00:00:00 dev <realm vxlan> dst <P fabric_transport_ip>
```

Requirements:

- the flood list is derived only from the accepted realm endpoint directory
  (current placement), never from ARP, FDB observations, or traffic;
- peers not hosting realm endpoints must not receive HER entries;
- unknown, stale, or non-enrolled VTEP addresses fail closed and are never
  dialed;
- broadcast, unknown-unicast, and multicast frames are replicated once per flood
  list member;
- after a frame's destination MAC is learned, traffic is unicast to the owning
  host's fabric transport address via the kernel FDB;
- learned FDB entries are dataplane cache only; they are never canonical
  placement and are rebuilt after restart;
- removal of the last realm endpoint from a host must withdraw that host's HER
  entries on all peers and remove learned state for the realm.

## Egress and ingress semantics

### Egress

For traffic from a local endpoint in realm R:

1. validate local endpoint identity/realm/source IP/MAC (anti-spoof);
2. apply canonical egress policy;
3. the frame is switched by the realm bridge: known unicast to a local TAP,
   known unicast to the VXLAN (learned FDB), or flooded per the HER contract;
4. VXLAN encapsulation uses the realm's current binding VNI and targets the
   destination host's fabric transport address through the shared WireGuard
   host fabric.

### Ingress

After WireGuard authenticates/decrypts a packet from a host:

1. the VNI must map to exactly one current AddressRealm binding
   (wrong/unknown/stale VNI drops with a visible counter);
2. the source host is the authenticated WireGuard peer (cryptokey routing on
   the fabric transport address), never asserted by inner-packet content;
3. the decapsulated Ethernet frame is delivered into the VNI-selected realm's
   L2 island;
4. TAP/bridge source-MAC and source-IP anti-spoofing and NetworkPolicy
   enforcement apply on the bridge/TAP path before delivery to a guest.

No packet may be delivered into a realm whose binding does not match the
received VNI. No inner-packet field may override the WireGuard-authenticated
source host identity.

## Policy and spoofing

One canonical NetworkPolicy generation may compile to:

- local TAP/bridge enforcement (now mandatory, not optional);
- realm routed enforcement;
- encapsulation egress validation;
- decapsulation ingress validation (VNI-to-realm binding and source-host
  authentication).

At minimum reject:

- spoofed source MAC;
- spoofed source IPv4;
- spoofed ARP sender IP/MAC;
- source endpoint not local to the current host;
- wrong realm/VNI;
- wrong/stale source host fabric generation;
- destination endpoint in another realm even when the IP matches;
- stale endpoint/placement/binding generation.

Fail-open partial policy transitions are forbidden. Because real MACs now cross
hosts, the TAP/bridge anti-spoof requirements are evidence-gating (see the real
functional gate), not optional hardening.

## Public/floating IP and egress

Unchanged from SPEC-0029: provider realization must use canonical endpoint
identity plus realm, never bare private IP; required evidence includes two
overlapping realms with the same private IP where only the endpoint owning the
tested binding receives the external traffic.

## MTU

The provider path includes at least:

```text
tenant packet
+ VXLAN encapsulation (50 bytes)
+ WireGuard encapsulation (60 bytes IPv4 / 80 bytes IPv6)
+ underlay headers
```

The implementation must derive a safe tenant MTU per layer
(`tenant_mtu = fabric_mtu − 50`), validate it against every peer's advertised
`fabric_mtu` at plan time, and propagate it through the existing guest network
configuration/DHCP path.

Required evidence:

- near-boundary allowed packet succeeds;
- oversize/PMTU behavior is explicit and does not silently black-hole supported
  traffic;
- MTU remains correct after restart/reconciliation;
- no canonical tenant identity depends on the raw provider MTU number.

## Scheduling, storage, drain, and host failure

Unchanged from SPEC-0029 (placement authority, storage fencing, drain
semantics, fail-closed unreachability semantics).

## Migration from P11 v2

Before privileged successor implementation:

1. retain `EndpointLocation`, the realm-scoped endpoint directory, and the
   planner's realm-scoped route/directory behavior;
2. retain the `RealmEncapsulationBinding` registry; migrate
   `encapsulation_kind` to `vxlan` under a new binding generation with full
   teardown of Geneve-owned state first;
3. retire the realm proxy MAC, deterministic tunnel MAC, per-(realm,
   remote-host) Geneve/bridge/veth attachments, and static per-attachment FDB
   steering;
4. implement the per-realm VXLAN device, bounded HER flood list, and learning
   attachment per this spec;
5. make TAP/bridge anti-spoof enforcement mandatory on the local path;
6. update provider conformance tests and evidence harnesses from the Geneve
   scenarios to the VXLAN/HER scenarios in this spec;
7. do not rewrite unrelated P9/P10 semantics.

## Provider conformance requirements

Before real-host promotion, portable/provider tests must cover:

- valid realm-to-VNI allocation (unchanged);
- duplicate allocation replay, VNI collision conflict, stale binding generation
  rejection, VNI lookup within current fabric domain, deletion/reuse ownership
  fence (unchanged);
- same CIDR in two realms accepted; same IP in two realms accepted; same IP
  twice in one realm rejected (unchanged);
- HER flood list contains exactly the peers hosting current realm endpoints;
- HER entry withdrawal when the last realm endpoint leaves a host;
- unknown/stale/non-enrolled VTEP in a plan is rejected;
- learned FDB state is rebuilt after restart and never treated as placement;
- wrong VNI ingress drop; unknown VNI ingress drop (unchanged);
- source host not matching the authenticated WireGuard peer drop;
- destination IP in wrong realm drop (unchanged);
- equivalent replay/unknown-outcome/reconcile behavior (unchanged);
- foreign VXLAN device/VNI protection.

## Real functional gate

Use at least three independent KVM/libvirt compute hosts unless a later accepted
SPEC strengthens the requirement.

The core scenario is mandatory:

```text
Realm A / Project A: 10.0.0.0/24
  A1 10.0.0.10 host-01
  A2 10.0.0.20 host-02

Realm B / Project B: 10.0.0.0/24
  B1 10.0.0.10 host-03
  B2 10.0.0.20 host-02
```

Prove:

1. A1 ARPs for A2 and receives A2's actual canonical MAC (cross-host, via HER);
2. A1 pings A2 (unicast after learning) and vice versa;
3. B1 ARPs for B2 and receives B2's actual canonical MAC;
4. A and B traffic never cross despite identical inner IPs;
5. DHCP discovery broadcast from A1 is answered across hosts by the realm-A
   DHCP authority;
6. unknown-unicast and broadcast frames are delivered to every host hosting
   realm endpoints and to no others;
7. an unattached/stale VNI delivers nothing;
8. anti-spoof rejection: a frame with an unaccepted source MAC or IP on a local
   TAP/bridge path is dropped with a visible counter;
9. the physical underlay carries no cleartext tenant traffic (capture filter:
   only the WireGuard port between enrolled hosts);
10. MTU boundary: near-boundary packet succeeds, oversize behavior is explicit;
11. restart/reconcile, drain, and cleanup leave zero leaked netns/bridge/veth/
    VXLAN/FDB/WireGuard/nft state across all hosts.
