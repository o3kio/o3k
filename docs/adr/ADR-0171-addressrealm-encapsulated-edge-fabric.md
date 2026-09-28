# ADR-0171 — AddressRealm-encapsulated edge fabric for overlapping tenant CIDRs

Status: Superseded
Date: 2026-08-20
Decision-accepted: 2026-08-20
Human-approval: requester acceptance recorded in issue #705 comment 5349129789
Supersedes: ADR-0170
Superseded-by: ADR-0186
Affected-services: network, compute, placement, scheduler, storage, kernel, edge, governance

Related issue: [#705](https://github.com/o3kio/o3k/issues/705)

Related decisions and specifications:

- [ADR-0160 — service topology and execution boundaries](ADR-0160-service-topology-and-execution-boundaries.md)
- [ADR-0165 — O3K Cloud OS and Cloud Kernel](ADR-0165-o3k-cloud-operating-system-and-cloud-kernel.md)
- [ADR-0168 — O3K Routed Fabric and node-local network execution](ADR-0168-o3k-routed-fabric-and-network-execution.md)
- [ADR-0169 — native persistent storage and the o3k-storage boundary](ADR-0169-native-persistent-storage-and-o3k-storage-boundary.md)
- [ADR-0170 — Namespaced Routed Edge Fabric](ADR-0170-namespaced-routed-edge-fabric.md)
- [SPEC-0026 — O3K Routed Fabric v1](../specs/SPEC-0026-o3k-routed-fabric-v1.md)
- [SPEC-0027 — native persistent storage v1](../specs/SPEC-0027-native-persistent-storage-v1.md)
- [SPEC-0028 — Namespaced Routed Edge Fabric v1](../specs/SPEC-0028-namespaced-routed-edge-fabric-v1.md)
- [SPEC-0029 — AddressRealm-encapsulated Edge Fabric v2](../specs/SPEC-0029-addressrealm-encapsulated-edge-fabric-v2.md)
- [P11 realm-overlay contract](../../contracts/edge-fabric-realm-overlay.md)
- [Execution-boundary contract](../../contracts/execution-boundaries.md)

This is a privileged multi-host networking change. The requester acceptance is
recorded on issue #705 and activates this ADR and SPEC-0029 as the P11 v2
implementation authority. Acceptance authorizes bounded implementation only;
it does not create a runtime, product, or real-host support claim. Those claims
remain gated on the evidence requirements below.

## Context

ADR-0170 established the first accepted P11 multi-host architecture:

- one host-local VM-facing bridge per active `AddressRealm`;
- one routed Linux network namespace per active realm/host;
- normal same-host ARP and local L2 inside one realm;
- control-plane-derived remote neighbor resolution using a realm proxy MAC;
- endpoint-location `/32` routes across a shared WireGuard host fabric;
- no cross-host ARP flooding or mandatory central network node;
- WireGuard as authenticated encrypted transport, not tenant authorization.

PR #703 then implemented only the first semantic/domain slice: endpoint location,
`RealmEndpointDirectory`, deterministic local-vs-remote neighbor resolution,
realm proxy MAC, host fabric public identity, and endpoint route planning. It did
not implement the privileged multi-host dataplane and created no P11 support
claim.

The accepted v1 profile deliberately required non-overlapping tenant prefixes
across the shared host fabric. That restriction is now considered too strong for
a general cloud product. Two independent customers should be able to create the
same RFC1918 CIDR, for example `10.0.0.0/24`, without becoming part of one
routing domain.

Linux network namespaces already isolate those duplicate prefixes locally. The
ambiguity appears only after traffic leaves a realm and enters a shared IP-only
fabric: bare destination `10.0.0.20` does not tell the host whether it belongs to
AddressRealm A or AddressRealm B.

The architecture therefore needs a cross-host realm identifier while preserving
the successful P9/P10 authority model and avoiding a mandatory OVN/OVS/EVPN or
custom eBPF control plane.

## Decision

### 1. `AddressRealm` is the tenant routing/isolation identity

For cross-host networking, an endpoint address is interpreted as:

```text
(AddressRealm ID, IP address)
```

not as a globally unique bare IP address.

Therefore these are distinct valid endpoints:

```text
(realm-A, 10.0.0.20)
(realm-B, 10.0.0.20)
```

The canonical `AddressRealm` UUID remains the stable O3K identity. The tenant
does not choose an overlay/VNI identifier, tunnel device, WireGuard peer, Linux
namespace name, route-table number, or provider-native encapsulation value.

### 2. Preserve the local AddressRealm topology from ADR-0170

This successor does not discard the useful local topology already accepted.
Each active AddressRealm on a compute host retains:

- one VM-facing host-local bridge compatible with the proven libvirt/TAP path;
- one bounded realm network namespace for routed realm behavior;
- endpoint-bound MAC/IP/ARP anti-spoofing;
- local bridge/TAP NetworkPolicy enforcement;
- routed policy/conntrack/NAT integration where required by P9;
- deterministic ownership/journal state for cleanup and reconciliation.

Same-host/same-realm endpoints may continue to use normal ARP and actual endpoint
MACs. Different AddressRealms never share the VM-facing realm bridge merely
because their CIDRs overlap.

### 3. Preserve the distributed endpoint directory and proxy-neighbor model

`o3kd` derives realm-scoped endpoint location only from accepted durable endpoint
and placement state. Packet learning, bridge FDB entries, ARP observations, or
kernel routes never become endpoint authority.

When a guest ARPs inside one AddressRealm:

```text
current local same-realm endpoint  -> actual endpoint MAC
current remote same-realm endpoint -> deterministic realm proxy MAC
unknown/stale/deleting/other realm  -> no synthetic reply
```

ARP/Ethernet broadcast is not flooded across hypervisors.

The same endpoint IP may appear in another AddressRealm without conflict because
directory lookup is scoped by `realm_id` before IP lookup.

### 4. Geneve carries AddressRealm identity across hosts

The P11 successor reference provider uses Geneve as a bounded unicast
encapsulation mechanism for cross-host realm identity.

For every active AddressRealm participating in the fabric, O3K maintains a
durable provider mapping equivalent to:

```text
RealmEncapsulationBinding {
    fabric_domain_id
    realm_id
    provider = geneve
    vni
    binding_generation
}
```

The exact Rust/wire type may differ, but the semantics may not.

Requirements:

- `realm_id` is canonical O3K identity;
- `vni` is provider-native execution mapping, never tenant-visible identity;
- one VNI maps to exactly one active AddressRealm within one fabric domain;
- one AddressRealm maps to one current VNI within that fabric domain;
- allocation is durable, collision-free, replay-safe, and fenced by generation;
- guests cannot request or override a VNI;
- ambiguous, duplicate, stale, or foreign VNI state fails closed;
- provider cleanup must prove ownership before removing a Geneve object/VNI.

The first implementation may use the simplest bounded Linux Geneve topology that
passes conformance for the approximately 10–20-host P11 profile. A static
per-realm/per-remote-host tunnel realization is acceptable if that is the most
debuggable kernel-native implementation. O3K must not introduce OVS, OVN, EVPN,
BGP, or custom eBPF merely to optimize tunnel multiplexing.

### 5. Geneve is not a regional Ethernet flood domain

Using Geneve does **not** change the P11 product claim to arbitrary regional L2.
The provider uses Geneve to carry realm identity and known unicast cross-host
traffic selected from accepted endpoint placement.

P11 still does not require:

- unknown-unicast flooding between hypervisors;
- ARP broadcast flooding between hypervisors;
- arbitrary Ethernet broadcast/multicast extension;
- distributed MAC learning as endpoint authority;
- tenant-controlled VNI/trunk semantics.

Remote endpoint location remains control-plane-derived. The target host is known
before encapsulation.

The capability remains truthfully described as:

```text
same_host_l2_adjacency: true
cross_host_connectivity: realm_encapsulated_routed
cross_host_arp_flooding: false
cross_host_unknown_unicast_flooding: false
overlapping_cross_host_cidrs: true
regional_arbitrary_l2: false
```

### 6. WireGuard remains one shared host transport and no longer routes tenant IPs

ADR-0170 used one shared WireGuard host fabric and allowed provider `AllowedIPs`
to be derived from tenant endpoint `/32`s. That is incompatible with overlapping
AddressRealms because identical tenant `/32`s cannot uniquely identify two
realms in one shared WireGuard routing context.

This successor therefore changes the WireGuard responsibility.

Each host receives a unique provider fabric transport identity equivalent to:

```text
FabricHostTransportIdentity {
    host_id
    wireguard_public_key
    underlay_endpoint
    fabric_transport_ip
    fabric_generation
    mtu_bounds
}
```

The fabric transport address comes from an operator/O3K-owned provider address
space and is not a tenant address.

WireGuard peers route/authenticate only provider host-fabric transport addresses
(or other non-tenant provider transport prefixes explicitly accepted by the
fabric contract). Tenant endpoint CIDRs and tenant `/32`s are not WireGuard
`AllowedIPs` in this profile.

Conceptually:

```text
host A fabric IP -> host B fabric IP
        WireGuard authenticated/encrypted transport

inside that protected path:
        Geneve VNI -> AddressRealm
        inner IP    -> tenant endpoint within that AddressRealm
```

This restores a clean separation:

```text
AddressRealm/VNI   = tenant routing/isolation context
NetworkPolicy      = tenant authorization
Geneve             = realm identity encapsulation
WireGuard          = host authentication/encryption
```

### 7. Cross-host packet path is realm-aware before tenant IP lookup

For a remote same-realm endpoint, the logical datapath is:

```text
VM-A
  |
ARP for 10.0.0.20
  |
local o3k-network answers realm proxy MAC
  |
realm-A namespace
  |
accepted destination = (realm-A, 10.0.0.20)
  |
accepted target host = host-B
  |
Geneve encapsulation with realm-A VNI
  |
WireGuard transport to host-B fabric transport IP
  |
Geneve VNI validation/demultiplex
  |
realm-A namespace on host-B
  |
validate current local endpoint 10.0.0.20
  |
VM-B
```

A simultaneous customer-B packet may carry the same inner source/destination
addresses but a different accepted AddressRealm/VNI and therefore reaches a
different realm namespace.

The fabric must never perform an unscoped tenant destination-IP lookup before
realm/VNI identity has been established.

### 8. Geneve termination belongs to bounded fabric execution state

The exact Linux plumbing is an implementation/provider concern, but it must
preserve the following topology invariant:

- WireGuard and provider fabric transport live in the shared host-fabric
  execution scope;
- Geneve encapsulation/decapsulation occurs on the protected host-fabric path;
- accepted VNI is validated before inner tenant traffic is delivered to a realm;
- inner tenant traffic enters only the corresponding AddressRealm execution
  context;
- no shared routing table may forward overlapping tenant IPs without the realm
  discriminator;
- realm-to-fabric and fabric-to-realm attachments are exact provider-owned
  objects with generation/ownership evidence.

The implementation may use static Linux Geneve devices, provider-owned bridges,
veths, neighbor entries, route tables, or metadata mode only when needed and
proven. These mechanisms remain below the canonical boundary.

### 9. PR #703 planner state is partially reusable but must be revised

The following merged semantics remain valid:

- `EndpointLocation`;
- one `RealmEndpointDirectory` per realm;
- local endpoint -> actual MAC;
- remote endpoint -> realm proxy MAC;
- accepted endpoint placement/generation;
- host fabric public identity concept;
- fail-closed planner validation.

Before privileged successor implementation, the planner must be revised so:

- all cross-host route/neighbor lookup remains explicitly realm-scoped;
- `FabricEndpointRoute` or its successor carries `realm_id`/realm binding;
- the global non-overlap rejection is removed only when the selected provider
  advertises overlapping-realm support;
- host fabric identity gains/derives a unique provider transport address;
- WireGuard planning stops using tenant endpoint `/32`s as peer `AllowedIPs`;
- a typed durable realm-to-Geneve provider mapping is added;
- VNI allocation/lookup/replay/conflict semantics are testable before kernel
  mutation.

No PR #703 code should be discarded merely because its old provider assumption
changed. Reuse the realm-scoped endpoint directory and change only the fabric
semantics that depended on global IP uniqueness.

### 10. Overlapping-prefix support is capability-gated

ADR-0168 intentionally kept `overlapping_prefixes` from becoming a permanent
false invariant. This successor activates overlap only for providers that prove
it.

The selected P11 Geneve-over-WireGuard provider must advertise a bounded
capability equivalent to:

```text
OverlappingAddressRealms = supported
RealmEncapsulation = geneve
CrossHostL2Adjacency = false
```

A provider without realm encapsulation continues to reject overlapping active
prefixes before mutation.

This permits a future direct-routed/BGP provider to remain non-overlapping while
a Geneve/OVN/other provider supports overlap without changing canonical tenant
resources.

### 11. Source validation is realm + endpoint + host scoped

Encapsulation must not weaken P9 anti-spoofing.

On egress, a cross-host packet is valid only when:

- ingress realm matches the accepted endpoint realm;
- inner source IP/MAC belongs to a current local endpoint in that realm;
- destination endpoint exists in the same realm or is otherwise explicitly
  authorized by canonical route/gateway intent;
- selected target host matches accepted endpoint placement;
- realm encapsulation binding/VNI generation is current;
- target fabric host generation is current.

On ingress, a packet is delivered only when:

- WireGuard authenticated the current source host fabric identity;
- Geneve VNI maps to one current AddressRealm;
- the source host is authorized to source the inner endpoint for that realm;
- destination endpoint belongs to that realm and is currently local on the
  receiving host;
- endpoint/placement/fabric/binding generations are current;
- NetworkPolicy permits the flow.

An inner destination IP match alone is never sufficient for delivery.

### 12. Local and cross-host NetworkPolicy remain one authority

Canonical NetworkPolicy may compile to multiple provider enforcement points:

- TAP/bridge path for local same-host L2;
- realm-routed path;
- realm-to-Geneve egress validation;
- Geneve-to-realm ingress validation.

These are realizations of one policy generation. Fail-open partial policy
updates are forbidden. A packet must not become permitted merely because it
changed from local to remote or because another customer uses the same IP.

### 13. MTU includes both Geneve and WireGuard overhead

The v1 MTU contract considered WireGuard. The successor must account for the
complete selected path, including Geneve and WireGuard encapsulation plus the
actual underlay family/options.

The provider reports bounded capability and derives a safe tenant MTU from the
real path. The effective MTU is propagated through the existing guest network
configuration/DHCP path.

P11 acceptance requires near-boundary traffic evidence and explicit detection of
fragmentation/PMTU black holes. A small ping does not prove the profile.

### 14. North/south networking remains distributed and realm-scoped

P9 egress/SNAT, public/floating-address, and stateful-policy semantics remain
canonical. P11 must integrate them with overlapping AddressRealms without
creating one ambiguous root-namespace tenant-IP table.

A public/FIP binding is resolved by canonical endpoint identity/realm, not by
bare private IP. Provider-native NAT/routing state must remain isolated to the
correct realm and endpoint-owning execution location.

No central Neutron-like network node is introduced.

### 15. Scheduling, drain, storage locality, and failure semantics remain unchanged

This ADR changes cross-host network identity and transport, not Cloud Kernel
scheduling authority.

P11 continues to reuse:

- authenticated agent inventory;
- Placement allocations;
- administrative state and drain;
- durable work leases and controller fencing;
- agent epochs and generations;
- P10 storage placement constraints;
- unknown-outcome/observe-before-retry semantics.

Host-local LVM still constrains placement. Shared Ceph RBD still requires clean
single-writer handoff or stronger accepted fencing. An unreachable host is not
assumed powered off and is not blindly evacuated.

### 16. Failure/replay rules extend to realm encapsulation state

The following are generation-bound provider state:

- realm-to-VNI binding;
- host fabric transport identity;
- Geneve tunnel/peer realization;
- realm-to-fabric attachment;
- endpoint-to-target-host route selection;
- remote proxy-neighbor realization;
- policy realization across local/routed/encapsulation paths.

Equivalent replay returns durable state. Same identity/generation with different
payload is conflict. Timeout after possible kernel mutation is unknown outcome.
Observation precedes retry. Stale controller, agent, endpoint, placement,
fabric, or realm-binding generation fails closed.

### 17. Support claims require an overlapping-realm real-host gate

The successor is not considered proven merely because two namespaces with the
same CIDR exist on one machine.

At minimum, the real multi-host gate must create two independent projects/
AddressRealms using the same CIDR and overlapping endpoint addresses across
multiple hypervisors, then prove:

- each project's local ARP behavior;
- remote proxy-ARP behavior;
- correct Geneve VNI/realm mapping;
- correct remote-host selection;
- successful allowed traffic inside each realm;
- denied cross-realm traffic despite identical IPs;
- wrong/stale VNI injection fails closed;
- wrong source host/endpoint identity fails closed;
- underlay contains only protected WireGuard transport, not cleartext tenant
  packets;
- no cross-host ARP/broadcast flooding is required;
- MTU-boundary traffic succeeds for the selected profile;
- cleanup leaves zero owned bridge/netns/veth/Geneve/VNI/route/neighbor/
  WireGuard/policy leaks and zero foreign mutations.

The exact real hypervisor count and topology bind the support claim.

## Consequences

### Positive

- independent customers may safely reuse common RFC1918 ranges;
- AddressRealm finally becomes a real end-to-end routing identity rather than a
  local-only namespace;
- WireGuard responsibilities become cleaner because it routes only host-fabric
  transport addresses;
- existing local ARP and distributed endpoint-directory behavior remains useful;
- no mandatory OVN/OVS/EVPN/BGP/custom-eBPF control plane is introduced;
- future eBPF/OVN/EVPN providers can replace/accelerate execution without
  redefining canonical tenant identity.

### Costs and risks

- Geneve adds another encapsulation layer and MTU overhead;
- provider state now includes VNI allocation and tunnel lifecycle;
- tunnel fanout may grow with active realm/host relationships;
- restart/reconciliation must rebuild realm-to-VNI and tunnel state correctly;
- operational debugging spans bridge -> realm netns -> Geneve -> WireGuard;
- the reference implementation must prove its exact Linux Geneve topology rather
  than assuming a convenient kernel behavior;
- this is more complex than the original non-overlapping routed profile.

For P11's approximately 10–20-host target, this complexity is accepted because
customer-overlapping CIDRs are a fundamental cloud capability and the change is
being made before the privileged fabric has been implemented broadly.

## Rejected alternatives

### Keep global non-overlap permanently

Rejected because it makes common tenant CIDRs a region-global coordination
problem and is too restrictive for a general-purpose cloud.

### One WireGuard interface/key per AddressRealm

Rejected as the default because tenant/realm count would directly multiply
WireGuard interfaces, keys, peer sets, and lifecycle state. It also couples
canonical AddressRealm topology too tightly to one encryption provider.

### Put tenant endpoint `/32`s in shared WireGuard `AllowedIPs`

Rejected because overlapping AddressRealms can contain identical `/32`s. Shared
WireGuard transport must route unique host-fabric addresses instead.

### Return the remote VM's real MAC and transport Ethernet directly

Rejected for this profile because it requires a cross-host L2/FDB/flooding model
that is not needed for P11's routed semantics.

### Mandatory OVN/OVS

Rejected because O3K can carry explicit realm identity with a much smaller
kernel-native provider for the 10–20-host edge profile. OVN remains a valid
future provider when broader Neutron/L2 semantics justify it.

### EVPN/BGP control plane now

Rejected because accepted endpoint placement already gives the O3K control plane
the remote-host mapping required at this scale. A second distributed routing
control plane is unnecessary for P11 v2.

### Custom eBPF dataplane now

Rejected because it adds kernel/program lifecycle complexity before the semantic
fabric model is proven. eBPF remains a future realization/acceleration path.

## Non-goals

This ADR does not add:

- arbitrary regional L2 adjacency;
- cross-host ARP/broadcast/multicast flooding;
- tenant trunks/VLAN transparency;
- VXLAN or EVPN;
- OVN/OVS as a requirement;
- custom eBPF dataplane;
- internal BGP;
- STUN/TURN/relay/rendezvous;
- live migration;
- blind automatic evacuation;
- storage migration or multi-attach;
- SR-IOV/DPDK;
- multi-region networking;
- P12 native API/CLI work.

## Migration from ADR-0170 / PR #703

ADR-0171 was accepted as the P11 v2 authority and is now superseded for new
fabric implementation by ADR-0186. The v1 and v2 documents remain useful
historical references for behavior retained by the v3 successor.

The migration requires:

1. activate `contracts/edge-fabric-realm-overlay.md`;
2. retire the old non-overlap implementation prompt;
3. retain PR #703 realm endpoint directory semantics;
4. revise fabric route/host identity types to be realm-aware and transport-IP
  based;
5. add durable realm-to-VNI provider mapping;
6. only then implement privileged Geneve/WireGuard realization.

No runtime compatibility/support claim changes merely because the successor is
accepted.

## Fitness functions

Before acceptance/merge of privileged implementation, repository checks should
be able to prove at least:

- canonical domain types do not expose Geneve interface names/raw commands;
- VNI/provider mapping cannot be tenant supplied;
- duplicate VNI binding in one fabric domain is rejected;
- same IP in two different AddressRealms is allowed by the successor planner;
- duplicate IP within one AddressRealm remains rejected;
- fabric endpoint route identity includes realm scope;
- WireGuard host transport planning contains no tenant endpoint prefixes;
- private WireGuard keys remain non-representable in public/control-plane
  identity types;
- stale realm binding/fabric/endpoint generations are rejected;
- evidence/cleanup contracts include Geneve/VNI state.

## External implementation references

The Linux `ip-link(8)` Geneve interface supports a VNI and a unicast remote
endpoint; Linux also supports externally controlled Geneve mode. The exact O3K
provider realization must be proven against the selected kernel/iproute2 profile
rather than inferred from documentation alone.

WireGuard's network-namespace behavior permits an interface to be moved while
its UDP socket remains in its creation namespace; O3K may continue to use this
property for the shared host transport where it simplifies underlay isolation.

References:

- https://man7.org/linux/man-pages/man8/ip-link.8.html
- https://www.wireguard.com/netns/
