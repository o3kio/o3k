# P11 AddressRealm-encapsulated edge-fabric contract

Status: Accepted

Superseded-by: `contracts/edge-fabric-stretched-l2.md` for P11 v3

Decision-accepted: 2026-08-20
Human-approval: requester acceptance recorded in issue #705 comment 5349129789

Related architecture:

- [ADR-0171](../docs/adr/ADR-0171-addressrealm-encapsulated-edge-fabric.md)
- [SPEC-0029](../docs/specs/SPEC-0029-addressrealm-encapsulated-edge-fabric-v2.md)
- [ADR-0168](../docs/adr/ADR-0168-o3k-routed-fabric-and-network-execution.md)
- [ADR-0170](../docs/adr/ADR-0170-namespaced-routed-edge-fabric.md)
- [current execution-boundary contract](execution-boundaries.md)

This accepted contract supersedes `contracts/edge-fabric-v1.md` for P11 v2
implementation authority. It is superseded for P11 v3 by
`contracts/edge-fabric-stretched-l2.md` (stretched-L2 VXLAN/head-end-replication
fabric); it remains useful only for v2 behavior that is explicitly retained by
the v3 authority. Acceptance authorizes bounded implementation only;
runtime, product, and real-host support claims remain gated by the evidence
requirements in this contract and SPEC-0029.

## Purpose

Define the semantic boundary for a P11 provider that supports overlapping tenant
CIDRs across hypervisors by carrying `AddressRealm` identity in Geneve while
using one shared WireGuard host transport.

The contract separates:

```text
AddressRealm / endpoint / policy identity -> canonical O3K authority
endpoint placement / realm directory      -> derived control-plane intent
realm -> encapsulation binding             -> durable provider mapping
Geneve/VNI/tunnel objects                  -> provider execution state
WireGuard host transport                   -> provider execution/security state
```

## Authority

### `o3kd` / Cloud Kernel owns

- AddressRealm, project, endpoint, fixed-IP/MAC, and policy identity;
- accepted endpoint host placement and generations;
- host administrative/scheduling state;
- durable operation/work/fencing identity;
- derivation of realm-scoped endpoint directories;
- derivation of realm-scoped remote endpoint destinations;
- provider mapping identity for realm encapsulation;
- accepted host fabric public/transport identity and generation;
- public/FIP/egress desired state;
- storage placement constraints;
- retry, compensation, reconciliation, and support-claim decisions.

### `o3k-network` / fabric provider owns only

- exact provider-owned realm bridges/TAP policy state;
- exact provider-owned realm netns/veth attachments;
- remote proxy-neighbor realization;
- provider-native realm-to-Geneve/VNI realization;
- provider-native known-unicast tunnel/peer state;
- exact provider-owned shared host fabric namespace;
- WireGuard private key and peer/interface state;
- MTU/provider route/FDB/neighbor state derived from accepted plans;
- bounded observations and deterministic cleanup of proven owned state.

The executor does not invent a tenant IP/MAC, realm, VNI, destination host,
public identity, or authorization decision.

## Canonical endpoint address key

Any cross-host endpoint lookup with overlap enabled uses:

```text
(realm_id, fixed_ip)
```

Bare `fixed_ip` is not a globally unique key.

Requirements:

- duplicate fixed IP in one current AddressRealm is conflict;
- the same fixed IP in a different AddressRealm is allowed;
- the same CIDR in a different AddressRealm is allowed;
- provider observations never merge two endpoints because their IP matches.

## Realm endpoint directory

The planner publishes a deterministic directory per AddressRealm. Required
semantic entry fields are:

```text
endpoint_id
project_id
realm_id
fixed_ip
canonical_mac
selected_host
endpoint_generation
placement_generation
```

The executor rejects stale or scope-conflicting entries. It never derives
current placement from ARP, bridge FDB, Geneve source MAC, kernel routes, or
observed traffic.

## Local neighbor contract

Inside one AddressRealm/local host:

```text
local destination  -> actual endpoint MAC
remote destination -> AddressRealm proxy MAC
unknown/other realm -> no synthetic reply
```

ARP is guest-driven/demand-driven. O3K does not require guest ARP-cache
injection.

No cross-host ARP flooding is part of the contract.

## Realm proxy MAC

The deterministic realm proxy MAC remains:

- locally administered/unicast;
- versioned/collision checked;
- derived from stable realm identity;
- provider execution state, not endpoint identity;
- used only to attract remote same-realm traffic to the local realm routing
  edge.

It does not mean the remote endpoint's real MAC is reachable across hosts.

## Realm encapsulation binding

The provider mapping layer exposes bounded semantic state equivalent to:

```text
RealmEncapsulationBinding {
    fabric_domain_id
    realm_id
    provider_kind
    provider_segment_id
    binding_generation
}
```

For the reference provider:

```text
provider_kind       = geneve
provider_segment_id = VNI
```

Requirements:

- tenant cannot choose `provider_segment_id`;
- current mapping is durable before external mutation;
- active VNI uniqueness within one fabric domain;
- one current VNI cannot identify two active realms;
- equivalent replay returns same mapping;
- conflicting same-generation mapping fails closed;
- stale generation cannot replace current mapping;
- cleanup requires exact ownership proof;
- foreign Geneve/VNI state is never adopted from name/number alone.

## Host fabric transport identity

A host fabric identity contains only public/provider-safe fields equivalent to:

```text
host_id
wireguard_public_key
underlay_endpoint
fabric_transport_ip
fabric_generation
provider_version
underlay_mtu
fabric_mtu
```

The fabric transport IP is O3K/operator infrastructure address space and must be
unique among active hosts in the fabric domain.

WireGuard private keys are host-local and never represented here.

## WireGuard transport contract

WireGuard is host authentication/encryption only.

The successor contract explicitly forbids deriving shared WireGuard peer
`AllowedIPs` from tenant endpoint prefixes when overlapping realms are enabled.

Peer routing/source validation uses provider host-fabric transport addresses or
other unique provider transport prefixes accepted by this contract.

Conceptually:

```text
peer host-B AllowedIPs -> host-B fabric transport address
```

not:

```text
peer host-B AllowedIPs -> tenant 10.0.0.20/32
```

The latter is ambiguous when another realm uses the same endpoint IP.

## Realm-aware remote endpoint plan

The planner emits a semantic route/destination value equivalent to:

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

The provider resolves:

```text
realm_id   -> current Geneve VNI
target_host -> current host fabric transport IP
```

A kernel route keyed only by tenant destination IP is never sufficient to select
a realm.

## Geneve egress contract

Before encapsulation the executor validates:

- source endpoint is current and local;
- source endpoint belongs to ingress realm;
- inner source IP/MAC matches canonical endpoint binding;
- destination lookup is scoped to the same realm or an explicitly authorized
  canonical gateway/route;
- destination host matches accepted placement;
- realm/VNI binding generation is current;
- destination host fabric generation is current;
- policy permits the flow.

The provider then emits known-unicast Geneve traffic using the accepted realm
VNI toward the accepted destination host's fabric transport address.

No endpoint host may be discovered through unknown-unicast learning/flooding.

## Geneve ingress contract

After current WireGuard host authentication/decryption, Geneve ingress must
validate:

- VNI maps to exactly one current realm in the local fabric domain;
- authenticated source host is current;
- source endpoint belongs to that realm and source host;
- source endpoint generation/placement is current;
- destination endpoint lookup is scoped to the VNI-selected realm;
- destination endpoint is current and local to receiving host;
- destination generation is current;
- NetworkPolicy permits the flow.

An inner IP match alone is insufficient.

Packets with unknown, stale, ambiguous, foreign, or wrong-realm VNI are dropped
and surfaced as bounded evidence/metrics without creating provider authority.

## Geneve realization constraints

The first Linux provider may choose the simplest proven kernel-native topology
for the 10–20-host target.

Allowed implementation choices include bounded static Geneve tunnel/device
state or externally controlled metadata mode only when the selected approach is
proven by focused conformance tests.

The provider must not add OVS, OVN, EVPN, BGP, or custom eBPF merely to make
Geneve multiplexing easier.

If the chosen static realization causes unacceptable tunnel/interface growth at
the declared P11 target, implementation must stop for architecture review rather
than silently introduce a new SDN control plane.

## No regional flood contract

The successor supports overlapping CIDRs without promising arbitrary regional
Ethernet.

Not required/permitted as implicit behavior:

- cross-host ARP flood;
- cross-host Ethernet broadcast flood;
- unknown-unicast flood;
- multicast flood;
- MAC/FDB learning as placement authority.

The control plane already knows destination endpoint placement.

## Policy contract

One canonical NetworkPolicy generation may compile to:

- local TAP/bridge path;
- realm routed path;
- Geneve egress admission;
- Geneve ingress admission.

All paths must converge to the same semantic policy generation. Partial
fail-open realization is forbidden.

Cross-realm communication remains denied unless explicit canonical route/gateway
intent plus policy permits it. Identical IPs in two realms never imply
connectivity.

## Public/FIP/NAT contract

Public/FIP and egress realization resolves private destination/source by
canonical endpoint ID + realm, not bare tenant IP.

When two realms use `10.0.0.10`, an external binding for one endpoint must never
match the other solely through address equality.

Provider-native shared/root tables must preserve realm discrimination or remain
realm-scoped before any tenant-IP match.

## MTU contract

Effective tenant MTU accounts for the complete path including Geneve,
WireGuard, and underlay headers/options.

The provider:

- reports bounded capability;
- selects/derives a safe tenant MTU;
- propagates it through existing guest network configuration;
- reconciles MTU after restart;
- proves near-boundary traffic in real-host evidence.

Provider MTU numbers are not canonical identity.

## Planner migration contract for PR #703

Merged PR #703 remains reusable for:

- EndpointLocation;
- RealmEndpointDirectory;
- local actual-MAC vs remote realm-proxy-MAC resolution;
- endpoint/placement generation fences;
- fail-closed validation.

It must be revised before privileged successor dataplane work so:

- all fabric endpoint routes include realm scope;
- host fabric identity includes/derives unique transport addressing;
- WireGuard planning no longer depends on tenant endpoint prefixes;
- realm/VNI provider mapping exists;
- overlap is capability-gated rather than globally rejected;
- tests accept duplicate CIDR/IP across different realms and still reject
  duplicates inside one realm.

## Scheduling, drain, failure, and storage

The successor does not alter accepted scheduling/storage authority.

- `Draining` excludes new placement;
- unreachable host is unknown, not powered off;
- no blind duplicate VM recreation;
- host-local LVM constrains placement;
- RBD single-writer handoff requires clean release or accepted fencing;
- existing controller work leases, fencing, agent epochs, generations,
  unknown-outcome, and observe-before-retry rules apply.

## Ownership and cleanup

Exact ownership proof applies to:

- realm bridges/TAP policy state;
- realm namespaces/veths;
- proxy-neighbor entries;
- realm encapsulation mapping/VNI;
- Geneve devices/tunnels/peer/FDB/neighbor/route state;
- shared fabric namespace;
- WireGuard interface/peers/private-key file;
- nftables/policy state;
- provider journals/manifests.

Names, VNI numbers, interface names, or inner IP addresses alone are never
ownership proof.

## Evidence contract

Full-profile evidence must prove:

- same-host real-MAC ARP;
- remote same-realm proxy-MAC ARP;
- two different projects/realms using the same CIDR across hosts;
- same endpoint IP used independently in both realms;
- successful in-realm allowed traffic for both;
- zero cross-realm misdelivery despite identical IPs;
- correct realm/VNI mapping;
- wrong/unknown/stale VNI drop;
- wrong source-host/endpoint drop;
- no cross-host ARP flood dependency;
- host transport encrypted by WireGuard;
- WireGuard tenant `/32` routing absent in overlap profile;
- policy allow/deny in both realms;
- FIP/public binding scoped to correct realm/endpoint;
- MTU boundary;
- LVM/RBD placement semantics;
- drain/reconnect/failure recovery;
- independent zero-leak/zero-foreign-mutation cleanup.

## Non-goals

This contract does not define arbitrary regional L2, cross-host flood behavior,
VXLAN/EVPN, OVN/OVS, custom eBPF, BGP, NAT traversal, live migration, blind
automatic evacuation, storage migration, multi-attach, SR-IOV/DPDK, multi-region,
or P12 API behavior.
