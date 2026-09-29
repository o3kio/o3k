# P11 Stretched-L2 edge-fabric contract

Status: Accepted

Decision-accepted: 2026-09-28
Human-approval: requester acceptance recorded in the introducing pull request, 2026-09-28

Supersedes: `contracts/edge-fabric-realm-overlay.md` for P11 v3

Related architecture:

- [ADR-0186](../docs/adr/ADR-0186-stretched-l2-edge-fabric-vxlan-her.md)
- [SPEC-0049](../docs/specs/SPEC-0049-stretched-l2-edge-fabric-v3.md)
- [ADR-0168](../docs/adr/ADR-0168-o3k-routed-fabric-and-network-execution.md)
- [ADR-0172](../docs/adr/ADR-0172-configurable-edge-fabric-transport-ports.md)
- [current execution-boundary contract](execution-boundaries.md)
- Shared substrate implementation: [o3kio/fabric](https://github.com/o3kio/fabric)

Aligned external decision: CHV
[ADR-021](https://github.com/kubedoio/chv/blob/main/docs/specs/adr/021-stretched-l2-vxlan-her-wireguard-fabric.md)
(kubedoio/chv#270).

This accepted contract supersedes `contracts/edge-fabric-realm-overlay.md` for
P11 v3 implementation authority. Acceptance authorizes bounded implementation
only; runtime, product, and real-host support claims remain gated by the
evidence requirements in this contract and SPEC-0049.

The WireGuard host-fabric substrate beneath this contract (netns, WireGuard
transport, per-network VXLAN/HER objects, ownership journaling, key hygiene)
is implemented once in the shared repository
[o3kio/fabric](https://github.com/o3kio/fabric) and consumed by git tag by
both O3K and CHV; its
[`contracts/fabric-provider-v1.md`](https://github.com/o3kio/fabric/blob/main/contracts/fabric-provider-v1.md)
is normative for that substrate, and
[`docs/change-control.md`](https://github.com/o3kio/fabric/blob/main/docs/change-control.md)
governs cross-project change requests. On any disagreement between this
contract and the shared provider contract about the substrate, the shared
provider contract wins for the substrate and this contract wins for the
realm/policy layers above it.

## Purpose

Define the semantic boundary for a P11 provider in which each `AddressRealm` is
one literal L2 broadcast domain (a stretched VLAN) across all enrolled
hypervisors: per-realm kernel VXLAN with bounded head-end replication and kernel
MAC learning, carried inside one shared authenticated/encrypted WireGuard host
transport, with overlapping tenant CIDRs across realms preserved.

The contract separates:

```text
AddressRealm / endpoint / policy identity -> canonical O3K authority
endpoint placement / realm directory      -> derived control-plane intent
realm -> encapsulation binding (VNI)       -> durable provider mapping
VXLAN/FDB/flood-list objects               -> provider execution state
WireGuard host transport                   -> provider execution/security state
```

## Authority

### `o3kd` / Cloud Kernel owns

- AddressRealm, project, endpoint, fixed-IP/MAC, and policy identity;
- accepted endpoint host placement and generations;
- host administrative/scheduling state;
- durable operation/work/fencing identity;
- derivation of realm-scoped endpoint directories;
- derivation of the per-realm HER flood list (which peers host realm endpoints);
- provider mapping identity for realm encapsulation (VNI);
- accepted host fabric public/transport identity and generation;
- public/FIP/egress desired state;
- storage placement constraints;
- retry, compensation, reconciliation, and support-claim decisions.

### `o3k-network` / fabric provider owns only

- exact provider-owned realm bridges/TAP policy state;
- exact provider-owned realm netns/veth attachments;
- provider-native realm-to-VXLAN/VNI realization;
- provider-native VXLAN device, learning, and HER flood-entry state;
- exact provider-owned shared host fabric namespace;
- WireGuard private key and peer/interface state;
- MTU/provider route/FDB/neighbor state derived from accepted plans;
- bounded observations and deterministic cleanup of proven owned state.

The executor does not invent a tenant IP/MAC, realm, VNI, destination host,
public identity, or authorization decision.

## Canonical endpoint address key

Unchanged from the realm-overlay contract: any cross-host endpoint lookup with
overlap enabled uses `(realm_id, fixed_ip)`; bare `fixed_ip` is not a globally
unique key; duplicate fixed IP in one current realm is conflict; the same fixed
IP or CIDR in a different realm is allowed; provider observations never merge
two endpoints because their IP matches.

## Realm endpoint directory

The planner publishes a deterministic directory per AddressRealm with the same
required semantic entry fields as the realm-overlay contract (`endpoint_id`,
`project_id`, `realm_id`, `fixed_ip`, `canonical_mac`, `selected_host`,
`endpoint_generation`, `placement_generation`).

The executor rejects stale or scope-conflicting entries. It never derives
current placement from ARP, bridge FDB, VXLAN source MAC, kernel routes, or
observed traffic. Learned FDB entries are dataplane cache, rebuilt on restart,
and are never placement authority.

## Local neighbor contract

Inside one AddressRealm, local and remote destinations are treated uniformly:

```text
current realm endpoint (any enrolled host) -> actual endpoint canonical MAC
unknown / absent / other realm             -> no synthetic reply
```

There is no realm proxy MAC in the v3 dataplane. ARP is guest-driven; guest ARP
requests for remote endpoints traverse the fabric via head-end replication and
are answered by the remote endpoint itself.

## Realm encapsulation binding

The durable provider mapping is unchanged in shape from the realm-overlay
contract, with `encapsulation_kind = vxlan`:

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

All realm-overlay binding invariants apply unchanged: VNI is not
tenant-supplied; active VNI uniqueness per fabric domain; idempotent replay;
generation fencing; ownership-checked deletion; fail-closed ambiguous observed
state; reuse only after owned tunnel state is proven absent.

## Stretched-L2 datapath contract

For each active realm/host the provider realizes, at minimum:

1. one VXLAN device carrying the realm's current binding VNI on the standard
   destination port (UDP/4789), terminating where fabric transport routing
   lives;
2. a learning attachment between that device and the realm's L2 island
   (`nolearning` must not be used);
3. a bounded HER flood list: one `00:00:00:00:00:00` flood entry per peer host
   currently hosting at least one current endpoint of the realm, targeting the
   peer's fabric transport address;
4. MTU derived per SPEC-0049 (`tenant_mtu = fabric_mtu − 50`).

Hard requirements:

- the flood list is derived only from the accepted endpoint directory;
- unknown, stale, or non-enrolled VTEP addresses fail closed;
- a received frame's VNI must map to exactly one current realm binding;
- the source host is the authenticated WireGuard peer (cryptokey routing), never
  an inner-packet assertion;
- TAP/bridge source-MAC/IP and ARP-sender anti-spoof enforcement is mandatory
  on the local path;
- NetworkPolicy enforcement applies on the bridge/TAP path before guest
  delivery;
- denied or dropped packets increment visible counters;
- foreign VXLAN/FDB/WireGuard state is rejected, never adopted or deleted;
- realm L2 segments must not be bridged into site-local physical switches.

## WireGuard host transport contract

Unchanged from the realm-overlay contract, including ADR-0172 port policy:

- one WireGuard interface and keypair per host in the shared fabric namespace;
- AllowedIPs carry only host fabric transport addresses, never tenant endpoint
  prefixes (mandatory: identical tenant `/32`s may exist in different realms);
- private keys are host-local, never in canonical state, plans, protocol
  messages, or ordinary evidence, and are fenced by host fabric generation;
- WireGuard authenticates and encrypts host transport only; it is not the realm
  discriminator and not a tenant authorization mechanism.

## Isolation guarantees

- Cross-realm isolation is structural: one VNI per realm; wrong/unknown/stale
  VNI has no delivery path; overlapping CIDRs never merge.
- Host admission is cryptographic: only enrolled peers with accepted public
  keys and current fabric generations participate.
- Intra-realm visibility is **that of a real VLAN**: endpoints of one realm can
  observe that realm's broadcast traffic, including across hosts. This is the
  intended stretched-L2 semantics and an accepted consequence of this contract.
- Placement and authorization authority remains the accepted control-plane
  directory and NetworkPolicy; the dataplane never widens them.

## Public/FIP, egress, scheduling, storage, drain, and failure semantics

Unchanged from the realm-overlay contract, keyed by canonical endpoint identity
plus realm, never bare private IP.

## Evidence gates

Runtime, product, or real-host support claims require the SPEC-0049 real
functional gate (three independent KVM/libvirt hosts) and provider conformance
requirements to be recorded as passing evidence, including at minimum:

- cross-host ARP resolved to the remote endpoint's actual canonical MAC;
- cross-host unicast after MAC learning;
- overlapping-realm isolation with identical inner IPs;
- DHCP broadcast across hosts;
- bounded flood delivery (hosting peers only);
- wrong/unknown VNI drop; anti-spoof rejection with visible counters;
- no cleartext tenant traffic on the physical underlay;
- MTU boundary behavior;
- zero leaked netns/bridge/veth/VXLAN/FDB/WireGuard/nft state after
  restart/reconcile, drain, and cleanup.

## Compatibility with prior contracts

`contracts/edge-fabric-v1.md` and `contracts/edge-fabric-realm-overlay.md`
remain historical authorities for behavior explicitly retained here (identity
model, binding registry semantics, WireGuard contract, execution discipline).
Where they conflict with this contract on cross-host dataplane semantics —
proxy-MAC neighbor resolution, the no-cross-host-flood requirement, Geneve
encapsulation — this contract prevails.
