# ADR-0186 — Stretched-L2 Edge Fabric: VXLAN head-end replication over the WireGuard host fabric

Status: Accepted
Date: 2026-09-28
Decision-accepted: 2026-09-28
Human-approval: requester acceptance recorded in the introducing pull request, 2026-09-28
Supersedes: ADR-0171
Superseded-by: none
Affected-services: network, compute, placement, scheduler, storage, kernel, edge, governance

Related issue: fabric alignment requested by the requester; aligned with
[kubedoio/chv#270](https://github.com/kubedoio/chv/issues/270) and CHV
[ADR-021](https://github.com/kubedoio/chv/blob/main/docs/specs/adr/021-stretched-l2-vxlan-her-wireguard-fabric.md).

Related decisions and specifications:

- [ADR-0168 — O3K Routed Fabric and node-local network execution](ADR-0168-o3k-routed-fabric-and-network-execution.md)
- [ADR-0170 — Namespaced Routed Edge Fabric](ADR-0170-namespaced-routed-edge-fabric.md)
- [ADR-0171 — AddressRealm-encapsulated edge fabric](ADR-0171-addressrealm-encapsulated-edge-fabric.md) (superseded by this ADR)
- [ADR-0172 — Configurable edge-fabric transport ports](ADR-0172-configurable-edge-fabric-transport-ports.md) (retained)
- [ADR-0176 — Canonical Network / AddressRealm lifecycle](ADR-0176-canonical-network-and-addressrealm-lifecycle-separation.md)
- [SPEC-0029 — AddressRealm-encapsulated Edge Fabric v2](../specs/SPEC-0029-addressrealm-encapsulated-edge-fabric-v2.md) (superseded by SPEC-0049)
- [SPEC-0049 — Stretched-L2 Edge Fabric v3](../specs/SPEC-0049-stretched-l2-edge-fabric-v3.md)
- [P11 stretched-L2 fabric contract](../../contracts/edge-fabric-stretched-l2.md)
- [Execution-boundary contract](../../contracts/execution-boundaries.md)
- Shared implementation authority: [o3kio/fabric](https://github.com/o3kio/fabric) —
  the hardened provider extracted from this design lineage (WireGuard host
  fabric + per-realm VXLAN/HER), normative contract
  [`contracts/fabric-provider-v1.md`](https://github.com/o3kio/fabric/blob/main/contracts/fabric-provider-v1.md)
  and change control
  [`docs/change-control.md`](https://github.com/o3kio/fabric/blob/main/docs/change-control.md)

This is a privileged multi-host networking decision. The requester acceptance
recorded in the introducing pull request activates this ADR and SPEC-0049 as the
P11 v3 implementation authority, replacing ADR-0171/SPEC-0029 and the
realm-overlay contract for that purpose. Acceptance authorizes bounded
implementation only; it does not create a runtime, product, or real-host support
claim. Those claims remain gated on the evidence requirements in SPEC-0049 and
the successor contract.

CHV (the Kubedo.io Cloud Hypervisor platform) has accepted the same fabric
decision in its ADR-021. The two projects now converge on one fabric design:
**per-realm kernel VXLAN with head-end replication, carried inside the existing
shared WireGuard host fabric**, so that every AddressRealm behaves as one literal
L2 segment (one VLAN) across all participating hypervisors.

The convergence is structural, not just documentary: the WireGuard
host-fabric substrate (netns, WireGuard transport, per-network VXLAN/HER
objects, ownership journaling, key hygiene) is implemented **once** in the
shared repository [o3kio/fabric](https://github.com/o3kio/fabric) and
consumed by both projects as git-tag dependencies
(`fabric-plan` / `fabric-linux` / `fabric-conformance`), pinned to one tag
fleet-wide. Its contract,
[`contracts/fabric-provider-v1.md`](https://github.com/o3kio/fabric/blob/main/contracts/fabric-provider-v1.md),
is normative for that substrate, and
[`docs/change-control.md`](https://github.com/o3kio/fabric/blob/main/docs/change-control.md)
governs how both consumers request changes: the design changes rarely,
deliberately, and for fabric-wide reasons — never per-project. Neither
project forks, patches, or re-implements it.

## Context

ADR-0171 established the P11 v2 architecture: AddressRealm identity carried in
Geneve, one shared WireGuard host transport, and overlapping tenant CIDRs
supported by keeping cross-host traffic known-unicast only. Its defining
properties were:

- remote ARP is answered locally with a deterministic realm proxy MAC;
- no cross-host ARP broadcast, unknown-unicast flood, or MAC learning;
- per-(realm, remote-host) Geneve attachments with static FDB entries;
- real guest MACs never cross hypervisors.

That design is secure and operationally clean, but it is **not a shared Ethernet
segment**. A customer workload that expects VLAN semantics — guest ARP resolved
to the peer's real MAC, DHCP broadcast discovery, unknown-unicast delivery,
non-IP L2 protocols — does not behave the same way across hypervisors as it does
on one hypervisor. The product requirement (raised by the requester and mirrored
in kubedoio/chv#270) is now explicit: an AddressRealm must be a literal
stretched L2 segment across all enrolled hosts, indistinguishable from a
physical switch, while remaining encrypted and authenticated across untrusted
networks.

A cross-project analysis of the alternatives concluded:

1. the P11 v2 fabric as-is cannot meet the requirement (no BUM delivery);
2. a plain WireGuard L3 mesh cannot meet the requirement (no L2 at all);
3. EVPN/BGP adds control-plane weight inappropriate at the 10–20-host target
   profile;
4. kernel VXLAN with head-end replication (HER) plus kernel MAC learning, inside
   the existing WireGuard fabric, delivers literal L2 semantics with bounded,
   enrolled-peers-only flooding and no new control-plane dependencies.

Kernel VXLAN with learning and head-end replication is a battle-tested Linux
datapath; the existing VNI registry, realm model, policy, public/FIP, and
execution-discipline layers carry over unchanged.

## Decision

### 1. Overlay datapath: per-realm VXLAN with head-end replication

- The realm encapsulation provider becomes **kernel VXLAN** (UDP/4789), one
  VXLAN device per active realm, VNI supplied by the existing
  `RealmEncapsulationBinding` registry (`encapsulation_kind = vxlan`).
- The VXLAN device terminates where the fabric transport routing lives (the
  shared fabric namespace or an equivalent attachment), with a learning bridge
  port connecting it to the realm's L2 island. The exact interface fanout is a
  provider choice under SPEC-0049 constraints, but there is **one VXLAN device
  per realm per host**, not one per remote host.
- **Kernel MAC learning is enabled** (`nolearning` is not used). After a guest
  ARP exchange crosses the fabric, subsequent frames are unicast to the owning
  host via the learned FDB entry.
- **BUM delivery uses head-end replication**: for every peer host that currently
  hosts at least one endpoint of the realm, the provider programs a static flood
  entry equivalent to
  `bridge fdb replace 00:00:00:00:00:00 dev <vxlan> dst <peer_fabric_transport_ip>`.
  Broadcast, unknown-unicast, and multicast frames are replicated once per such
  peer. There is no multicast underlay and no EVPN/BGP.
- The flood list is **scoped and bounded**: only enrolled, current, authenticated
  fabric peers hosting realm endpoints receive HER entries. Stale or unknown
  peers must never be dialed.

### 2. What is retained from P11 v2 (unchanged)

- The **WireGuard host fabric** exactly as accepted: one `wg-o3k` per host in the
  shared fabric namespace, one keypair per host, private key host-local and never
  in canonical state, AllowedIPs carrying only peer fabric-transport `/32`s, and
  the ADR-0172 port policy (default UDP/65001, fail-closed conflicts, advertised
  endpoints). WireGuard remains host authentication and encryption only; it is
  not the realm discriminator.
- The **AddressRealm model**, including overlapping tenant CIDRs across realms
  and the `(realm_id, fixed_ip)` endpoint key. Each realm is its own VNI and its
  own broadcast domain, so identical tenant IPs in different realms never merge.
- The **VNI registry semantics**: not tenant-supplied, unique per fabric domain,
  generation-fenced, reuse only after old tunnel state is proven absent.
- The **RealmEndpointDirectory** as placement/policy authority, the canonical
  NetworkPolicy model, the public/FIP provider, the realm netns local topology,
  and the plan/journal/ownership/generation execution discipline of ADR-0168.

### 3. What is retired from P11 v2

- The **realm proxy MAC** for remote neighbor resolution: remote endpoints now
  answer guest ARP with their **actual canonical MAC** across the fabric.
- The deterministic **tunnel MAC**, the per-(realm, remote-host) Geneve devices,
  bridges, veth fanout, and static per-attachment FDB steering.
- The **"no cross-host flood contract"** of SPEC-0029, replaced by the bounded
  HER contract of SPEC-0049.
- The Geneve UDP/6081 transport surface (ADR-0172's Geneve port knob becomes
  vestigial; its WireGuard port policy is retained).

### 4. Neighbor and DHCP semantics

- Guest ARP for a remote same-realm endpoint is flooded via HER, reaches the
  remote guest, and is answered with the real MAC. Same-host and cross-host
  ARP/ping behavior are indistinguishable to the guest.
- One DHCP authority per realm may serve all hosts: DHCP discovery broadcasts
  traverse the fabric like any other L2 broadcast.

### 5. Ingress validation and anti-spoofing

Because real MACs and IPs now cross hosts, the structural MAC-hiding isolation
of v2 is gone and must be replaced by explicit enforcement:

- a received frame's VNI must map to exactly one **current** realm binding
  (wrong/unknown/stale VNI fails closed);
- the source host is identified by the authenticated WireGuard peer (cryptokey
  routing on the fabric transport address), never by inner-packet content;
- **TAP/bridge source-MAC and source-IP anti-spoofing becomes mandatory** on the
  local path (reject unaccepted source MAC, IPv4, and ARP sender IP/MAC), and
  NetworkPolicy enforcement on the realm bridge/TAP path is required, not
  optional;
- placement authority remains the accepted control-plane directory; kernel FDB
  learning is dataplane cache only and is never canonical placement.

### 6. MTU

The provider path is `tenant packet + VXLAN (50 bytes) + WireGuard (60 bytes
IPv4 / 80 bytes IPv6) + underlay`. The safe tenant MTU is derived per layer
(`tenant_mtu = fabric_mtu − 50`; `fabric_mtu = underlay_mtu − WireGuard
overhead`), validated against every peer at plan time, and propagated through
the guest network configuration/DHCP path.

## Consequences

Positive:

- literal stretched-VLAN semantics per AddressRealm across all enrolled hosts:
  real ARP, DHCP broadcast, unknown-unicast, and non-IP L2 protocols work
  transparently; same-hypervisor and cross-hypervisor behavior are identical;
- all inter-site traffic remains authenticated and encrypted by WireGuard; no
  cleartext tenant traffic ever touches the physical underlay;
- overlapping CIDRs across realms are preserved (VNI per realm);
- no new control-plane dependencies (no BGP/EVPN, no multicast), fitting the
  10–20-host target profile;
- the existing portable realm/VNI/policy/public layers and the execution
  discipline are reusable; the change is concentrated in the Linux provider
  dataplane slice.

Negative / accepted risks:

- **Intra-realm privacy becomes that of a real VLAN**: every endpoint in a realm
  can observe that realm's broadcast traffic; the v2 property "remote MACs never
  cross hosts" is gone by design.
- BUM traffic crosses every host currently hosting realm endpoints; ARP noise
  and chatty protocols propagate fabric-wide per realm.
- HER fan-out is O(peers hosting realm endpoints) per BUM frame; acceptable at
  the target scale, must be revisited beyond it.
- Stretched L2 across WAN links is a known operational risk (broadcast storms,
  latency-sensitive quorum systems); SPEC-0049 scopes it to enrolled hosts and
  forbids bridging realms into site-local physical switches.
- Anti-spoofing correctness now depends on mandatory TAP/bridge enforcement
  instead of structural MAC hiding; this must be proven by evidence, not
  assumed.

## Guardrails

- VNI allocation, uniqueness, generation fencing, and reuse rules are unchanged
  from SPEC-0029.
- HER flood entries must only ever target current, enrolled, authenticated peers
  hosting realm endpoints; unknown VTEP addresses fail closed.
- The WireGuard private key handling rules of SPEC-0029 are unchanged.
- Foreign VXLAN/FDB/WireGuard state is rejected, never adopted or deleted.
- Wrong-VNI, stale-binding, and unknown-source-host ingress must drop with a
  visible counter.
- Realm L2 segments must not be bridged into site-local physical switches.
- Fabric mutations remain journaled-before-mutation, idempotent, and reconciled
  at startup.

## Non-goals

- EVPN/BGP control plane (revisit beyond the 10–20-host profile; the VNI/flood
  list abstraction is designed so it can replace HER later).
- Multicast underlay replication.
- Cross-realm L2 connectivity or merging realms.
- Live migration (unchanged from P11 v2: unsupported).
- IPv6 fabric transport (unchanged).

## Implementation scope note

This ADR changes the accepted architecture and its normative SPEC/contract. The
privileged Linux provider implementation (currently Geneve-based in
`crates/o3k-network/src/linux_fabric/`) is migrated in bounded follow-up work
under SPEC-0049's migration and evidence requirements. The migration target
for the WireGuard host-fabric substrate is the shared provider in
[o3kio/fabric](https://github.com/o3kio/fabric) (already proven in
production form by CHV): the workspace pins its git-tag dependencies and a
CI conformance gate (`crates/o3k-network/tests/fabric_conformance.rs`)
proves the pinned tag on O3K's toolchain continuously; the
`linux_fabric` migration onto `LinuxFabricProvider` then proceeds in
bounded phases, deleting the duplicated substrate while keeping the
portable realm/policy/public layers. No runtime, product, or real-host
support claim is created by this acceptance alone.
