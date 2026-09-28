# ADR-0172 — Configurable edge-fabric transport ports

Status: Accepted
Date: 2026-08-21
Decision-accepted: 2026-08-21
Human-approval: Senol Colak, 2026-08-21
Supersedes: none
Superseded-by: none
Affected-services: network, edge, installer, operations, governance

Related decisions and specifications:

- [ADR-0168 — O3K Routed Fabric and node-local network execution](ADR-0168-o3k-routed-fabric-and-network-execution.md)
- [ADR-0171 — AddressRealm-encapsulated edge fabric](ADR-0171-addressrealm-encapsulated-edge-fabric.md)
- [SPEC-0029 — AddressRealm-encapsulated Edge Fabric v2](../specs/SPEC-0029-addressrealm-encapsulated-edge-fabric-v2.md)
- [ADR-0186 — Stretched-L2 edge fabric](ADR-0186-stretched-l2-edge-fabric-vxlan-her.md)
- [SPEC-0049 — Stretched-L2 Edge Fabric v3](../specs/SPEC-0049-stretched-l2-edge-fabric-v3.md)
- [P11 realm-overlay contract](../../contracts/edge-fabric-realm-overlay.md)
- [Execution-boundary contract](../../contracts/execution-boundaries.md)

This ADR remains authoritative for WireGuard transport-port ownership and
configuration. Its Geneve-specific P11 v2 text is historical and is superseded
for the v3 dataplane by ADR-0186/SPEC-0049, which specifies per-realm VXLAN on
UDP/4789. It does not change `AddressRealm` semantics or create a P11 support
claim.

This decision affects privileged multi-host networking and operational firewall
configuration. It was accepted under the human architecture and security
approval process required by ADR-0154; the P11 v3 dataplane-specific provisions
are now governed by ADR-0186/SPEC-0049.

## Context

ADR-0171 established the P11 reference fabric separation:

```text
AddressRealm / Geneve VNI = tenant routing and isolation context
NetworkPolicy              = tenant authorization
Geneve                     = realm identity encapsulation
WireGuard                  = host authentication and encryption
```

The current Linux provider historically used implementation defaults such as
UDP/51820 for WireGuard and UDP/6081 for Geneve. Those numeric values are
provider execution details and must not become canonical Cloud Kernel or tenant
network semantics.

For the approximately 10–20-host edge-cloud profile, one shared WireGuard
interface/listener per compute host is preferable to per-peer or per-tenant
listeners. All enrolled peers can share one listening socket because peer
identity and authentication come from WireGuard public keys, not from distinct
UDP ports.

O3K also benefits operationally from one recognizable default port across the
fabric, provided that the value remains operator-configurable and is validated
before activation.

UDP/65001 is in the IANA Dynamic/Private range. It is therefore suitable as an
O3K deployment default, but it is not reserved for O3K and cannot be assumed to
be globally unused. Port availability must be treated as a host/operator
configuration concern rather than as a protocol invariant.

The superseded P11 v2 Geneve provider used UDP/6081 as its standard destination
port. P11 v3 uses per-realm VXLAN on UDP/4789 as specified by ADR-0186 and
SPEC-0049; that port is likewise inside the authenticated WireGuard host
transport and is not normally an underlay-facing firewall/service requirement.

## Decision

### 1. Fabric ports are provider configuration, never tenant identity

WireGuard and Geneve port numbers belong to bounded edge-fabric/provider
configuration.

They MUST NOT become fields whose values are tenant-selected or semantically
required by canonical resources such as:

- `AddressRealm`;
- `NetworkIntent`;
- `EndpointIntent`;
- `NetworkPolicy`;
- public/floating-address intent;
- Neutron-compatible tenant resources.

Changing a provider port must not require a canonical tenant network schema
change.

### 2. WireGuard default is UDP/65001

The P11 reference provider default WireGuard listening port is:

```text
UDP/65001
```

This is an O3K deployment convention only. O3K does not claim an IANA service
assignment or exclusive ownership of UDP/65001.

The value MUST be operator-configurable through the repository's normal
configuration mechanism. Production code must not depend on UDP/65001 as a
hard-coded protocol invariant.

### 3. One WireGuard listener per host per fabric domain

For each active WireGuard-backed fabric domain, one compute host normally owns:

```text
one WireGuard interface
one host private/public key pair
one UDP listener
many authenticated peers
```

AddressRealms, Geneve VNIs, projects, and tenant networks share this host
transport. They do not allocate additional WireGuard listeners or UDP ports.

The P11 reference profile has one fabric domain per compute host and therefore
normally one WireGuard listening port per compute host.

### 4. The normal cluster profile uses one common port, but peers consume the advertised endpoint

The normal deployment should configure the same WireGuard port on all compute
hosts for simple firewalling, monitoring, and diagnosis:

```text
compute-01 -> underlay-IP:65001
compute-02 -> underlay-IP:65001
compute-03 -> underlay-IP:65001
```

However, peer configuration MUST use each host's advertised effective underlay
endpoint rather than assuming that the remote port equals the local port.

A bounded per-host override is therefore compatible with the architecture when
the normal configuration system supports it:

```text
compute-01 -> 10.77.0.11:65001
compute-02 -> 10.77.0.12:65100
```

The canonical host-fabric identity continues to expose an effective
`underlay_endpoint`; the numeric provider port is not independently promoted to
tenant state.

### 5. Port changes are generation-bound fabric changes

Changing the effective WireGuard listening endpoint of a host changes provider
fabric state and MUST participate in the existing fabric generation,
reconciliation, and stale-state fencing rules.

A port change does not inherently require WireGuard private-key rotation, but
peers must converge on the new advertised endpoint before the old endpoint is
considered removed.

Stale peer endpoint configuration must not become authoritative merely because a
kernel WireGuard peer still exists.

### 6. Historical P11 v2 Geneve port

For historical P11 v2 implementations, the Geneve provider default was:

```text
UDP/6081
```

That v2 destination port was provider configuration. It does not apply to the
P11 v3 VXLAN dataplane, whose destination port is fixed at UDP/4789 by
SPEC-0049.

In the historical P11 v2 topology, Geneve transport was carried across the
protected WireGuard host fabric. Therefore the physical compute underlay normally needs to
permit the configured WireGuard UDP port, not Geneve UDP/6081 between tenant or
underlay addresses.

### 7. No random fallback or silent port mutation

O3K MUST NOT silently choose a random replacement WireGuard port when the
configured/default port is unavailable.

If the configured port cannot be used, activation/preflight must fail clearly
and direct the operator to choose another port.

This preserves deterministic firewall configuration, monitoring, evidence, and
troubleshooting.

### 8. Installer/doctor validates the effective configuration

The installer/doctor or equivalent preflight path must validate at least:

- port value is in `1..=65535`;
- the configured UDP listener can be used and is not already owned by unrelated
  software;
- the effective host endpoint is visible to the fabric configuration;
- a conflicting listener is reported without killing or modifying foreign
  processes.

The host's configured ephemeral/local port range should be inspected where
practical. If the selected WireGuard port lies inside that range, O3K should
warn unless the selected operating profile requires a stronger failure rule.
O3K must not rewrite the host ephemeral-port range merely to reserve its chosen
port.

### 9. Firewall contract

The normal P11 deployment requires underlay reachability equivalent to:

```text
enrolled compute underlay endpoints
    -> enrolled compute underlay endpoints
    UDP/<configured WireGuard port>
```

With defaults this is UDP/65001.

UDP/6081 is not normally exposed on the physical underlay when Geneve is carried
inside the WireGuard fabric.

Firewall source restrictions are defense in depth. WireGuard public-key
authentication remains the host-transport authentication mechanism.

### 10. Configuration hierarchy

The effective provider configuration follows the repository's established
configuration precedence. Semantically it is equivalent to:

```text
provider default
    -> fabric/cluster operator configuration
        -> bounded host override, if supported
```

Reference defaults are:

```text
wireguard_listen_port = 65001
geneve_destination_port = 6081
```

Exact CLI, environment-variable, file, Helm, or systemd names are implementation
contracts and must follow the existing O3K configuration system rather than
being independently invented by each launcher or test harness.

## Security considerations

- Moving from UDP/51820 to UDP/65001 does not increase WireGuard cryptographic
  security. Port obscurity is not an authentication mechanism.
- A predictable port is preferred for deterministic firewalling and operations.
- Tenants cannot select host transport ports.
- WireGuard private keys remain host-local under ADR-0171; this ADR does not
  change key authority.
- Geneve VNI/AddressRealm isolation remains unchanged; sharing one WireGuard
  listener among tenants does not merge their routing or authorization
  contexts.
- A port conflict must fail closed without modifying the foreign listener.

## Consequences

Positive:

- O3K gains a recognizable reference WireGuard port without encoding it into
  tenant semantics.
- Operators can resolve collisions without rebuilding binaries or changing
  canonical APIs.
- Firewall documentation becomes simple for the normal profile: one configured
  UDP port between compute hosts.
- Peer endpoints can still support heterogeneous ports when genuinely needed.
- Geneve remains hidden behind the authenticated host transport in the normal
  topology.

Costs:

- every launcher, deployment profile, test harness, firewall check, and evidence
  collector must consume one authoritative effective configuration rather than
  duplicate numeric constants;
- changing a host port requires peer convergence and generation-aware
  reconciliation;
- UDP/65001 can conflict with local software because it is not reserved for O3K.

## Alternatives considered

### Keep UDP/51820 permanently

Rejected as an architectural invariant. UDP/51820 is a common WireGuard default
and is technically valid, but O3K has no reason to make it canonical or
unconfigurable.

### Random port per host

Rejected for the reference profile. It adds firewall, monitoring, diagnosis,
and restart complexity without meaningful security benefit.

### One WireGuard port/interface per tenant or AddressRealm

Rejected. Tenant isolation is provided by AddressRealm/VNI and NetworkPolicy,
not by transport port separation. Per-tenant listeners would unnecessarily
multiply interfaces, keys, peer state, and firewall rules.

### Historical v2: expose Geneve UDP/6081 directly on the underlay

Rejected for the reference profile. ADR-0171 intentionally places Geneve realm
identity inside the authenticated/encrypted WireGuard host transport.

## Fitness functions and acceptance evidence

Before this decision can support a runtime claim, tests/evidence should prove:

1. provider default resolves to WireGuard UDP/65001; a v2 Geneve provider, if
   still exercised for compatibility, resolves to UDP/6081 and the v3 provider
   resolves VXLAN to UDP/4789;
2. a custom WireGuard port such as UDP/65123 is accepted and used by the real
   listener;
3. peers use the advertised remote `IP:port`, including asymmetric host ports if
   host override is supported;
4. a custom v2 Geneve destination port, where that historical provider remains
   exercised, is reflected in provider realization;
5. invalid values such as `0` or values above `65535` are rejected before
   privileged mutation;
6. doctor/preflight detects an occupied configured UDP port without mutating the
   foreign process;
7. P11 scripts, captures, firewall/NAT rules, and deployment manifests consume
   the configured value rather than a duplicated `51820`/`65001` constant;
8. changing a host port advances/reconciles fabric provider state and stale peer
   endpoints are not accepted as current;
9. underlay evidence shows WireGuard on the configured port while tenant
   VXLAN (or historical Geneve) traffic remains protected inside the host
   transport;
10. canonical tenant network resources remain independent of provider port
    numbers.

## Non-goals

This ADR does not:

- solve the historical P11 v2 Geneve dataplane forwarding bug or implement the
  P11 v3 VXLAN migration;
- change AddressRealm, VNI, proxy-neighbor, policy, scheduling, drain, or storage
  semantics;
- introduce NAT traversal, STUN/TURN, relay services, or dynamic port discovery;
- request or claim an IANA service-name/port assignment;
- create a broader P11 product support claim.
