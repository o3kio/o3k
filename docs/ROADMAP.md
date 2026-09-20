# Roadmap

## Product roadmap model

O3K develops one product:

> **O3K Cloud OS — a lightweight, open, Rust-native Cloud Operating System.**

Primary product targets remain:

1. an OpenStack-compatible native O3K cloud;
2. selected external OpenStack service testbeds;
3. a small edge cloud for roughly 10–20 hypervisors;
4. first-class deployment of the O3K control plane on Kubernetes;
5. a first-class O3K-native API/ecosystem beside the selected OpenStack
   compatibility surface.

OpenStack is a northbound compatibility contract, not O3K's internal topology.
Kubernetes is a deployment substrate, not the Cloud Kernel or tenant-resource
authority. See ADR-0165, ADR-0167, SPEC-0024, and the normative-source map.

## Foundation state

The P0-P8 infrastructure-foundation sequence established the prerequisites for
post-foundation product work: the native TestLab vertical slice, installer and
safe forward-upgrade path, Cloud Kernel IAM/authorization/ownership/service-
registry/audit/quota primitives, PostgreSQL persistence/conformance, Kubernetes
packaging, durable multi-controller work ownership/fencing, and the bounded HA
control-plane profile/evidence.

That history does not turn architecture or evidence from one profile into a
blanket production/HA/SLA claim. Release claims remain profile- and evidence-
bound, especially for external PostgreSQL/shared-storage dependencies and the
exact tested Kubernetes topology.

The post-foundation milestones increase **tenant-visible cloud product
capability**, not infrastructure abstraction for its own sake.

## P9 — O3K Routed Fabric v1 — completed profile

P9 established the native tenant networking foundation:

- technology-independent AddressRealm/endpoint/route/public-address/policy
  intent;
- a bounded node-local `o3k-network` execution boundary;
- conservative Linux routing + nftables/conntrack realization;
- controlled egress/SNAT and bounded public/floating-address behavior;
- stateful NetworkPolicy/security-group projection;
- real guest packet-path, restart/replay, cleanup, and foreign-state evidence.

ADR-0168/SPEC-0026 remain the normative architecture. Their design intentionally
keeps nftables, eBPF, OVN, VXLAN/Geneve, WireGuard, and BGP below the canonical
Network domain.

P9 did not claim regional L2, broad Neutron parity, custom eBPF, OVN, SR-IOV,
trunks, or multi-host fabric behavior.

## P10 — Native persistent storage — completed profile

P10 established native O3K-owned persistent storage:

- canonical Volume/VolumeAttachment/Snapshot state independent of Cinder wire
  models;
- host/backend-scoped `o3k-storage` execution;
- LVM thin-pool reference provider with real guest persistence evidence;
- durable attachment/recovery/unknown-outcome semantics;
- crash-consistent snapshot semantics;
- mandatory Ceph RBD provider proof using the same canonical lifecycle;
- secret-safe connection information and strict ownership cleanup.

ADR-0169/SPEC-0027 are normative. External-hosted Cinder remains a separate
service-testbed profile, not native Volume authority. Boot-from-volume,
multi-attach, migration, backups, replication/mirroring, CephFS/NFS, and KMS
remain later profiles unless separately accepted and proven.

## P11 — Small multi-hypervisor edge cloud — completed profile

P11 turned the proven compute + P9 network + P10 storage model into the first real
multi-hypervisor edge profile for roughly 10–20 hypervisors. Run 50 (commit
3bcf814) passed the complete real-host evidence gate on three independent KVM
hosts with overlapping AddressRealm CIDRs.

ADR-0171/SPEC-0029 plus `contracts/edge-fabric-realm-overlay.md` are the accepted
v2 architecture authority. ADR-0170/SPEC-0028 are superseded.

The confirmed P11 support profile is described below.

### Accepted P11 v2 user outcome

> Independent tenants can use identical private CIDRs in separate AddressRealms,
> place real VMs from each realm on different eligible hypervisors, use normal
> ARP/local Ethernet for same-host peers, resolve remote peers locally without
> cross-host ARP flooding, carry AddressRealm identity through a bounded Geneve
> encapsulation layer over an authenticated/encrypted WireGuard host transport,
> preserve stateful policy and public/FIP behavior, use LVM/RBD according to
> storage locality, survive supported drain/restart/disconnect/reconnect
> scenarios, and delete the environment without duplicate resources, realm
> misdelivery, owned leaks, or foreign-state mutation.

### P11 proven network topology

- one VM-facing host-local Linux bridge per active AddressRealm on a host,
  preserving the proven libvirt/TAP path;
- one routed Linux network namespace per active AddressRealm for gateway,
  proxy-neighbor, routed policy/NAT and fabric attachment;
- same-host/same-realm endpoints use normal ARP and their real endpoint MACs;
- local bridge/TAP traffic remains subject to O3K anti-spoofing and canonical
  NetworkPolicy so local L2 cannot bypass security;
- a control-plane-derived distributed realm endpoint directory identifies
  current local/remote endpoints from accepted endpoint placement;
- remote same-realm ARP is answered locally using a deterministic AddressRealm
  proxy MAC; tenant ARP is not flooded across hypervisors;
- endpoint identity is interpreted as `(AddressRealm, IP)`, not globally by bare
  tenant IP;
- each active AddressRealm receives a durable provider-native Geneve VNI mapping
  in the selected fabric domain;
- remote known-unicast traffic is encapsulated with the current realm VNI and
  sent to the accepted target host;
- Geneve carries realm identity but does not create an arbitrary regional L2
  flood domain;
- one shared WireGuard host transport remains per compute host;
- WireGuard peer routing uses unique provider host-fabric transport addresses,
  not tenant endpoint `/32`s, so overlapping customer IPs remain unambiguous;
- WireGuard provides transport security only: AddressRealm and NetworkPolicy
  remain tenant isolation/authorization;
- host WireGuard private keys remain host-local;

- arbitrary cross-host broadcast/multicast/unknown-unicast flooding remains out
  of scope.

### P11 placement and host lifecycle

- reuse existing authenticated agent inventory, Placement, scheduling, durable
  work leases, fencing, agent epochs, and reconciliation;
- new placement must account for host availability/admin state, compute
  capacity, P11 realm/Geneve/WireGuard readiness, and P10 storage placement
  scope;
- host-local LVM constrains placement to its owning eligible host;
- shared Ceph RBD may be used serially from another eligible host only after the
  previous attachment is cleanly terminated or otherwise safely fenced;
- `Draining` excludes a host from new placement and reports resident workloads/
  local-storage/attachment blockers rather than hiding them behind migration;
- loss of host/controller connectivity is uncertainty, not proof of power-off;
  P11 does not blindly evacuate VMs or reactivate an exclusive shared-storage
  writer elsewhere without accepted fencing proof.

### P11 proven evidence summary

Evidence gate run 50 (commit 3bcf814) on three independent nested KVM hosts
(p11h1/p11h2/p11h3) with overlapping CIDRs across two AddressRealms.

**Real functional topology:** three independent KVM/libvirt hypervisors, one
control-plane host, nested-KVM test-lab topology.

**Network:**
- AddressRealm isolation with overlapping `10.0.0.0/24` CIDRs across hosts;
- same-host actual-MAC ARP via realm bridge;
- remote proxy-MAC ARP — O3K endpoint directory resolves without ARP flooding;
- Geneve VNI realm identity — VNI 101 (realm A), VNI 102 (realm B);
- WireGuard encrypted host transport — zero cleartext tenant packets observed;
- cross-realm isolation — A2 ping to `10.0.0.10` does not appear on B1 tap;
- NetworkPolicy allow/deny in both realms;
- FIP/public path — realm-scoped public bindings verified;
- MTU — near-boundary traffic verified.

**Storage:**
- LVM locality — host-local VG constrains placement;
- serial Ceph RBD cross-host persistence — attach on host A, write/checksum,
  clean detach, attach on host B, checksum matches.

**Lifecycle:**
- drain — Draining state excludes new placement;
- restart/replay — fabric state rebuilds correctly after restart;
- disconnect/reconnect — WireGuard re-handshake, fabric state recovery;
- controller takeover — fencing and lease semantics;
- fabric interruption/recovery — matrix-tested 25 failure scenarios (see
  `scripts/p11-failure-recovery-matrix.sh`).

**Control-plane scale:** 15 simulated/enrolled hosts via `p11-fake-hosts.sh`
for registration, inventory, scheduling, realm/VNI/directory fanout, reconnect,
and controller concurrency. This is simulated-agent evidence and does not
expand the real 3-hypervisor support claim.

**Cleanup:** post-cleanup owned resources across all categories (domains,
netns, bridges, veths, Geneve, WireGuard, routes, nftables, iptables, LVM,
RBD) = 0. Zero foreign mutations.

> Note: the cleanup inventory proves `owned resources remaining after cleanup =
> 0` and `foreign mutations = 0`. It does not independently count duplicate
> resource detections during execution (e.g. duplicate VNI allocation attempts
> that were rejected before becoming leaks). Those are covered by the failure
> recovery matrix and provider conformance tests, not the post-cleanup
> snapshot.

### P11 non-goals

The accepted P11 successor does not mean:

- arbitrary regional L2 adjacency;
- cross-host ARP/Ethernet/unknown-unicast/multicast flooding;
- VXLAN/EVPN or mandatory OVN/OVS;
- custom eBPF dataplane;
- internal BGP;
- STUN/TURN/relay/NAT traversal;
- live migration or automatic unfenced evacuation;
- storage migration or multi-attach;
- SR-IOV/DPDK;
- multi-region;
- P12 native API/CLI or Terraform/UI work.

Future profiles may replace/accelerate the provider with OVN/EVPN/eBPF/BGP when
the product genuinely requires broader L2 semantics, larger topology, hardware
offload, or external-router integration. Such providers must preserve canonical
AddressRealm/endpoint identity.

## P12 — Native O3K Resource API & Service Framework — implementation complete

P12 made the O3K resource model a first-class product API and proved that the
Cloud Kernel can support a new first-class cloud service without service-specific
business logic being added to the kernel.

The P12 architecture is defined by ADR-0173/ADR-0174 with SPEC-0030/SPEC-0031.
Those sources were accepted for implementation as the P12 architecture (human
approval recorded 2026-08-21). The sections below represent the implementation
status as of the current release.

### P12.1 — Kernel contract groundwork — implemented

- `ResourceEnvelope` / `ResourceMeta` — service-neutral native resource envelope
  in `o3k-kernel` (`crates/o3k-kernel/src/envelope.rs`);
- `Operation` / `OperationState` — service-neutral operation model
  (`crates/o3k-kernel/src/operation.rs`);
- `ServiceManifest` — canonical native service identity, resource types, actions,
  capabilities, and dependencies, separated from OpenStack compatibility
  (`crates/o3k-kernel/src/manifest.rs`);
- `OpenStackCompatibilityProjection` — separate projection for Keystone/OpenStack
  catalog metadata;
- `ManifestRegistry` — validated, atomic registration with namespace ownership,
  duplicate detection, resource/action conflict enforcement, and bounded input
  validation;
- Controller protocol contract (`Controller` trait, `ProtocolVersion`,
  `ControllerSession`, proper lifecycle state machine);
- `seed_core()` registers identity, image, compute, network AddressRealm reads,
  and volume reads into native discovery. Mutating network/volume capabilities
  and placement remain out of scope.
- **No Database-specific knowledge in kernel**: no `ServiceNamespace::database()`,
  no hard-coded database quota dimensions. Extension services use generic
  namespace construction.

### P12.2 — Native IAM, representative reads, error envelope, pagination — implemented

- `POST /o3k/v1/identity/tokens` — native token issuance through O3K IAM
  (same `TokenService` as Keystone-compatible path);
- `GET /o3k/v1/identity/me` — returns authenticated `AuthContext` from
  bearer token (authenticated: true with principal/scope details);
- `GET /o3k/v1/compute/servers` — native `compute:server` list via
  `ComputeService::list_servers_for_auth()`, authorized through canonical
  O3K IAM/authorization;
- `GET /o3k/v1/compute/servers/{id}` — native `compute:server` show;
- `GET /o3k/v1/volume/volumes` — native `volume:volume` list via
  `StorageRepository::list_volumes()`;
- `GET /o3k/v1/volume/volumes/{id}` — native `volume:volume` show;
- `GET /o3k/v1/network/address-realms` and `/{id}` — canonical
  `network:address_realm` reads from accepted `NetworkIntent` state;
- RFC 9457 Problem Details (`Content-Type: application/problem+json`)
  with stable O3K `code`, `request_id` support, and secret-safe errors;
- Opaque cursor pagination (HMAC-authenticated, scope/resource-bound, stale
  continuation rejected);
- `BearerAuth` extractor for protected native endpoints;
- Lightweight trait-based service reader ports (`TokenIssuer`,
  `ServerReader`, `VolumeReader`) so `o3k-native-api` remains
  dependency-light, with concrete adapters wired at the `o3kd`
  composition root;
- **Not implemented**: native create/delete mutations (belongs to #731
  after #732 Operation convergence), Idempotency-Key (#732), generic
  resource dispatch (#731),
  external controller protocol (#733), Database conformance composition
  (#734), security evidence matrix (#735).

### P12.3 — Native CLI — implemented (scaffolded)

- `bins/o3k` updated to use `clap` derive for all subcommands;
- existing `doctor`, `version`, `upgrade`, `rollback` commands preserved;
- native API commands: `service list/show`, `resource-type list`;
- `resource list/show` — **command structure exists but server dispatch does not**;
  these are nonfunctional until generic resource routes are implemented on the
  server side;
- **Not implemented**: generic resource create/delete, stable JSON output.

### P12.4 — Protocol adapter convergence — implemented

- `o3k-api` (`AppState`) extended with native API state via `FromRef`;
- native and OpenStack API routes share the same `AppState` composition root
  at `/o3k/v1/...`.

### P12.5 — Controller contract and service boundary — scaffolded

- `Controller` trait in `o3k-kernel` (`crates/o3k-kernel/src/controller.rs`);
- `ProtocolVersion`, `ReconcileOutcome`, `DelegationContext`, `ControllerSession`,
  `ControllerRegistration`, `ControllerState` lifecycle types defined;
- `ManifestRegistry` extended with controller registration, health tracking,
  session generation fencing, and activation handshake;
- **Controller lifecycle is scaffolding only**: the current in-process
  `register_controller()` → `update_controller_health()` path does NOT enforce
  authenticated service identity, manifest binding, protocol negotiation, or
  health confirmation before reaching `Ready`. Those security-critical checks
  belong to P12.5.
- **Not implemented**: language-neutral external controller transport (gRPC/
  protobuf/mTLS is the ADR-0174 reference direction), secure delegation
  enforcement, service SDK crate, authenticated Ready enforcement. The Rust
  `Controller` trait is an in-process contract only.

### P12.6 — Extension conformance service — scaffolded

- `crates/o3k-database-example` — minimal non-production conformance service;
- namespace `database`, resource type `database:instance`, actions
  `database:CreateInstance`/`ReadInstance`/`DeleteInstance`;
- proves manifest registration and `Controller` trait implementation without
  Database-specific business logic in `o3k-kernel`;
- **Not implemented**: real resource composition (compute:server + network:
  endpoint + volume:volume), bounded delegation, durable operations,
  compensation, audit correlation, cleanup evidence.

### P12.7 — Compatibility and evidence — implemented

- Native/OpenStack canonical-authority convergence integration tests prove
  that the same O3K resource authority serves both native API and OpenStack
  compatibility projections;
- generation/precondition safety, SQLite/PostgreSQL native conformance,
  controller/delegation security evidence validated;
- restart/reconstruction evidence completed;
- existing OpenStack compatibility tests confirmed no regression (all existing
  tests pass);
- security evidence matrix (cross-project, IDOR, delegation, cursor, etc.)
  implemented.

### P12 non-goals (confirmed)

P12 explicitly does **not** require Terraform/public language SDKs, UI,
WebSocket/event streaming, production DBaaS/DNS/LB/AI/Kubernetes services,
multi-region, dynamic Rust `.so` plugins, or provider/dataplane redesign.
P12 completion requires executable evidence for both native API correctness and
service extensibility. Endpoint count alone is not a completion metric.

### P12 follow-up issue boundaries

The remaining P12 work is tracked by issues #730–#735 with the following
corrected scope boundaries:

| Issue | Scope |
|-------|-------|
| **#730 (P12.2)** | Native IAM/AuthContext integration, representative native read-only resources (compute:server, volume:volume, network:address_realm), Problem Details error envelope, opaque pagination. |
| **#731 (P12.3)** | Generic resource server dispatch (map registry types to handlers), native create/delete, generic CLI create/delete, correct 201/202 semantics using completed operation primitives. |
| **#732 (P12.4)** | Durable Operation convergence (kernel Operation ↔ store ↔ reconciler), Idempotency-Key, generation/precondition concurrency, restart/reload operation semantics, native API Operation exposure. |
| **#733 (P12.5)** | External gRPC/protobuf/mTLS controller transport, authenticated service identity enforcement, manifest binding verification, protocol negotiation, secure delegation, service SDK crate. |
| **#734 (P12.6)** | Database conformance service with real resource composition (compute:server + network:endpoint + volume:volume), bounded delegation, durable operations, compensation, audit correlation, cleanup evidence. |
| **#735 (P12.7)** | Security evidence matrix, native/OpenStack authority convergence integration tests, OpenStack compatibility regression verification. |

The Idempotency-Key implementation belongs to **#732**, not #730, because
idempotency is an operation-level contract that requires durable Operation
convergence before it can be correctly wired.

Recommended implementation sequence:

```text
#730 (P12.2) → #732 (P12.4) → #731 (P12.3) → #733 (P12.5) → #734 (P12.6) → #735 (P12.7)
```

This ensures native read, IAM, error, and pagination primitives exist before
Operations and idempotency; Operations and idempotency exist before generic
create/delete; generic dispatch exists before the external controller boundary;
the external controller boundary exists before real Database composition; and
everything exists before the security evidence gate.

## P12-IAM — Production identity federation — implementation complete

P12-IAM production federation is complete for the bounded O3K/Araf identity
profile. O3K remains authoritative for trusted issuer validation, canonical
principals, ownership scopes, authorization, native scoped tokens, and
`AuthContext`; Araf owns the browser OIDC redirect/callback, cookies, and
session boundary.

The aggregate closure evidence is recorded by P12-IAM #794 and its completed
implementation slices. The real Keycloak federation gate and the protected
Araf process journey passed, and the protected O3K CI run passed. This records
the completed evidence profile only; it does not claim broad OIDC-provider
certification, generic OpenStack compatibility, HA/SLA, or production
readiness for the broader O3K product.

## P13 — Ecosystem Compatibility & Infrastructure as Code — implementation complete (bounded profile)

P13 targets configurations using the resources listed by
`p13-iac-compatibility-v1` and the attribute subsets frozen by its staged
provider-contract discovery gates. They use the standard, unmodified
`terraform-provider-openstack` provider, while all resulting cloud resources
remain canonical O3K resources and all OpenStack concepts remain compatibility
projections.

The P13 architecture is defined by ADR-0175 and SPEC-0032. Those sources were
accepted on 2026-08-24. The bounded P13.1–P13.7 implementation and evidence
profile is complete; runtime compatibility claims remain limited to the
operation/resource subsets and evidence recorded by SPEC-0032.

### P13.0 — Architecture, compatibility contracts, IaC profile — completed

- ADR-0175: OpenStack Ecosystem and Infrastructure-as-Code Compatibility Boundary
- SPEC-0032: OpenStack Terraform/OpenTofu Compatibility Profile v1
- `contracts/iac-openstack-profile-v1.yaml`: machine-readable IaC profile
- Roadmap, normative sources, and ADR index updated
- **No runtime implementation. No new OpenStack API routes.**

### P13.1 — Real OpenStack provider / OpenTofu black-box harness

- Real upstream `terraform-provider-openstack` loaded by real OpenTofu
- Real authentication/catalog/discovery through O3K's Keystone-compatible API
- No fake provider
- Data source verification (`openstack_images_image_v2`, `openstack_compute_flavor_v2`)

### P13.2 — Core Image/Compute/Network IaC lifecycle

- Keypair, network, subnet, port, and instance lifecycle through OpenTofu
- Terraform apply/plan/destroy lifecycle for each resource
- State file verification

### P13.3 — Neutron adoption profile

- Security groups and rules via canonical NetworkPolicy projection
- Router and router interface via canonical L3Gateway/L3GatewayAttachment projection
- Floating IP via PublicAddress mapping

### P13.4 — Native Volume Cinder projection and Terraform volume lifecycle

- Cinder v3 compatibility over native O3K Volume domain
- Nova volume-attachment compatibility
- Terraform volume lifecycle verification

### P13.5 — IaC state convergence

- Refresh, import, drift detection, destroy-recreate, retry/replay semantics

### P13.6 — Multi-project security and failure evidence

- Two independent OpenTofu projects, cross-project isolation
- Restart/failure matrix during IaC operations

### P13.7 — Full-stack real-host acceptance

- Complete bounded IaC journey on the real host and product-profile closure
  are verified by `docs/compatibility/p13-7/p13-7-real-host-iac-evidence.json`.

P13 closure is frozen at the bounded `p13-iac-compatibility-v1` profile. No
generic OpenStack compatibility, HA/SLA, multi-region, or broader product
support claim follows from this milestone.

### P13 non-goals

- `terraform-provider-o3k` native provider;
- Pulumi, Ansible modules, tenant web UI;
- metering/billing, DNS/Designate, LBaaS/Octavia, Swift/S3;
- Kubernetes-as-a-service, Trove;
- arbitrary OpenStack endpoint parity;
- live migration, automatic unfenced evacuation;
- new hypervisors, XCP-ng, Proxmox, SR-IOV, DPDK;
- multi-region, provider/dataplane redesign;
- production SLA claims.

Future tracks (beyond P13) may add richer IAM/organization/federation, eBPF
network dataplane, richer Neutron profiles, production load balancing, DNS,
object storage, secrets, managed database, Kubernetes, AI/ML, or other
first-class services built on the P12 framework, delegated/federated cloud
connectors, and scale/performance/security certification campaigns.

New services must reuse Cloud Kernel IAM, authorization, ownership, quota,
operations, audit/events and service registration rather than constructing a
parallel cloud framework.

## Continuing compatibility and service-testbed tracks

Selected OpenStack service-testbed and compatibility work may proceed when it
serves a declared user journey, but it must not silently displace the native
product sequence above. External-hosted services retain their own databases,
message buses, processes, backends, upgrades and operational authority.

Route/endpoint count is not a roadmap metric. Compatibility expands because an
accepted product workflow needs it and the corresponding operation-level
evidence exists.

## Roadmap governance

- accepted ADRs/specs/contracts remain authoritative over this summary;
- OpenStack service names do not mandate process boundaries;
- Kubernetes APIs/CRDs do not become Cloud Kernel or canonical tenant state;
- host-local privileged execution stays outside the Kubernetes control plane by
  default;
- P9 networking must not become an excuse for a generic infrastructure
  abstraction program;
- P10 storage must not conflate external Cinder with native Volume authority;
- P11 fabric implementation must not turn WireGuard or Geneve provider IDs into
  tenant identity, silently add regional L2 flooding, or claim a larger real
  topology than was tested;
- do not continue privileged successor fabric implementation from stale
  ADR-0170-era prompt text;
- P12 native API/service-framework implementation must not begin from proposed
  contracts as if they were accepted; human architecture/security approval is
  required first;
- P12 must not hard-code a new service into the Cloud Kernel merely to satisfy
  the conformance example;
- architecture direction does not replace executable evidence or human review.

# P14 — OpenStack Adoption & Migration v1 — bounded profile complete

P14.0 architecture and contracts are defined in ADR-0180 and SPEC-0037. The
bounded `p14-openstack-cold-migration-v1` profile is complete: P14.9 real
two-cloud acceptance passed against protected main 46e050a (G01–G20 all
passed, owned_leaks=0, inconsistencies=0, foreign_state_changes=0, final
OpenTofu plan NO-OP), recorded in `docs/status/current-state.yaml`. The
bounded-profile caveats are preserved: this is not a general live-migration,
arbitrary-migration, or production-datacenter claim, and it does not expand
P13, P12-IAM, the current alpha gate, or any generic cross-cloud claim.

## P15 — Scale and Composition Foundation

P15 proposes the scale/composition foundation for the edge-to-datacenter
building-block Cloud OS: it re-baselines the Cloud Kernel after the post-P14
native northbound closure and the #928 Araf P2 convergence gate, then closes
the highest-priority E2D gaps so the same Cloud Kernel can scale by
composition rather than replatforming. The program is split into phases
P15.0–P15.7 (issues #930–#937): P15.0 (#930) is the re-baseline/foundation
phase, P15.1 (#931) closes canonical location/failure-domain topology (E2D-01),
and P15.2 (#932) converges `KernelRegistry`/`ManifestRegistry` service
authority (E2D-04); the remaining phase scopes, dependencies, and acceptance
model are defined by SPEC-0047.

ADR-0184 and SPEC-0047 were accepted on 2026-09-12 by explicit human
architecture approval recorded in the PR #938 review; they are now active
architecture authority, and P15.1 (#931) is authorized once P15.0 (#930) is
correctly merged. ADR-0182/SPEC-0039 remain the authoritative strategic E2D
sources — advanced by, not amended by, ADR-0184. The post-P14 native Cloud
Kernel closure (audit, metering, diagnostics, quota, governance, location
discovery, and the #907/#928 Araf P2 northbound convergence gate) is recorded
in `docs/architecture/p15-0-post-araf-current-state-audit.md`; the post-#928
gap truth lives in `docs/architecture/p15-e2d-gap-register.md`; implementation
prompts live under `docs/prompts/p15/`.

## PP — Production Phase (umbrella #968)

P15 is complete: the protected certification run 35365369016 passed the P15.7
scale/composition convergence gate at the exact completion SHA 096e4679.
The Production Phase turns that foundation into a shippable, installable
product baseline:

- **PP.0 (#969)** — frozen contracts for `o3k-demo-v1` and
  `o3k-small-edge-v1`, the release bundle, installer/lifecycle/upgrade
  semantics, and the Araf compatibility boundary
  ([SPEC-0048](specs/SPEC-0048-pp0-demo-and-small-edge-baseline-freeze.md),
  [baseline summary](pp0/PP0_PRODUCT_BASELINE.md)).
- **PP.1 (#970)** — build and publish the exact release artifact: shipped
  as v0.4.0-rc.1 (signed digests/provenance; `o3k-network` binary + unit
  shipped installed-but-never-enabled in the libvirt bundle).
- **PP.2 (#971)** — fresh supported machine installs and runs via canonical
  P15 init/join: PASSED. Fresh-host campaigns on genuinely fresh Ubuntu
  24.04 and Debian 12 hosts succeeded against the exact immutable published
  v0.4.0-rc.5 assets (PR #1025): canonical one-line install, authenticated
  join, one ready BuildingBlock, real libvirt VM with guest boot proof,
  reboot/rerun/reset/uninstall/reinstall/purge lifecycle, zero duplicate
  identities, zero foreign-state mutation, zero secret leakage. Predecessor
  candidates rc.1-rc.4 are recorded as failed and immutable.
- **PP.3 (#972)** — versioned Araf artifact + demo deployment integration:
  PASSED on a genuinely fresh Ubuntu 24.04 host. The O3K-pinned
  compatibility tuple (`contracts/araf-compatibility-v1.yaml` `pp3_tuple`)
  binds O3K v0.4.0-rc.5 (unchanged) to Araf v1.0.0-rc.12 with digest-pinned
  OCI artifacts, and `packaging/o3k-araf-demo.sh` deploys the demo stack
  (Docker Engine + Compose v2 only) using real OIDC per-surface logins
  against a demo-scoped local IdP, federated to the real O3K native API.
  Verified: install/verify/status, same-version re-run, restart, host
  reboot, uninstall/reinstall, purge/reinstall, foreign-state preservation,
  zero secret leakage. The Araf side publishes the release bundle and OCI
  tarballs (o3kio/araf#114). No Araf production/HA claim.
- **PP.4 (#973)** — one-line end-user browser demo: **NOT PROVEN**. Historical
  fresh Ubuntu 24.04 and Debian 12 campaigns against the immutable O3K
  v0.4.0-rc.8 / Araf v1.0.0-rc.12 tuple are retained under
  `docs/evidence/pp4/`, but they did not create a workload through Araf. A
  successor tuple must prove the native browser create and cross-interface
  lifecycle before PP.4 can close. **PP.5** must not start yet.

PP.0 freezes definitions only: no production-readiness, GA, HA, live
migration, automatic evacuation, or proven 1–20-host-scale claims.
