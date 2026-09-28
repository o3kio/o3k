# ADR-0182 — End-to-end edge-to-datacenter building-block Cloud OS

Status: Accepted
Date: 2026-09-08
Human-approval: Senol Colak, 2026-09-08
Supersedes: none
Superseded-by: none
Affected-services: governance, cloud-kernel, identity, compute, network, image, placement, volume, service-registry, deployment, compatibility, future-services

Normative specification: [SPEC-0039](../specs/SPEC-0039-edge-to-datacenter-building-block-cloud.md)

## Context

O3K already has the foundations of a small OpenStack-compatible cloud: a shared
Cloud Kernel, native IAM, compute, network, image, placement and volume domains,
typed execution boundaries, OpenStack-compatible northbound APIs, Terraform/
OpenTofu compatibility, a native service framework, and a proven small
multi-hypervisor edge profile.

That success creates a product-design risk. O3K could accidentally stop at
"smaller OpenStack" or split into different products for small edge deployments
and larger datacenter deployments.

The intended product is broader and simpler:

> **O3K is one Cloud Operating System from edge to datacenter. A small office
> server room, a customer-owned datacenter cage, and a large datacenter cloud
> use the same cloud authority, APIs, resource model, IAM, service catalog,
> automation, and execution contracts. Capacity and failure domains are added
> as building blocks instead of forcing a replatform.**

The word "same" is the important invariant. It does **not** mean that a three-
host edge deployment and a thousand-host datacenter must have identical process
counts, database topology, scheduler internals, or network realization. Large
scale may require cells, sharding, hierarchy, regional partitioning, or other
internal scale mechanisms. Those mechanisms must remain implementation details
behind the same O3K product contracts rather than creating a second cloud
architecture for customers to migrate to.

OpenStack compatibility has a second strategic purpose beyond client/API
compatibility. It is also an ecosystem compatibility layer. A deployment should
be able to select specialized upstream OpenStack services such as Octavia,
Designate, Barbican, Manila, or other services when their dependency contracts
are proven against O3K, without requiring O3K to reimplement every service.

## Decision

### 1. O3K is one operating system across the scale continuum

O3K SHALL target the following continuum with one product architecture:

```text
small office / branch / factory
        -> customer-owned server room
        -> dedicated datacenter cage
        -> multi-rack private cloud
        -> datacenter-scale cloud
```

Moving along this continuum must not require changing the tenant resource model,
IAM model, public IDs, API family, Terraform/OpenTofu model, Araf product model,
or service-discovery model merely because the deployment became larger.

Evidence and supported limits remain profile-specific. A proven 10–20-host edge
profile is not evidence for 100, 1,000, or more hosts.

### 2. The deployment building block is capability- and failure-domain based

O3K defines a **deployment building block** as an independently joinable unit of
capacity and capability with explicit failure-domain identity.

A building block may contribute one or more of:

- compute execution capacity;
- network execution capability;
- storage execution capability;
- control-plane participation where the selected deployment profile requires it;
- region/availability/failure-domain identity;
- service capabilities used by placement and catalog discovery.

A building block is **not** a mandated server SKU, fixed rack layout, or promise
that every process runs on every node. The exact physical composition belongs to
a deployment profile.

The architectural rule is:

> **Scale by adding or partitioning building blocks while preserving O3K cloud
> semantics. Do not require customers to replace the cloud architecture as they
> grow.**

### 3. Large-scale internal topology may evolve without becoming a new product

Datacenter scale may require implementation mechanisms such as:

- scheduler partitions or cells;
- control-plane sharding;
- database partitioning or replicated PostgreSQL topologies;
- regional or failure-domain work ownership;
- hierarchical capacity aggregation;
- network/fabric scale mechanisms different from the first small-edge provider;
- storage providers appropriate to larger failure domains.

These are allowed and expected when evidence requires them.

They must not silently introduce a second canonical resource model, a second IAM
model, incompatible APIs, or an edge-to-datacenter migration boundary inside
O3K itself.

### 4. The service catalog is a product composition mechanism

The O3K service registry/catalog SHALL support operator-selected cloud
capabilities.

A deployment may expose a minimal profile such as:

```text
Identity
Image
Compute
Network
Volume
```

and may add selected capabilities such as:

```text
Load Balancing
DNS
Secrets
Object Storage
Metering
Kubernetes
Database
AI/GPU services
```

A catalog entry must identify its authority/ownership mode. At minimum the
architecture distinguishes:

- **native O3K service** — O3K owns canonical resource state and lifecycle;
- **external-hosted service** — an independently operated service owns its own
  service state while authenticating/discovering/consuming selected O3K
  compatibility surfaces;
- future delegated/federated modes only where separately specified.

The catalog must never present an external-hosted service as an O3K-native
implementation.

### 5. OpenStack compatibility is also an ecosystem extension boundary

Before implementing a specialized cloud service natively, O3K SHOULD evaluate
whether an upstream OpenStack service can be hosted against the existing O3K
compatibility surface.

Examples include Octavia, Designate and Barbican. Such integration is not
assumed to be plug-and-play. Each service requires a bounded dependency-contract
discovery and conformance profile covering the exact Keystone/Nova/Neutron/
Glance/Placement/Cinder or other behavior it consumes.

The default sequence is:

```text
real upstream service
-> discover exact dependency calls and semantics
-> classify existing O3K compatibility coverage
-> implement only bounded missing compatibility/canonical capability
-> prove real service lifecycle, restart, failure and cleanup
-> publish the service in the catalog only for the proven profile
```

This preserves OpenStack ecosystem value without recreating OpenStack's internal
service topology inside O3K.

### 6. Fast edge adoption is a product target, not an unmeasured claim

O3K SHALL optimize for very fast bootstrap on prepared infrastructure: initialize
an O3K control plane, select a service profile, enroll prepared building blocks,
and expose O3K/OpenStack-compatible endpoints with minimal operator steps.

Marketing language such as "in seconds" may be used only after a repeatable
profile-specific benchmark proves the measured boundary being claimed.

A control-plane bootstrap measurement must not be presented as the time required
to provision physical servers, switches, Ceph clusters, external databases,
external OpenStack services, images, certificates, BGP, or other dependencies
that were pre-existing or prepared separately.

### 7. Edge and datacenter are evidence profiles, not separate product identities

"Small edge cloud" remains a valid bounded evidence/support profile. It is the
first proven rung of the end-to-end scale model, not the final architectural
ceiling of O3K.

Future larger profiles SHALL publish exact tested limits and topology, for
example host count, control-plane topology, database profile, provider topology,
failure domains, capacity and latency budgets, and required external
dependencies.

No larger-scale claim follows automatically from the small-edge profile.

### 8. Araf and automation stay continuous across scale

The intended operator/tenant continuity is:

- the same Araf product model;
- the same O3K native API family;
- the same selected OpenStack compatibility contracts;
- the same IAM/AuthContext semantics;
- the same resource ownership and operation model;
- the same Terraform/OpenTofu compatibility approach;
- capability-driven UI/catalog changes instead of separate edge/datacenter
  applications.

This ADR does not require multi-cloud aggregation in Araf. It requires that an
O3K deployment does not become a different product merely because it grows.

## Product model

```text
                           O3K CLOUD OS

                 same IAM / API / resource model
                 same operations / service catalog
                 same automation / execution contracts
                                |
        +-----------------------+-----------------------+
        |                       |                       |
     EDGE BLOCKS            CAGE / RACK BLOCKS      DC-SCALE BLOCKS
        |                       |                       |
  few prepared hosts      larger failure domains   cells/shards if needed
        |                       |                       |
        +-----------------------+-----------------------+
                                |
                     one O3K cloud architecture
```

Service composition is orthogonal to physical size:

```text
Core native O3K
  + optional native O3K services
  + proven external-hosted OpenStack services
  = operator-selected service catalog
```

## Post-acceptance architecture and implementation review — 2026-09-08

This section records a comprehensive implementation audit against the accepted
decision above. It does **not** silently change the accepted decision. Where the
audit identifies a new design choice that is not already implied by this ADR,
that choice remains a required follow-up decision rather than becoming accepted
merely because it is listed here.

### Review verdict

The current implementation does **not** require a foundational rewrite to reach
the edge-to-datacenter goal. The most important foundations point in the right
direction:

- O3K already has one canonical cloud authority rather than per-service cloud
  authorities;
- durable Operations, unknown-outcome handling, reconciliation and ownership-
  safe cleanup are suitable for scale-out execution;
- compute/network/storage agents already use typed, authenticated and fenced
  execution boundaries;
- PostgreSQL support and durable multi-controller work leases/fencing provide a
  credible HA/control-plane base;
- P11 proves a real multi-host edge topology and intentionally keeps the
  canonical Network model independent of the first Linux/Geneve/WireGuard
  realization;
- the P12 ServiceManifest/controller framework provides the right basis for
  extensible services;
- P13 proves a bounded unmodified OpenStack Terraform/OpenTofu provider path;
- P14 proves a bounded real OpenStack-to-O3K cold migration path with rollback,
  restart/recovery, cutover and final IaC convergence.

The missing work is therefore primarily the **scale and composition layer above
those primitives**, not replacement of the Cloud Kernel.

### Gap register

The severities below mean **severity relative to making the future end-to-end
edge-to-datacenter product claim**. They are not statements that the current
bounded P11/P13/P14 profiles are broken.

| ID | Severity | Current gap | Required closure |
|---|---|---|---|
| E2D-01 | BLOCKER-to-claim | **Canonical topology/failure-domain model is incomplete.** Service manifests structurally contain `regions` and `availability_domains`, but current native descriptors commonly publish them empty; Placement providers are host-shaped and do not carry a canonical hierarchy. | Define and implement stable Region / AvailabilityDomain / failure-domain identity and its relationship to blocks, hosts, network fabrics and storage domains. The model must be discoverable by native API/Araf and project cleanly to OpenStack region/AZ semantics. |
| E2D-02 | BLOCKER-to-claim | **Placement is flat.** The current scheduler is deterministic capacity-based selection over enabled providers and VCPU/MEMORY_MB/DISK_GB; it has no provider hierarchy, topology constraints, generic traits/capabilities, affinity/anti-affinity, or failure-domain spreading. | Extend Placement without creating a second scheduler model: hierarchical resource providers or an equivalent topology graph, generic capabilities/traits, locality constraints, failure-domain-aware filtering/spreading, and deterministic/fenced allocation semantics. |
| E2D-03 | BLOCKER-to-claim | **The deployment building block is an accepted concept but not yet a first-class runtime/operator concept.** | Implement a block lifecycle/projection that is linked to Placement/execution identities instead of duplicating them. It must support enroll, capability publication, Ready/Unavailable/Draining state, drain blockers, replacement/removal, failure-domain identity, capacity aggregation and Araf/operator visibility. |
| E2D-04 | BLOCKER-to-composable-catalog | **Service discovery has two overlapping registry generations.** The static `KernelRegistry` is still used for Keystone/catalog behavior while `ManifestRegistry` is the newer dynamic service-manifest/controller model; the source still documents coexistence. | Converge runtime service authority so native discovery, capability discovery and OpenStack catalog projection are derived from one authoritative manifest/service state. A compatibility projection may remain separate, but there must not be two competing service inventories. |
| E2D-05 | BLOCKER-to-composable-catalog | **Runtime service catalog and desired deployment composition are conflated.** O3K can register/discover services, but there is no authoritative declarative object/artifact that says “this site shall run this versioned set of services with these dependencies”. | Define a declarative `CloudProfile`/deployment-composition contract (name not normative here) distinct from the runtime catalog. It must describe desired services, versions, ownership mode, dependencies, required capabilities, locality, configuration references and upgrade order. Runtime catalog publication follows readiness; it does not itself install a service. |
| E2D-06 | HIGH | **Hosted OpenStack service integration is proven only in bounded cases such as external Cinder; generic packaging/lifecycle is absent.** | Build a reusable hosted-service conformance/profile mechanism: pin upstream version, discover dependency calls, freeze required compatibility, declare DB/MQ/secrets/dependencies, install/upgrade/restart health, verify end-to-end behavior, and publish support only after evidence. Octavia/Designate/Barbican must each pass independently. |
| E2D-07 | BLOCKER-to-edge-product | **Site autonomy and WAN-loss behavior are not an explicit product contract.** “Same OS” could otherwise be misread as one stretched synchronous control plane. | Define the local site/autonomy boundary. An office/cage cloud must not require a central SaaS or WAN for already-local workload execution/reconciliation. Identity behavior during upstream IdP outage, local/break-glass access, hosted-service dependencies and reconnect semantics must be explicit. Multi-site/fleet/federation is a separate layer; do not stretch one database/control plane across unreliable WAN merely to preserve the “same OS” message. |
| E2D-08 | BLOCKER-to-DC-scale | **The historical P11 v2 Geneve+WireGuard/Linux provider is an edge-scale reference provider, not datacenter-scale evidence.** Three real hosts and 15 simulated agents do not prove hundreds/thousands of hosts, fabrics, routes or endpoint-directory fanout; the accepted P11 v3 VXLAN/HER successor is not yet runtime evidence. | Keep canonical Network/AddressRealm semantics and add/prove one or more datacenter fabric profiles when needed (for example EVPN/VXLAN/BGP, OVN, hardware integration, or another provider). Define inter-block routing, gateway/public-address HA, route/endpoint distribution and scale limits without leaking provider technology into the Cloud Kernel. |
| E2D-09 | HIGH | **Building-block removal/maintenance is not complete for a mature datacenter.** P11 drain can exclude new placement and expose blockers, but live migration, safe evacuation and storage migration are not supported claims. | Define workload-mobility profiles. Small edge may legitimately stop on blockers; a datacenter profile needs evidence-backed cold relocation and/or live migration, fencing-safe evacuation policy, network state movement, shared/local storage rules, and deterministic rollback. Never implement blind evacuation without fencing. |
| E2D-10 | BLOCKER-to-DC-scale | **Multi-controller correctness exists, but control-plane scale partitioning does not.** Durable leases/fencing solve ownership, not indefinite scheduler/API/reconciler/database scale. | Measure the current PostgreSQL + multi-controller architecture first. Introduce cells, work partitions, hierarchical scheduling, DB partitioning or other scale mechanisms only where measurements require them. Preserve one logical O3K authority and idempotency across partitions. |
| E2D-11 | HIGH | **Operational observability is incomplete.** Structured tracing exists and `o3k-compute` has limited metrics, but `o3kd` has no declared Prometheus `/metrics` surface and no OTLP exporter; block/capacity/reconciliation/service health is not yet a complete operator telemetry model. | Define a supported observability contract: API latency/errors, operation/reconciliation lag, work leases, scheduler decisions/capacity, agent/block health, provider failures, DB health, service-catalog readiness and security-relevant audit correlation. Prometheus/OpenTelemetry are adapters, not Cloud Kernel dependencies. |
| E2D-12 | HIGH | **Control-plane backup/restore is not yet a complete product capability.** Repository operational inventory records backup/restore tooling as missing; workload backup/DR is also outside current native storage scope. | Provide tested control-plane backup/restore for each supported persistence profile, including credentials/PKI/config and external dependency boundaries. Separately define tenant workload backup/snapshot/restore/DR profiles instead of implying that database backup protects workloads. |
| E2D-13 | BLOCKER-to-fast-adoption | **Fast bootstrap is not yet the desired edge experience.** The installer is a bounded TestLab/package path, not a production `init + join blocks + select services` workflow. | Define “prepared host”, implement low-touch control-plane bootstrap and authenticated block enrollment, preflight capabilities, generate client/Araf configuration, reconcile the selected CloudProfile, and benchmark the exact boundary. Keep physical switch/storage provisioning outside the timing claim unless O3K actually performs it. |
| E2D-14 | HIGH | **PKI/credential lifecycle is stronger in contract than in implementation.** Compute enrollment defines certificate rotation, but the repository audit finds the rotation RPC contract more complete than the runtime implementation; admin/password rotation is also backlog work. | Complete certificate issuance/renewal/rotation/revocation/recovery at scale for agents/controllers/services; support overlapping trust during rolling rotation; prove stale certificate/session rejection and loss/recovery. No large fleet should depend on manually replaced long-lived credentials. |
| E2D-15 | HIGH | **Image/artifact distribution is host-local and not datacenter-scale proven.** Verified agent-local materialization is a good edge safety boundary, but no large-fleet distribution/cache topology has been proven. | Define scalable image/content distribution and cache-pressure behavior while preserving digest authority: external object storage/registry, peer/cache hierarchy, or another measured design. Control-plane API nodes must not become bulk image bottlenecks. |
| E2D-16 | MEDIUM | **Storage topology is only partly expressed in the general placement model.** LVM locality and serial Ceph RBD behavior are proven, but rack/AZ/failure-domain placement, backend capability classes, movement and large shared-storage topology need a general contract. | Model storage capabilities/locality/failure domains through Placement/block descriptors and provider contracts. Do not hard-code Ceph into canonical Volume semantics. Add movement/replication/encryption/backup only as explicit provider/product profiles. |
| E2D-17 | HIGH | **Scale evidence stops far below the product ceiling.** Current real multi-host evidence is intentionally small; simulation cannot substitute for real scale/failure-domain proof. | Create an explicit scale ladder (for example edge, cage, rack/private-cloud, DC) with real host/failure-domain counts, workload density, API/scheduler/reconciliation load, block churn, failure injection, rolling upgrade, DB/fabric/storage behavior and latency/resource budgets. Promote claims rung by rung only. |
| E2D-18 | HIGH-governance | **Repository truth is not yet mechanically singular.** Current README/roadmap/profile/status/release material contains historical contradictions (for example small-edge completion versus older status entries, and release-channel/status wording). | Establish one generated or mechanically cross-validated product-state source from which README status/profile/release summaries are derived. CI must fail when `current-state`, profile registry, release channel, README and roadmap disagree on current claims. |

### Architecture constraints derived from the review

The following constraints are important enough to make explicit before further
scale implementation:

1. **Do not create a second capacity authority for “building blocks”.** The
   building-block view should extend or aggregate Placement/resource-provider
   and execution-agent truth; it must not become a parallel scheduler database.
2. **Do not use the runtime service catalog as the installer.** Desired service
   composition and runtime-ready service discovery are separate states and must
   have separate contracts.
3. **Do not stretch a single synchronous control plane across edge sites just to
   claim one product.** Same OS means semantic/operational continuity, not one
   WAN-dependent failure domain.
4. **Do not freeze P11's network implementation as the datacenter topology.**
   The canonical Network model is the invariant; provider technology may change
   by scale profile.
5. **Do not make live migration a hidden prerequisite for the smallest edge
   profile.** Small profiles may expose drain blockers; larger profiles may
   require stronger mobility guarantees.
6. **Do not advertise an upstream OpenStack service because its endpoint can be
   registered.** Dependency behavior, version, health, restart, upgrade and
   cleanup must all be proven.
7. **Do not shard early.** First measure the current PostgreSQL/multi-controller
   architecture. Add cells/shards only at an observed bottleneck while keeping
   public semantics stable.
8. **Do not let Araf invent topology or capability truth.** Araf consumes
   authoritative O3K capability/topology/service discovery and may guide UX;
   backend authorization and resource authority remain server-side.

### Recommended closure order

The gap register should be closed in dependency order rather than as a feature
shopping list:

```text
1. canonical topology/failure domains
   + Placement hierarchy/capabilities
   + runtime registry convergence

2. declarative CloudProfile/service composition
   + first-class block lifecycle
   + fast authenticated init/join path

3. site autonomy contract
   + datacenter fabric/storage topology
   + workload mobility/maintenance profiles

4. observability + backup/restore + PKI rotation
   + scalable image/content distribution

5. measured control-plane partitioning only where needed
   + real scale ladder / failure-domain evidence
   + hosted OpenStack service profiles
```

This ordering keeps the building-block idea as an architectural capability
rather than a marketing layer over a flat scheduler and static catalog.

## Consequences

### Positive

- O3K has a clear product identity beyond "smaller OpenStack".
- Edge installations can grow without a planned product migration to a separate
  datacenter architecture.
- Scale-specific internals remain free to evolve behind stable contracts.
- The service catalog becomes a first-class composition mechanism.
- OpenStack compatibility gains strategic value as an ecosystem extension layer,
  not only a client-compatibility feature.
- Specialized services can be reused from upstream where that is cheaper and
  operationally sound.
- Araf, OpenStack clients, SDKs and Terraform/OpenTofu can remain stable as
  infrastructure grows.

### Negative

- Preserving semantic continuity across radically different scales is a strong
  constraint on future architecture changes.
- Datacenter scale will still require substantial new implementation and real
  evidence; the building-block model does not remove distributed-systems work.
- Hosted OpenStack services can reintroduce operational dependencies such as
  service databases and message buses, so their footprint must be explicit.
- A customizable service catalog increases compatibility/version/support matrix
  complexity.
- Site autonomy plus future fleet/federation creates another boundary that must
  remain distinct from local cloud authority.
- "Edge to datacenter" can be over-marketed unless every scale claim remains
  evidence-bound.

## Rejected alternatives

### Separate O3K Edge and O3K Datacenter products

Rejected because customers should not need to replatform when a successful edge
installation grows into a larger private cloud.

### Require identical process topology at every scale

Rejected because this would confuse product continuity with implementation
uniformity and would prevent necessary sharding, cells, HA and scale-specific
provider designs.

### Reimplement every useful OpenStack service in Rust

Rejected because OpenStack compatibility is deliberately valuable as an
ecosystem boundary. Native implementation should be chosen only when it creates
a material architectural, operational, performance or product advantage.

### Ship one fixed service distribution

Rejected because an office edge cloud, an AI/GPU edge installation, a sovereign
private cloud and a large datacenter may require different capabilities. The
catalog must be explicit and composable.

### Treat a service-catalog entry as proof of implementation

Rejected. Catalog exposure is allowed only for a declared ownership mode and a
versioned, evidence-backed support profile.

### Treat “same OS” as one geographically stretched control plane

Rejected. Product continuity does not justify coupling independent office/cage
failure domains to a WAN or globally synchronous database. Multi-site/fleet/
federation requires its own authority and outage contract.

## Required follow-up

- SPEC-0038 defines the enforceable building-block, scale-continuity, catalog and
  claim requirements;
- product/profile documentation must describe the small-edge profile as the
  first bounded scale rung rather than O3K's architectural maximum;
- track and close E2D-01 through E2D-18 above before making the corresponding
  product claims;
- future scale work must preserve the same Cloud Kernel/public-contract model
  even if cells, sharding or hierarchical scheduling are introduced;
- converge static/dynamic service registry authority before presenting arbitrary
  service-catalog composition as a supported product feature;
- define desired deployment composition separately from runtime service
  discovery;
- define site autonomy/disconnection semantics before presenting O3K as a broad
  office/branch edge platform;
- hosted-service profiles should use black-box dependency-contract discovery in
  the style proven by the OpenTofu/OpenStack compatibility work;
- release and benchmark documentation must separate fast O3K bootstrap from
  external infrastructure provisioning time;
- create a mechanically validated single source of truth for product/profile/
  release status;
- README/product wording should present "one Cloud OS from edge to datacenter"
  as product direction while keeping current support claims evidence-bound.
