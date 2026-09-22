# O3K

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo/o3k-horizontal-reversed.svg" />
    <source media="(prefers-color-scheme: light)" srcset="brand/logo/o3k-horizontal.svg" />
    <img alt="O3K" src="brand/logo/o3k-horizontal.svg" width="340" />
  </picture>
</p>

<p align="center">
  <strong>One Cloud Operating System from edge to datacenter.</strong><br />
  Start with a few prepared hosts. Scale by adding capability-bearing building blocks without replatforming.<br />
  OpenStack-compatible northbound. O3K-native cloud authority in the middle. Provider-neutral typed execution southbound.
</p>

<p align="center">
  <img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-f59e0b" />
  <img alt="Implementation: Rust" src="https://img.shields.io/badge/implementation-Rust-111827" />
  <img alt="Kubernetes target" src="https://img.shields.io/badge/Kubernetes-first--class%20target-326ce5" />
  <img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache--2.0-3b82f6" />
</p>

![O3K Cloud Operating System architecture](docs/architecture/o3k-cloud-os.svg)

O3K is a **cloud kernel — literally born in the cloud**. It is built from scratch in Rust around a shared cloud authority rather than inherited service boundaries. The Cloud Kernel owns identity and authorization, resource ownership, desired state, operations, scheduling, reconciliation, quotas, metering, durable audit/event identity, and failure semantics; compatibility APIs stay northbound and infrastructure execution stays southbound.

The product goal is **one operating system end to end**: from a small office or
factory server room, through a customer-owned datacenter cage, to a larger
private or datacenter cloud. The same O3K resource model, IAM, APIs, service
catalog, automation and execution contracts remain in place as the deployment
grows. Larger profiles may introduce cells, sharding, hierarchical scheduling,
or different provider topologies internally; customers should not have to move
from an "edge product" to a different "datacenter product" simply because they
added capacity.

O3K is **not** a service-for-service Rust rewrite of Nova, Neutron, Keystone,
Glance, Placement, and Cinder. OpenStack service names define compatibility
surfaces; O3K owns its internal cloud model.

Core principles:

- **One Cloud OS from edge to datacenter.** Edge and datacenter are scale/evidence
  profiles of the same product architecture, not different O3K products.
- **Scale by building blocks, not by replatforming.** Capacity, capabilities and
  failure domains are added behind the same cloud contracts.
- **OpenStack compatibility is northbound.** Existing CLI/SDK/Terraform
  workflows remain valuable contracts and a path into the wider OpenStack
  service ecosystem.
- **O3K owns cloud authority.** Public IDs, ownership, desired state,
  scheduling, operations, and reconciliation are O3K concerns.
- **The Cloud Kernel is shared.** IAM, authorization, resource ownership,
  operations, quotas, audit/event identity, and failure semantics are reused by
  first-class O3K domains.
- **The service catalog is composable.** A deployment can expose only the cloud
  capabilities it needs and may combine native O3K services with explicitly
  supported external-hosted services.
- **Execution is southbound.** Host agents/providers perform bounded mutations
  and report observations.
- **Kubernetes is a first-class deployment target.** Kubernetes may operate the
  O3K control plane, but it does not become O3K's VM scheduler, tenant-resource
  database, or Cloud Kernel.

> **Current engineering status:** alpha. P9 (routed fabric), P10 (native
> persistent storage), and P11 (bounded multi-hypervisor edge cloud) established
> the first real edge-scale IaaS path. P12 added the native resource API/service
> framework, P12-IAM production federation is complete, P13 passed its bounded
> unmodified OpenStack Terraform/OpenTofu compatibility profile, and P14.9 passed
> the bounded real OpenStack-to-O3K cold-migration G01–G20 acceptance profile.
> After P14, the Araf-driven northbound closure delivered canonical Region/AZ
> discovery (ADR-0181/SPEC-0038), resource/action schema discovery (SPEC-0040),
> bounded native queries (#906), canonical Operations (#898) and relationships
> read (#899), domain actions (#897), generic update (#905), native quota
> (SPEC-0043), IAM governance (SPEC-0044), durable audit (SPEC-0042), operator
> diagnostics (SPEC-0045), authoritative metering (ADR-0183/SPEC-0046), and the
> #907 Araf P2 northbound convergence gate (#928) — the gate ran with the fake
> execution provider, so it proves Cloud Kernel/northbound integration, not
> execution/scale.
> These are strong implementation milestones, not a blanket production, full
> OpenStack parity, multi-region, live-migration, or datacenter-scale claim.

> **PP.4 Core status (2026-09-22):** immutable `v0.4.0-rc.21`,
> `v0.4.0-rc.22` and `v0.4.0-rc.23` are preserved as historical PP.4
> candidates, not as certification. rc.21 proves native replay convergence
> plus a fresh-Ubuntu native/KVM smoke; rc.22 proves the fresh-Ubuntu native
> lifecycle, bidirectional OpenStack compatibility and Horizon HTTP
> readiness, then fails the required unmodified Horizon witness because O3K
> had no Keystone unscoped password authentication for the login bootstrap.
> rc.23 proves those two bounded identity/pagination repairs plus the whole
> rebooting Ubuntu lifecycle through cross-interface delete convergence, then
> fails the required TestLab teardown because a server deleted through the
> native interface kept its auto-created port `ACTIVE` (#1034). The current
> source carries all three bounded repairs — Horizon login/bootstrap identity
> compatibility, bounded Nova/Neutron collection pagination, and
> server-owned endpoint release across both interfaces — and is still not a
> certified candidate. The successor is not named, tagged or published here;
> the complete Ubuntu + Debian native-first campaign, bounded Horizon
> witness and full cross-interface lifecycle remain unproven. O3K is not
> production-ready by this evidence.

Next program: **P15 — Scale & Composition Foundation** (issue #929,
ADR-0184 (accepted), prompts in `docs/prompts/p15/`).

## One Cloud OS from edge to datacenter

The intended scale continuum is:

```text
office / branch / factory
        -> customer server room
        -> dedicated datacenter cage
        -> multi-rack private cloud
        -> datacenter-scale cloud
```

The invariant across that continuum is the product contract, not a frozen
internal process topology:

```text
same IAM / AuthContext
same resource ownership model
same O3K native API family
same selected OpenStack compatibility contracts
same Operation / reconciliation semantics
same service catalog model
same Terraform / OpenTofu approach
same Araf product model
same typed execution-provider contracts
```

A small deployment may be operationally simple. A larger deployment may need
HA controllers, PostgreSQL topologies, cells, sharding, hierarchical capacity,
multiple fabric/storage domains, or other scale mechanisms. Those mechanisms
must remain behind the same O3K cloud semantics so growth does not become a
customer replatforming event.

O3K calls the capacity/capability unit in this model a **deployment building
block**. A block may contribute compute, network, storage, control-plane
participation, or other capabilities and carries explicit failure-domain
identity. It is not a fixed hardware SKU or a requirement that every service
runs on every node.

A building block is **not** intended to become a second capacity/scheduling
authority. The implementation must extend or aggregate Placement/resource-
provider and execution-agent truth so capacity, topology and lifecycle remain
consistent.

See [ADR-0182 — edge-to-datacenter building-block Cloud OS](docs/adr/ADR-0182-edge-to-datacenter-building-block-cloud-os.md)
and [SPEC-0039 — edge-to-datacenter building-block cloud](docs/specs/SPEC-0039-edge-to-datacenter-building-block-cloud.md).

## Architecture reality check

The foundation is compatible with the end-to-end goal; the project does **not**
need to be rewritten. The remaining risk is presenting the building-block idea
before the missing scale/composition layer exists.

The accepted ADR contains the complete post-acceptance audit. The important
current gaps are:

| ID | Severity for future product claim | Gap |
|---|---|---|
| E2D-01 | BLOCKER-to-claim | Canonical topology is durable and exposed on `/o3k/v1/topology/*`: regions/AZs plus a validated generic failure-domain hierarchy and provider/host/fabric/storage references (ADR-0181/SPEC-0038, P15.1 #931). OpenStack AZ (Nova) projection, binding consumers, and real-scale evidence remain open. |
| E2D-02 | BLOCKER-to-claim | Placement/scheduling is still flat capacity selection; no hierarchy, generic traits, topology constraints or failure-domain spreading. (Carve-out: a validated failure-domain hierarchy now exists as canonical topology authority outside placement/consumption; placement itself still does not consume it — P15.1 #931.) |
| E2D-03 | BLOCKER-to-claim | Building blocks are an accepted architecture concept but not yet a first-class operator/runtime lifecycle. |
| E2D-04 | BLOCKER-to-composable-catalog | Converged in P15.2: `ManifestRegistry` is the canonical runtime service authority; `KernelRegistry` is a derived compatibility facade. Real-process evidence remains tracked by the P15.2 acceptance tests. |
| E2D-05 | BLOCKER-to-composable-catalog | O3K lacks a declarative desired service-composition/`CloudProfile` layer distinct from runtime service discovery. |
| E2D-06 | HIGH | Reusable hosted OpenStack service install/version/dependency/upgrade/conformance machinery is not yet generalized beyond bounded profiles such as Cinder. |
| E2D-07 | BLOCKER-to-edge-product | Local site autonomy and WAN-loss semantics are not yet an explicit product contract; same OS must not mean one stretched WAN-dependent control plane. |
| E2D-08 | BLOCKER-to-DC-scale | The P11 Linux/Geneve/WireGuard fabric is a bounded edge reference provider, not datacenter-scale fabric evidence. |
| E2D-09 | HIGH | Drain exists, but mature workload mobility/relocation/live migration/fenced evacuation and storage movement remain unproven. |
| E2D-10 | BLOCKER-to-DC-scale | Multi-controller leases/fencing exist, but cells/shards/hierarchical work partitioning and large PostgreSQL/control-plane scale remain unproven. |
| E2D-11 | HIGH | Operator diagnostics/capacity projection (SPEC-0045), durable audit (SPEC-0042), and metering (SPEC-0046) now exist; `o3kd` still lacks a declared metrics surface (no `/metrics`, no OTLP) and latency/lag/lease telemetry (P17). |
| E2D-12 | HIGH | Tested control-plane backup/restore tooling is incomplete; workload backup/DR is a separate future product profile. |
| E2D-13 | BLOCKER-to-fast-adoption | Current installer/TestLab is not yet the production `init + select profile + authenticated block join` experience. |
| E2D-14 | HIGH | mTLS enrollment is strong, but certificate/admin credential rotation/revocation/recovery is not yet fully implemented at fleet scale. |
| E2D-15 | HIGH | Verified host-local image materialization exists, but large-fleet image/content distribution and cache hierarchy are not proven. |
| E2D-16 | MEDIUM | Storage locality is proven for current profiles, but general rack/AZ/failure-domain storage topology and movement need Placement/block integration. |
| E2D-17 | HIGH | Real scale evidence stops at the bounded edge rung; larger cage/rack/DC profiles need their own real load/failure/upgrade evidence. |
| E2D-18 | HIGH-governance | README/roadmap/profile/current-state/release material still has historical truth drift; product claim state needs one mechanically cross-validated source. A post-#928 re-baseline gap register now exists (`docs/architecture/p15-e2d-gap-register.md`); P15 plans the mechanical cross-check (#433). |

These gaps do not invalidate P11/P13/P14. They define what must be closed before
O3K can honestly market the **end-to-end edge-to-datacenter** claim as a proven
production capability. The canonical post-#928 record for all rows of this gap
table is the re-baseline register at
[`docs/architecture/p15-e2d-gap-register.md`](docs/architecture/p15-e2d-gap-register.md).

### What “same OS” must not mean

```text
NOT: one synchronous database stretched across office WAN links
NOT: one network implementation forced from 3 hosts to 3,000 hosts
NOT: a second building-block scheduler beside Placement
NOT: service catalog registration pretending to install a service
NOT: an Octavia/Designate/Barbican endpoint implying compatibility
NOT: simulated scale being promoted to real datacenter evidence
```

The intended model is instead:

```text
                     same O3K product semantics
                              |
             +----------------+----------------+
             |                                 |
       local edge site                    datacenter cloud
       local authority                    scale partitions
       local execution                    cells/shards if measured
             |                                 |
             +----------- same APIs ------------+
                         same IAM model
                         same resources
                         same automation
```

Multi-site/fleet/federation may later provide a common management plane, but it
must not destroy local site autonomy or turn an unreliable WAN into the local
cloud's correctness boundary.

## One-line TestLab install (alpha)

On a clean Ubuntu 24.04 or Debian 12 x86_64 VM:

```bash
curl -sfL https://get.o3k.io | sudo sh -
```

`get.o3k.io` is only a convenience redirect to the official GitHub Release
asset. The canonical direct alpha URL is:

```bash
curl -sfL https://github.com/o3kio/o3k/releases/download/v0.2.0-alpha.2/install.sh | sudo sh -
```

The future stable URL will be
`https://github.com/o3kio/o3k/releases/latest/download/install.sh` —
it is **not** the alpha source and must not be used before a stable release
exists.

The installer is pinned to its own release: it installs the verified
`v0.2.0-alpha.2` release bundle, bootstraps the libvirt TestLab (`test-vm`
ACTIVE, console verified), and writes client credentials to
`/etc/o3k/admin-openrc` and `/etc/o3k/clouds.yaml` — the admin password is
never printed.

**Supported:** Ubuntu 24.04 x86_64, Debian 12 x86_64, libvirt TestLab alpha.
Version pinning and the dev/test overrides (`O3K_VERSION`,
`O3K_RELEASE_BASE`), credentials, idempotent re-run, uninstall/purge, and
troubleshooting: [docs/INSTALLER.md](docs/INSTALLER.md).

**Not claimed:** production, HA, Kubernetes HA, full OpenStack parity,
arbitrary datacenter scale, multi-region, live migration, ARM/RHEL/etc.

Fast bootstrap on prepared infrastructure is a product target. Claims such as
"in seconds" or "in minutes" remain profile-specific measurement claims and
must not include pre-existing physical, storage, network or external-service
provisioning as if O3K performed it.

The target adoption flow is conceptually:

```text
prepare hosts
   -> o3k init
   -> select CloudProfile
   -> authenticated block join
   -> capability/failure-domain discovery
   -> selected services become Ready
   -> Araf + O3K/OpenStack client configuration
```

That is a target architecture. The current TestLab installer must not be
presented as if this entire production flow already exists.

## What runs today

![O3K current runtime topology](docs/architecture/o3k-runtime-topology.svg)

```text
OpenStack clients
      |
    o3kd
      |
SQLite/PostgreSQL + O3K domain/scheduler/reconciler
      |
 versioned provider boundary
      |
 o3k-compute  o3k-network  o3k-storage
      |            |            |
libvirt     Geneve+WG     LVM / Ceph RBD
```

`o3kd` is the current integrated control-plane composition shell. Host-local
real compute, network, and storage execution cross typed gRPC+mTLS agent
boundaries. Multi-host topology with overlapping tenant CIDRs, Geneve realm
encapsulation over WireGuard host transport, and LVM/RBD storage is proven on
three real hosts with 15 simulated scale hosts for the bounded edge profile.
Durable work leases/controller fencing and PostgreSQL support provide important
scale foundations, but do not themselves prove datacenter-scale scheduling,
networking, database or control-plane throughput.

Northbound, the native `/o3k/v1` surface is live for identity,
compute/network/volume resources, discovery (including regions and
resource-schemas), topology (canonical regions/AZs plus the generic
failure-domain hierarchy and provider/host/fabric/storage references on
`/o3k/v1/topology/*`), operations, relationships, audit, quota, governance,
diagnostics, and metering; the Araf product consumes this native surface.

The current Placement/scheduler implementation is intentionally simple: enabled
host-shaped ResourceProviders advertise VCPU/MEMORY_MB/DISK_GB inventory and the
scheduler performs deterministic capacity-based selection. That is adequate for
the proven profile but is not the final failure-domain-aware datacenter
scheduler.

## Kubernetes-native target

Kubernetes deployability is a **main O3K product target**, not community
packaging added later.

The target architecture is:

```text
OpenStack / O3K clients
          |
   Gateway / Service
          |
+------------- Kubernetes -------------+
|  o3kd-1     o3kd-2     o3kd-3        |
|      \         |         /             |
|          PostgreSQL                    |
|   probes / rollout / config / metrics |
+----------------+----------------------+
                 |
           versioned mTLS
                 |
      external hypervisor hosts
                 |
            o3k-compute
                 |
         libvirt / QEMU / KVM
```

The governing rules are deliberately strict:

1. Kubernetes operates the **control-plane processes**; O3K remains the cloud
   authority.
2. Cloud Kernel/domain crates do not depend on Kubernetes APIs.
3. PostgreSQL is required before an HA/cloud-native Kubernetes support claim;
   SQLite remains the single-controller/TestLab store.
4. Multiple `o3kd` replicas require durable work ownership and controller
   fencing. Pod replication alone is not correctness.
5. Hypervisor/network/storage execution stays host-local by default instead of
   being forced into privileged pods.
6. Kubernetes CRDs may later manage the O3K installation, but do not become the
   canonical database for servers, networks, volumes, or operations.
7. Pod-local state is cache/scratch only for authoritative control-plane data.
8. OCI images + Helm are the first packaging target; an Operator is justified
   only when O3K-specific lifecycle automation needs one.
9. Datacenter scale must be measured before cells/shards are introduced; HA and
   scale are separate claims.

See [ADR-0167 — Kubernetes-native control-plane deployment](docs/adr/ADR-0167-kubernetes-native-control-plane-deployment.md).

## Durable control loop

![O3K durable control loop](docs/architecture/o3k-control-loop.svg)

```text
intent
-> authorization
-> durable desired state + operation
-> scheduling
-> provider command
-> infrastructure mutation
-> observation
-> reconciliation / compensation
```

A timeout is an **unknown outcome**, not proof of failure. O3K observes before
retrying an operation whose side effect may already have happened.

## OpenStack compatibility mapping

| OpenStack surface | O3K domain |
|---|---|
| Keystone | O3K IAM |
| Glance | O3K Image |
| Nova | O3K Compute |
| Neutron | O3K Network |
| Placement | O3K Capacity / Placement |
| Cinder | O3K Volume compatibility / hosted integration where selected |

OpenStack compatibility serves two product purposes:

1. preserve clients, SDKs, Terraform/OpenTofu and operator knowledge;
2. provide a bounded ecosystem integration surface for maintained upstream
   OpenStack services when their exact dependency contracts are proven.

It is not a promise that every upstream OpenStack service works automatically.

## Composable service catalog

OpenStack compatibility is also an ecosystem extension boundary. O3K does not
need to reimplement every specialized OpenStack project in Rust to make that
capability available to an O3K deployment.

An operator-selected catalog may conceptually look like:

```text
Identity        native O3K
Image           native O3K
Compute         native O3K
Network         native O3K
Volume          native O3K
Load Balancing  external-hosted Octavia   (when profile-proven)
DNS             external-hosted Designate (when profile-proven)
Secrets         external-hosted Barbican  (when profile-proven)
```

Other deployments may expose only the minimal core or select different
capabilities for AI/GPU edge, sovereign cloud, storage-heavy, or datacenter
profiles.

External OpenStack services are **not** assumed to work automatically. Each
hosted-service profile must freeze the exact upstream version and discover/prove
the exact O3K/OpenStack dependency behavior it consumes before the catalog can
advertise support. Catalog registration never converts an external-hosted
service into an O3K-native implementation claim.

### Desired composition is not the runtime catalog

For the customized service-catalog idea to become a real product feature, O3K
needs two distinct layers:

```text
operator desired state

CloudProfile / deployment composition
    services + versions + ownership modes
    dependencies + locality + configuration refs
                    |
                    v
          deployment reconciliation
     system packages / OCI / Helm / external service
                    |
                    v
           health/readiness proof
                    |
                    v
        authoritative ServiceManifest state
                    |
          +---------+----------+
          |                    |
     O3K discovery       OpenStack catalog
```

The runtime catalog answers **what is actually available now**. The deployment
composition answers **what this cloud should run**. Keeping them separate avoids
advertising a service before it is installed, healthy and profile-proven.

`ManifestRegistry` is the single runtime service authority. `KernelRegistry`
is retained only as a compatibility projection facade bound to that authority;
arbitrary desired catalog composition remains a separate CloudProfile concern.

## Building blocks and Placement

The building-block model should reuse, not bypass, O3K Placement:

```text
Region
  -> Availability / failure domain
      -> deployment block
          -> ResourceProvider / execution agent
              -> CPU / memory / disk / devices / provider capabilities
```

The exact hierarchy is still to be specified. What is already decided is that
there must be **one capacity authority**.

The current `ResourceProvider` model is flat and host-shaped. Datacenter-scale
Placement must add topology/capability semantics without introducing a separate
block scheduler. Generic traits/capabilities should carry things such as GPU,
network/fabric readiness, storage locality/backend class or other provider
features rather than hard-coding every future technology into the scheduler.

## Edge site autonomy

For O3K to be credible in office/server-room edge deployments, the local site
must remain a useful cloud when its WAN connection is impaired.

The intended direction is:

```text
                     optional fleet/federation
                              |
                         unreliable WAN
                              |
               +--------------+--------------+
               |                             |
          O3K edge site                  O3K DC site
          local control                  local control
          local execution                local execution
          local reconciliation           local reconciliation
```

The exact identity/federation behavior during an upstream IdP outage still needs
a dedicated contract. Existing workloads and local reconciliation must not
depend on a central SaaS merely because future fleet management exists.

## Datacenter scale is a provider/evidence problem, not a new Cloud OS

The P11 fabric is deliberately bounded. A future datacenter profile may use a
different network realization—for example EVPN/VXLAN/BGP, OVN, hardware-backed
fabric integration, or another proven provider—while preserving the canonical
Network/AddressRealm model.

The same applies to storage and control-plane scale:

```text
canonical Compute / Network / Volume / Placement
                   |
          stable typed contracts
                   |
       +-----------+-----------+
       |           |           |
   edge provider  cage provider  DC provider
```

Cells, sharding, hierarchical scheduling or database partitioning should be
introduced only after measurements show the current architecture has reached a
real limit. O3K should not copy OpenStack's historical scale topology in advance.

## Operations required for the end-to-end claim

A datacenter product needs more than correct CRUD. Before broad production scale
is claimed, O3K needs evidence-backed profiles for:

- failure-domain-aware Placement and capacity aggregation;
- block add/drain/remove/replace lifecycle;
- safe workload relocation, with live migration where the selected profile
  requires it and explicit blockers/downtime where it does not;
- fenced evacuation/recovery rather than blind duplicate activation;
- network gateway/public-address resilience and datacenter fabric scale;
- storage locality/failure domains and explicit movement/backup behavior;
- API/scheduler/reconciler/database load and backpressure;
- Prometheus/OpenTelemetry-compatible observability adapters;
- control-plane backup/restore and separate workload backup/DR profiles;
- rolling control-plane/agent/provider/service upgrades and rollback;
- certificate/service credential rotation and revocation;
- scalable image/content distribution;
- independent leak/foreign-state verification at every scale rung.

## Persistence

- **SQLite**: supported default for TestLab and single-controller profiles.
- **PostgreSQL**: supported production-oriented persistence backend where the
  declared profile and evidence cover it.

PostgreSQL plus durable work leases is a strong control-plane foundation, but a
single logical PostgreSQL deployment must not be assumed to scale without limit.
Database HA, failover, backup, connection pressure, partitioning and geographic
placement remain deployment/evidence concerns.

O3K does not use shared-SQLite or distributed-filesystem workarounds as a
shortcut to Kubernetes HA.

## Product profiles

O3K has one product architecture. Deployment/evidence profiles prove bounded
parts of the same edge-to-datacenter continuum and must not be mistaken for
separate O3K products:

- **OpenStack service testbed** — host selected external OpenStack services
  against declared O3K compatibility surfaces;
- **native O3K TestLab/cloud** — minimal/single-host evidence for the native
  Cloud Kernel and IaaS path;
- **small edge cloud** — the first real multi-host scale rung: P11 proves
  overlapping CIDRs, Geneve+WireGuard fabric, LVM locality, serial RBD,
  drain/restart/failure recovery, three real hosts and 15 simulated scale hosts,
  with an initial target around 10–20 hypervisors;
- **future cage/private-cloud/datacenter profiles** — must use the same O3K
  product contracts while publishing their own exact host/failure-domain counts,
  HA/database/provider topology, workload density, performance budgets, upgrade
  behavior and failure evidence.

A useful future evidence ladder is conceptually:

```text
TestLab
   -> edge
   -> customer cage / rack
   -> larger private cloud
   -> datacenter-scale profile
```

Each rung must be proven independently. Simulated agents may supplement but do
not replace real failure-domain evidence.

Kubernetes is a deployment substrate target across applicable control-plane
profiles, not a separate cloud-authority model.

## Documentation and claim truth

O3K's evidence discipline is one of its strengths, but repository status wording
has accumulated historical drift across README, roadmap, product profiles,
`docs/status/current-state.yaml`, release/channel material and old milestone
text.

The end state should be one mechanically validated product-state source with
README/roadmap/release summaries generated from or checked against it. CI should
fail closed when two authoritative-looking surfaces disagree about profile
maturity, release version, supported database/HA posture or scale evidence.

Until that convergence exists, detailed support claims must continue to defer to
the exact normative profile and evidence artifacts rather than broad README
language.

## Quick start

```bash
cargo build
cargo run --bin o3kd
```

For real libvirt execution use [docs/TESTLAB.md](docs/TESTLAB.md).

## Read the design

- [Brand and visual identity](brand/README.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Visual summary](docs/architecture/O3K_CLOUD_OS_SUMMARY.md)
- [ADR-0165 — Cloud OS / Cloud Kernel](docs/adr/ADR-0165-o3k-cloud-operating-system-and-cloud-kernel.md)
- [ADR-0166 — O3K IAM / Keystone compatibility](docs/adr/ADR-0166-o3k-iam-and-keystone-compatibility-boundary.md)
- [ADR-0167 — Kubernetes-native control plane](docs/adr/ADR-0167-kubernetes-native-control-plane-deployment.md)
- [ADR-0182 — edge-to-datacenter building-block Cloud OS](docs/adr/ADR-0182-edge-to-datacenter-building-block-cloud-os.md)
- [ADR-0181 — canonical location identity (regions and availability domains)](docs/adr/ADR-0181-canonical-location-identity.md)
- [ADR-0183 — authoritative metering and bounded usage aggregation](docs/adr/ADR-0183-authoritative-metering-and-bounded-usage-aggregation.md)
- [ADR-0184 — P15 scale and composition foundation](docs/adr/ADR-0184-p15-scale-and-composition-foundation.md)
- [SPEC-0039 — edge-to-datacenter building-block cloud](docs/specs/SPEC-0039-edge-to-datacenter-building-block-cloud.md)
- [SPEC-0038 — canonical location discovery v1](docs/specs/SPEC-0038-canonical-location-discovery-v1.md)
- [SPEC-0046 — native metering definitions and bounded usage aggregation v1](docs/specs/SPEC-0046-native-metering-v1.md)
- [SPEC-0047 — P15 scale and composition foundation](docs/specs/SPEC-0047-p15-scale-and-composition-foundation.md)
- [P15 post-Araf current-state audit](docs/architecture/p15-0-post-araf-current-state-audit.md)
- [P15 E2D gap register (post-#928 re-baseline)](docs/architecture/p15-e2d-gap-register.md)
- [Product requirements](docs/PRODUCT_REQUIREMENTS.md)
- [Roadmap](docs/ROADMAP.md)
- [Normative source map](docs/NORMATIVE_SOURCES.md)

## Development model

O3K is a clean-slate Rust implementation owned and developed by Kubedo GmbH.
It is based on public OpenStack APIs/specifications, public client behavior, O3K
ADRs/specifications/contracts, and independently produced evidence.

## License

Apache-2.0.
