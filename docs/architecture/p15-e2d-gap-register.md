# P15 — E2D gap register

Updated classification of the ADR-0182 gap register (E2D-01 through E2D-18)
against the P15 re-baseline. This register is the planning input for
[ADR-0184](../adr/ADR-0184-p15-scale-and-composition-foundation.md) and
[SPEC-0047](../specs/SPEC-0047-p15-scale-and-composition-foundation.md).

| Item | Value |
| --- | --- |
| Baseline | `21fe687c387a04f107b6e87fac04060b1c28e449` (protected `origin/main`, merge of PR #928) |
| Date | 2026-09-12 |
| Issue | #930 (P15.0), under umbrella #929 (P15) |
| Source requirements | [ADR-0182](../adr/ADR-0182-edge-to-datacenter-building-block-cloud-os.md) gap register; [SPEC-0039](../specs/SPEC-0039-edge-to-datacenter-building-block-cloud.md) |
| Method | Full E2D gap audit against the baseline SHA, with re-verification of a sample of cited paths and line numbers |

## Methodology

Classification vocabulary:

- **CLOSED** — requirement fully implemented and evidenced at the baseline.
- **PARTIAL** — some requirement elements exist with evidence; others are absent.
- **OPEN** — no in-tree implementation of the requirement.
- **DEFERRED-BY-DESIGN** — explicitly out of scope per accepted ADR/SPEC.
- **EVIDENCE-ONLY-GAP** — implementation exists but the required evidence does not.

Rules:

- API or route existence alone is not closure. Closure requires the accepted
  requirement to be met with matching evidence at the named evidence tier.
- Severity labels in "Claim impact" are carried over from ADR-0182 and mean
  severity relative to the future end-to-end edge-to-datacenter product claim;
  they are not statements that current bounded profiles are broken.
- P15.1–P15.7 owner assignments follow the GitHub issue scopes (verified
  2026-09-12). P16–P19 assignments follow the proposed post-P15 program map in
  ADR-0184 Decision 8 under the #929 umbrella. That map is planning input for
  sequencing and claim governance, not accepted architecture, and P16–P19
  issues are intentionally not filed yet (see cross-cutting notes).

## Summary

| ID | Short title | Classification | P15+ owner |
| --- | --- | --- | --- |
| E2D-01 | Canonical topology / failure-domain model | PARTIAL | P15.1 #931 |
| E2D-02 | Hierarchical, capability-aware placement | PARTIAL | P15.3 #933 |
| E2D-03 | Building Block as runtime/operator concept | PARTIAL | P15.5 #935 |
| E2D-04 | Service-registry authority convergence | OPEN | P15.2 #932 |
| E2D-05 | Declarative CloudProfile artifact | OPEN | P15.4 #934 |
| E2D-06 | Generic hosted-service machinery | PARTIAL | P19 (hosted machinery; Octavia/Designate/Barbican proofs) |
| E2D-07 | Site autonomy / WAN-loss contract | OPEN | P16 |
| E2D-08 | Datacenter fabric profiles | PARTIAL | P16 |
| E2D-09 | Workload mobility / fenced evacuation | PARTIAL | P16 |
| E2D-10 | Control-plane scale partitioning | OPEN | P18 (measurement starts in P15.7 #937) |
| E2D-11 | Operational observability contract | PARTIAL | P17 (remainder) |
| E2D-12 | Control-plane backup/restore | OPEN | P17 |
| E2D-13 | Production init + authenticated join | EVIDENCE-ONLY-GAP | P15.6 #936 |
| E2D-14 | PKI lifecycle completion | PARTIAL | P17 (tracking issue not yet filed) |
| E2D-15 | Fleet image/artifact distribution | PARTIAL | P17 |
| E2D-16 | Storage topology in the placement model | PARTIAL | P16 |
| E2D-17 | Scale ladder / real scale evidence | OPEN | P18 (first rungs under P15.7 #937) |
| E2D-18 | Mechanically singular repository truth | PARTIAL | P15.0 plan + #433 |

## E2D-01 — Canonical topology / failure-domain model

- **Accepted requirement:** stable Region / AvailabilityDomain / failure-domain
  identity related to blocks, hosts, network fabrics, and storage domains;
  discoverable by native API/Araf; projects cleanly to OpenStack region/AZ
  semantics (ADR-0182).
- **Current implementation:** canonical topology is now durable and
  authoritative. `topology_regions`, `topology_availability_domains`,
  `failure_domains`, and `topology_bindings` tables exist in SQLite
  (`crates/o3k-store/migrations/0046_topology.sql`) and PostgreSQL
  (`crates/o3k-store/migrations_postgres/0029_topology.sql`), with the
  `o3k_kernel::TopologyStore` port implemented for both backends and unified
  dispatch (`crates/o3k-store/src/sqlite/topology.rs`,
  `crates/o3k-store/src/postgres/topology.rs`,
  `crates/o3k-store/src/unified/topology.rs`). `LocationRegistry`
  (`crates/o3k-kernel/src/location.rs:575`) is the single topology authority,
  reconstructed from durable state at startup via `from_snapshot`
  (`location.rs:661`), with `O3K_LOCATIONS` declarations converged idempotently
  into the store (`bins/o3kd/src/composition/mod.rs:256-292`). Generic typed
  `FailureDomain` (`location.rs:183`) with `class` site/building/room/row/rack/
  chassis/power-domain/network-domain/storage-domain (`location.rs:120`),
  validated acyclic parent/child hierarchy (cycle, self-parent, depth-64,
  rank-nesting, cross-AZ rules), durable generation (CAS) and metadata; and
  `TopologyBinding` references to resource-provider/host/fabric-domain/
  storage-domain targets — references only, provider-neutral (`location.rs:252`).
  Native API (SPEC-0047 §4.1):
  `GET/POST /o3k/v1/topology/failure-domains`,
  `GET/PUT/DELETE /o3k/v1/topology/failure-domains/{id}` (If-Match generation),
  `GET/PUT/DELETE /o3k/v1/topology/failure-domains/{id}/bindings[/{kind}/{target}]`,
  and operator region/AZ declaration
  `PUT/DELETE /o3k/v1/regions/{region}` and
  `PUT/DELETE /o3k/v1/regions/{region}/availability-domains/{az}`
  (`crates/o3k-native-api/src/topology.rs`). Reads require an authenticated
  principal (`topology:ReadTopology`); mutations require system scope + operator
  (`topology:ManageTopology`) and fail closed without a durable audit sink; every
  mutation publishes a canonical audit event. `seed_core` now publishes canonical
  regions/AZs — no longer empty — via `seed_core_with_locations`
  (`crates/o3k-kernel/src/manifest.rs:1578`). Keystone region projection is
  derived from canonical topology when exactly one region is configured, else the
  historical `RegionOne` default; multi-region catalog projection is deferred
  (`bins/o3kd/src/composition/mod.rs:287-292`;
  `crates/o3k-identity/src/lib.rs:559-565`).
- **Evidence:** kernel unit tests for hierarchy validity (cycle/rank/depth/
  cross-AZ), durability, and restart reconstruction
  (`crates/o3k-kernel/src/location.rs:2271+`); store conformance plus PostgreSQL
  parity tests including concurrency/CAS/replay
  (`crates/o3k-store/tests/postgres_topology.rs`); native API route, authz, and
  schema tests (`crates/o3k-native-api/src/topology.rs:1530+`);
  `bins/o3kd/tests/p15_1_topology_process.rs` (real o3kd: durable convergence,
  restart survival, derived catalog region, project-scoped 403) and
  `bins/o3kd/tests/p15_1_topology_operator.rs` (operator CRUD + audit through the
  production router, accepted TestIssuer pattern).
- **Remaining delta:** OpenStack AZ (Nova, `OS-EXT-AZ`) projection from canonical
  topology is not implemented; host/fabric/storage-domain consumers of
  `TopologyBinding` references (P16); real-scale / topology-at-scale evidence
  (P15.7 #937 / P18).
- **Dependency:** none upstream; this identity is the foundation E2D-02/03/16/17
  build on.
- **Claim impact:** BLOCKER-to-claim.
- **Recommended owner:** P15.1 #931.

## E2D-02 — Hierarchical, capability-aware placement

- **Accepted requirement:** extend Placement without creating a second
  scheduler model: hierarchical resource providers or an equivalent topology
  graph, generic capabilities/traits, locality constraints,
  failure-domain-aware filtering/spreading, and deterministic/fenced
  allocation semantics (ADR-0182).
- **Current implementation:** flat host-shaped `ResourceProvider { id, node_id,
  state, generation, inventories, allocations }` in
  `crates/o3k-placement/src/lib.rs`; inventories only VCPU/MEMORY_MB/DISK_GB; no
  traits or affinity; deterministic first-fit / most-free-first scheduler in
  `crates/o3k-scheduler/src/lib.rs`. Exists: generation fencing
  (`StaleGeneration`), durable `AllocationIntent` begin/commit/abandon,
  `reconcile_consumers`, `ProviderState::{Enabled,Draining,Unavailable,Deleted}`.
- **Evidence:** `crates/o3k-compute/tests/placement_crash_window.rs`;
  `crates/o3k-store` placement repository tests; P11 drain evidence
  `docs/ROADMAP.md:131-145`.
- **Remaining delta:** provider hierarchy or topology graph, generic
  traits/capabilities, affinity/anti-affinity, and failure-domain spreading —
  the last depends on E2D-01 identity.
- **Dependency:** E2D-01; must not fork into a second scheduler model.
- **Claim impact:** BLOCKER-to-claim.
- **Recommended owner:** P15.3 #933.

## E2D-03 — Building Block as runtime/operator concept

- **Accepted requirement:** a block lifecycle/projection linked to
  Placement/execution identities: enroll, capability publication,
  Ready/Unavailable/Draining state, drain blockers, replacement/removal,
  failure-domain identity, capacity aggregation, Araf/operator visibility
  (ADR-0182).
- **Current implementation (P15.5):** the Cloud Kernel owns a bounded,
  generation-fenced `BuildingBlock` lifecycle and durable SQLite/PostgreSQL
  records. Native operator routes support enrollment, lifecycle actions and
  bounded projections whose capacity/capabilities are derived from Placement
  and authenticated agent state; canonical failure-domain IDs are validated
  through `LocationRegistry`.
- **Evidence:** kernel lifecycle and store round-trip/fencing tests, plus the
  real `o3kd` restart persistence test
  (`bins/o3kd/tests/p15_5_building_block_process.rs`).
- **Remaining delta:** a live authenticated agent/libvirt execution gate and
  full operator/Araf convergence evidence remain before a COMPLETE claim.
- **Dependency:** E2D-01 (failure-domain identity), E2D-02 (placement link).
- **Claim impact:** BLOCKER-to-claim.
- **Recommended owner:** P15.5 #935.

## E2D-04 — Service-registry authority convergence

- **Accepted requirement:** native discovery, capability discovery, and
  OpenStack catalog projection derived from one authoritative manifest/service
  state; a compatibility projection may remain separate, but there must not be
  two competing service inventories (ADR-0182).
- **Current implementation (P15.2):** `ManifestRegistry`
  (`crates/o3k-kernel/src/manifest.rs`) owns manifests, controller state and
  lifecycle. Native discovery, resource/action readiness and diagnostics read
  that authority. `KernelRegistry`
  (`crates/o3k-kernel/src/registry.rs`) is retained only as a derived
  compatibility facade; when bound, Keystone projection checks canonical
  existence/readiness and linked `OpenStackCompatibilityProjection` metadata.
- **Evidence:** `bins/o3kd/tests/p15_2_service_registry_process.rs` proves
  native discovery, resource discovery, lifecycle/readiness, Keystone catalog
  projection and restart reconstruction against both SQLite and disposable
  PostgreSQL; `bins/o3kd/tests/p12_6_process.rs`,
  `bins/o3kd/tests/p12_7_convergence.rs`, and
  `discovery_advertises_only_reachable_lifecycle_operations`
  (`crates/o3k-native-api/src/lib.rs`) provide the supporting process and
  reachability evidence.
- **Remaining delta:** none for the accepted service-registry authority
  convergence requirement; desired service composition remains P15.4.
- **Dependency:** none hard; touches the Keystone catalog projection in
  `crates/o3k-identity/src/lib.rs:1538-1553`.
- **Claim impact:** BLOCKER-to-composable-catalog.
- **Recommended owner:** P15.2 #932.

## E2D-05 — Declarative CloudProfile artifact

- **Accepted requirement:** an authoritative declarative object/artifact
  distinct from the runtime catalog describing desired services, versions,
  ownership mode, dependencies, required capabilities, locality, configuration
  references, and upgrade order; runtime catalog publication follows readiness
  and does not itself install a service (ADR-0182).
- **Current implementation:** no `CloudProfile` artifact or object in code; only
  runtime registration (`ManifestRegistry` plus `O3K_MANIFEST_DIR`) and the
  static catalog exist.
- **Evidence:** none — there is nothing to evidence.
- **Remaining delta:** define and implement the artifact, its validation, and
  reconciliation of runtime state against it.
- **Dependency:** E2D-04 is the recommended predecessor (single authority).
- **Claim impact:** BLOCKER-to-composable-catalog.
- **Recommended owner:** P15.4 #934.

## E2D-06 — Generic hosted-service machinery

- **Accepted requirement:** a reusable hosted-service conformance/profile
  mechanism — pin upstream version, discover dependency calls, freeze required
  compatibility, declare DB/MQ/secrets/dependencies, install/upgrade/restart
  health, verify end-to-end behavior, publish support only after evidence;
  Octavia/Designate/Barbican each pass independently (ADR-0182).
- **Current implementation:** one bounded instance proven: external Cinder
  (SPEC-0023). No generic hosted-service machinery; Octavia/Designate/Barbican
  are docs-only entries (`README.md:373-375`).
- **Evidence:** `tests/real-cinder-workflow-guards.sh`,
  `tests/cinder-chap-compute-gate.sh`, `tests/tempest-cinder-subset.sh`,
  `tests/real-cinder-evidence/`.
- **Remaining delta:** the generic mechanism plus per-service conformance
  proofs.
- **Dependency:** E2D-05 (composition contract); the SPEC-0023 testbed pattern
  as reference.
- **Claim impact:** HIGH.
- **Recommended owner:** P19 (Hosted Ecosystem & Extended Cloud Services) for
  the generic machinery and the Octavia/Designate/Barbican per-service proofs.

## E2D-07 — Site autonomy / WAN-loss contract

- **Accepted requirement:** a local site/autonomy boundary such that an
  office/cage cloud does not require a central SaaS or WAN for already-local
  workload execution/reconciliation; explicit identity behavior during upstream
  IdP outage, local/break-glass access, hosted-service dependencies, and
  reconnect semantics; multi-site/federation is a separate layer and one
  database/control plane must not be stretched across unreliable WAN
  (ADR-0182).
- **Current implementation:** federation requires an OIDC discovery URL with a
  5s timeout and 300s cache (`bins/o3kd/src/composition/mod.rs:43-54`); no
  break-glass/local-token outage contract; no site-autonomy spec; multi-site
  deferred.
- **Evidence:** none dedicated.
- **Remaining delta:** the autonomy spec plus outage identity behavior and
  reconnect semantics.
- **Dependency:** ADR-0179 / SPEC-0036 federated identity ingress exists as the
  base.
- **Claim impact:** BLOCKER-to-edge-product.
- **Recommended owner:** P16 (Site Autonomy, Datacenter Fabric & Workload
  Mobility).

## E2D-08 — Datacenter fabric profiles

- **Accepted requirement:** keep canonical Network/AddressRealm semantics and
  add/prove one or more datacenter fabric profiles (for example EVPN/VXLAN/BGP,
  OVN, hardware integration, or another provider); define inter-block routing,
  gateway/public-address HA, route/endpoint distribution, and scale limits
  without leaking provider technology into the Cloud Kernel (ADR-0182).
- **Current implementation:** P11 Geneve+WireGuard/Linux fabric proven on three
  real hosts plus 15 simulated agents (`docs/ROADMAP.md:100-175`,
  SPEC-0028/0029). The DC fabric candidate
  `compatibility/p9-routed-fabric-v1-planned.yaml` has status `planned` and is
  not advertised; there is no OVN/EVPN/hardware provider.
- **Evidence:** P11 fabric evidence `docs/ROADMAP.md:100-175`; the planned
  profile record.
- **Remaining delta:** at least one proven DC-scale fabric provider with
  inter-block routing, gateway HA, endpoint distribution, and measured scale
  limits.
- **Dependency:** E2D-01 topology identity; provider-boundary discipline.
- **Claim impact:** BLOCKER-to-DC-scale.
- **Recommended owner:** P16 (Site Autonomy, Datacenter Fabric & Workload
  Mobility).

## E2D-09 — Workload mobility / fenced evacuation

- **Accepted requirement:** workload-mobility profiles; a small edge profile may
  legitimately stop on drain blockers, but a datacenter profile needs
  evidence-backed cold relocation and/or live migration, fencing-safe
  evacuation policy, network state movement, shared/local storage rules, and
  deterministic rollback; never blind evacuation without fencing (ADR-0182).
- **Current implementation:** drain exists — `ProviderState::Draining` excludes
  placement, blockers are reported honestly (`docs/ROADMAP.md:141-145`), and
  diagnostics projects Draining-to-Degraded with reason. No relocation, live
  migration, evacuation, or storage movement (`README.md:218` records live
  migration as not claimed).
- **Evidence:** P11 drain evidence `docs/ROADMAP.md:131-145`; durable
  leases/fencing from the multi-controller work are the fencing foundation.
- **Remaining delta:** mobility profiles and fencing-safe evacuation with
  deterministic rollback, proven per profile.
- **Dependency:** E2D-03 (blocks); existing durable fencing.
- **Claim impact:** HIGH.
- **Recommended owner:** P16 (Site Autonomy, Datacenter Fabric & Workload
  Mobility). The drain/blocker basis is already delivered (P11 evidence above);
  P16 owns the mobility profiles and fencing-safe evacuation remainder.

## E2D-10 — Control-plane scale partitioning

- **Accepted requirement:** measure the current PostgreSQL + multi-controller
  architecture first; introduce cells, work partitions, hierarchical
  scheduling, DB partitioning, or other scale mechanisms only where
  measurements require them; preserve one logical O3K authority and idempotency
  across partitions (ADR-0182).
- **Current implementation:** multi-controller correctness exists — durable
  leases/fencing (`docs/reports/P7_MULTI_CONTROLLER_ACCEPTANCE_EVIDENCE.md`,
  `crates/o3k-compute/tests/multi_controller_acceptance.rs`, controller
  sessions and heartbeat at `bins/o3kd/src/composition/mod.rs:255-302`). No
  cells, sharding, or hierarchical scheduling (`o3k-cellhv` is a gRPC
  hypervisor provider client, not a scheduler cell). No control-plane scale
  measurements exist.
- **Evidence:** the multi-controller evidence listed above.
- **Remaining delta:** baseline scale measurements first; partitioning only if
  measurements require it.
- **Dependency:** none hard; measurement infrastructure overlaps E2D-17.
- **Claim impact:** BLOCKER-to-DC-scale.
- **Recommended owner:** P18 (Measured Datacenter Scale); baseline measurement
  can start under P15.7 #937.

## E2D-11 — Operational observability contract

- **Accepted requirement:** a supported observability contract covering API
  latency/errors, operation/reconciliation lag, work leases, scheduler
  decisions/capacity, agent/block health, provider failures, DB health,
  service-catalog readiness, and security-relevant audit correlation;
  Prometheus/OpenTelemetry are adapters, not Cloud Kernel dependencies
  (ADR-0182).
- **Current implementation:** durable audit (SPEC-0042, `/o3k/v1/audit[/{id}]`,
  `crates/o3k-api/src/lib.rs:572-573`; production-mandatory `DurableAuditSink`
  at `bins/o3kd/src/composition/mod.rs:309-310`); operations read
  (`/o3k/v1/operations`); operator diagnostics (SPEC-0045,
  `crates/o3k-api/src/lib.rs:631-647`); metering (SPEC-0046); quota
  (SPEC-0043); governance (SPEC-0044); `o3k-compute` agent `/metrics`,
  `/healthz`, `/readyz` (`bins/o3k-compute/src/main.rs:304`); `o3kd` exposes
  `/healthz` and `/readyz` only (`crates/o3k-api/src/lib.rs:379-380`).
  Missing: `o3kd` has no `/metrics` (grep-verified negative), no OTLP/OTel
  exporter, and no API-latency, reconciliation-lag, work-lease,
  scheduler-decision, or DB-health telemetry.
- **Evidence:** route tests for the existing read surfaces; the missing
  surfaces are absence findings.
- **Remaining delta:** the observability contract, an `o3kd` metrics surface,
  and exporter adapters.
- **Dependency:** none hard; service-catalog readiness state comes from the
  `ManifestRegistry`.
- **Claim impact:** HIGH.
- **Recommended owner:** P17 (Production Operations & Trust), observability
  remainder.

## E2D-12 — Control-plane backup/restore

- **Accepted requirement:** tested control-plane backup/restore for each
  supported persistence profile, including credentials/PKI/config and external
  dependency boundaries; separately define tenant workload
  backup/snapshot/restore/DR profiles instead of implying that database backup
  protects workloads (ADR-0182).
- **Current implementation:** `docs/operations/operational-outcomes-inventory.yaml:165`
  records `rust_owner: docs only; no backup/restore tooling exists`. No
  `scripts/o3k-backup*` exists.
- **Evidence:** none.
- **Remaining delta:** backup/restore tooling and tests per persistence
  profile; tenant workload DR profiles as a separate track.
- **Dependency:** credential/PKI inventory boundary overlaps E2D-14.
- **Claim impact:** HIGH.
- **Recommended owner:** P17 (Production Operations & Trust).

## E2D-13 — Production init + authenticated join

- **Accepted requirement:** define "prepared host", implement low-touch
  control-plane bootstrap and authenticated block enrollment, preflight
  capabilities, generate client/Araf configuration, reconcile the selected
  CloudProfile, and benchmark the exact boundary; physical switch/storage
  provisioning stays outside the timing claim unless O3K actually performs it
  (ADR-0182).
- **Current implementation:** `o3k init` and `o3k join` are wired to the
  production composition router. Init selects and durably reconciles the
  canonical CloudProfile, creates a short-lived digest-only enrollment grant,
  and emits secret-free client/discovery configuration. Join validates the
  grant and prepared-host certificate binding, consumes capability/inventory
  discovery, assigns canonical topology/failure-domain references, registers
  the execution agent and Placement provider, enrolls the P15.5 BuildingBlock,
  persists the bootstrap phase, and records bounded audit events. SQLite and
  PostgreSQL migrations/ports are present; retries serialize through the
  bootstrap lock and converge through the durable enrolled-agent projection.
  The TestLab installer remains a separate profile and is not presented as
  this flow.
- **Evidence:** kernel/store/native API tests cover phase/grant invariants,
  restart-safe durable state, single-use rejection, and unauthenticated or
  malformed init requests. Focused daemon tests and package clippy/checks
  pass. Real-process init → join → execution-boundary evidence and a measured
  bootstrap boundary benchmark remain outstanding.
- **Remaining delta:** complete the real-process evidence gate and benchmark;
  certificate renewal/rotation/revocation remains E2D-14 and is not claimed by
  this bounded enrollment flow.
- **Dependency:** E2D-05 (CloudProfile), E2D-03 (blocks), E2D-14 (enrollment).
- **Claim impact:** BLOCKER-to-fast-adoption.
- **Recommended owner:** P15.6 #936.

## E2D-14 — PKI lifecycle completion

- **Accepted requirement:** complete certificate issuance/renewal/rotation/
  revocation/recovery at scale for agents, controllers, and services; support
  overlapping trust during rolling rotation; prove stale certificate/session
  rejection and loss/recovery; no large fleet should depend on manually
  replaced long-lived credentials (ADR-0182).
- **Current implementation:** the PARTIAL basis is proven — mTLS enrollment and
  agent epochs (SPEC-0015; `tests/real-compute-agent-mtls.sh`,
  `tests/real-compute-agent-process-mtls.sh`). Renewal, rotation, revocation,
  and recovery at fleet scale are unimplemented: `RotateCertificate` exists
  only in the proto (`proto/compute/v1/compute_agent.proto:9,41-47`;
  SPEC-0015:79) with zero Rust implementation, and no revocation, renewal, or
  recovery runtime exists. Rotation is the decisive missing lifecycle
  capability.
- **Evidence:** the real-host mTLS enrollment scripts.
- **Remaining delta:** implement rotation/renewal/revocation/recovery and prove
  stale rejection and loss/recovery at fleet scale.
- **Dependency:** agent-control mTLS exists; enrollment ties into E2D-13 join.
- **Claim impact:** HIGH.
- **Recommended owner:** P17 (Production Operations & Trust); P17 tracking
  issue not yet filed.

## E2D-15 — Fleet image/artifact distribution

- **Accepted requirement:** scalable image/content distribution and
  cache-pressure behavior while preserving digest authority — external object
  storage/registry, peer/cache hierarchy, or another measured design;
  control-plane API nodes must not become bulk image bottlenecks (ADR-0182).
- **Current implementation:** host-local verified materialization only: a
  digest-checked bounded `ImageCache` (`crates/o3k-image/src/lib.rs:83-262`)
  and a control-plane-to-agent chunked artifact push with a 64MB cap and 256KB
  chunks (`crates/o3k-compute-agent/src/artifact.rs:12-14`). No peer/cache
  hierarchy and no external registry/object-store integration.
- **Evidence:** image-cache tests in `crates/o3k-image`; artifact push tests in
  `crates/o3k-compute-agent`.
- **Remaining delta:** choose and implement a distribution topology and prove
  cache-pressure behavior; preserve digest authority.
- **Dependency:** block enrollment (E2D-13); digest authority exists.
- **Claim impact:** HIGH.
- **Recommended owner:** P17 (Production Operations & Trust).

## E2D-16 — Storage topology in the placement model

- **Accepted requirement:** model storage capabilities, locality, and failure
  domains through Placement/block descriptors and provider contracts; do not
  hard-code Ceph into canonical Volume semantics; add
  movement/replication/encryption/backup only as explicit provider/product
  profiles (ADR-0182).
- **Current implementation:** LVM host locality and serial Ceph RBD cross-host
  attachment are proven (`tests/lvm-provider-workflow-guards.sh`,
  `tests/ceph-rbd-workflow-guards.sh`, `docs/ROADMAP.md:135-138`). A vestigial,
  unpopulated `availability_zone` field remains (`crates/o3k-api/src/volume.rs:155`);
  there is no rack/AZ storage placement and no movement profiles. Canonical
  volume semantics are provider-neutral.
- **Evidence:** the workflow-guard scripts and ROADMAP entries above.
- **Remaining delta:** a storage capability/locality/failure-domain model
  expressed through Placement, plus movement profiles as explicit contracts.
- **Dependency:** E2D-01 (failure domains), E2D-02 (placement capabilities).
- **Claim impact:** MEDIUM.
- **Recommended owner:** P16 (Site Autonomy, Datacenter Fabric & Workload
  Mobility).

## E2D-17 — Scale ladder / real scale evidence

- **Accepted requirement:** an explicit scale ladder (for example edge, cage,
  rack/private-cloud, DC) with real host/failure-domain counts, workload
  density, API/scheduler/reconciliation load, block churn, failure injection,
  rolling upgrade, DB/fabric/storage behavior, and latency/resource budgets;
  promote claims rung by rung only (ADR-0182).
- **Current implementation:** `compatibility/product-profiles.yaml` contains
  `p14`, `p13`, `openstack-service-testbed`, `native-rust-testlab`, and
  `small-edge-cloud` — no cage/rack/DC rungs. Maximum real multi-host evidence
  is the P11 profile: three nested-KVM hosts plus 15 simulated hosts
  (`README.md:262`). Existing measurements are workflow-latency measurements,
  not scale evidence.
- **Evidence:** P11 evidence; `docs/measurements.md` is latency-oriented.
- **Remaining delta:** define the ladder, set rung gates, and execute them.
- **Dependency:** consumes evidence from E2D-01 through E2D-16; spans all P15
  programs.
- **Claim impact:** HIGH.
- **Recommended owner:** P18 (Measured Datacenter Scale); the first real-host
  evidence rungs can start under P15.7 #937.

## E2D-18 — Mechanically singular repository truth

- **Accepted requirement:** one generated or mechanically cross-validated
  product-state source from which README status/profile/release summaries are
  derived; CI must fail when `current-state`, the profile registry, the release
  channel, README, and roadmap disagree on current claims (ADR-0182).
- **Current implementation:** `docs/status/current-state.yaml`
  (`status_kind: authoritative-current-state`; evidence vocabulary
  passed|failed|not-executed|not-proven);
  `scripts/validate-profile-state.py` (profile-set match, field contract,
  evidence vocabulary, native-alpha isolation, source-commit resolvability,
  consistency with `docs/release-tracker.md`);
  `tests/profile-state.sh` mutation-rejection CI harness (six mutations must be
  rejected). Missing: nothing cross-validates the README/ROADMAP/E2D register
  against `current-state.yaml` — the `README.md:131-148` table is manually
  duplicated from ADR-0182. Issue #433 owns release-claim validation; P15
  extends `validate-profile-state.py` rather than creating new machinery.
- **Evidence:** `tests/profile-state.sh` harness.
- **Remaining delta:** extend the existing validator to cover README/ROADMAP/E2D
  register consistency with `current-state.yaml`.
- **Dependency:** none; extends #433.
- **Claim impact:** HIGH-governance.
- **Recommended owner:** P15.0 plan + #433.

## Cross-cutting notes

- Nothing in this register is CLOSED, and nothing is a pure
  EVIDENCE-ONLY-GAP: every PARTIAL item has a concrete remaining
  implementation delta, not merely a missing evidence run.
- The #928 gate must not be cited as progress on E2D-02, E2D-08, E2D-09,
  E2D-10, or E2D-17. Its execution provider is `O3K_PROVIDER=fake`
  (`crates/o3k-provider/src/lib.rs:406`); it proves northbound contract
  convergence, not scale or real-host execution.
- E2D-18 is an extension of the existing `scripts/validate-profile-state.py`
  validator and `tests/profile-state.sh` harness, not greenfield machinery.
- API existence is not closure: several routes exist for PARTIAL items (for
  example `/o3k/v1/regions` under E2D-01), but the accepted requirement is
  wider than the route.
- P16–P19 owner assignments follow the proposed post-P15 program map in
  ADR-0184 Decision 8: P16 Site Autonomy, Datacenter Fabric & Workload
  Mobility (E2D-07/08/09/16); P17 Production Operations & Trust (E2D-11
  remainder/12/14/15); P18 Measured Datacenter Scale (E2D-10/17); P19 Hosted
  Ecosystem & Extended Cloud Services (E2D-06 plus the Octavia/Designate/
  Barbican per-service hosted proofs). This map is planning input for
  sequencing and claim governance under the #929 umbrella, not accepted
  architecture; each program requires its own ADR, and P16–P19 issues are
  intentionally not filed yet.
