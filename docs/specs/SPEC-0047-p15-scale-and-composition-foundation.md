# SPEC-0047 — P15 Scale and Composition Foundation

Status: Accepted (human architecture approval for ADR-0184/SPEC-0047 recorded on 2026-09-12 in the PR #938 review)
Related issue: [#929](https://github.com/o3kio/o3k/issues/929) (umbrella), [#930](https://github.com/o3kio/o3k/issues/930) (P15.0), [#931](https://github.com/o3kio/o3k/issues/931)–[#937](https://github.com/o3kio/o3k/issues/937) (P15.1–P15.7)
Related decision: [ADR-0184](../adr/ADR-0184-p15-scale-and-composition-foundation.md)
Related contracts: [contracts/core-architecture-boundaries.toml](../../contracts/core-architecture-boundaries.toml), [contracts/cloud-kernel-services.yaml](../../contracts/cloud-kernel-services.yaml), [contracts/cloud-kernel-actions.yaml](../../contracts/cloud-kernel-actions.yaml) (as amended per phase)

## 1. Purpose

This specification is the target contract for the P15 Scale & Composition
Foundation program (umbrella issue #929, decision
[ADR-0184](../adr/ADR-0184-p15-scale-and-composition-foundation.md)).

Program definition (ADR-0184 Decision 1): P15 extends the proven O3K Cloud
Kernel with the topology, composition, Placement, deployment-building-block
and bootstrap foundations necessary for one O3K architecture to grow from
edge deployments toward datacenter deployments without changing canonical
cloud semantics or creating a second product architecture.

P15 is **not** the datacenter-scale proof. Scale-ceiling claims belong to
later programs (P18) and require their own measured evidence.

## 2. Scope and non-goals

Program-level non-goals, verbatim from the P15 definition:

- no runtime work in P15.0;
- no cells, sharding, multi-region execution, live migration, evacuation,
  EVPN/VXLAN/OVN, new Ceph behavior, Octavia, Designate, Barbican, Manila,
  object storage, Kubernetes-service, DBaaS or AI service APIs, billing,
  marketplace, organization hierarchy, or Araf UI.

Genuine defects found in current `main` are recorded separately (their own
issues), not silently fixed inside a P15 phase.

## 3. Normative inputs and current baseline

- Baseline: `origin/main` at `21fe687c` (P15.0 re-baseline, issue #930).
- Current-state audit: [docs/architecture/p15-0-post-araf-current-state-audit.md](../architecture/p15-0-post-araf-current-state-audit.md).
- Gap register: [docs/architecture/p15-e2d-gap-register.md](../architecture/p15-e2d-gap-register.md)
  (E2D-01..E2D-18; P15 addresses the foundation gaps E2D-01/02/03/04/05/13,
  contributes to E2D-18, and leaves E2D-06..E2D-17 to the post-P15 programs
  per ADR-0184 Decision 8).
- Strategic authority: [ADR-0182](../adr/ADR-0182-edge-to-datacenter-building-block-cloud-os.md)
  and [SPEC-0039](SPEC-0039-edge-to-datacenter-building-block-cloud.md) define
  the edge-to-datacenter direction, the deployment building block, the
  composable catalog, and the claim rules this program implements. This
  specification does not amend them.
- Program decision: [ADR-0184](../adr/ADR-0184-p15-scale-and-composition-foundation.md)
  (Accepted 2026-09-12 via PR #938; active P15 architecture authority).

## 4. Phase definitions and dependency order

Dependency order (ADR-0184 Decision 2): P15.0 re-baseline -> P15.1 -> P15.2
(P15.1 and P15.2 mutually independent) -> P15.3 (needs P15.1) -> P15.4
(needs P15.2) -> P15.5 (needs P15.1+P15.3+P15.4) -> P15.6 (needs P15.4+P15.5)
-> P15.7 (needs all). A phase's dependencies must be merged with their own
evidence before dependent work cites them.

Every phase below lists: objective; in-scope; out-of-scope; authority model;
security requirements; database implications; OpenStack compatibility
implications; Araf implications; failure/restart behavior;
idempotency/concurrency requirements; required tests; required real-process
evidence; claim limitations; acceptance criteria.

### 4.0 P15.0 — re-baseline (#930)

- **Objective:** re-establish a single auditable baseline for scale and
  composition work after the post-P14/Araf convergence landing (#887–#907,
  PRs #920–#928).
- **In scope:** normative documents only — this specification, ADR-0184, the
  E2D gap register, the current-state audit; terminology alignment.
- **Out of scope:** runtime code changes of any kind.
- **Authority model:** documentation-only; no authority changes.
- **Security requirements:** none (no runtime surface).
- **Database implications:** none.
- **OpenStack compatibility implications:** none.
- **Araf implications:** none; Araf-relevant contracts are named for later
  phases only.
- **Failure/restart behavior:** not applicable.
- **Idempotency/concurrency requirements:** not applicable.
- **Required tests:** none beyond existing CI (ADR index validation,
  markdown link validation).
- **Required real-process evidence:** none.
- **Claim limitations:** no new product, scale, or compatibility claims are
  created by P15.0.
- **Acceptance criteria:** ADR-0184 and SPEC-0047 merged with
  `Status: Accepted` (human approval recorded 2026-09-12, PR #938); gap
  register and audit doc merged; ADR index updated;
  validator-clean.

### 4.1 P15.1 — canonical topology/failure domains (#931)

- **Objective:** complete the canonical topology model beyond Region/AZ with
  a generic failure-domain hierarchy under Region/AZ.
- **In scope:** generic failure-domain model under Region/AZ; bindings of
  failure domains to providers/hosts/fabric/storage by reference; fix
  `seed_core` empty locations; Keystone region/AZ projection derived from
  canonical topology.
- **Out of scope:** scheduling or capacity logic; provider-specific topology
  in public semantics; a hard-coded rack/row model unless an accepted
  contract requires it; Araf-owned topology.
- **Authority model:** LocationRegistry remains the single topology
  authority ([ADR-0181](../adr/ADR-0181-canonical-location-identity.md));
  this phase extends it. Topology describes and references; it never
  schedules.
- **Security requirements:** topology reads/writes are authorized
  operations; cross-scope reads fail closed; no provider internals (host
  names, fabric details) leak into tenant-visible semantics.
- **Database implications:** failure-domain and binding tables/migrations in
  the kernel store; SQLite and PostgreSQL parity required for every new
  table, index, and migration.
- **OpenStack compatibility implications:** Keystone region/AZ list/projection
  becomes a derived read of canonical topology; existing compatibility
  profile records updated, not bypassed.
- **Araf implications:** topology discovery consumed by Araf as derived
  read-only truth; Araf contributes no topology state.
- **Failure/restart behavior:** topology state is durable and survives
  control-plane restart; seeding is idempotent and restart-safe.
- **Idempotency/concurrency requirements:** deterministic IDs; unique
  constraints on failure-domain identity; concurrent enrollment of bindings
  cannot create duplicates.
- **Required tests:** domain invariant tests for the failure-domain model;
  IAM/authorization tests for topology reads/writes; protocol/contract tests
  for discovery payloads; regression tests proving `seed_core` locations are
  non-empty; process tests for Keystone projection derivation.
- **Required real-process evidence:** process-level discovery tests against a
  real `o3kd` (SQLite and PostgreSQL passes), consistent with the evidence
  ladder's process tier.
- **Claim limitations:** claims cover the topology model and its projection
  only; no placement, scale, or HA claims.
- **Acceptance criteria:** generic failure domains under Region/AZ merged
  with parity tests; bindings by reference merged; `seed_core` non-empty
  regression green; Keystone region/AZ derivation proven in process tests;
  E2D-01 advanced per the gap register's evidence rules.
- **Real-process evidence boundary (process tests):** topology mutation
  authorization requires a system-scope `operator` identity, which in a real
  deployment is federated (OIDC); there is no offline, non-OIDC path to such a
  token, so offline real-process evidence covers durable region/AZ convergence,
  restart survival, Keystone catalog-region derivation, topology reads, and the
  project-scoped 403 denial under real Keystone password auth
  (`bins/o3kd/tests/p15_1_topology_process.rs`). Operator-authenticated
  topology CRUD is proven in-process against the production router with the
  real durable store and the accepted `TokenIssuer` (`bins/o3kd/tests/
  p15_1_topology_operator.rs`); the federated real-process operator CRUD path
  remains to be evidenced at the P15.7 convergence gate, mirroring the existing
  araf P2 Keycloak harness (`bins/o3kd/tests/araf_p2_convergence.rs`).
- **Notes (P15.1 findings):** only one `o3kd` may drive a given store (the
  in-memory single-item reads reflect only local mutations; store-backed
  collection reads observe the full durable sequence). Topology reads are
  authenticated-principal-wide, so binding references (provider/host/fabric/
  storage ids) are visible to any authenticated principal; a tenant-safe
  projection can be introduced later if needed.

### 4.2 P15.2 — service-registry authority convergence (#932)

- **Objective:** converge runtime service authority to a single native
  authority so native discovery and the OpenStack catalog are projections of
  one state.
- **In scope:** KernelRegistry/ManifestRegistry convergence plan and
  implementation; derived catalog and native discovery; safe migration path
  for existing consumers; advertised-implies-executable preserved.
- **Out of scope:** CloudProfile desired composition (P15.4); installing or
  deploying services via the catalog; changes to external-hosted service
  lifecycles.
- **Authority model:** one authoritative native service/manifest state;
  catalog and discovery are derived projections and never authorities
  (ADR-0184 Decision 5).
- **Security requirements:** service registration and capability publication
  are authenticated operator-domain operations; projections must not broaden
  caller authority or leak undeclared endpoints.
- **Database implications:** registry store convergence (single source
  tables/state); migration path for existing rows; SQLite/PostgreSQL parity
  for the converged schema and every migration step.
- **OpenStack compatibility implications:** Keystone catalog content remains
  a derived projection; catalog records updated only via the converged
  authority; compatibility profile registry unchanged in authority.
- **Araf implications:** Araf consumes native discovery from the single
  authority; no Araf-side service inventory duplication.
- **Failure/restart behavior:** convergence cutover is restart-safe;
  partially migrated state reconstructs to the converged authority on
  restart.
- **Idempotency/concurrency requirements:** deterministic service identity;
  idempotent registration; concurrent registration of the same service cannot
  fork state.
- **Required tests:** domain tests for the converged registry model; IAM
  tests for registration authority; protocol tests for derived catalog and
  discovery payloads; migration tests (old -> new, rollback where feasible);
  regression tests for existing consumers; process tests proving catalog and
  discovery derive from one state.
- **Required real-process evidence:** process-level tests with a real
  `o3kd` on both stores, including restart reconstruction.
- **Claim limitations:** claims cover registry convergence and projection
  derivation; no composition or hosted-service claims.
- **Acceptance criteria:** single native service authority merged with
  migration evidence; catalog and native discovery derived in process tests;
  advertised-implies-executable regression green; E2D-04 advanced per the
  gap register's evidence rules.

### 4.3 P15.3 — hierarchical/capability-aware Placement (#933)

- **Objective:** extend Placement to a hierarchical, capability-aware model
  per ADR-0184 Decision 4.
- **In scope:** ResourceProvider model with inventories, allocations,
  parent/child topology, capabilities/traits, failure-domain references;
  candidate selection supporting quantity, required/forbidden capabilities,
  location constraints, failure-domain constraints, and locality.
- **Out of scope:** cells/sharding/partitioning (no cells without
  measurements — P18); provider-specific scheduling semantics; any second
  capacity authority (e.g. Building Block-owned capacity).
- **Authority model:** Placement is the single scheduling/capacity authority;
  it consumes topology constraints from LocationRegistry (P15.1) but topology
  does not schedule.
- **Security requirements:** allocation authority requires authenticated
  service principals; candidate visibility respects ownership scope; provider
  internals stay out of tenant responses.
- **Database implications:** placement schema evolution (provider hierarchy,
  inventories, traits, failure-domain references, allocations); durable
  allocation records preserved across the migration; SQLite/PostgreSQL
  parity required.
- **OpenStack compatibility implications:** Nova/Placement-compatible
  behavior remains inside the accepted compatibility profile; any
  profile-visible change requires profile records per SPEC-0022 before
  advertisement.
- **Araf implications:** capacity/Topology views consumed by Araf as derived
  reads of Placement and LocationRegistry.
- **Failure/restart behavior:** allocations durable before side effects
  (persist intent first); scheduler restart reconstructs from durable state;
  unknown-outcome classification preserved.
- **Idempotency/concurrency requirements:** deterministic candidate ordering;
  idempotent, fenced allocation claims (generation fencing); concurrent
  claims cannot double-allocate; compensation for cross-service mutations.
- **Required tests:** domain tests for the provider/traits model and state
  machine; IAM tests for allocation authority; protocol tests for selection
  constraints; provider-conformance fakes for capability reporting;
  compensation/failure tests (claim, crash, reclaim); regression tests for
  existing flat placement behavior; process tests for end-to-end scheduling.
- **Required real-process evidence:** process-level scheduling tests with a
  real `o3kd`; real execution evidence beyond the fake provider is staged in
  P15.7.
- **Claim limitations:** claims cover the placement model and its bounded
  process evidence; no datacenter-scale scheduling claims.
- **Acceptance criteria:** hierarchical providers, traits, and failure-domain
  constraints merged with parity tests; deterministic/fenced allocation
  semantics proven; no-cells-without-measurements guardrail enforced in
  review; E2D-02 advanced per the gap register's evidence rules.

### 4.4 P15.4 — declarative CloudProfile/service composition (#934)

- **Objective:** define and implement the declarative desired-deployment-
  composition contract, semantically separated from observed service state
  and the consumable catalog.
- **In scope:** CloudProfile (name not final) describing selected services,
  ownership mode, versions, dependencies, required capabilities,
  placement/locality constraints, config references, and upgrade ordering;
  drift between desired and observed state surfaced via canonical Operations.
- **Out of scope:** runtime catalog semantics (the catalog remains a derived
  projection); tenant resource state in CloudProfile; managing
  external-hosted service internals (they retain their own lifecycle).
- **Authority model:** CloudProfile is the single desired-composition
  authority; ManifestRegistry/converged registry records observed/existing
  services; the catalog is the consumable projection (ADR-0184 Decision 6).
- **Security requirements:** profile CRUD is an operator-domain authorized
  operation; config references never carry secrets in the profile object;
  profile reads do not expose provider credentials or endpoints.
- **Database implications:** new desired-composition store area (profiles,
  revisions, drift/operation linkage); SQLite/PostgreSQL parity required.
- **OpenStack compatibility implications:** none direct; the catalog remains
  derived and registration still does not install software.
- **Araf implications:** Araf may present desired-vs-observed drift from
  canonical Operations; Araf does not own composition truth.
- **Failure/restart behavior:** profiles are durable and versioned; drift
  detection resumes after restart; partially applied reconciliation is
  resumable.
- **Idempotency/concurrency requirements:** deterministic profile identity
  and revisioning; idempotent reconciliation steps; concurrent edits resolve
  via optimistic concurrency (revision fencing).
- **Required tests:** domain tests for the profile model and drift semantics;
  IAM tests for operator authority; protocol tests for the profile contract;
  compensation tests for failed reconciliation steps; regression tests
  ensuring the catalog is unaffected by profile changes; process tests for
  drift surfacing through Operations.
- **Required real-process evidence:** process-level reconciliation tests with
  a real `o3kd` on both stores.
- **Claim limitations:** claims cover the composition contract and drift
  surfacing; no automated upgrade-orchestration or hosted-service lifecycle
  claims.
- **Acceptance criteria:** CloudProfile contract merged with parity tests;
  drift surfaced via canonical Operations proven in process tests;
  desired/observed/catalog separation enforced by tests; E2D-05 advanced per
  the gap register's evidence rules.

### 4.5 P15.5 — deployment Building Block lifecycle (#935)

- **Objective:** make the deployment building block a first-class runtime
  and operator concept linked to canonical authorities.
- **In scope:** enrollment, identity, capability publication, failure-domain
  membership; administrative states Ready/Unavailable/Draining;
  removal/replacement with honest drain blockers; capacity projection derived
  from Placement; operator/Araf visibility.
- **Out of scope:** block-owned capacity or scheduling (a second scheduler/
  capacity database is forbidden); live migration/evacuation semantics;
  zero-drain-guarantee claims.
- **Authority model:** Building Blocks compose/link LocationRegistry topology
  (P15.1), Placement capacity (P15.3), CloudProfile composition (P15.4), and
  execution identities; the block record owns lifecycle/administrative state
  only (ADR-0184 Decision 3).
- **Security requirements:** enrollment and identity are authenticated
  (certificate-bound where applicable); capability publication is attested;
  block state changes are authorized operator operations.
- **Database implications:** block lifecycle state store; linkage tables to
  topology/placement/execution identities; SQLite/PostgreSQL parity.
- **OpenStack compatibility implications:** none direct; capacity projection
  remains derived from Placement and is not advertised as a new compatibility
  surface.
- **Araf implications:** block health/state and drain blockers are visible to
  operators/Araf as derived reads.
- **Failure/restart behavior:** block state durable; restart reconstructs
  block membership and resumes in-flight transitions; drain blockers persist
  and remain honest across restart.
- **Idempotency/concurrency requirements:** deterministic block identity;
  idempotent enrollment; fenced state transitions (generation/epoch);
  concurrent drain and placement decisions cannot race into double-allocated
  capacity.
- **Required tests:** domain tests for the block lifecycle state machine;
  IAM tests for enrollment authority; protocol tests for capability
  publication; provider-conformance fakes for execution identity linkage;
  compensation tests for failed enrollment/removal; regression tests for
  placement invariants; process tests for the full enroll->ready->drain->
  remove path.
- **Required real-process evidence:** **real execution boundary** — the #928
  fake provider is not sufficient for P15.5 execution claims; at least one
  real provider path (e.g. the libvirt TestLab profile) must exercise block
  membership, capability publication, and drain blockers against a real
  `o3kd`.
- **Claim limitations:** claims cover the block lifecycle and its bounded
  real-execution evidence; no evacuation, live migration, or zero-downtime
  maintenance claims.
- **Acceptance criteria:** block lifecycle merged with parity and process
  tests; drain blockers honest and test-proven; capacity projection derived
  from Placement verified; E2D-03 advanced per the gap register's evidence
  rules.

### 4.6 P15.6 — production init + authenticated join (#936)

- **Objective:** implement the low-touch production bootstrap and
  authenticated enrollment path: `o3k init`, CloudProfile select,
  `o3k join`.
- **In scope:** control-plane initialization; identity and certificate
  issuance for controllers and joining blocks; provider/agent registration;
  Placement publication; failure-domain assignment; profile reconciliation;
  readiness signaling; client/Araf config generation.
- **Out of scope:** provisioning physical infrastructure (switches, storage
  arrays, external databases, external OpenStack services); timing claims
  that include pre-provisioned external work.
- **Authority model:** init/join flows write only through the canonical
  authorities (IAM for identity, LocationRegistry for failure-domain
  assignment, Placement for publication, CloudProfile for composition); no
  parallel bootstrap authority.
- **Security requirements:** authenticated join (no unauthenticated
  enrollment); certificate-bound identities with rotation path; bootstrap
  credentials are short-lived and never logged. Boundary: P15.6 covers
  bootstrap-time certificate issuance and re-issuance for enrolled hosts
  only; fleet-scale certificate rotation/renewal/revocation/recovery remains
  E2D-14 owned by P17 (`RotateCertificate` is currently proto-only).
- **Database implications:** bootstrap/init state and issuance records in the
  kernel store; SQLite/PostgreSQL parity.
- **OpenStack compatibility implications:** none direct; post-init catalog
  remains a derived projection.
- **Araf implications:** generated client/Araf configuration consumes the
  same discovery and identity contracts.
- **Failure/restart behavior:** interrupted init/join is resumable or cleanly
  reversible; no half-initialized control plane presents a usable API.
- **Idempotency/concurrency requirements:** idempotent init and join steps;
  deterministic enrollment identity; concurrent joins cannot duplicate
  registrations.
- **Required tests:** domain tests for bootstrap state; IAM tests for join
  authentication; protocol tests for init/join contracts; failure tests for
  interrupted init/join; regression tests for readiness semantics; process
  tests for the full init->join->ready flow.
- **Required real-process evidence:** real-process init/join against a real
  `o3kd` on both stores; **any bootstrap timing claim requires a repeatable
  profile-specific benchmark** whose measured boundary excludes
  pre-provisioned external work O3K does not perform.
- **Claim limitations:** claims cover the init/join workflow and its measured
  boundary; no "production cloud in seconds" or full-site readiness claims.
- **Acceptance criteria:** init/join merged with process evidence;
  authenticated join proven with stale/replay rejection; benchmark
  methodology documented before any timing wording; E2D-13 advanced per the
  gap register's evidence rules.

### 4.7 P15.7 — scale/composition convergence and real-host evidence gate (#937)

- **Objective:** prove the full building-block journey end to end on real
  execution boundaries and converge all claims to evidence.
- **In scope:** the complete journey — fresh deploy -> init -> profile ->
  enroll multiple real blocks -> topology appears -> capacity appears ->
  workload -> topology/capability placement enforced -> add block -> drain
  block with honest blockers -> remove/rejoin/replace -> restart control
  plane and PostgreSQL -> IDs/topology/profile survive -> native API
  authoritative -> OpenStack projection convergent. Araf is an optional
  external consumer and is outside the mandatory TestLab/P15.7 dependency
  chain; if configured, it may be observed as additional evidence.
- **Out of scope:** proving the final scale ceiling; hiding or working around
  drain blockers; simulated-agent substitution for real blocks.
- **Authority model:** the same canonical authorities as P15.1–P15.6; this
  phase adds no new authority, only evidence.
- **Security requirements:** the journey runs under the production IAM and
  execution-identity contracts; restart and replacement preserve identity and
  fencing.
- **Database implications:** journey covers both SQLite and PostgreSQL
  profiles where the profile claims require it; PostgreSQL runs include the
  restart matrix.
- **OpenStack compatibility implications:** OpenStack projection convergence
  is verified against the accepted compatibility profile vocabulary only.
- **Araf implications:** Araf may consume the same topology/capacity/service
  truth at journey end, with no dashboard-specific state. Araf availability is
  optional and must not gate TestLab readiness or P15.7 completion.
- **Failure/restart behavior:** mid-journey control-plane and PostgreSQL
  restart; block failure injection; recovery without lost IDs, topology, or
  profile state.
- **Idempotency/concurrency requirements:** every journey step is idempotent;
  concurrent block operations preserve allocation and identity invariants.
- **Required tests:** the per-phase test suites remain green; the journey
  adds integration/regression coverage for every arrow in the journey list.
- **Required real-process evidence:** **real execution boundary throughout;
  the #928 fake provider is not sufficient for P15.5–P15.7 execution
  claims.** Multiple real blocks, real providers, restart matrix, and
  failure injection are mandatory; the evidence ledger records exact
  versions, host counts, and limits.
- **Claim limitations:** P15.7 proves the building-block architecture, **not**
  the scale ceiling; blockers are exposed honestly.
- **Acceptance criteria:** full journey green on real blocks with the restart
  matrix; evidence ledger merged (non-DRAFT for the claims made); native
  authority and projection convergence proven; E2D-01/02/03/04/05/13 and
  E2D-18 statuses updated per the gap register's evidence rules.

## 5. Cloud Kernel invariants

Normative restatement of ADR-0184's invariants (MUST language):

1. There MUST be exactly one canonical cloud authority. Native API,
   OpenStack compatibility, Araf, Terraform/OpenTofu, and Building Blocks
   MUST consume or project that same O3K authority; none MAY create a
   parallel one.
2. Building Blocks MUST NOT be a second Placement. Capacity and scheduling
   truth MUST live only in Placement.
3. Topology MUST NOT schedule. Location/failure-domain truth MUST be
   descriptive and referential; scheduling decisions MUST be made only by
   Placement.
4. CloudProfile MUST represent desired composition only; it MUST NOT become
   runtime discovery. Observed service truth and consumable catalog
   projections MUST be separate states.
5. Catalog registration MUST NOT install software. Advertised-implies-
   executable MUST be preserved through evidence, not registration.
6. OpenStack compatibility MUST be derived from canonical O3K state; it MUST
   NEVER become an authority over it.
7. Araf MUST NOT be authoritative. Araf discovers capabilities, schemas,
   topology, relationships, quota, metering, governance, and operations from
   O3K; no dashboard-specific truth MAY live in the kernel.
8. Scale mechanisms (cells/sharding/partitioning) MUST follow measurements;
   they MUST NOT be introduced without an observed bottleneck and MUST remain
   behind unchanged product contracts.
9. WAN MUST NOT be a local correctness dependency. P15 preserves this future
   multi-site invariant (E2D-07) and does not solve it.

## 6. Evidence and claim governance

Evidence ladder order (per the repository test strategy): ADR/SPEC/contract/
profile validation -> domain/IAM/store/migration/policy tests -> provider/
external-service conformance -> portable simulated-profile integration ->
process-level public-client tests -> execution component or hosted-service
real-host gate -> full native/testbed/edge gate -> restart/failure matrix ->
release gate. Work proceeds in this order unless an accepted issue justifies
otherwise.

Per-phase claim rules:

- A phase may claim only what its own evidence tier proves; profile-scoped.
- API existence alone changes no gap status; the gap register updates only
  with landed evidence (per
  [docs/architecture/p15-e2d-gap-register.md](../architecture/p15-e2d-gap-register.md)).
- Evidence ledgers with frozen-head placeholders (DRAFT) support no claim
  that depends on a `[pending]` value.
- The #928 northbound gate (fake execution provider) is not execution or
  scale evidence; P15.5–P15.7 execution claims require real execution
  boundaries.

#433 extension plan: extend
[scripts/validate-profile-state.py](../../scripts/validate-profile-state.py)
— or add a thin sibling validator wired into the same CI gate — so that
README/roadmap/E2D-register claims are derived from or cross-checked against
[docs/status/current-state.yaml](../status/current-state.yaml),
[compatibility/product-profiles.yaml](../../compatibility/product-profiles.yaml),
and the verified vocabulary of
[docs/compatibility/matrix.yaml](../compatibility/matrix.yaml). Release
generation fails closed on any disagreement. Issue #433 remains the tracking
issue; this machinery is the single claim system — no second claim system is
created.

## 7. Acceptance model for the P15 program

P15 (umbrella #929) is complete when all of the following hold:

1. Phases P15.0–P15.7 (issues #930–#937) are closed with their per-phase
   acceptance criteria met and evidence merged.
2. ADR-0184 has passed human architecture approval (or the program's
   normative basis is re-recorded explicitly).
3. The P15 evidence ladder is green for every claim the program makes:
   domain through release-gate tiers, per phase.
4. The E2D gap register reflects only evidence-backed statuses for
   E2D-01/02/03/04/05/13/18, with all other gaps unchanged and explicitly
   deferred to the post-P15 programs (P16–P19).
5. README/roadmap/E2D-register claims derive from, or pass cross-check
   against, the machine-readable evidence state; the #433-extended validator
   is green in CI.
6. Claim boundaries hold: no datacenter-scale, multi-region, HA, live-
   migration, evacuation, zero-downtime-maintenance, arbitrary-compatibility,
   all-services, or seconds-bootstrap claims appear anywhere without new,
   specific, profile-scoped evidence.

Completion of P15 authorizes planning of the post-P15 programs; it does not
accept their architecture.
