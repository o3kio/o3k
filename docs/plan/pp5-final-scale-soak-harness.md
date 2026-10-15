# PP.5 final scale and soak harness plan

## Issue and intent

Implement the harness-only execution and evidence path for PP.5 S3/S10/S20 and
K-min/K-full, retaining product source SHA `3acf2976aaab3b97f69aeab689d5c73f8eb7ce5f`
and the already accepted development-foundation evidence unchanged.

## Profile and authority

- Profile: protected O3K small-edge real-host/TestLab evidence.
- Canonical domain: O3K Compute and Capacity lifecycle, Placement eligibility,
  durable operation/reconciliation evidence.
- Compatibility edge: selected Nova-compatible server lifecycle used only as
  an observation/traffic path; no new public API behavior.
- Authority: O3K owns tenant identity, placement and lifecycle. TestLab
  libvirt hosts and agents are execution providers only.
- Database: one run-owned PostgreSQL campaign identity; no shared destructive
  database and no proxy outage represented as a PostgreSQL restart.
- Execution: exact verified release bundle, isolated TestLab epoch, port range,
  domain/storage prefix and evidence root per run. Runs serialize by default.

## Files expected to change

- `scripts/p15-7-real-host-journey.sh` — use tier-driven host cardinality and
  release artifact installation while retaining the existing accepted lifecycle
  checks.
- `scripts/bootstrap-disposable-testlab.sh` — opt-in, verified release bundle
  installation; existing source-build behavior remains for other lanes.
- `scripts/pp5_scale_tier.sh`, `scripts/pp5_soak.sh`, and a small shared Python
  evidence-contract module — tier guards, soak orchestration, samples and
  source/release binding.
- `scripts/validate_pp5_evidence.py` and its tests — bind tier rows to raw
  artifacts and reject missing/failed/inconsistent evidence.
- `.github/workflows/real-host-validation.yml` — canonical protected validation workflow; scale/soak entrypoints remain disabled until the complete lifecycle and evidence producer is integrated
  entry points pinned to explicit candidate and artifact identities.
- `tests/` — contract, workflow, shell and evidence regressions.
- `docs/plan/` — this implementation plan and operator contract updates.

## Contracts and operations

The harness consumes existing authenticated compute create/show/delete,
BuildingBlock join/drain/ready/remove, canonical topology/capacity, operations,
Placement and reconciliation projections. No Rust API or compatibility
contract is expanded. The evidence contract binds every result to exact source,
tree, release/tag/archive, SBOM/provenance/signature, harness, database, run,
host set and timestamps.

## Evidence tier and tests

Required evidence tier is protected real-host scale plus uninterrupted 2-hour
and 12-hour churn. Tests must first reject incorrect eligible cardinality,
scale/duration substitutions, missing source/release/database bindings, missing
samples/restart events, cleanup leaks, foreign changes and prematurely ended
soaks. The real protected runner remains authoritative for kernel/libvirt and
duration evidence.

Resource trend analysis is fixed before any campaign. It requires at least ten
samples, groups them into five chronological buckets, and compares each
bucket's median. A leak trend is reported only when the last bucket exceeds the
first by at least the predeclared per-resource threshold and at least three of
the four bucket transitions rise. This treats a one-time allocation followed
by a stable plateau as bounded while detecting sustained growth. The thresholds
are versioned in `scripts/pp5_scale_soak_contract.py` and copied into each raw
run artifact.

No Cargo package or Rust binary is expected to change. Run focused Python/shell
and workflow tests first, then the mandatory workspace fmt, clippy and tests.

## Bounded execution handoff

- Affected Cargo packages/binaries: none. The PP.5 scripts launch the existing
  protected `o3kd`, `o3k-compute`, and `o3k-compute-bin` artifacts only.
- Expected runner symbols: the scale journey's `required_child_agent_ids`,
  `provision_vms_bounded`, `record_scale_checkpoint`, replacement/maintenance
  selection, and final evidence writer; `bootstrap-disposable-testlab.sh`'s
  binary selection; the campaign's lane dispatch and time budget; and the
  evidence validator's `validate_run_artifact`, `validate_scale_tier`, and
  `validate_soak_tier` paths.
- Tests to add first: pure contract tests for every tier cardinality and soak
  duration; identity/digest/database binding failures; missing/incorrect
  per-host samples; resource-trend decisions; soak event spacing; and final
  evidence binding of K-min to the exact S10 artifact and K-full to the exact
  S20 artifact. Then add shell/workflow dispatch tests and mocked command
  adapter tests that prove no mutation occurs before identity and capacity
  preconditions pass.
- Widen scope only if the existing real-host journey cannot prove an exact
  eligible-host cardinality, if its lifecycle stages assume a fixed five-host
  set, if the bootstrap cannot install the verified archive, or if the
  protected runner cannot own a restartable PostgreSQL process for the full
  soak. Any such widening stays in harness/workflow code; product changes
  require a separate demonstrated defect and successor candidate.
- Known boundary: local tests prove evidence parsing and fail-closed command
  selection, not nested KVM capacity, authenticated joins, release
  authenticity, PostgreSQL process restart, or elapsed soak duration. Those
  require protected real-host evidence.

## Normative constraints consulted

ADR-0162 requires staged evidence and prevents a skipped/fake gate from
becoming real-host evidence. ADR-0163 and SPEC-0024 require profile-specific,
source-bound claims and separate external dependencies. The execution-boundary
contract keeps scheduling/identity/durable state in O3K and host mutation in
bounded execution providers. The existing protected release workflow is the
authority for release identity; this PR must not change the current release
version or publish a release.

## Public reference inputs and provenance

No third-party implementation is imported or copied. Inputs are the existing
O3K test harness, public O3K APIs exercised by it, repository release manifests,
and the accepted PP.5 task contract.

## Cross-service dependencies and compensation

The campaign uses existing compute/network/capacity lifecycle and PostgreSQL
durable operations. Each campaign owns its database, TestLab epoch, ports,
domains, disk paths and evidence. Cleanup remains supported API teardown followed
by ownership-checked host cleanup; foreign resources are never deleted.

## Uncertainties and non-goals

The current runner is single-job and its external PostgreSQL mode only severs a
run-owned proxy route; it does not restart PostgreSQL. A valid soak gate must
prove an actual run-owned PostgreSQL process restart and maintain churn across
the full monotonic duration. If the protected runner cannot provide a durable
12-hour worker and an isolated restartable PostgreSQL service, the workflow
must fail closed as `ENVIRONMENT_GAP` rather than manufacture evidence.

Non-goals: product/runtime changes, release-version changes, publishing rc.25,
dispatching real S3/S10/S20/soak campaigns in this PR, changing PP.5 scale or
soak requirements, physical Fabric acceptance, or claiming PP.5 completion.
