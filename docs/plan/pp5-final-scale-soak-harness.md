# PP.5 final scale and soak harness plan

## Issue and intent

This PR completes the fail-closed scale/soak evidence contract and policy guards
for PP.5 S3/S10/S20 and K-min/K-full while retaining product source SHA
`3acf2976aaab3b97f69aeab689d5c73f8eb7ce5f` and the already accepted
development-foundation evidence unchanged. The scale/soak lanes are
`DEFERRED_BY_POLICY`: no campaign is dispatched, no release is published, and
no acceptance result is claimed. This deferral does not block PP.5 development
foundation work or waive the tiers from eventual final acceptance.

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

## Scope completed in this PR

- `scripts/pp5_scale_tier.sh` and `scripts/pp5_soak.sh` validate requested
  tier parameters and stop at a shared `DEFERRED_BY_POLICY` boundary before
  creating evidence or changing TestLab state.
- `scripts/p15-7-real-host-journey.sh` rejects legacy scale/soak phase requests
  at the same pre-mutation policy boundary; accepted S1/S2/S5 and foundation
  lanes retain their existing behavior.
- `scripts/pp5_scale_soak_contract.py` and `scripts/validate_pp5_evidence.py`
  retain strict identity, lifecycle, duration, resource, and evidence checks;
  every lifecycle summary and soak sample is bound to a separate,
  digest-checked, source/run/workflow/database-bound observation artifact.
- `.github/workflows/real-host-validation.yml` does not expose S3/S10/S20 or
  K-min/K-full dispatch options. No scale/soak workflow is added by this PR.
- Release verification produces a structured, exact-identity report for later
  evidence binding. This PR does not bump the release version or publish an
  artifact.
- `tests/` and `docs/` record policy deferral, fail-closed entrypoints, and
  evidence-contract regressions.

The native scale and continuous-soak producers, protected lane dispatch,
release publication, and real acceptance campaigns remain deferred work. The
eventual acceptance contract below remains required; fixtures and local checks
are parser regressions, not runtime evidence.

## Eventual contracts and operations

The harness consumes existing authenticated compute create/show/delete,
BuildingBlock join/drain/ready/remove, canonical topology/capacity, operations,
Placement and reconciliation projections. No Rust API or compatibility
contract is expanded. The evidence contract binds every result to exact source,
tree, release/tag/archive, SBOM/provenance/signature, harness, database, run,
host set and timestamps.

## Eventual evidence tier and tests

Required eventual evidence tier is protected real-host scale plus uninterrupted
2-hour and 12-hour churn. Contract tests reject incorrect eligible cardinality,
scale/duration substitutions, missing source/release/database bindings, missing
samples/restart events or sample captures, cleanup leaks, foreign changes and
prematurely ended soaks. The protected runner must retain the actual read-only
API, process, and host observations referenced by these records. Contract
fixtures do not establish those runtime facts; the real protected runner remains
authoritative for kernel/libvirt and duration evidence.

Resource trend analysis is fixed before any campaign. It requires at least ten
samples, groups them into five chronological buckets, and compares each
bucket's median. A leak trend is reported only when the last bucket exceeds the
first by at least the predeclared per-resource threshold and at least three of
the four bucket transitions rise. This treats a one-time allocation followed
by a stable plateau as bounded while detecting sustained growth. The thresholds
are versioned in `scripts/pp5_scale_soak_contract.py` and copied into each raw
run artifact.

No Cargo package or Rust binary changes in this PR. Validation covers the
contract and policy boundary only; it does not establish runtime evidence.

## Bounded execution handoff

- Affected Cargo packages/binaries: none. The deferred-only wrappers do not
  bootstrap the protected `o3kd`, `o3k-compute`, or `o3k-compute-bin` artifacts.
- Implemented entrypoints: `scripts/pp5_scale_tier.sh`,
  `scripts/pp5_soak.sh`, the shared `scripts/pp5-policy.sh` boundary, and the
  early phase guard in `scripts/p15-7-real-host-journey.sh`. The contract
  validator remains offline and cannot launch acceptance work.
- Contract regressions cover every tier cardinality and soak duration;
  identity/digest/database binding failures; missing/incorrect per-host
  samples and their separate captures; resource-trend decisions; soak event
  spacing; lifecycle observation artifact binding; and exact scale-baseline
  binding for K-min/K-full.
- Shell and workflow regressions prove the deferred policy boundary runs before
  campaign state changes. This PR deliberately does not dispatch protected
  lanes. Widen scope only if the existing real-host journey cannot prove an exact
  eligible-host cardinality, if its lifecycle stages assume a fixed five-host
  set, if the bootstrap cannot install the verified archive, or if the
  protected runner cannot own a restartable PostgreSQL process for the full
  soak. Any such widening stays in harness/workflow code; product changes
  require a separate demonstrated defect and successor candidate.
- Known boundary: local tests prove evidence parsing and fail-closed command
  selection, not nested KVM capacity, authenticated joins, release
  authenticity, PostgreSQL process restart, or elapsed soak duration. Those
  require protected real-host evidence.

The current validator checks artifact shape, campaign identity, digests, and
consistency between retained capture bytes and normalized summaries. It does
not cryptographically authenticate the observer or prove that a capture came
from a live API, process, or host. This PR supplies no scale/soak producer or
observer attestation verifier, and the lane entrypoints remain disabled by
policy. Do not treat a parser PASS over handcrafted fixtures as runtime or
acceptance evidence. Before any future scale/soak lane is enabled, its
protected producer must retain actual observer output as the input to
normalization and the certification path must verify that output's protected
workflow provenance.

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
