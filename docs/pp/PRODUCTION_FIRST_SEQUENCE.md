# Production-first sequencing

Status: Accepted program sequencing

## Goal

O3K must reach a stable, evidence-backed production-readiness baseline before the project resumes dashboard integration and enhancement breadth.

The Production Phase (PP) therefore certifies **O3K Core only**.

Araf remains the intended native next-generation O3K dashboard, but it is a separately versioned client and is not an O3K readiness, cloud-state, IAM, topology, Placement, or resource authority.

## Sequence

```text
PP.4 Core
  -> native lifecycle + real KVM
  -> bounded OpenStack CLI/Horizon witness

PP.5
  -> 3-20 host lifecycle/failure/soak hardening

PP.6
  -> backup/restore
  -> PKI lifecycle
  -> observability/diagnostics
  -> upgrade/recovery

PP.7
  -> final O3K Core production-readiness verdict
  -> freeze stable release/API/profile/support boundary

POST-PP
  -> Araf native compatibility/certification (#1029 / o3kio/araf#128)
  -> Araf HA/failure certification (o3kio/araf#106)
  -> Araf live upgrade/rollback (o3kio/araf#113)
  -> dashboard/UX/service enhancements
```

## Accepted PP execution strategy

The current execution order is:

1. Finish affordable PP.5 engineering and correctness validation against the
existing PP.5 requirements and technical thresholds.
2. Defer the expensive S3/S10/S20 scale, K-min/K-full endurance, and physical
deployment acceptance campaigns for cost and infrastructure reasons. These
campaigns remain mandatory PP.5 acceptance gates; this deferral is neither a
passing result nor a waiver.
3. Proceed with PP.6 engineering and affordable validation independently of
the deferred PP.5 acceptance work. PP.6 must not weaken, remove, or reinterpret
PP.5 requirements, and PP.6 progress does not close PP.5.
4. Begin PP.7 final certification only after all mandatory PP.5 and PP.6
evidence exists and has passed its applicable review and acceptance gates.

PP.5 remains open while any mandatory acceptance gate is unexecuted or
unaccepted. PP.7 final certification is not yet authorized. This sequencing
does not authorize release publication, a stable-release claim, or production
certification.

## Phase status vocabulary

These status values apply to their stated phase, workstream, activity, or
acceptance gate. They have distinct meanings:

- `ENGINEERING_COMPLETE`: scoped implementation and affordable engineering
  validation are complete for the recorded scope. This does not certify the
  phase or pass unrun acceptance gates.
- `DEFERRED_BY_POLICY`: an identified activity is postponed by cost,
  infrastructure, or program policy. It remains a required acceptance activity
  unless an accepted authority changes that requirement. Deferral is not PASS
  and is not a waiver.
- `ACCEPTANCE_PENDING`: required evidence, execution, or review remains
  outstanding. The associated phase remains open.
- `CERTIFIED`: every mandatory gate for the declared profile has passed, the
  source-bound evidence is recorded and reviewable, and the applicable
  acceptance authority has accepted certification.

The values are not interchangeable. `ENGINEERING_COMPLETE` and
`DEFERRED_BY_POLICY` do not mean `CERTIFIED`; `DEFERRED_BY_POLICY` is never a
passing acceptance result.

## Current PP sequencing state

| Phase | Current interpretation |
| --- | --- |
| PP.5 | Affordable engineering and correctness validation continue. S3/S10/S20, K-min/K-full, and physical-deployment acceptance are `DEFERRED_BY_POLICY`; those gates remain `ACCEPTANCE_PENDING`, and PP.5 remains open. |
| PP.6 | Engineering may proceed independently of PP.5's deferred acceptance. Workstream status is scoped; PP.6 is not certified until all mandatory gates pass. |
| PP.7 | `ACCEPTANCE_PENDING` and not yet authorized. Final certification requires all mandatory PP.5 and PP.6 evidence. |

The PP.5 execution plan remains authoritative for its test matrix, technical
thresholds, and acceptance requirements. This governance update changes none
of them.

## Stable O3K handoff

PP.7 must produce one exact integration baseline:

- stable O3K version/tag;
- exact source SHA;
- public release assets;
- SBOM/provenance/signature evidence;
- supported OS matrix;
- supported small-edge profile;
- native API contract/version;
- bounded OpenStack compatibility contract;
- IAM/auth contract;
- upgrade/support boundary;
- known limitations.

Post-stable clients must consume that published baseline rather than development branches.

## Horizon and Araf

Horizon is an external OpenStack compatibility witness only.

Araf is the product dashboard, but its certification starts after the O3K stable-core freeze.

Neither client contributes to O3K `Ready`.

## Change discipline

After PP.7:

- routine Araf changes must not require a new O3K release;
- genuine O3K defects found during Araf integration are fixed through normal stable maintenance releases;
- Araf must not redefine stable O3K authority or contracts locally;
- enhancements may not weaken production-readiness evidence.

## Principle

> Production readiness first. Stable integration target second. Enhancements third.
