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
