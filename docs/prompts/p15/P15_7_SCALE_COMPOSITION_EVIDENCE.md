# P15.7 — Scale and Composition Real Evidence

Issue: #937. Fetch protected `origin/main`; verify the baseline is
21fe687c387a04f107b6e87fac04060b1c28e449 (PR #928) or a later protected merge;
do not start from stale branches or worktrees. Verify P15.0 (#930) through P15.6
(#936) are all merged. Read the umbrella issue #929 before writing code. This is
the real convergence gate for the whole P15 program.

Pre-flight: record the Required agent plan fields before any code change.

```text
Required agent plan:
- Issue: #937
- Deployment/evidence profile: protected full-profile runner; real o3kd +
  production composition router + real auth + PostgreSQL with SQLite parity +
  REAL execution boundary
- Canonical service/domain: end-to-end Cloud Kernel convergence
- OpenStack compatibility adapter: Keystone projection convergence checked
  against the same canonical truth
- Authority mode: o3k-implemented end to end; execution boundary real (no
  fake provider)
- Files expected to change: tests/ evidence harnesses, runner configuration,
  docs/evidence entries; no architecture changes
- Contracts/specs affected: ADR-0184, SPEC-0047 evidence clauses
- Provenance: ADR-0184, SPEC-0047, p15-e2d-gap-register.md, repository
  evidence conventions
- Operations/actions/resources: the full journey below, each step a durable
  canonical operation
- Database assumptions: PostgreSQL primary for the gate, SQLite parity
  demonstrated for the same journey
- Cross-service dependencies/compensation: every cross-service mutation shows
  compensation/unknown-outcome handling per SPEC-0021
- Evidence tier: full real-host gate on the protected runner
- Tests first: journey steps already covered by P15.1-P15.6; this slice wires
  them into one protected-runner gate
- Known uncertainties: runner capacity for multiple real execution hosts;
  record actual limits in the defect ledger instead of hiding them
- Explicit non-goals: proving arbitrary datacenter scale or the final scale
  ceiling; re-opening P15.1-P15.6 architecture
```

This phase is authorized under Accepted ADR-0184/SPEC-0047 once its listed
dependency phases are merged and its review passes per REVIEW_AND_MERGE.md;
the PR must record the authorization line with its actual state.

## Objective

Run the real convergence gate on the protected runner — real `o3kd` +
production composition router + real auth + PostgreSQL + SQLite parity + REAL
execution boundary — proving the full journey: fresh deployment → initialize
Cloud Kernel → select CloudProfile → enroll multiple real execution
hosts/blocks → canonical topology appears → ResourceProvider capacity appears →
create workload → enforce topology/capability placement → add Building Block →
capacity expands without replatforming → drain a block → new allocations avoid
it (blockers honest) → remove/rejoin/replace → restart control plane → restart
PostgreSQL where appropriate → canonical IDs/topology/profile survive → native
API authoritative → OpenStack projection convergent. Araf is an optional
external consumer: when configured, the journey may record separate
reachability/projection observations, but Araf is never a TestLab, readiness,
or mandatory P15.7 dependency.

## Authoritative dependencies

Read before editing: ADR-0184 (Accepted), SPEC-0047 (Accepted),
`docs/architecture/p15-e2d-gap-register.md`,
`docs/architecture/p15-0-post-araf-current-state-audit.md`. Mandatory per
AGENTS.md: `README.md`, `docs/PROJECT_CHARTER.md`, `docs/CLEAN_IMPLEMENTATION.md`,
`docs/ARCHITECTURE.md`, `docs/NORMATIVE_SOURCES.md`, `docs/TEST_STRATEGY.md`,
ADR-0165/0166/0167/0160/0162/0163, SPEC-0020/0021/0022/0024/0025,
`compatibility/product-profiles.yaml`, `contracts/execution-boundaries.md`,
`contracts/core-architecture-boundaries.toml`.

## Architecture boundaries and guardrails

Guardrails are normative:

- The protected full-profile runner is a final verifier, not requirements
  discovery: every step must already be covered by P15.1-P15.6 tests.
- Do not modify the runner to hide a missing contract or portable test.
- Fake/skipped/ready/repository-only results are not real-host evidence.
- #928's fake-provider gate is not evidence here: this gate uses a REAL
  execution boundary.

## In scope

- The protected-runner gate executing the full journey above end to end.
- Honest blocker exposure at every step (drain blockers, enrollment failures,
  reconciliation drift).
- `owned_leaks` accounting and a defect ledger per repository convention.
- Restart/failure matrix: control-plane restart, PostgreSQL restart where
  appropriate, execution-host disconnect/rejoin.
- Evidence artifacts recorded under `docs/evidence/` per repository
  convention.

## Out of scope

- Architecture changes to P15.1-P15.6 (failures feed issues, not silent
  redesign).
- New compatibility endpoints or claims.
- Scale-ceiling or performance claims (P18 owns measurements).

## Authority model

End-to-end `o3k-implemented` authority with a REAL execution boundary.
Canonical IDs, topology, profile, and allocations remain O3K-authoritative
throughout; the OpenStack projection consumes the same truth. Araf is an
optional external consumer and is not part of O3K authority or this gate's
mandatory completion criteria.

## Security requirements

Real auth throughout; no disabled auth, no test-only trust bypasses in the
gate. Cross-tenant concealment checks included in the journey. No secrets in
evidence artifacts (redact tokens, certificates material, connection info).

## Database implications

PostgreSQL is the primary gate database; the same journey demonstrates SQLite
parity. Canonical IDs/topology/profile survive control-plane restart and
PostgreSQL restart where appropriate.

## OpenStack compatibility implications

The Keystone projection must be convergent with canonical truth at the end of
the journey. Compatibility checks use existing profile records only; no new
advertised surface.

## Araf implications

Araf may consume the same canonical truth (topology, services, building blocks)
when an endpoint is explicitly provided. Record optional Araf evidence when it
is available; an absent or unavailable endpoint is `not_configured` or
`unavailable`, never a P15.7 blocker.

## Failure and restart behavior

The restart/failure matrix is part of the gate: control-plane restart,
PostgreSQL restart where appropriate, execution-host loss and rejoin. Each must
preserve canonical IDs, topology, profile, and allocations, and must resume or
compensate in-flight operations honestly.

## Idempotency and concurrency requirements

The journey exercises retried and concurrent operations (enrollment, workload
creation, allocation) and shows deterministic identity converging without
duplicates.

## Required tests

All P15.1-P15.6 suites green, plus the wired protected-runner gate. Journey
regressions become part of the standard evidence set.

## Required real-process evidence

The protected-runner gate itself: real `o3kd`, production composition router,
real auth, PostgreSQL + SQLite parity, REAL execution boundary, multiple real
execution hosts/blocks enrolled, full journey executed, restart/failure matrix
executed, `owned_leaks` and defect ledger published, artifacts under
`docs/evidence/`.

## Claim limitations

This gate proves the building-block architecture converges end to end. It does
NOT prove arbitrary datacenter scale or the final scale ceiling. #928's
fake-provider gate is not evidence here. Do not upgrade any release,
deployment, or compatibility claim beyond this evidence tier.

## Validation ladder

Package-level checks were satisfied by P15.1-P15.6; this slice additionally
runs the protected full-profile runner gate. Before completion run
`cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test --workspace --all-features`, plus
`scripts/check-architecture-boundaries.py`,
`scripts/check-maintainability-guards.py`, and any contracts validators the
evidence harness touches.

## Acceptance criteria

Issue #937 acceptance criteria met; full journey green on the protected runner
with a real execution boundary; blockers and defects honestly exposed; claims
limited to what this gate proves.

## Completion

```text
Full journey green on protected runner: PASS
REAL execution boundary used (no fake provider): CONFIRMED
PostgreSQL + SQLite parity demonstrated: PASS
Restart/failure matrix executed: PASS
Canonical IDs/topology/profile survive restarts: PASS
Native API authoritative + OpenStack projection convergent: PASS
Araf optional observation: NOT APPLICABLE unless explicitly configured
owned_leaks + defect ledger published: YES
No scale-ceiling claims made: CONFIRMED
P15.7 implementation authorized: YES under Accepted ADR-0184, contingent on listed dependencies merged (verify per Execution prerequisites)
Required CI/governance: PASS
Exact HEAD reviewed: YES
```
