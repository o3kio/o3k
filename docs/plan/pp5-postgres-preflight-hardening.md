# PP.5 PostgreSQL preflight hardening

Issue: #1037, reproducible Small Edge TestLab prerequisites. This is a bounded
harness fix following the missing PostgreSQL runner configuration, not a new
product feature or a production-readiness claim.

Profile: small-edge-cloud, source-built non-certifying development evidence.
Authority: O3K Cloud Kernel (`o3k-implemented`); PostgreSQL is external shared
infrastructure. No OpenStack adapter, public action/resource, domain, migration,
Cargo package, binary, or execution protocol changes.

Consulted: README, Charter, Clean Implementation, Architecture, normative source
map, Test Strategy; ADR-0160/0162/0163/0165/0166/0167;
SPEC-0020/0021/0022/0024/0025; product profiles; execution and core-boundary
contracts; #1037. Constraints: staged validation, explicit ownership, redacted
errors, no foreign mutation, no claims beyond source/profile-bound evidence.
ADR-0162 is proposed, not an additional accepted architecture decision.

Files/symbols: `scripts/provision_pp5_postgres.py` (preflight, psql invocation,
run-name validation), protected real-host workflow (early prerequisite gate),
portable CI and negative tests. No new dependencies. Inputs are this repository
at da9623c95b006786a24d9320df7672bba37471ee and the observed runner failure;
no external or Go implementation inputs.

Tests first: missing tools/account/connection, timeout, insufficient privileges,
non-loopback/invalid URL, unsafe/oversized identifiers, existing run resources,
secret-bearing subprocess diagnostics, SQL/credentials absent from argv,
read-only SQL and workflow ordering. These can falsify the fix without creating
databases, starting daemons, or touching active campaign resources.

Preflight records incremental atomic, redacted, run/source-bound evidence.
Every invocation retains a separate artifact; later successful probes cannot
erase failed attempts. The workflow uploads them even when preflight fails.
Provisioning repeats it: an early pass is not a reservation or proof of later
availability. The existing four purpose-specific databases and ownership cleanup
remain mandatory; a successful preflight cannot certify S5.

Uncertainties: local peer access does not prove the subsequently created role's
TCP login; provision/sentinel verification proves that separately. Infrastructure
may change after preflight. Interrupted SQL mutation has unknown outcome and must
use the existing ownership ledger, never blind retries.

Non-goals: redesign accepted restart/auth evidence, weaken destructive guards,
change PostgreSQL service configuration, push the active PR, launch privileged
campaigns, merge, release, certify production or introduce scale/soak. This
isolated worktree must be reviewed/integrated and rerun on its new exact SHA.
Widen scope only on an executable failure demonstrating another boundary defect.

## Verification and integration boundary

Portable negative tests, database-purpose guards, campaign-ownership guards,
real-host workflow guards, YAML parsing, shell syntax and `cargo fmt --all --
--check` pass. A live local PostgreSQL smoke test provisioned four independent
`side_preflight_20260926_02` databases and a dedicated role, verified all four
sentinels plus the P13 purpose guard, then removed only those test resources.
The read-only probe separately passed on the current host. No server settings,
active campaign state or parent checkout were changed.

The smoke test also falsified an initial credential transport implementation:
`PGDATABASE` does not accept the connection URI here. The corrected invocation
uses explicit libpq environment fields; a real TCP login with the newly created
role verified the correction. SQL is sent through stdin, never argv.

This patch does not certify PostgreSQL/P13 product suites or S5. Full workspace
clippy/tests, independent review, exact-head CI/approval and campaign evidence
remain integration gates. No Rust source changed, and expensive workspace tests
were not launched alongside the parent's active acceptance work.

## Reconciliation with PP.5 foundation

The review baseline is the current #1046 foundation head, not the parent of
efe63712. The integrated delta preserves the foundation's protected restart
environment guard and its four-purpose authority. It adds deterministic
run-owned role validation, PostgreSQL role-length validation, `statement_timeout`
and `lock_timeout`, a temporary mode-0600 `PGPASSFILE`, and removal of
credential-bearing connection variables from child-process environments. SQL
continues to be supplied on stdin and subprocess failures remain redacted.

`scripts/pp5-fast-gate.sh` is the canonical repository-owned entrypoint for
manual and workflow PostgreSQL prerequisite phases. Its preflight phase is
deliberately before TestLab mutation; provisioning, verification, and cleanup
delegate to the same purpose-map authority. Project/operator authentication
and P13 provider tests remain later phases because they depend on the
bootstrapped TestLab and built provider surface; the workflow records those
dependencies rather than pretending they are pre-bootstrap checks.
