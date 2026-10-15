# PP.6 production operations gap analysis

Status: engineering audit for PP.6 #975; not acceptance evidence or a
certification.

Baseline: protected `main` `0712245ec372616d5c039bcf3dc989341db5f397`
(2026-10-16). Profile scope is the PP.6 bounded O3K Demo/Small Edge profiles;
SQLite remains the minimal TestLab/default profile and PostgreSQL the
production-oriented persistence profile. This audit does not claim PP.5 or
PP.6 completion.

## Dated implementation status

Status recorded 2026-10-16 against protected `main`
`0712245ec372616d5c039bcf3dc989341db5f397`:

- The decision packet is open as [PR #1091](https://github.com/o3kio/o3k/pull/1091)
  at `2c307ebddc59534fce4b59046497f97816c53b86`. ADR-0189 and SPEC-0050
  remain proposals pending explicit human architecture/security acceptance;
  the PR does not authorize production backup/restore or PKI implementation.
  All seven protected checks are successful at this exact head; GitHub review
  and approval remain absent, and there is no merge.
- The SQLite lock-cancellation slice is open as [PR #1092](https://github.com/o3kio/o3k/pull/1092)
  at `84a12abc69ecd189dda84ca18b5797e6fa87d64f`. Its focused test passes
  locally; exact-head independent review is clean, all seven protected checks
  are successful, but GitHub approval is absent and there is no merge. It is
  evidence for one SQLite lock/busy cancellation/retry case, not the complete
  #1089 matrix.
- The diagnostics projection slice is open as [PR #1093](https://github.com/o3kio/o3k/pull/1093)
  at current head `ff14561d57e10378a943d54d6e77e7d56f278b74`. The prior head
  `d46ab58517a543d29309de8546597081d2898400` failed protected Clippy; this
  head contains the targeted fix without changing the reviewed product
  behavior. One protected check is in progress and six have completed
  successfully; GitHub review/approval is absent, and exact-head review
  remains pending. Local evidence covers SQLite and
  PostgreSQL 16.15. The HIGH raw-error leakage and MEDIUM unbounded
  active-lease findings apply to the older reviewed head
  `22c3dc5983f480580789be8c9e5840c8d2a43c5b` and are not asserted against
  this current head.
- The combined readiness-diagnostics slice is open as [PR #1096](https://github.com/o3kio/o3k/pull/1096)
  at `b73c19ac8d0826656b81dad85fa70d1146ee7100`. It validates combined
  control-plane `healthz`/`readyz` and compute-agent `readyz` JSON. Exact-head
  review is clean, all seven protected checks are successful, and GitHub
  approval remains pending.
- The operator runbook slice is open as [PR #1097](https://github.com/o3kio/o3k/pull/1097)
  at `48c6b2dde1d4342ca51d891e6b3df782680cd162`. Independent review is
  clean; all seven protected checks are successful and GitHub review/approval
  is absent.
- #1084, #1085, #1086 and #1087 remain open and blocked on explicit human
  acceptance of the proposed backup/restore and trust-recovery decisions.
  #1089 remains open. Its second SQLite unavailable-store slice is [PR #1095](https://github.com/o3kio/o3k/pull/1095)
  at `00588e3901deef520408631ced1c1a203e631ff0`; independent review is
  clean at the exact head, all seven protected checks are successful, and
  there is no GitHub approval or merge.
  #1095 covers only the missing-parent fail-closed path; its local tests and
  checks pass and it does not complete the #1089 matrix. The #1089
  unknown-outcome test was withheld after independent HIGH findings and remains
  a gap while a stronger mTLS/file-backed case is developed. The pressure audit
  found no defensible canonical `SQLITE_FULL` test because the write fit in
  allocated pages; forcing growth would require filler-table injection, so it
  provides no PR or evidence claim. An audit of #640 found no safe independent
  PP.6.4 implementation slice.
- The separate file-backed SQLite store/adapter reopen regression is open as
  [PR #1099](https://github.com/o3kio/o3k/pull/1099) at current head
  `daf144e4aee50531949d3d9fae6c4d7d78a18bc9`, which fixes the teardown
  finding. It exercises the existing production mTLS unknown-outcome path with
  two targeted tests; local targeted test, package Clippy, formatting and diff
  checks pass. Exact-head independent review is clean; protected CI has
  started, with installer-negative, OCI identity smoke and Tempest passing,
  while Rust, Mock Cinder, araf convergence and supply-chain remain in
  progress. The PostgreSQL-selected test remains retained but was not run
  locally because `O3K_DATABASE_URL` was absent.
- The scoped test-support/API replay evidence is open as [PR #1100](https://github.com/o3kio/o3k/pull/1100)
  at `4449368c90e1c8b7731fb87f25611cde9fe24d55` (tree
  `360acbdb192549eb2541642a724ae637201728af`). Its two-file change has local
  targeted-test, Clippy, formatting and diff-check validation; at that exact
  head protected CI is pending/in progress, exact-head independent review is
  clean, and GitHub review/approval is absent.
- The targeted diagnostics remediation is open as [PR #1101](https://github.com/o3kio/o3k/pull/1101)
  at `509d1ef009380b5877b5eb7b24888955a35b72ad`. Its package test, Clippy
  and formatting checks pass locally; exact-head independent review is clean,
  all seven protected CI checks are successful, and GitHub review/approval
  remains absent.
- The bounded support-bundle contract proposal is open as [PR #1102](https://github.com/o3kio/o3k/pull/1102)
  at `d7d33655c2c899a8bae66f79c1ff6fa6d86243c7`. It adds Proposed SPEC-0051
  and its schema without runtime implementation; protected CI is mixed
  (one check in progress and six successful), and GitHub review/approval is
  absent.
- The PostgreSQL outage/reconnect evidence slice is open as [PR #1103](https://github.com/o3kio/o3k/pull/1103)
  at current head `100928c03b63c3882c13f3067131f089a8a5183c`. The prior head
  `14e93d45eba4912fafdb3a0a2080e60f42ee7cc5` failed its required PostgreSQL
  outage lane with `ConnectionReset`. The fix has all seven protected checks
  queued, including the real PostgreSQL lane; local formatting, package check,
  targeted Clippy, YAML parse and diff checks pass. Docker port mapping still
  prevents the local PostgreSQL lane, so local evidence is not PASS. Exact-head
  independent review is clean. Protected CI has Rust, Mock Cinder and
  supply-chain in progress; installer-negative has passed; araf convergence,
  OCI identity smoke and Tempest are queued. GitHub review/approval is absent.
- PP.6.4 child issue [#1098](https://github.com/o3kio/o3k/issues/1098) is open
  under parent #975. Implementation is gated on accepted ADR-0189/SPEC-0050
  and dependent #1084–#1086; #640 remains its rollback/crash-recovery authority.
- PP.5 remains acceptance-pending with its deferred campaigns unchanged, and
  PP.7 remains unauthorized.

## Summary

PP.6 can proceed while the S3/S10/S20, K-min/K-full, and physical-deployment
PP.5 acceptance campaigns remain deferred. The PP.5 gates remain mandatory.
Several requested components already exist and should be extended at their
current authority boundaries: store-level SQLite snapshots, upgrade rollback,
native operator diagnostics, bootstrap enrollment, durable Operations, and
Placement/topology/BuildingBlock repositories. None of those components alone
provides complete control-plane backup/restore, full PKI lifecycle, or an
operator support bundle.

The first decision boundary is PP.6.1: accepted sources establish the need for
profile-scoped backup/restore, SQLite/PostgreSQL distinction, and external
state limits, but do not establish artifact authentication/encryption, fresh
host restore, controller fencing/lease treatment, or crash-safe restore
semantics. The design PR proposes those missing details. Production code and a
new CLI/API are out of scope until human architecture/security review accepts
the proposal.

## Workstream audit

| Workstream | Existing code and evidence | Gap / needed decision | Store/security boundary | Dependencies and independence |
| --- | --- | --- | --- | --- |
| 1. Control-plane backup/restore | Upgrade backup and rollback in `bins/o3k/src/upgrade/{backup.rs,engine.rs,runner.rs,state.rs}`; store snapshot API and tests in `crates/o3k-store/src/sqlite/core.rs` and `crates/o3k-store/src/tests.rs`; canonical repositories under `crates/o3k-store/src/{sqlite,postgres}/`; bootstrap state in `bins/o3kd/src/native_adapters/bootstrap.rs`. Upgrade runner performs SQLite WAL checkpoint, `VACUUM INTO`, nonempty/`quick_check` verification, then copies config, release metadata, and prior binaries. Store has tested `backup_to_file`. | No production Postgres backup/restore workflow; upgrade backup is local rollback support, not portable recovery. No versioned whole-artifact contract, fresh-host restore, whole-artifact authenticity/encryption, cross-file consistent cut, restore fencing/lease protocol, interrupted restore protocol, or foreign-target preflight. Need human-reviewed ADR/SPEC/manifest contract. | SQLite snapshot is database-consistent through SQLite mechanisms, but copying live config alongside it does not guarantee a common cut. PostgreSQL needs a database-native consistent dump (SPEC-0024 names `pg_dump`/`psql`); it also needs restore/version/role checks. Neither permits raw live DB-file copying. Sensitive bootstrap/PKI/config state needs explicit protected handling. Provider VM/storage bytes are excluded. | First and blocking PP.6 workstream; independent of deferred PP.5 campaigns. SQLite, Postgres, secrets, and restore-fencing implementation should be separate PRs after design approval. |
| 2. PKI lifecycle | mTLS, certificate-bound agent identity, bootstrap enrollment, and certificate validation exist in `crates/o3k-compute-agent`, `crates/o3k-service-sdk`, and `bins/o3kd/src/native_adapters/bootstrap.rs`; `contracts/execution-boundaries.md` binds cert identity to agent identity. SPEC-0015 has a certificate-rotation RPC contract. | The implemented join/handshake path does not establish PP-profile issuance renewal, overlapping trust rotation, revocation, compromised/replaced-host rejection, or recovery journey. Need define issuer/private-key custody, revocation source, grace/overlap, re-enrollment, and relationship to restore. | Durable enrollment state is in the selected store; private host keys remain host-local. SQLite/Postgres semantics should match at store API level; PostgreSQL backup consistency and controller coordination still matter. Never export agent private keys. CA/issuer recovery is security-sensitive and requires explicit key-custody approval. | Restore semantics must be approved first for trust/enrollment state. Rotation and revocation journeys can then be implemented independently of metrics and pressure work. |
| 3. Observability/diagnostics | Accepted diagnostics contract `contracts/native-diagnostics-v1.schema.json`, SPEC-0045, API in `crates/o3k-native-api/src/diagnostics.rs`, adapter in `bins/o3kd/src/native_adapters/diagnostics.rs`, and operator diagnostics tests/evidence draft `docs/evidence/ISSUE_903_OPERATOR_DIAGNOSTICS.md`. `o3k doctor` is read-only. Structured tracing and request/operation identity already exist in relevant paths. | No complete PP.6 support bundle or full metric surface for `o3kd`; ADR-0182 records no declared `/metrics`/OTLP and incomplete reconciliation/lease/DB/service observability. Need surface backup/restore/upgrade/PKI states and safe failure correlation through existing projections, plus a bounded redacted bundle. Do not create a second health authority. | SQLite/Postgres health details differ and must be labelled by backend; connection strings/secrets never appear. Diagnostics are a projection and cannot mutate or remediate canonical state. | Existing health/diagnostics foundation is reusable. Status fields that depend on backup/PKI contracts follow those contracts; basic support bundle design can proceed in parallel after its own data/redaction review. |
| 4. Upgrade, rollback, crash recovery | Existing bounded engine has persisted phases, lock/fencing, restart resume from durable phase, release compatibility fences, rollback chain, atomic 0600 state writes, file hashes, SQLite integrity checks, doctor/API checks. Coverage is in `bins/o3k/src/upgrade/*`, `docs/plan/o3k-upgrade.md`, and upgrade unit/process tests. It safely observes service state after timeout. | No arbitrary downgrade; no PostgreSQL upgrade/rollback path; no PP.6 cross-host backup/restore; no guarantee for a fresh-host rebuild or active leases. #640 remains the generalized rollback/backup/crash-resume issue and explicitly requires separate SQLite/Postgres semantics. Need document the boundary and test bounded restart phases from exact PP artifacts. | Existing upgrade machinery assumes local SQLite and host-local state. PostgreSQL migrations/transaction behavior are distinct; do not extend SQLite rollback primitives by assumption. Migration compatibility remains fail-closed. | Reuse; do not replace the engine. Clarify its boundary in design/runbook. PP.6.1 restore semantics must precede upgrade interaction tests; affordable failure tests can proceed separately. |
| 5. Resource pressure/operator error | Existing quota limits, bounded APIs/diagnostics, Placement capacity checks, upgrade disk preflight/lock, store outage handling, and durable/idempotent Operations provide useful local protections. Existing store and process suites cover selected concurrency, outage, and unknown-outcome cases. | No joined PP.6 acceptance matrix for nearly/full disk, DB full/unavailable, memory/FD pressure, corrupt/malformed config/profile, bad/repeated operator commands, backup destination failure, or zero-unowned-mutation under interrupted recovery. Need select bounded injections and expected canonical state outcomes. | SQLite has file/WAL/lock/disk-full failure modes; PostgreSQL has WAL/connection/transaction/role/disk failures. Run distinct real backend tests. Never count missing PostgreSQL infrastructure as pass. | Can proceed as disposable acceptance tests once backup protocol is specified; does not need new scheduling/lifecycle authority. Restore/upgrade crash tests consume workstream 1 and 4 decisions. |
| 6. Documentation/supportability | #944 is the documentation authority; existing `docs/INSTALLER.md`, `docs/plan/o3k-upgrade.md`, PP sequence, SPEC-0045 diagnostics, product profile/SPEC-0024, and evidence schemas cover portions. | No evidenced PP.6 operator runbook covering supported backup modes, restore preconditions, key recovery, PKI replacement, interrupted recovery, safe diagnostics, limitations, and when external workload state must be restored separately. Docs must follow accepted contracts and observed implementation. | Document backend-specific preconditions, especially SQLite filesystem/WAL and PostgreSQL tool/version/role behavior. Redact command output and examples. | User/support docs should follow accepted behavior and implementation evidence. No separate documentation truth system; update #944 outputs. |

## Existing authority coverage and uncovered design

- ADR-0163 and SPEC-0024 define deployment claims and persistence profiles.
  SPEC-0024 §Database profiles requires SQLite checkpoint/filesystem backup
  requirements and identifies `pg_dump`/`psql` for PostgreSQL; it explicitly
  excludes automatic SQLite-to-PostgreSQL migration.
- ADR-0182 E2D-12 requires tested control-plane backup/restore including
  credentials/PKI/config and external-dependency boundaries. It explicitly
  separates tenant workload backup/DR.
- ADR-0167 requires PostgreSQL and durable work ownership/fencing before an HA
  claim; Kubernetes or pod-local files are not canonical state.
- SPEC-0008 defines operation intent and observe-before-retry after process
  restart, but not backup/restore or stale lease treatment after restoring a
  database to another host.
- SPEC-0015 describes certificate identity and a rotation RPC contract;
  SPEC-0047 §P15.6 limits current enrollment to join/re-issuance and leaves
  fleet rotation/renewal/revocation/recovery open.
- SPEC-0045 covers the bounded native diagnostics API and authorization. Its
  projection is not a metrics, backup, PKI, or support-bundle contract.
- #640 owns generalized rollback and crash resume; `docs/plan/o3k-upgrade.md`
  and current `bins/o3k` code implement bounded local SQLite upgrade rollback.
- #944 owns documentation architecture and operator docs; it is not a new
  operational authority.

The missing PP.6.1 contract is therefore a profile-scoped artifact plus a
restore/recovery protocol, including security-sensitive issuer/secret custody,
controller identity and fencing behavior, target-state preflight, and
cross-resource consistency. These decisions cannot be inferred from existing
upgrade rollback code.

## Prioritized PR sequence

| Order | PR-sized unit | Depends on | Implementation boundary |
| --- | --- | --- | --- |
| 0 | Governance sequence and status vocabulary (PR #1082) | None | Documentation only; no acceptance requirements changed. |
| 1 | PP.6.1 architecture/SPEC/manifest contract proposal | Accepted profile, ADR-0167, ADR-0182, SPEC-0024, #640, SPEC-0008 | Human architecture/security review required; no production code. |
| 2 | Backup manifest validation and SQLite artifact publication | Order 1 approval | No CLI/API; use store-consistent snapshot; atomic staging/publication, verify/incomplete/corrupt/mismatch/retry cases. |
| 3 | PostgreSQL backup/restore adapter | Order 1 approval; existing store/migration readiness | Real isolated PostgreSQL 16; hard failure if unavailable; no silent skip. |
| 4 | Fresh-host restore, fencing and reconciliation | Order 1 approval; orders 2 and 3 | Disposable host/store only; prove safe activation, no unowned mutations, crash/restart boundaries. |
| 5 | PKI renewal/rotation/revocation/re-enrollment | Order 1 trust/key-custody decision | No private key export; restore/re-enrollment trust journey. |
| 6 | Diagnostics/support evidence extension | Existing SPEC-0045; orders 1 and 5 for related status | Extend existing projection and redaction coverage; no new readiness authority. |
| 7 | Resource pressure/operator error matrix | Orders 2–4 for backup/restore failures | Disposable SQLite/PostgreSQL; no change to scheduler/lifecycle authority. |
| 8 | PP.6 operator/support docs and claim evidence | Implemented, tested behavior from 2–7 | Feed into #944 and profile/evidence records; documentation follows evidence. |

Workstreams 2–8 above are independently reviewable PRs and do not authorize PP.7.
The order is a dependency order for implementation, not permission to claim a
completed phase.

## PP.6.1 executable evidence plan

Each test result must bind source SHA, test/harness identity, database backend
and exact server version, migration set, deployment profile, artifact digest,
and fixture/host identity. Test output and support artifacts must pass secret
scanning. Use disposable data and host paths; no deferred scale/soak or
physical multi-host campaign is required or authorized here.

Required regression gates:

1. SQLite: live writes with WAL enabled; checkpoint plus supported snapshot;
   restore to a fresh temporary host/data directory; compare canonical resource,
   Operation, Placement, topology, BuildingBlock, IAM/bootstrap identities and
   selected audit state; restart/reconcile and prove no unowned provider mutation.
2. PostgreSQL: isolated real PostgreSQL 16 instance; `pg_dump` to a new target
   database and restore with supported `psql`/restore tooling while a concurrent
   writer proves one database-consistent cut. Missing DB must fail the required
   lane, never pass as skipped.
3. Backup crash points: before snapshot, during DB export, during manifest,
   before final publish, and after publish/before success response. Incomplete
   artifacts are never selected as committed; retry is idempotent.
4. Restore crash points: preflight, target staging, DB restore, files/secret
   unwrap, fencing/lease transition, first startup, and reconciliation. Re-run
   yields a safe terminal state or explicit operator action; no blind provider
   mutation.
5. Reject corrupt/tampered/truncated archives, missing content, invalid
   signature/encryption metadata, wrong installation/profile/backend, unknown
   format, schema/migration mismatch, unsupported O3K version, and nonempty or
   foreign target state before destructive mutation.
6. Secret-safe output: scan logs, CLI JSON, doctor output, bundle metadata and
   evidence for tokens, private keys, credentials, DB URLs, and provider payloads.
7. Foreign state: seed unrelated databases, files, services, libvirt guests,
   storage and network objects; restore must preserve them byte-for-byte and
   report zero unowned mutations.
8. Reconciliation: prove restored Operation identities and state, placement
   allocations, topology and BuildingBlocks survive; prove pre-restore lease
   ownership cannot authorize stale controllers; observe before any provider
   retry after an unknown outcome.

No PostgreSQL lane is PASS when PostgreSQL was unavailable. A skipped lane is
`ACCEPTANCE_PENDING`.
