# PP.6 production operations gap analysis

Status: engineering audit for PP.6 #975; not acceptance evidence or a
certification.

Baseline: protected `main` `c5197f845b81058bc769b52a0c97329211ff9454`
(2026-10-15). Profile scope is the PP.6 bounded O3K Demo/Small Edge profiles;
SQLite remains the minimal TestLab/default profile and PostgreSQL the
production-oriented persistence profile. This audit does not claim PP.5 or
PP.6 completion.

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
