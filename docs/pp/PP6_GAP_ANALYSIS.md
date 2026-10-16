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
`0712245ec372616d5c039bcf3dc989341db5f397`. The following is the verified
GitHub state; every listed PR is open and unmerged, with no GitHub approval.

- Decision packet [#1091](https://github.com/o3kio/o3k/pull/1091): head
  `b8ddd03551ef2984ac70acef3fa1f5febe6236d4`, tree
  `c488afc005c37d77e659f21e92087ab1b78df51a`; independent review is clear and
  all seven protected checks pass. GitHub approval remains absent.
  ADR-0189/SPEC-0050 remain Proposed, so #1084–#1087 are blocked.
- SQLite lock/busy slice [#1092](https://github.com/o3kio/o3k/pull/1092):
  `580829150a5c0e9a2131e7967c7ca449db714aed`, tree
  `b19fb0085958ca7301ca8c5a93c7c4b41de16d03`; installer, OCI and Tempest
  checks pass, remaining protected checks are in progress. Focused local test
  and independent review pass; this is one #1089 case only.
- Authority doctor [#1093](https://github.com/o3kio/o3k/pull/1093):
  `f9c3844dfb9d4d8e9b7099a2c34f23f486016f73`, tree
  `2438fd6047c2d7c406f609a9bec910f66778f9dc`; a missing `controller_sessions`
  fixture table that caused the earlier exact-head Rust failure is fixed.
  Focused overflow and adjacent coordination-query tests pass locally; two
  independent reviews are clear. Six protected checks pass and Rust is in
  progress; GitHub approval remains absent.
- Readiness diagnostics [#1096](https://github.com/o3kio/o3k/pull/1096):
  `b73c19ac8d0826656b81dad85fa70d1146ee7100`, tree
  `1a5ebdeab8b5c6814f12b46236c5408968317331`; all protected checks pass.
- Installation/health runbook [#1097](https://github.com/o3kio/o3k/pull/1097):
  `48c6b2dde1d4342ca51d891e6b3df782680cd162`, tree
  `d9ed5872c33621d199480b628eda5a69fcce4485`; all protected checks pass and
  independent review is clean. #944 remains partial.
- Resource-pressure/operator-error parent [#1089](https://github.com/o3kio/o3k/issues/1089)
  remains partial. SQLite unavailable-store [#1095](https://github.com/o3kio/o3k/pull/1095)
  (`00588e3901deef520408631ced1c1a203e631ff0`, tree
  `d49c30d37c85f47cbeb640e09461b5e3f0f2ca4a`) has all checks passing and
  clean independent review. Replay [#1099](https://github.com/o3kio/o3k/pull/1099)
  (`daf144e4aee50531949d3d9fae6c4d7d78a18bc9`) and timeout identity
  [#1100](https://github.com/o3kio/o3k/pull/1100)
  (`4449368c90e1c8b7731fb87f25611cde9fe24d55`, tree
  `360acbdb192549eb2541642a724ae637201728af`) are narrow passing slices.
  WAL pressure [#1104](https://github.com/o3kio/o3k/pull/1104), head
  `83e7dd01ffdbf960d6dcd3b10c5f95b2c0d5aa3b`, has all checks passing and
  remains limited to SQLite. PostgreSQL storage pressure and the full matrix
  remain unproven; no fixture is promoted to real-backend evidence.
- Diagnostics remediation [#1101](https://github.com/o3kio/o3k/pull/1101):
  `f76acabcf8fa63c7e498e63a9d6f630dc1266a90`, tree
  `c3677e4f84d6367c097a0ae25f78c26460bc71eb`; Clippy was fixed and all
  protected checks are queued. Focused local tests and independent review pass.
  Support-bundle contract
  [#1102](https://github.com/o3kio/o3k/pull/1102) remains Proposed only:
  `d7d33655c2c899a8bae66f79c1ff6fa6d86243c7`, tree
  `856ab2a14331aae0068799aec2ce440aa17b2f33`.
- PostgreSQL outage/reconnect [#1103](https://github.com/o3kio/o3k/pull/1103):
  `9f6420e662c885837458e3e799bf64752ef40bc5`, tree
  `d2dfe87737f88131fbf8c78167a37f63af0902fd`; all seven protected checks and
  the required real PostgreSQL outage/reconnect evidence step pass. Evidence
  artifact `12018522281` has SHA-256
  `6aef46ec1f3124b00af83d7875465ba1264e7127eeee593b611e72ff12177aad`.
  GitHub approval remains absent; this proves only the scoped outage/reconnect
  case.
- Diagnostics correlation [#1105](https://github.com/o3kio/o3k/pull/1105),
  `1abf308ee67fb28d075935226f16b9d7ee1d2b44`, and CloudProfile error
  classification [#1106](https://github.com/o3kio/o3k/pull/1106),
  `8c1bfbe6cc6fbeb9d93258710dda88687d828bf6`, have clean focused reviews;
  #1105 checks pass and #1106 Rust remains in progress. Paginated diagnostics
  [#1107](https://github.com/o3kio/o3k/pull/1107) is currently
  `6facf37832a6b1fe742aa9c0df4e0510b7da3e38`, tree
  `daf792816933239e50f9ae1077734ae3151e7a63`; independent review is clear and
  its protected checks are queued.
- Diagnostics/capacity runbook [#1108](https://github.com/o3kio/o3k/pull/1108):
  `fcddeaf526c44516ef0d894e7d681cb87d63b5af`, tree
  `53ed4ab1072868af7acaac13cfb98316b2b4c3c6`; six protected checks pass and
  Rust is in progress. Independent review is clean; #944 remains partial.
- Upgrade/recovery [#1098](https://github.com/o3kio/o3k/issues/1098) is open
  under #975 and remains partial, governed by #640. It cannot claim
  PostgreSQL or fresh-host recovery before the approved backup/restore design.
  PP.5 remains ACCEPTANCE_PENDING and PP.7 remains unauthorized.
- PostgreSQL pool exhaustion [#1111](https://github.com/o3kio/o3k/pull/1111):
  `8bca9e7fbac36190c33358596af8b45695c10415`, tree
  `9d5126ab83a726b1b0f1c31d659ce961d3fca93f`; six protected checks pass and
  Rust, including the required real PostgreSQL lane, is in progress. The local
  disposable PostgreSQL attempt failed at container connectivity and produced
  no evidence artifact. Independent review is clear; approval is absent.
- Network pool exhaustion [#1112](https://github.com/o3kio/o3k/pull/1112):
  `6ea517025d178c4247ec38ed12d454532aecb5ea`, tree
  `a167a4bad4e8ef5e4881d3541de44cafcaddd838`; six protected checks pass and
  Rust is in progress. Package tests and independent review pass; evidence is
  limited to the in-memory NetworkService store. Approval is absent.
- Native storage capacity rejection [#1113](https://github.com/o3kio/o3k/pull/1113):
  `6effcd795663216bca3e7cb7ad28ad5689842af3`, tree
  `bd2284f322afd32079066bdd04058f5426bb7d54`; package tests and Clippy pass,
  exact-head protected checks and independent GitHub review are in progress.
  This fake-provider test proves durable lifecycle handling after a known
  `Capacity` result; it does not prove real LVM capacity detection. #1089 remains
  partial.

## Post-snapshot status refresh

Recorded against the current open PR state after the preceding snapshot; these
are implementation and CI observations, not acceptance or merge decisions.

- Doctor durable controller authority [#1093](https://github.com/o3kio/o3k/pull/1093)
  at `f9c3844dfb9d4d8e9b7099a2c34f23f486016f73` now has all seven protected
  checks passing. It remains open without GitHub approval and does not by
  itself establish full diagnostics acceptance.
- Native storage capacity rejection [#1113](https://github.com/o3kio/o3k/pull/1113)
  at `6effcd795663216bca3e7cb7ad28ad5689842af3` has all seven exact-head
  protected checks passing. The result remains a bounded fake-provider
  lifecycle test and is not real storage-capacity evidence or a native-volume
  product claim.
- PostgreSQL server pressure [#1114](https://github.com/o3kio/o3k/pull/1114)
  is currently at `a2ee310064039779348e443935a5d7f736842a07`; a prior workflow
  failure remains recorded on the PR and a fresh protected run is pending.
  No PostgreSQL pressure PASS is claimed.
- Read-only diagnostics routes [#1115](https://github.com/o3kio/o3k/pull/1115)
  is currently at `7e342171710172b454afe776a0be853b9bc45525`. Focused tests and
  independent review are clear; exact-head protected CI is pending. The slice
  proves route read-only behavior only and does not create a support-bundle
  contract or complete diagnostics acceptance.

ADR-0189/SPEC-0050 remain Proposed, SPEC-0051 support-bundle work remains
Proposed, and no backup/restore or PKI production implementation is authorized.
GitHub approvals and applicable exact-head evidence remain outstanding across
the open PRs. PP.5 #1081 remains untouched and ACCEPTANCE_PENDING; deferred
physical campaigns remain deferred; PP.7 #976 remains unauthorized.

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
