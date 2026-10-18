# ADR-0189 — PP.6 control-plane backup and restore

Status: Proposed — requires separate exact-revision human architecture and
security/technical approval before implementation
Date: 2026-10-15
Affected-services: cloud-kernel, deployment, identity, governance
Parent: PP.6 #975; general rollback/backup authority #640
Related: ADR-0163, ADR-0167, ADR-0182, SPEC-0008, SPEC-0024, SPEC-0047

## Context

O3K has bounded local upgrade rollback support. The upgrade engine snapshots a
SQLite database with a WAL checkpoint and `VACUUM INTO`, captures selected
installation files and binaries, and records an upgrade rollback manifest.
This does not provide a portable backup/restore for a fresh control-plane host
or for the production-oriented PostgreSQL profile.

Accepted authorities already require SQLite backup/checkpoint/filesystem
constraints, PostgreSQL `pg_dump`/`psql`, and tested control-plane backup
including configuration/credentials/PKI and external-state boundaries
(SPEC-0024, ADR-0182 E2D-12). They do not define the backup artifact, how
secrets are protected, how a restored controller is fenced, or how partial
backup/restore operations recover.

## Proposed decision

1. A PP.6 backup is a portable, versioned recovery artifact for authoritative
   O3K control-plane state and the minimum O3K-owned installation metadata
   needed to validate/restore that state. It is distinct from the local
   upgrade rollback chain and from tenant workload backup/DR.
2. A backup is valid only after its complete contents are staged, checked,
   authenticated, and atomically published as committed. A partial artifact is
   never discoverable as a successful backup.
3. Database snapshots use supported database-native consistency mechanisms:
   SQLite checkpoint plus `VACUUM INTO`; PostgreSQL consistent dump using the
   supported `pg_dump`/restore tooling. Cross-file configuration, release,
   identity, and trust material is captured at a coordinated control-plane
   quiescence point. That point accounts for API writes, background jobs,
   reconciliation/provider dispatch, in-flight Operations, and lease renewal,
   and binds each database/file member to one recorded consistency generation.
   The exact pause, drain, unknown-outcome, and resume protocol is a human
   decision. The consistency generation is artifact evidence only, not new
   canonical state or an authority. The mechanism must reuse accepted
   Operation/controller coordination or remain in the backup run context; it
   must not create a parallel lifecycle authority. Raw copying of a live
   database file is unsupported; backup fails if it cannot prove a common cut.
4. The manifest binds source O3K release/version and source SHA, deployment
   profile, store backend/version, schema version and migration identity,
   installation identity, snapshot method/time, inventory and digests for all
   artifact members, and the exact external-state exclusions.
5. Canonical database state is restored as one store image. It includes
   resources and durable Operations, Placement allocations/provider mappings,
   topology and BuildingBlocks, IAM/security scope, bootstrap/enrollment,
   audit and other durable kernel repositories. It does not include
   provider-owned VM disks, external storage payloads, or external-hosted
   service databases.
6. Secret-bearing material is never emitted in plaintext in artifacts,
   diagnostics, or evidence. Sensitive restore material uses an
   operator-managed encryption key whose recovery is outside the backup
   artifact. The concrete key-wrapping and issuer-key recovery mechanism
   remains an explicit security approval item; no encryption key is generated
   from a public installation identifier or stored beside the artifact. The
   authenticated metadata binds the canonical manifest, every payload
   ciphertext digest, encryption parameters, and format identity. Archive
   limits, supported entry types, and safe no-follow extraction rules must be
   chosen before implementation.
7. Restore targets a fresh O3K-owned installation/data target. Preflight
   validates artifact authenticity, compatibility, profile/backend/schema,
   destination ownership and emptiness before mutation. A foreign or nonempty
   target is rejected. Existing external provider state is not modified by
   restore.
8. Restore records durable phases and operation identity before side effects.
   If the operation is surfaced through the control plane, it uses the existing
   canonical Operation authority. Otherwise its protected journal is procedural
   recovery metadata only and cannot define cloud desired/observed state. After
   a crash, it observes target state and resumes safely or stops in an explicit
   recoverable failure state. It never blindly repeats a possibly completed
   destructive operation.
9. Before serving mutations or dispatching reconciliation after restore, the
   control plane must establish current controller ownership/fencing and
   prevent pre-restore leases/epochs from authorizing work. The exact identity
   preservation, epoch advancement, and activation procedure require human
   approval because existing authority does not define restore takeover.
10. Restore validates and exposes canonical state before reconciliation. Any
    provider action follows normal authorization, ownership, operation, and
    observe-before-retry contracts. Backup/restore creates no new resource,
    placement, topology, or lifecycle authority.

PostgreSQL database dumps do not by themselves define restoration of cluster
roles, passwords, or global privileges. Whether a minimal target role is
recreated from trusted installation configuration or by another allowlisted
mechanism requires security review; artifact-supplied global roles and
privileges must not be applied implicitly. PKI readiness is a hard activation
gate: restored database state remains inactive until the approved issuer/trust
recovery or re-enrollment path passes its checks.

## Scope

PP.6 profiles only: SQLite Demo/TestLab where retained and PostgreSQL
Small Edge production-oriented profile. Single-site recovery only. The design
does not introduce multi-region disaster recovery, HA, a stretched database,
or an external-service backup coordinator.

## Interface boundary

No native API is proposed. Existing conventions include the host-operator `o3k`
CLI (`o3k doctor`, `o3k upgrade`, `o3k rollback`) and internal store interfaces.
Whether PP.6 adds `o3k backup`/`o3k restore`, exact flags, confirmation,
machine-readable output, and restore activation controls is a human-reviewed
public CLI decision. No new API or CLI is part of this proposal's approved
surface.

## Consequences

- Upgrade rollback keeps its current bounded SQLite/local-host meaning and
  remains unchanged.
- SQLite and PostgreSQL get separately evidenced snapshot/restore paths under
  one manifest identity model.
- An O3K database backup does not restore tenant VM/storage bytes or an
  external-hosted service. Their independent restore and mapping consistency
  must be stated to the operator.
- If required encryption material or supported source version is unavailable,
  restore fails before target mutation.
- A restore that cannot prove fencing/ownership remains inactive and requires
  operator recovery; it must not claim readiness.

## Human approval required

Concrete implementation defaults for D2/D4/D7/D8/D9/D10/D12/D13, the
matching proposed schema fields, negative-test prototype results and the
single exact-revision technical decision request are consolidated in
[`PP6_TECHNICAL_CONTRACT_APPROVAL.md`](../pp/PP6_TECHNICAL_CONTRACT_APPROVAL.md).
They remain proposed until the named interim reviewer records explicit
technical acceptance against the complete source commit. The ADR-0190
governance and PostgreSQL/SQLite signing-mode decisions are settled and are
not reopened by this request.

Proposed amendments A1–A9 (2026-10-16) to the D1–D13 recommendations are listed
in [the decision packet](../pp/PP6_BACKUP_RESTORE_DECISION_PACKET.md#proposed-amendments-2026-10-16).
Architecture proposal acceptance is recorded below. The interim
non-independent review arrangement is accepted under ADR-0190, but its
durable decision URL and protected integration remain pending. Separate
exact-revision technical/security decisions and implementation conditions
remain pending; this ADR remains Proposed.

### Review amendments (2026-10-17)

[Review comment 6239123579](https://github.com/o3kio/o3k/issues/975#issuecomment-6239123579)
expressly records recommendations, not architecture or independent security
acceptance. The existing packet incorporates the following proposal changes,
subsequently accepted by architecture at the revision recorded below.
The interim non-independent security/technical review route is accepted
under ADR-0190, subject to durable decision linkage and protected integration.
Exact-revision decisions and unresolved conditions remain **PENDING**; this ADR
remains **Proposed**:

- **D2 (proposed amendment after ADR-0190 decision):** PostgreSQL 16 uses
  bounded online signing only for authenticated backup artifacts belonging to
  the configured site/profile. That signing authority cannot authorize
  restore, fencing, restore-journal transitions, or controller activation.
  Offline recovery-key custody and restore-journal signing authority remain
  separate. SQLite small-edge/TestLab retains Option A (operator-assisted
  offline artifact signing) where supported. This records the selected
  operational mode, not a concrete signer implementation or accepted
  cryptographic contract. Signer boundary, request authentication, replay
  control, key custody, trust provisioning, rotation, revocation, recovery,
  failure behavior, and negative tests remain PENDING. Record protected
  custody details outside this ADR; do not publish secret material or
  sensitive storage locations here.
- **D4:** every O3K process opening the store, including CLI and maintenance
  paths, must honor the same startup/store-access lock. The existing storage
  execution lock is not this invariant. Stopping local daemons and taking a
  local lock is insufficient for PostgreSQL: preventing O3K writer-role login
  and proving no writer sessions remain, including remote controllers and
  Unix-socket reconnects, are mandatory before capture. The exact HBA admission
  barrier rejects all local connections after one already-open control session
  verifies/clears existing sessions; before dump begins, that control session
  must be gone and only the designated remote read-only dump session may exist.
- **D7:** recommend independently administered Redfish/BMC power-off, with
  per-site TLS trust, source serial binding, at most five-minute evidence age
  and a fresh authenticated observation before activation. The D2 offline
  Ed25519 journal/evidence key signs the record; the target recovery verifier
  uses its separately installed public trust anchor. Evidence collection must
  be independent of the source host. Demo/TestLab without independent fencing
  is limited to capture/verify; fresh-host activation is unsupported. D3 issuer
  replacement and old-source credential rejection at every verifier, plus
  target-only PostgreSQL writer access, are lasting activation gates in
  addition to independent source exclusion. Neither a signature nor lease
  expiry substitutes for that exclusion.
- **D8/A6:** recommend an `o3k:o3k` owner-only recovery directory (0700; files
  0600), consistent with the packaged service identity, on verified local
  ext4. Use distinct target-reservation and startup/store-access locks; retain
  reservation through commit and require a reviewed continuous startup-lock
  handoff to the intended controller before `STARTED`. Forward journal records
  require offline signing, including reconciliation and commit while the
  controller runs: roughly ten signing round-trips. Separate unsigned failure
  markers may only deny progress. They cannot modify the signed chain or
  authorize mutation, activation, recovery, discard or reuse. When safe marker
  persistence is impossible, preserve prior signed state and pending intent,
  report failure and require inspection. Signing does not defend the target
  database against a target-root attacker. Exact handoff, signing/transfer,
  filesystem versions and recovery authority remain PENDING.
- **D9/A7:** retain the proposed 4 GiB aggregate plaintext bound and raise the
  reservation cap to **9 GiB**, so `max(2 × measured source bytes + 1 GiB,
  6 GiB)` can reserve 9 GiB at that bound. Never truncate the reservation. The
  1 GiB per-member cap applies to the whole SQLite snapshot and the whole
  PostgreSQL custom dump. Representative peak-space measurements remain
  PENDING; these proposed numbers are not measured acceptance evidence.
- **D10:** validate the complete unfiltered `pg_restore --list` inventory
  before executing archive SQL, classifying all expected object/data entries
  and explicitly allowlisted tool-generated entries under a version-pinned
  mapping to the migration inventory. Then independently validate the restored
  catalog, definitions and privileges. A matching TOC name does not prove a
  function, trigger or default expression is safe; the exact-release
  pre-execution definition policy, grants and inventory revision remain
  PENDING. Unknown entries must be rejected, not silently filtered out.
- **D12/A8:** recommend rejecting the withdrawal/deferral of the interface
  dependency. An approved exact-release operator invocation and #944 runbook
  are prerequisites for operational recovery acceptance. Command names,
  flags, exit codes and public CLI/API behavior require their own reviewed
  contract; none are approved here.

ADR-0190's accepted interim governance decision names `senolcolak` as human
architecture and security/technical reviewer and risk owner for the bounded
PP.6 profiles through 2026-11-30 or the PP.6 final decision, whichever occurs
first. This review is explicitly non-independent and accepts the residual risk
that one reviewer can miss a defect. The exact decision is recorded in
[ADR-0190](ADR-0190-pp6-interim-single-maintainer-review-gate.md); each
contract decision must cite its exact reviewed revision and identify its
conditions. This governance decision does not accept this ADR, SPEC-0050,
SPEC-0051, the schema, or runtime behavior. ADR-0099 release-level human review
remains applicable.

### Architecture decision recorded (2026-10-17)

- **Authority:** senolcolak.
- **Decision:** architecture proposal **ACCEPTED**, including the stated
  conditions, for the amended D1–D13/A1–A9 packet, this ADR and SPEC-0050 at
  `610f914b4c25112f67798402db8b83c9caf0cf55`.
- **Decision evidence:** [explicit “accept” comment 6239984922](https://github.com/o3kio/o3k/issues/975#issuecomment-6239984922),
  responding to [exact-revision request 6239743723](https://github.com/o3kio/o3k/issues/975#issuecomment-6239743723).
  The [separate PR review](https://github.com/o3kio/o3k/pull/1143#pullrequestreview-5559773466)
  pins that reviewed source; PR approval alone is not contract acceptance.
- **Remaining conditions:** the decision supplies no missing custody/tool/deadline
  values (D2), startup-handoff contract (D8), deployment-specific BMC capability
  and authority (D7), measured artifact/staging evidence (D9), PostgreSQL
  grants/inventory/definition policy (D10), or operator interface/runbook (D12).
  Existing D4 exclusion and evidence requirements remain mandatory. Unresolved
  values, capabilities and evidence require explicit applicable reviewer
  resolution; none may be invented by implementation.
- **Independent security:** not performed or claimed. A bounded,
  non-independent interim review route is recorded under ADR-0190; its durable
  decision URL and protected integration are pending. The exact technical/
  security decision on this contract remains pending.
- **Normative status:** this ADR, SPEC-0050 and the artifact schema remain
  **Proposed**. No normative acceptance revision or #1084 implementation is
  authorized. SPEC-0051 technical acceptance remains a separate decision.

### Interim governance and signing-mode decision (2026-10-18)

The authorized human accepted the bounded interim, non-independent
single-maintainer review arrangement and selected PostgreSQL Option B and
SQLite Option A where supported under ADR-0190, against exact revision
`d62853bed83b7d5e1b63118a2d17bd48dac2e2aa`. The PostgreSQL online signing
authority is limited to authenticated backup artifacts for the configured
site/profile; it cannot authorize restore, fencing, restore-journal
transitions, or controller activation. Offline recovery and restore-journal
authority remain separate. See the [ADR-0190 decision
record](ADR-0190-pp6-interim-single-maintainer-review-gate.md#human-decision-recorded-2026-10-18).

This decision selects the signing mode and its authority limit only. It does
not accept this ADR, SPEC-0050, SPEC-0051, the artifact schema, or backup
runtime. Concrete signer implementation, key custody, rotation, revocation,
trust, recovery, and negative tests remain pending separate exact-revision
technical/security review. D1–D13/A1–A9 conditions, PostgreSQL real-backend
evidence, protected integration, and all release-level review requirements
remain in force.

### Decisions to record

Reviewers must decide or approve the proposal for:

1. manifest identity, canonical state inventory, consistency boundary, and
   format evolution;
2. PostgreSQL snapshot/restore tooling and ownership/role requirements;
3. encryption, signing/authentication, trust anchors, secret and issuer-key
   recovery/custody;
4. installation identity and controller identity behavior on fresh-host
   restore;
5. stale lease/fencing invalidation and the gate before first reconciliation;
6. crash-safe phases, retries, target ownership/emptiness and foreign-state
   rejection;
7. whether to add a host-operator CLI and its confirmation/output contract.
8. quiescence generation and how API writes, background work, provider
   dispatch, in-flight Operations, and leases are paused, drained, or
   classified;
9. PostgreSQL role/privilege restoration and least-privilege target creation;
10. restore-journal protection, exclusive target reservation, and crash
    recovery after ambiguous filesystem/database outcomes;
11. installation/site identity preservation or regeneration, controller
    credential replacement, and out-of-band fencing of any surviving source
    controller;
12. archive member/count/size/path-depth limits and authenticated payload
    encoding details;
13. failure recovery after controller startup, including stopping/fencing
    dispatch and resolving in-flight canonical Operations without treating an
    already activated target as a pre-activation quarantine.

## Decision worksheet for implementation readiness

The following bounded recommendations have architecture proposal acceptance
at the revision above, retaining all stated conditions. They do not authorize
production implementation. Independent security acceptance and resolution of
the outstanding parameters/evidence must be recorded in this ADR before #1084
implementation begins.

| Decision | Recommended bounded choice | Approval still required |
| --- | --- | --- |
| PostgreSQL snapshot format and restore privilege policy | PostgreSQL 16 `pg_dump` custom format (`-Fc`) as one opaque regular-file member; restore with the matching supported `pg_restore` into a newly provisioned empty O3K database. The approved invocation must use `--exit-on-error`, `--no-owner`, and `--no-acl`, or a reviewed equivalent that demonstrably enforces the ownership/ACL policy; if the tool cannot enforce it, fail before mutation. Restore only with an installation-provisioned, least-privilege database role and an approved extension/object allowlist. A known partial restore error before `STARTED` enters `FAILED_RECOVERABLE`; an unknown outcome enters `QUARANTINED`. The target stays inactive in both cases. It is discarded/recreated or recovered only by an approved idempotent path. Activate only after complete restore, integrity, privilege, and migration validation. Do not use `PGDATA` copies or cluster-wide `pg_dumpall`. | Confirm tool/version policy, extension/object allowlist, database ownership, exact role privileges, and least-privilege target-role provisioning. Artifact data must not mutate roles, passwords, tablespaces, ownership, or ACLs beyond approved object policy. |
| SQLite snapshot primitive | Reuse `SqliteStore::backup_to_file` and its `VACUUM INTO` behavior after the accepted SQLite WAL/checkpoint and consistency boundary has been proven. | Confirm the operation can be coordinated with config, bootstrap/trust material, API writes, workers, provider dispatch, and lease activity; the existing store primitive alone is not that barrier. |
| Public operator surface | Keep the first implementation slice internal, with no CLI or API addition. Revisit an `o3k` operator command only under a reviewed interface contract. | No public command, flags, confirmation behavior, or output format is accepted by this proposal. |
| Signing and encryption | Review the selected mode: bounded online artifact signing for PostgreSQL only, restricted to authenticated backup artifacts for configured site/profile; Option A offline artifact signing for SQLite small-edge/TestLab where supported. Keep recovery and restore-journal authority offline and separate from the online signer. | Accept the concrete signer boundary, authentication and replay protections, cryptographic profile, trust provisioning, custody, tool versions, rotation/revocation, recovery, failure behavior and tests. ADR-0190 selects modes but supplies none of these implementation values. The release Ed25519 key is not a backup key. |
| Restore activation | Review D3/D7 independent Redfish/BMC exclusion plus issuer replacement, rejection of old-source credentials, fresh target epoch and target-only PostgreSQL writer access. Never restore lease ownership as active. | Accept the profile restriction without BMC, exact evidence custody/verifier and deployment capability, PKI readiness and first reconciliation gate. |
| Restore journal and target reservation | Review D8 service-user ownership, offline signed transitions and separate denial-only failure markers. Keep target reservation distinct from startup exclusion through commit. | Accept exact path, filesystem, signing/transfer and controlled startup handoff, stale-operation recovery authority and unknown-outcome handling. |
| Outer artifact and limits | Review D9/A7 regular-file allowlist with no outer compression, 1 GiB member/4 GiB aggregate bounds and the full staging formula with a 9 GiB reservation cap. Authenticate before extraction or mutation. | Accept only after representative member/artifact/peak-space measurements; reject unsupported entries and never truncate the computed reservation. |

These recommendations narrow review but do not establish a common consistency
cut or settle cryptographic/security semantics. The first implementation PR
remains blocked until the applicable rows above and approval items 1–13 are
resolved. Existing implementation can be audited and tests can be planned,
but code must not infer approval from this worksheet.

Production implementation must not begin until the applicable security and
architecture decisions have accepted human review. The first authorized slice
proves store-startup exclusion and a consistent SQLite cut, followed by
manifest validation and backup publication/verification. It adds no public
CLI/API or PostgreSQL adapter. A separately accepted operator interface is
required before exposing that surface or claiming operational recovery.

## Evidence required before claiming PP.6 support

See [PP.6 gap analysis and executable plan](../pp/PP6_GAP_ANALYSIS.md) and
[SPEC-0050](../specs/SPEC-0050-pp6-control-plane-backup-restore.md). This
proposal is architecture intent, not runtime evidence.
