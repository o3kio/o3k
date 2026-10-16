# ADR-0189 — PP.6 control-plane backup and restore

Status: Proposed — requires human architecture and security approval before
implementation
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

Proposed amendments A1–A9 (2026-10-16) to the D1–D13 recommendations are listed
in [the decision packet](../pp/PP6_BACKUP_RESTORE_DECISION_PACKET.md#proposed-amendments-2026-10-16).
They are not accepted; reviewers record accept, amend or reject for each one
in this ADR.

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

The following are bounded recommendations for review. They are not accepted
decisions and do not authorize production implementation. An approving
architecture/security review should record the selected option and any
conditions in this ADR before #1084 implementation begins.

| Decision | Recommended bounded choice | Approval still required |
| --- | --- | --- |
| PostgreSQL snapshot format and restore privilege policy | PostgreSQL 16 `pg_dump` custom format (`-Fc`) as one opaque regular-file member; restore with the matching supported `pg_restore` into a newly provisioned empty O3K database. The approved invocation must use `--exit-on-error`, `--no-owner`, and `--no-acl`, or a reviewed equivalent that demonstrably enforces the ownership/ACL policy; if the tool cannot enforce it, fail before mutation. Restore only with an installation-provisioned, least-privilege database role and an approved extension/object allowlist. A restore error or unknown outcome after target mutation and before `STARTED` enters `FAILED_RECOVERABLE`; the target stays inactive and quarantined. It is discarded/recreated or recovered only by an approved idempotent path. Activate only after complete restore, integrity, privilege, and migration validation. Do not use `PGDATA` copies or cluster-wide `pg_dumpall`. | Confirm tool/version policy, extension/object allowlist, database ownership, exact role privileges, and least-privilege target-role provisioning. Artifact data must not mutate roles, passwords, tablespaces, ownership, or ACLs beyond approved object policy. |
| SQLite snapshot primitive | Reuse `SqliteStore::backup_to_file` and its `VACUUM INTO` behavior after the accepted SQLite WAL/checkpoint and consistency boundary has been proven. | Confirm the operation can be coordinated with config, bootstrap/trust material, API writes, workers, provider dispatch, and lease activity; the existing store primitive alone is not that barrier. |
| Public operator surface | Keep the first implementation slice internal, with no CLI or API addition. Revisit an `o3k` operator command only under a reviewed interface contract. | No public command, flags, confirmation behavior, or output format is accepted by this proposal. |
| Signing and encryption | Keep the backup authentication/encryption profile undecided. Use a backup-specific trust/key lifecycle, separate from release signing keys, and require externally protected operator key recovery. | Select algorithms, envelope fields, canonical authenticated encoding, nonce/key-wrapping rules, trust distribution and rotation, issuer-key recovery, and secret inclusion policy. The release Ed25519 key is not a backup key. |
| Restore activation | Require a fresh runtime controller identity/epoch and an approved source-controller stop or out-of-band fencing step before enabling writes or provider dispatch. Never restore lease ownership as active. | Define stable site identity versus runtime identity, the fencing proof, lease reacquisition, PKI readiness, and the first reconciliation gate. |
| Restore journal and target reservation | Keep journal data outside the target database and bind it to the target identity and artifact digest; fail closed on ambiguous or conflicting state. | Select protected location, owner/authentication, exclusive reservation, crash cleanup, and recovery behavior for unknown filesystem/database outcomes. |
| Outer artifact and limits | Use a single regular-file artifact with a closed member allowlist as the starting candidate; authenticate member metadata before extraction or target mutation. | Select encoding/compression and numeric limits for member count, path depth, member and aggregate sizes, compression ratio, and staging capacity. Reject unsupported entries before extraction. |

These recommendations narrow review but do not establish a common consistency
cut or settle cryptographic/security semantics. The first implementation PR
remains blocked until the applicable rows above and approval items 1–13 are
resolved. Existing implementation can be audited and tests can be planned,
but code must not infer approval from this worksheet.

Production implementation must not begin until the security-sensitive items
and any public CLI contract have accepted human review. If approved, the first
implementation slice is internal manifest validation and SQLite backup
publication/verification, with no CLI/API and no PostgreSQL behavior in that
PR.

## Evidence required before claiming PP.6 support

See [PP.6 gap analysis and executable plan](../pp/PP6_GAP_ANALYSIS.md) and
[SPEC-0050](../specs/SPEC-0050-pp6-control-plane-backup-restore.md). This
proposal is architecture intent, not runtime evidence.
