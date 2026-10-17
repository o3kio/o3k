# ADR-0190 — PP.6 interim single-maintainer review gate (proposed)

Status: Proposed — requires explicit human acceptance
Date: 2026-10-18
Affected-services: governance, deployment, identity
Parent: PP.6 #975; ADR-0189; SPEC-0050; SPEC-0051
Supersedes: none

## Context

ADR-0189 and SPEC-0050 have an accepted architecture proposal from senolcolak
but still require independent security acceptance. SPEC-0051's technical
architecture/security decisions remain Proposed/PENDING. No independent
security authority is assigned. The PP.6 tracking direction recorded in issue
#975 comment 6242789269 permits a narrowly scoped governance amendment to
consider an interim single-maintainer risk model, while preserving its
non-independent disclosure.

This is a review artifact only. It does not promote any Proposed contract,
authorize backup/restore or PKI runtime, satisfy independent review, or waive
any D1-D13/A1-A9, SPEC-0051, evidence, or protected-review gate.

## Proposed decision

For PP.6 only, permit senolcolak to perform interim architecture and
security/technical review for the exact revision named in the approval record.
Every resulting record must state non-independent single-maintainer review.
The named interim risk owner is senolcolak. The residual risk is that one
reviewer can miss a security defect, and that an agent or automated review
cannot substitute for a qualified independent human. This proposal does not
waive ADR-0099's signed-release human-review requirements or its
--require-approved gate.

Scope is limited to single-site o3k-small-edge-v1 PostgreSQL 16
production-oriented operations and bounded o3k-demo-v1 SQLite small-edge,
development, and TestLab operations. SQLite remains an intentional supported
small-edge/TestLab profile; this amendment does not make SQLite evidence
production evidence for PostgreSQL. HA, multi-region recovery,
external-hosted service databases, PP.5, PP.7, and unlisted capabilities are
excluded.

The amendment would expire on 2026-11-30 or on the recorded PP.6 final
decision, whichever occurs first. Expiry does not invalidate a release or
evidence record accepted against this exact amendment before expiry; it
prevents new contract or runtime acceptance after expiry until renewed or
replaced by independent review. Re-review is mandatory before expiry and
after any cryptographic, fencing, journal, PostgreSQL policy, operator
interface, or support-bundle schema change. #1146 remains deferred and is
not a waiver or substitute.

## Backup signing alternatives for human decision

The reviewer must explicitly choose one option for the PostgreSQL profile and
record the choice against the exact revision.

### Option A — offline-only

Retain the current D1/D2 proposal: each backup uses a human detached-signature
round trip to a disconnected workstation. Offline artifact and journal keys
remain in two-person custody. Scheduled or unattended backup is unsupported.
This minimizes online signing exposure but makes every backup dependent on
operator availability and introduces a signing outage window.

### Option B — bounded online artifact signing

Add a distinct non-exportable online artifact-signing key in an isolated
signing service or HSM/TPM-backed host. A dedicated offline Ed25519 backup
signer root certifies the online signing key, site/profile binding, validity,
and revocation. This root is separate from the X25519 HPKE recipient key,
artifact-signing key, journal/evidence key, and release key. The online key may sign
only a frozen D1 manifest and ciphertext digest set for its configured site;
it may not sign restore-journal transitions, fencing evidence, activation,
discard, or recovery decisions. Requests require immutable manifest digest,
site/profile binding, nonce/replay protection, short expiry, rate limiting,
and fail-closed revocation. Offline custody remains mandatory for root,
journal/evidence keys, key provisioning, rotation, and emergency revocation.
Signer unavailability fails the backup rather than producing an unsigned
artifact. Tests must cover altered bytes, wrong site/profile, replay,
interruption, rotation, revocation, and publication failure.

Option B is recommended for the PostgreSQL production profile because it
removes a human round trip from routine backup cadence while preserving
offline authority over recovery and journal transitions. It is a material
D2/A3 amendment and must not be implemented or claimed until explicitly
accepted. Option A remains the lower-exposure choice for SQLite small-edge
and TestLab.

Option B does not select a service, daemon, HSM, workstation, tool version,
custody location, rotation schedule, or signing profile. Those concrete values
are separate implementation-critical D2/A3 decisions requiring human review
and an applicable architecture/security record; no implementation may infer
them from this proposal.

## Required decision

The authorized human must Accept, Amend, or Reject this proposal against the
exact source revision <SHA>, and separately choose Option A or B for
PostgreSQL. The external request must replace <SHA> with the 40-character
source revision and include the exact review URL. A decision is incomplete
without both fields.
The record must include reviewer identity and role, non-independent
disclosure, risk owner, date, exact revision, expiry, residual risks,
conditions, and review URL. Independent security acceptance remains pending
unless a qualified independent reviewer is separately designated.

## Consequences and unchanged gates

An accepted amendment would permit only the named interim review process. It
would not accept ADR-0189, SPEC-0050, SPEC-0051, their schemas, or any
implementation. D4 exclusion, D7 fencing, D8 journal handoff, D9 measured
bounds, D10 PostgreSQL grants/TOC/definition policy, D12 operator contract,
D13 inventory, and all failure and real-backend evidence remain mandatory.

## Sources

- [ADR-0189](ADR-0189-pp6-control-plane-backup-and-restore.md) and
  [SPEC-0050](../specs/SPEC-0050-pp6-control-plane-backup-restore.md)
- [SPEC-0051](../specs/SPEC-0051-pp6-bounded-support-bundle-v1.md)
- [PP6_BACKUP_RESTORE_DECISION_PACKET.md](../pp/PP6_BACKUP_RESTORE_DECISION_PACKET.md)
- [ADR-0099](ADR-0099-human-review-evidence-package.md) human-review evidence package
- [ADR-0154](ADR-0154-engineering-governance-lifecycle.md) governance proposal,
  consulted as proposed guidance and not treated as an accepted authority
- PP.6 issue [#975 comment 6242789269](https://github.com/o3kio/o3k/issues/975#issuecomment-6242789269)
