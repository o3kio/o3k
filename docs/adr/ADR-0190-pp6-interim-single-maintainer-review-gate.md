# ADR-0190 — PP.6 interim single-maintainer review gate

Status: Accepted — interim PP.6 governance decision; implementation contracts remain Proposed
Date: 2026-10-18
Affected-services: governance, deployment, identity
Parent: PP.6 #975; ADR-0189; SPEC-0050; SPEC-0051
Supersedes: none

## Context

ADR-0189 and SPEC-0050 have an accepted architecture proposal from senolcolak
and remain subject to their unresolved technical/security conditions.
SPEC-0051's technical architecture/security decisions remain
Proposed/PENDING. No independent security reviewer is assigned; the bounded
interim non-independent route is defined and accepted below. The PP.6 tracking direction recorded in issue
#975 comment 6242789269 permits a narrowly scoped governance amendment to
consider an interim single-maintainer risk model, while preserving its
non-independent disclosure.

This ADR records a governance decision only. It does not promote any Proposed
contract, authorize backup/restore or PKI runtime, satisfy independent review,
or waive any D1-D13/A1-A9, SPEC-0051, evidence, or protected-review gate.

## Accepted interim decision

The authorized human accepted this bounded interim arrangement against the
exact proposed revision recorded below. `senolcolak` is the named human
architecture and security/technical reviewer and risk owner. Every review
under this arrangement must explicitly state that it is a non-independent
single-maintainer review. The accepted residual risk is that one reviewer can
miss a security defect; agent or automated analysis is not an independent
human review. ADR-0099 signed-release human-review requirements and its
`--require-approved` gate remain in force.

The interim substitution is limited to the independent-security role
requirement for future, exact-revision decisions on ADR-0189, SPEC-0050 and
SPEC-0051, within the profiles and expiry below. It does not itself accept
those contracts. Each contract needs a separate technical/security decision
and must explicitly reference this ADR and the applicable decision record.
SPEC-0051's technical decision remains separate. A PR approval or acceptance
of this ADR alone cannot promote those contracts or authorize dependent
runtime code. Any independent human review required by a release gate remains
a separate gate.

Scope is limited to single-site o3k-small-edge-v1 PostgreSQL 16
production-oriented operations and bounded o3k-demo-v1 SQLite small-edge,
development, and TestLab operations. SQLite remains an intentional supported
small-edge/TestLab profile; this amendment does not make SQLite evidence
production evidence for PostgreSQL. HA, multi-region recovery,
external-hosted service databases, PP.5, PP.7, and unlisted capabilities are
excluded.

The amendment expires on 2026-11-30 or on the recorded PP.6 final
decision, whichever occurs first. Expiry does not invalidate a release or
evidence record accepted against this exact amendment before expiry; it
prevents new contract or runtime acceptance after expiry until renewed or
replaced by independent review. Re-review is mandatory before expiry and
after any cryptographic, fencing, journal, PostgreSQL policy, operator
interface, or support-bundle schema change. #1146 remains deferred and is
not a waiver or substitute.

## Backup signing alternatives and selected profile modes

The authorized human selected the signing mode below. This selects the
operational mode only; it does not accept the proposed concrete signer,
custody, trust, recovery, rotation, revocation, or test design.

### Option A — offline-only (selected for SQLite where supported)

The selected mode retains a human detached-signature round trip to a
disconnected workstation for SQLite small-edge/TestLab where supported. The
proposed custody model keeps offline artifact and journal keys in two-person
custody; that concrete custody requirement remains subject to the separate D2
technical decision. This mode makes each backup dependent on
operator availability. Under the proposed D4 exclusion protocol the controller
remains stopped throughout signing, so signing delays extend API downtime and
may cause missed backup windows and a longer recovery point interval.

### Option B — bounded online artifact signing (selected for PostgreSQL)

The following concrete design is the proposal for technical review; the
human's selection accepts only the mode and authority restriction recorded
below, not these implementation details.

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

Online-key compromise could authenticate a forged artifact for the permitted
site/profile; encryption alone does not establish trustworthy origin. The
review must accept that residual risk and specify independently provisioned
verification trust, signing-key validity/revocation and bounded replay rules.
Missing custody material, wrong keys, interrupted signing and incomplete
publication must fail closed. Recovery/journal authority remains offline.

For PostgreSQL 16 production-oriented operations, the selected mode is Option
B: online signing may authenticate only a backup artifact for the configured
site/profile. It cannot authorize restore, fencing, restore-journal
transitions, or controller activation. Offline recovery-key custody and
offline restore-journal authority remain separate. D4 still requires the
accepted controller exclusion and consistent cross-file capture; online
signing does not authorize live cross-file capture. The concrete signer and
its security lifecycle remain pending technical contract decisions.

For SQLite small-edge and TestLab, retain Option A where supported. This
profile choice does not make SQLite evidence production evidence for
PostgreSQL.

Option B does not select a service, daemon, HSM, workstation, tool version,
custody location, rotation schedule, or signing profile. Those concrete values
are separate implementation-critical D2/A3 decisions requiring human review
and an applicable architecture/security record; no implementation may infer
them from this proposal.

## Human decision recorded (2026-10-18)

- **Authority:** `senolcolak`, human architecture and security/technical
  reviewer and named interim risk owner.
- **Decision:** ACCEPT the temporary single-maintainer review arrangement for
  the bounded PP.6 profiles, acknowledging that the review is non-independent
  and accepting the documented residual risk. Existing release-level
  human-review requirements continue to apply.
- **Signing selection:** Option B for PostgreSQL production operations, limited
  to signing authenticated backup artifacts for the configured site/profile;
  no authority for restore, fencing, journal transitions, or activation.
  Retain Option A for SQLite small-edge/TestLab where supported.
- **Exact reviewed revision:**
  `d62853bed83b7d5e1b63118a2d17bd48dac2e2aa`.
- **Decision source:** explicit human decision supplied for PP.6 against that
  revision. [PR #1147](https://github.com/o3kio/o3k/pull/1147) identifies the
  reviewed proposal, and its [review](https://github.com/o3kio/o3k/pull/1147#pullrequestreview-5562255580)
  records review of that exact revision. That earlier approval is not itself
  treated as this ACCEPT/Option B decision. A durable URL for this specific
  decision is pending publication by the decision-maker; no contract promotion
  or runtime gate may rely on this local record until the URL is attached.
- **Expiry:** 2026-11-30 or the PP.6 final decision, whichever occurs first.
- **Conditions:** matching amendments must reference this decision; separate
  exact-revision technical/security decisions remain required for ADR-0189,
  SPEC-0050 and SPEC-0051. The concrete PostgreSQL signer implementation,
  custody, key rotation/revocation, trust, recovery and negative tests remain
  pending. No backup or restore runtime is authorized by this decision.

## Consequences and unchanged gates

Once this amendment and its decision record have durable review linkage and
protected integration, it permits only the named interim review process. It
does not accept ADR-0189, SPEC-0050, SPEC-0051, their schemas, or any
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
