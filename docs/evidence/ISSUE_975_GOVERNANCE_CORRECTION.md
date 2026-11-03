# #975 PP.6 closure governance correction

## Issue and intent

This change addresses the PP.6 parent issue #975, whose closure had been used
for milestone completion even though its final acceptance criteria remained
open. It keeps the tracking issue open until the final owner GO and evidence
review are explicitly recorded.

## Confirmed closure cause

GitHub issue events show repeated manual closures by a repository maintainer,
including 2026-11-03 at 09:02:31 UTC and 13:14:17 UTC. Earlier manual closures
also occurred on 2026-10-17, 2026-10-18, and 2026-10-24. The reviewed merge
references and repository workflows did not show automatic closure as the
cause; milestone PRs stated that #975 remained open. The issue was reopened
after this review, and its comment records the outstanding obligations.

## Prevention mechanism

`.github/workflows/pp6-epic-closure-guard.yml` listens for closure of #975 and
reopens it unless the `pp6-final-go` label is present. The label is a deliberate
human gate: it may be applied only after the final owner GO, links to the
required operational/release evidence, and a zero actionable
BLOCKER/HIGH/MEDIUM review are recorded. The guard uses only the GitHub token's
`issues: write` permission and does not change source, release, or deployment
state.

The guard prevents accidental closure and milestone/keyword auto-closure from
being treated as acceptance. It cannot prevent a repository administrator
from intentionally bypassing the label or disabling the workflow; the final
acceptance record remains authoritative.

## Bounded implementation plan

- **Profile and authority:** PP.6 tracking governance only; GitHub issue state
  and labels are the sole authority affected. No O3K service, resource, or
  OpenStack adapter is involved.
- **Files and packages:** `.github/workflows/pp6-epic-closure-guard.yml` and
  this evidence record; no Cargo package, binary, database, runtime, or
  deployment changes.
- **Normative inputs:** #975 final acceptance criteria; `PP6_COMPLETION_MATRIX.md`
  says merged milestones do not imply PASS and final owner acceptance is
  outstanding; ADR-0189/SPEC-0050 require executable evidence and do not
  authorize closure by technical proposal alone. GitHub issue events confirm
  the actual manual-closure cause.
- **Operations and evidence:** issue #975 close event is the only operation;
  an unlabelled close must reopen and post a bounded explanation. The
  falsification check is actionlint plus the repository workflow-validation
  test, followed by protected CI and human review. No E1–E5 product evidence is
  claimed.
- **Uncertainties and non-goals:** the workflow cannot constrain an
  administrator who disables it or applies the label prematurely. It does not
  change release state, merge PRs, resolve restore authority, or authorize
  PP.7/Araf work. Widen only if protected review finds a concrete failure in
  the event/label gate.

## PP.6 status at implementation

PP.6 remains **BLOCKED**. PR #1209 merged through the protected queue into
`main` at `157448428552259fa50ba81917207f33d8544cba` on 2026-11-03. Its
required protected checks passed, including cargo-test, PostgreSQL WAL and
tablespace pressure, installer-negative, OIDC identity, supply-chain, Tempest
Gate A, and Mock Cinder. These checks establish the reviewed source merge;
they do not establish installed-release qualification. The authenticated
`v0.4.0-rc.26` artifact remains immutable; installed Q1/Q2 qualification and
PostgreSQL 16 restore evidence remain outstanding.

## Validation

- `bash tests/workflow-validation.sh /tmp/o3k-actionlint-1.7.7/actionlint`:
  PASS, including this workflow and the repository's duplicate-key regression
  check.
- Protected CI and human review: pending.
- This workflow is governance automation only and supplies no E1–E5 technical
  qualification evidence.
