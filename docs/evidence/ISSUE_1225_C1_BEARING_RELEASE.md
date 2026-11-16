# Issue #1225 — C1-bearing release (Option A) decision and evidence record

Status: implementation proposed; awaiting protected review, exact-revision
acceptance (ADR-0190), and published rc.28 qualification evidence.

## Decision

Issue #1225 isolated the installed-release blocker: the packaged-path
startup guard (fail-closed, SPEC-0050 §7.2) requires an authenticated C1
installation policy, while the protected release workflow built releases
without the C1 manifest authority (`packaging/make-release.sh:194` default
`O3K_C1_INSTALLATION_POLICY_ENABLED=0`), so every installed release was
dead-on-arrival (rc.27 E4 run `pp6-e4-20261115-ubuntu02`: o3kd `failed`,
o3k-compute `inactive`).

Per the 2026-11-16 decision request on #1225, this change implements
**Option A**: C1-bearing releases with operator-controlled offline signing.
Option B (relaxing the guard) is not taken; the fail-closed startup guard
is byte-untouched. rc.27 is not retagged or mutated; a successor tag is
required (ADR-0185).

## Exact change set (branch fix/1225-c1-bearing-release, base fb15c27d)

- `.github/workflows/release.yml` — the bundle step now sets
  `O3K_C1_INSTALLATION_POLICY_ENABLED=1` and sources
  `O3K_C1_INSTALLATION_POLICY_KEY_ID` / `O3K_C1_INSTALLATION_POLICY_PUBLIC_KEY`
  from variables on the approval-gated `release` environment. Only public
  key material enters CI; `make-release.sh` fails closed (exit 2) when the
  variables are unset or malformed. Prerelease notes now state the C1
  ceremony requirement.
- `tests/packaging-bundle.sh` — positive test asserting the exact
  `installation_policy_format` / `installation_policy_path` /
  `installation_policy_authority` manifest block, a negative assertion that
  the default build carries no C1 fields, and five fail-closed builder
  cases (unset/malformed key id or public key emit no manifest).
- `docs/RELEASE.md` — documents the C1 build inputs and custody constraint.
- `docs/operator/C1_OFFLINE_SIGNING_CEREMONY.md` — new operator runbook
  (previously a documented gap): custody roles, prepare → offline sign →
  install journey, freshness obligations (24 h revocation refresh,
  90 day certificate ceiling), PostgreSQL backend note, verify/deny
  expectations.
- `tests/pp6-c1-ceremony/` — qualification-only ceremony tooling
  (throwaway-key signer `sign.py`, disposable-guest driver
  `run-guest-ceremony.sh`, README). Never shipped in a release bundle;
  never used with production keys.
- `bins/o3k/tests/pp6_c1_ceremony_signer.rs` — pins the signer against the
  canonical Rust verifiers (`verify_signed`, `verify_policy`,
  `verify_initial_state_transition`, `verify_trust_bundle`) with tamper
  negatives.

## Security/architecture acceptance request

The release-contract change is exactly the release.yml env block above at
this PR's head commit. Acceptance per ADR-0190 is constituted by the named
reviewer's approval of this PR at its exact head plus the protected merge
SHA; the plan was recorded on #1225 before implementation
(comment 2026-11-16). No private key material is introduced anywhere; no
policy, state, or trust document is synthesized by CI; the packaged-path
guard and all C1 verifiers are unchanged.

## Evidence

- `tests/packaging-bundle.sh`: C1 manifest emission + fail-closed cases
  (run on the clean review head).
- `cargo test -p o3k --test pp6_c1_ceremony_signer`: signer output passes
  the canonical verifiers; tamper negatives fail.
- Disposable Ubuntu 24.04 guest ceremony run: recorded under the evidence
  directory referenced below once executed (driver:
  `tests/pp6-c1-ceremony/run-guest-ceremony.sh`).

## Residual obligations (not part of this change)

- Protected review + CI, then rc.28 published only from the protected
  reviewed source through the existing signed release workflow.
- Installed Q1/Q2 re-run on the published rc.28 via the PP.6 harness,
  including the real libvirt lifecycle and the PG16 restart/reconciliation
  lane (new scenario, `--c1-backend postgresql`).
- Persistent-workload enablement remains separately gated on #1085/#1086
  (authenticated PostgreSQL recovery/fencing) and #1087 (certificate
  replacement/revocation).
- PP.5/PP.6/PP.7 umbrella issues remain open; this change claims no
  certification.
