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
Option B (relaxing the guard) is not taken. rc.27 is not retagged or mutated; a successor tag is
required (ADR-0185). The startup guard is strengthened, not relaxed: see
the two guard fixes below.

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
  the default build carries no C1 fields, and six fail-closed builder
  cases (unset/malformed key id or public key, and a flag value other than
0/1, emit no manifest).
- `packaging/install.sh` — fail-fast ceremony gate: a C1-bearing bundle
  without the three signed inputs now refuses before any host mutation.
  Previously the refusal happened at the post-install C1 block, after the
  payload files were installed but before the ownership ledger was written,
  so the documented recovery (`--c1-prepare-only`) failed on "foreign"
  files. The post-install block keeps the authoritative check unchanged.
- `tests/pp6_c1_install_journey.sh` — full-installer cases for the early
  gate (fires without inputs, passes with named inputs, never fires under
  `--c1-prepare-only`, leaves no host mutation).
- Release prep to `0.4.0-rc.28` (workspace version/lock, installer pin,
  worker asset, Helm/Docker defaults, qualification fixtures,
  `docs/releases/v0.4.0-rc.28.md`), following the established pattern;
  rc.27 is immutable and not retagged (ADR-0185).
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
- `bins/o3k/src/recovery_installation.rs` — startup-guard gap found by the
  disposable-guest negative matrix: the v1 `NEVER_RECOVERED` startup path
  read `/etc/o3k/recovery-trust.json` and the durable trust high-water but
  never authenticated them, so a tampered installed trust bundle did not
  deny startup. Startup now runs the same `load_trust` verification
  (digest binding, scope, revocation freshness) the designated-tip path
  already used. Fail-before/pass-after: the new root+namespace test
  `tampered_trust_bundle_denies_startup_observation_on_never_recovered`
  fails without the fix and passes with it; the full
  `pp6_c1_reanchor_realfs` suite (the six pre-existing tests plus the two
  added here) passes with it.
- `bins/o3k/src/recovery_installation.rs` + `recovery_files.rs` —
  observer-identity gap found by the same guest matrix: the guard opened
  the `o3k:o3k 0700` journal directory and the `o3k:o3k-compute 0711` data
  root with fd-anchored reads for every consumer, so the compute service
  identity (traverse-only) could never start on a provisioned C1
  installation. SPEC-0050 §7.2.1 gives a NEVER_RECOVERED installation no
  recovery-journal dependency, so the guard now falls back to fail-closed
  metadata-only identity verification for callers that cannot open those
  directories; content access still requires the authority to open them.
  Fail-before/pass-after:
  `genesis_startup_observation_supports_the_compute_identity` fails before
  and passes after, including tampered-trust and substituted-journal-dir
  negatives for the compute identity.

## Security/architecture acceptance request

The release-contract change is exactly the release.yml env block above at
this PR's head commit. Acceptance per ADR-0190 is constituted by the named
reviewer's approval of this PR at its exact head plus the protected merge
SHA; the plan was recorded on #1225 before implementation
(comment 2026-11-16). No private key material is introduced anywhere; no
policy, state, or trust document is synthesized by CI; the C1 verifiers
(`recovery_identity.rs`, `recovery_trust.rs`) are unchanged, and the
packaged-path guard is strengthened (trust authentication at genesis;
observer-identity metadata verification), never relaxed.

## Evidence

- `tests/packaging-bundle.sh`: C1 manifest emission + fail-closed cases
  (run on the clean review head).
- `cargo test -p o3k --test pp6_c1_ceremony_signer`: signer output passes
  the canonical verifiers; tamper negatives fail.
- Disposable Ubuntu 24.04 guest ceremony runs (vendor-verified
  `ubuntu-24.04-server-cloudimg-amd64.img` SHA-256
  `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`,
  throwaway qualification keys, C1-bearing bundle built from this branch on
  the Debian 12 baseline): the ceremony-less install was refused at the
  early gate before any host mutation; prepare -> offline sign -> install
  succeeded; `o3kd` and `o3k-compute` reached `active` and
  `/healthz` returned `{"status":"ok"}`; every negative was rejected —
  tampered policy/state/trust at install (provisioning rejection), and
  tampered installed policy, missing state high-water, and tampered
  installed trust at startup, with recovery after each restore. The matrix
  exposed and fixed two further real defects during development (the
  installer mid-abort foreign-file trap and the observer-identity startup
  gap). On the final bundle (source `5d763e20`, archive SHA-256
  `1ccde68861b38753fad438d25c9a8a6ae98abc8192db5c42a9c3c08d814c0235`) a full
  ceremony run passed every assertion, and two further consecutive full
  passes were recorded on the intermediate head that differed only in the
  journal fallback's error-class restriction. This is
  disposable-guest qualification evidence, not the protected-harness
  installed Q1/Q2 (which remains NOT_RUN until rc.28 is published).

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
- Normative tension recorded for the reviewer: SPEC-0050 §7.2.1 says a
  NEVER_RECOVERED installation "has no recovery-journal or installed
  journal-trust dependency"; the genesis-startup `load_trust` call makes
  startup authenticate trust (including 24 h revocation freshness) before
  any designation. This branch treats that as a fail-closed tightening
  required by the #1225 successor acceptance ("negative tests for
  missing/tampered C1 policy and stale identities"); the reviewer must
  ACCEPT the tightening, or ask for the digest-only variant (tamper
  detection without freshness gating) recorded as the smallest alternative.
- Operators must budget the 24 h revocation refresh cadence
  (`o3k recovery-trust-update`) for any installation that outlives a day
  (docs/operator/C1_OFFLINE_SIGNING_CEREMONY.md).
