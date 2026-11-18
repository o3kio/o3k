# rc.28 edge-pilot GO/NO-GO report (issue #1225, 2026-11-17)

**Verdict: NO-GO for the edge pilot today — the blocker fix is implemented
and locally qualified, but the pilot requires the published rc.28, which does
not exist yet.** This is a gate-status report, not a failure report: every
locally executable gate passes. The remaining gates are operator-only by
design (protected review, release-environment custody, Sigstore publication,
protected-harness Q1/Q2, physical edge hardware).

## Exact source and artifacts

- Fix branch: `fix/1225-c1-bearing-release`, PR #1229 (the branch is stacked
  on PR #1231's exception commit; see the PR for the current head). The
  ceremony-tested bundle was built from pre-rebase `5d763e20`, whose tree is
  content-identical to the rebased equivalent on the branch.
- Blocked release: `v0.4.0-rc.27`, tag object
  `80cdab1568ef0972602214d0c4656ad70858c07e`, source
  `9427e7668afa76bf1f043c9adabe1d616cf5924a` — immutable, not retagged;
  #1225 documents its dead-on-arrival installed startup.
- Local qualification bundle (NOT the release): `0.4.0-rc.28` libvirt,
  source `5d763e20`, archive SHA-256
  `1ccde68861b38753fad438d25c9a8a6ae98abc8192db5c42a9c3c08d814c0235`,
  Debian 12 glibc-2.36 baseline binaries, C1-bearing manifest with the
  throwaway qualification authority `c1qual-policy-2026-11`.
- Companion: PR #1231 (`fix/supply-chain-rustsec-2026-0543`) — reviewed
  exception for the new chrono unmaintained advisory that otherwise fails
  every CI run since 2026-11-17. #1229 is stacked on #1231's commit so its
  CI is green now; after #1231 merges, #1229 rebases onto main with no
  content change.

## What is proven (local, disposable-guest, qualification-only keys)

Two consecutive full passes of `tests/pp6-c1-ceremony/run-guest-ceremony.sh`
on clean disposable Ubuntu 24.04 KVM guests (vendor-verified cloud image
SHA-256 `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`),
plus earlier partial runs that caught real defects:

1. A C1-bearing bundle refuses a ceremony-less install before any host
   mutation (early gate), with the journey message.
2. The complete journey works: `install.sh --c1-prepare-only` → unsigned
   descriptor → offline signing (throwaway keys, host-side
   `tests/pp6-c1-ceremony/sign.py`, pinned to the canonical Rust verifiers by
   `bins/o3k/tests/pp6_c1_ceremony_signer.rs`) → install with
   `--c1-policy/--c1-state/--c1-trust` → `o3kd` and `o3k-compute` both
   `active`, `/healthz` `{"status":"ok"}`.
3. Negative matrix all fail closed: tampered policy/state/trust at install
   (provisioning rejection); tampered installed policy, missing state
   high-water, and tampered installed trust at startup; recovery after each
   restore.
4. Root+namespace suites: all eight `pp6_c1_reanchor_realfs` tests pass,
   including fail-before/pass-after for the two guard fixes
   (`tampered_trust_bundle_denies_startup_observation_on_never_recovered`,
   `genesis_startup_observation_supports_the_compute_identity`).
5. Gates on the PR head: `cargo fmt --all -- --check`, `cargo clippy
   --workspace --all-targets --all-features -- -D warnings`, `cargo test
   --workspace --all-features`, and the packaging/installer/release shell
   suites all pass. (One o3k-store timeout test is load-flaky on this
   development host; it passes in isolation and in CI.)

Defects found and fixed by this campaign (all in the PR): installer
mid-abort foreign-file trap; genesis startup did not authenticate installed
trust; the startup guard fd-opened directories the compute service identity
may only traverse, so `o3k-compute` could never start on a provisioned C1
installation.

## What is NOT proven (operator-gated)

- **Published rc.28**: requires protected review/merge of #1229 (+ #1231),
  the `release` environment variables `O3K_C1_INSTALLATION_POLICY_KEY_ID` /
  `O3K_C1_INSTALLATION_POLICY_PUBLIC_KEY` (public key of the real offline
  authority), then tag `v0.4.0-rc.28` and the protected release workflow;
  then independent Sigstore/provenance/archive/binary verification.
- **Installed Q1/Q2 on the published release** via the PP.6 harness
  (readiness, real libvirt tenant create/boot/reboot/delete, network
  cleanup), including the not-yet-defined PG16 restart/reconciliation
  scenario.
- **The physical edge pilot itself** (hardware, site network).
- The ceremony used throwaway keys on the build host; production custody
  (2-of-3 custodians, offline workstation) is exercised only in the real
  pilot.

## Residual risks

- **SPEC-0050 §7.2.1 tension RESOLVED (owner decision on #1225, 2026-11-18)**:
  the digest-only variant was requested. Genesis startup authenticates
  installed trust digest-only (tamper detection without freshness gating);
  designated or previously recovered installations keep the full freshness/
  revocation gate. The correction PR implements exactly that scope, so rc.28
  carries it from the protected merge.
- **24 h trust refresh cadence**: any installation that enters recovery
  designation needs `o3k recovery-trust-update` operations; documented in
  `docs/operator/C1_OFFLINE_SIGNING_CEREMONY.md`.
- **v2 selector observer gap**: #1230 (unreachable in rc.28).
- **One-line installer**: by design it stops at the C1 journey message on
  C1-bearing releases; operators must use the bundle's `packaging/install.sh`
  ceremony path.
- The disposable-guest qualification used the libvirt TestLab profile with
  SQLite; no PostgreSQL, no VM lifecycle stage, no network-storm or soak
  coverage is claimed.

## Next operator action

1. Review/merge PR #1231, then PR #1229 (exact-head acceptance per
   ADR-0190; the security-relevant head content is the release.yml env block,
   install.sh gate, and the two guard fixes).
2. Configure the two `release`-environment variables with the real authority
   key id/public key; tag `v0.4.0-rc.28` from the protected merge; verify the
   publication independently (Sigstore bundle, provenance, archive and binary
   digests).
3. Run the protected-harness installed Q1/Q2 on the published rc.28 with the
   real custody ceremony (docs/operator/C1_OFFLINE_SIGNING_CEREMONY.md),
   adding the PG16 restart/reconciliation scenario.
4. Only then execute the controlled edge pilot with disposable workloads,
   recording evidence under the PP matrices and #968.

**Persistent workloads remain NO-GO** until #1085/#1086 (authenticated
PostgreSQL recovery/fencing) and #1087 (certificate replacement/revocation)
pass, independent of this report.
