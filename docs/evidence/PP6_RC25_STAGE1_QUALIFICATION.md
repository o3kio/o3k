# PP.6 Stage 1 — rc.25 release readiness and qualification evidence

**Exact protected source:** `8e3cfa4e1f0023e29217da709be3de6930a5e891`
(merge of #1201; includes #1198, #1199, #1200, #1202).
**Candidate tag:** `v0.4.0-rc.25` — **not created**; requires explicit human
authorization and the protected `release` environment approval.
**Status:** preflight PASS (source-built); release creation, installed-release
guest qualification and power-loss evidence BLOCKED on human authorization
and a dedicated qualification host. Nothing here closes #1086 or #975.

This document records exact-source evidence only. Source-built results are
not authenticated installed-release results.

## 1. Gate 1 — release readiness verification (PASS)

- Protected `main` fetched and byte-identical to the required SHA
  `8e3cfa4e1f0023e29217da709be3de6930a5e891`.
- Required protected CI on that push: `CI` and `Mock Cinder Component Test`
  both `success` (workflow runs 41319990487 / 41319990509).
- Package version `0.4.0-rc.25` (`Cargo.toml`), installer pin
  `v0.4.0-rc.25` (`packaging/get-o3k.sh:118`), Docker/Helm defaults
  `0.4.0-rc.25`; `tests/release-gate.sh` derives both dynamically and is
  consistent.
- `v0.4.0-rc.25` tag and GitHub release did not exist at verification time;
  latest published release is `v0.4.0-rc.24`.
- `.github/workflows/release.yml` hardcoded notes described a PP.4 Core
  candidate: corrected by PR #1203 (notes-only; protected tag rules,
  `release` environment approval, alpha channel `v0.4.0-rc.5` and upgrade
  minimum `v0.4.0-rc.5` unchanged). PR #1203 awaits human review/merge.

## 2. Gate 2 — release preflight (PASS, source-built; workflow steps pending)

Executed on a detached worktree at the exact protected source:

- `scripts/build-release-binaries-debian12.sh`: PASS. Debian bookworm
  (12.15) rootfs, rustc 1.97.1, `cargo build --release --locked`.
  glibc floor proof: `o3kd`, `o3k`, `o3k-compute` require at most glibc
  2.34 (baseline 2.36).
- Executable SHA-256 (Debian 12 baseline build):
  - `o3kd` `aa4062d8eca4091a790cf9e5b6d4445de5bbb02dd6aee20d58f59039ef570f3f`
  - `o3k` `a8e4a0dcdb3fe00d14649e04b375f3922f77b71ca4b28b2eff3c5baf5e7de84a`
  - `o3k-compute` `08b91dd518608ec196b2cb6d8beb4f6021529e579027a8ef8c187a39b46102c7`
- Production publisher absence: the release-profile `o3k` rejects
  `recovery-migrate-v2` (`unrecognized subcommand`, exit 2; absent from
  `--help`).
- `packaging/make-release.sh 0.4.0-rc.25 libvirt`,
  `make-release-archive.sh`, `verify-release-bundle.sh`: PASS, including
  the verifier's own "A10.1 migration publisher is absent from release
  binary" check.
  - bundle tarball `dist/o3k-0.4.0-rc.25-linux-x86_64.tar.gz`
    `54d60e9e1887b232a384ba3678e6302fc6b916c1b7cc42ab79f0a35487d08c02`
  - `dist/install.sh` `ec9112ea2d21c065b406fc07db330fd5a6c913bdaf52dbb966dd49bde38cf1e9`
  - manifest binds `version 0.4.0-rc.25`, `source_commit 8e3cfa4e…`,
    `schema_version 53`, `upgrade_from.min_version v0.4.0-rc.5`.
- NOT_RUN locally (workflow-only, require GitHub OIDC on the protected
  runner): `make-provenance-sigstore.sh`, cosign keyless signing of
  `release-digests.txt`, `verify-release-sigstore.sh`, Rekor evidence, and
  immutable prerelease publication. These execute only inside the protected
  release workflow after tag creation and environment approval.

## 3. Gate 3/4 — guest provisioning and installed-release qualification (BLOCKED)

The qualification harness `tests/pp6-qualification/host-env.py` (subcommands
`provision`, `destroy`, `force-restart`, `capture-installation`; SHA-256
verified images; run-scoped identity checks) refuses to provision on this
host: IPv4 `ip_forward=1` and IPv6 `all/forwarding=1`. Per the mission and
the harness safety contract, the shared development host was **not**
altered. A dedicated qualification host (KVM/libvirt, forwarding disabled,
no production O3K state, verified Debian 12 + Ubuntu 24.04 cloud images,
isolated networking, separate ext4 recovery-state and journal devices)
remains an outstanding human/infrastructure dependency. Consequently:
exact-artifact installation, C1/C1.1 installed first-install/signed-state/
trust/quarantine/restart cases, guest poweroff/restart, and
`capture-installation` are **NOT_RUN**.

## 4. Gate 5 — Phase B source-built process evidence (partial PASS)

All results are source-built at the exact protected source, run as root on
local ext4 with test-only Ed25519 signing authority. Test keys are not
production custody evidence. This host is not a clean guest; no
installed-release claim is made.

- Journal-v2 consumer unit suite (`restore_journal_v2`, feature
  `a10-process-test-hooks`): **12/12 PASS** — allowlisted transitions;
  Phase B path/mutation executor closed; bounded confirmation binding
  operation+artifact; exact-bytes retry and conflicting-request fork
  rejection; noncanonical/duplicate-member JSON rejection; exact v2
  policy/release/installation/backend bindings; signature tamper, wrong
  signer, wrong scope, revocation and expiry fail closed; sequence/hash
  binding, duplicate replay and branch conflict rejection; append requires
  the exact authenticated prior record prefix; verification record binds
  the complete accepted result; terminal `INACTIVE_VERIFIED` inert and
  denies runtime.
- `pp6_recovery_files` (privileged ext4, `backup-test-hooks`): **4/4 PASS**
  — crash boundaries (before file fsync / after file fsync / after rename /
  after directory fsync) preserve only complete old or new bytes;
  symlink, stale CAS and path replacement rejected; no-follow exclusive
  named lock; packaged-posture acceptance with writable-posture and stale
  device/inode rejection.
- `pp6_c1_startup_process`: **1/1 PASS** — missing fixed release metadata
  denies before store.
- `pp6_c1_prepare`: **3/3 PASS**.
- `pp6_backup_verify_quarantine_process`: **1/1 PASS**.
- `pp6_doctor_quarantine_process`: **1/1 PASS**.
- `pp6_c1_reanchor_realfs` (real ext4, private mount namespace, test-only
  signer): see suite log; includes the signed `NEVER_RECOVERED` migration
  journey through the real `recovery-migrate-v2` CLI with 20 process
  interruption boundaries, replay, and mixed-generation denial.

Retained failures: two first-attempt failures were harness-invocation
artifacts, not product defects — (1) the D8 crash hooks require the
`backup-test-hooks` feature (documented only in code), (2) the migration
journey requires `O3K_A10_SOURCE_O3K` plus a manually staged
`target/a10-fixture/candidate-o3k`. Both were corrected and rerun; the
original logs are preserved alongside the passing logs.

### Newly found product defect (FAIL, retained)

`signed_never_recovered_migration_runs_through_real_cli` **FAILS** at the
exact protected source, reproducibly (three runs): the interrupted
publication boundary itself behaves correctly ("PASS selector
rename-before-directory-fsync: exact signed event visible; v1
policy/high-water/manifest preserved"), but the post-selector process
restart cannot exact-forward to completion. The publisher fails inside
`verify_v2_selected_generation` with, after a temporary scratch-only
diagnostic patch (reverted, never committed):

    Persistence("exact-forward generation verification failed: release checksum inventory is malformed")

Root cause (confirmed by source inspection, no fix attempted here):
`recovery_release_inventory::parse_release_sums`
(`bins/o3k/src/recovery_release_inventory.rs:89-110`) rejects every line
whose path does not start with `"./"`, while the required-asset lookups in
`verify_active_v2_release_inventory` (`:37-47`) use bare names
(`install.sh`, `o3k-<version>/manifest.json`, …) and the map keys retain
the `"./"` prefix. The real signed `release-digests.txt` produced by
`packaging/make-provenance-sigstore.sh` uses bare asset names (matching
`packaging/get-o3k.sh`'s parser), so the inventory verifier can never
accept the authentic digest manifest: unprefixed lines fail parsing, and
`./`-prefixed lines would fail the bare-name asset-set check. Because
`verify_v2_selected_generation` calls this verifier with
`require_complete_generation`, the defect blocks both the A10.1
exact-forward migration completion and operational startup admission of
any v2-selected installation. Introduced with `f879a379` ("gate startup on
complete v2 release inventory"); the #1198 journey evidence appears to
predate that gate. A fail-before control run at the #1198 protected merge
`30a6c6e504ae57d46e686cd45d9960fe0f5291c6` fails identically at the same
assertion, confirming the defect shipped with #1198 and that #1199
(Phase B) did not introduce it. This defect blocks the Gate 5
valid-PREFLIGHTED publication process lane and must become its own
issue/PR; it is tracked as issue #1204 and is not fixed in this campaign.

All other Gate 5 lanes above are unaffected (they do not exercise the v2
inventory verifier).

NOT_RUN (remain open): installed-release execution of all of the above;
the D8-A10-01–16 lanes as exact-release installed process qualification;
guest force-restart/power-cut durability; independent security review.
No PostgreSQL target was created or mutated; no controller was activated;
no operational lease, reconciliation or provider dispatch occurred.

### Gate 5 lane mapping (mission checklist)

| Lane | Status | Evidence |
|---|---|---|
| Valid signed `PREFLIGHTED` publication | PARTIAL | consumer authentication covered by unit suite; end-to-end publication through the real CLI is blocked by #1204 |
| Replay and equal-sequence fork rejection | PASS (unit) | `sequence_hash_binding_duplicate_replay_and_branch_conflicts_are_rejected`, `append_requires_the_exact_authenticated_prior_record_prefix`, `retry_is_exact_bytes_and_conflicting_request_is_a_fork` |
| Wrong signer, scope, policy digest, release identity | PASS (unit) | `signature_tamper_wrong_signer_scope_revocation_and_expiry_fail_closed`, `v2_policy_release_installation_and_backend_bindings_are_exact` |
| Corrupted and noncanonical records | PASS (unit) | `noncanonical_and_duplicate_member_json_is_rejected` |
| Write/fsync/rename/readback interruptions | PARTIAL | `pp6_recovery_files` crash boundaries PASS on real ext4 (process level); journal-v2-specific interruption matrix NOT_RUN |
| Crash/restart with incomplete records | PARTIAL | selector rename crash boundary PASS; exact-forward resume FAIL (#1204); `crash_resume_classifies_lost_ack_known_partial_unknown_and_foreign_state` PASS (unit) |
| Trust revocation and device/inode substitutions | PASS | revocation unit tests; `accepts_packaged_posture_and_rejects_writable_posture_and_stale_identity` (device/inode), `startup_observation_rejects_mixed_generations` |
| D8 exclusion conflicts | PARTIAL | named-lock exclusivity PASS; service-level D8-A10-13–16 lanes NOT_RUN |
| Terminal `INACTIVE_VERIFIED` startup denial | PASS (unit) | `terminal_inactive_verified_is_inert_and_denies_runtime`; systemd-level denial NOT_RUN |
| No PG mutation / controller readiness / lease / reconciliation / provider dispatch | PASS | `path_and_mutation_executor_remain_closed_in_phase_b`; publisher and Phase B code contain no such paths; confirmed by inspection at the exact source |

## 5. Human authorization and infrastructure still required

1. Review/merge PR #1203 (release-notes correction).
2. Authorize immutable tag `v0.4.0-rc.25` on the final protected commit and
   approve the protected `release` environment.
3. Provide the dedicated qualification host per Gate 3.
4. Owner decisions remain outstanding for A10 publisher production
   enablement, activated-recovery (#1086/#975 obligations preserved), and
   independent security acceptance.
