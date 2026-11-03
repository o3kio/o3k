# PP.6 A10.1 publisher signed-release provenance compatibility fix

Follow-up to #1204 / merged PR #1206 (v2 release inventory verifier fix).
Source/unit evidence plus the real-filesystem process journey below; not
installed-release, production, power-loss, or independent-security
qualification. #975 and #1086 remain open.

## Environment

- Worktree: `/home/ubuntu/o3k-prov-compat`, branch
  `fix/pp6-publisher-provenance-compat`, based on protected main
  `9512832ad79da3cc555739dfd94e5708598e2ca4` (merge of PR #1206).
- Filesystem containing `/var/lib`: `/dev/sda1`, ext4, mounted at `/`.
- Kernel: 6.8.0-142-generic x86_64; 16 cores.
- Toolchain: cargo/rustc 1.97.1 (debug/unoptimized profile).
- Runner: root via `sudo -n`; the journey uses the harness's private mount
  namespace with disposable fixture bind mounts.

## Root cause

PR #1206 fixed the v2 startup-admission inventory verifier but not the A10.1
migration publisher. `verify_target_release_provenance_reader` and
`verify_source_release_provenance_bytes` in
`bins/o3k/src/recovery_migration_publisher.rs` each carried their own copy of
the signed-digest parser plus a strict `signed_assets.len() ==
required.len()` six-asset equality. The authentic
`release-digests.txt` produced by `packaging/make-provenance-sigstore.sh`
(`sha256sum <asset>` from the dist root) has seven bare-name entries — the
six required assets plus `provenance.json` — so both verifiers rejected every
real signed source and target release with "release digest statement has an
unexpected asset set" / "source release has an unexpected signed asset set".
The publisher could never authenticate a real signed release.

## Fix

Minimal diff; publisher error reasons remain the publisher's own
`MigrationError::Rejected(...)` variants:

- `parse_signed_release_digests` (from #1206, in
  `recovery_release_inventory.rs`) is now `pub(crate)` and is used by both
  publisher verifiers instead of the two inline parser copies;
- both verifiers now require every required asset to be present and tolerate
  additional signed assets (the authentic `provenance.json` entry);
- the parser also rejects unsafe paths (absolute, `./`-prefixed, `.`/`..`/
  empty components) and duplicates, matching startup admission.

Unchanged security properties:

- the release signature is verified over the exact original digest bytes
  before any parsing (`verify_release_signature` runs first in both
  verifiers);
- the signed candidate archive digest must equal the independently computed
  artifact digest; archived `manifest.json`/`SHA256SUMS` bytes must hash to
  the signed digests; the installed manifest must be the exact
  `manifest_with_verified_artifact` augmentation of the signed bundle
  manifest; the installed source `SHA256SUMS` must hash to the signed digest;
- bounded input handling is unchanged (root-owned bounded reads via
  `read_root_input`/`read_root_file` with `MAX_INPUT`; archive members are
  read with `.take(MAX_INPUT + 1)`);
- no signer private material is added anywhere; the test-only Ed25519
  fixture seed is constructed in memory only.

`bins/o3k/tests/pp6_c1_reanchor_realfs.rs`: the `a10_release_digests`
fixture now signs the extra `provenance.json` entry in every source and
target release, so the real-filesystem journey exercises authentic
seven-entry provenance through the real publisher CLI.

## Fail-before (base tree, fix reverted, tests present)

Base: protected main `9512832ad79da3cc555739dfd94e5708598e2ca4`;
publisher source blob `fe79db422e4b3fc49df0bb0cf34eb3922a0e23cd`,
inventory blob `6ea499ad4468abf752bbff7bd318dfb2753b0735` (both at HEAD, via
`git rev-parse HEAD:<path>`). The publisher file was temporarily restored to
its HEAD content with the new test module appended; the
`recovery_release_inventory` fix and the realfs fixture change stayed in
place (they do not affect the publisher code under test).

Command:

```
cargo test -p o3k --all-features --lib \
  recovery_migration_publisher::signed_release_provenance_tests
```

Result: FAILED. Log: `/tmp/pp6-fail-before.log` (sha256
`0f9ea0406b6ede93e38673976c48e2f0300e76e4d714c42290a4c5f2d4b53962`).
6 passed; 1 failed: `authentic_seven_entry_signed_manifest_is_accepted_by_both_verifiers`
panicked with

```
Rejected("release digest statement has an unexpected asset set")
```

i.e. the authentic seven-entry signed manifest is rejected by the unfixed
publisher. All negative tests (missing assets, digest mismatch, malformed
entries, tampered/wrong signature) already passed at base.

## Fix-after (this branch)

Same command. Result: PASS, 7/7. Log: `/tmp/pp6-fix-after-focused.log`
(sha256 `5d14bd335ae4fd440c7d20ffd64c0002dc90ce929cccb6dacc9a671761411abc`).

## Test matrix (new unit tests, `signed_release_provenance_tests`, cfg
`all(test, feature = "a10-process-test-hooks")`, test-only fixture signer)

- authentic seven-entry manifest accepted by both
  `verify_target_release_provenance_reader` (in-memory tar.gz candidate with
  manifest+SHA256SUMS matching the signed digests, augmented installed
  manifest via `manifest_with_verified_artifact`) and
  `verify_source_release_provenance_bytes`; exact byte-identical retry
  re-verification retains the same authenticated identities — PASS;
- each of the six missing mandatory assets rejected by both verifiers — PASS;
- signed archive digest mismatch rejected — PASS;
- archive bytes disagreeing with the signed digests rejected — PASS;
- installed-manifest mismatch and installed checksum-inventory mismatch
  rejected — PASS;
- duplicate, short/uppercase digest, extra-column, absolute, `./`-prefixed,
  `..`, and empty-component entries rejected — PASS;
- tampered-after-signing and wrongly-signed (unpinned key) manifests
  rejected — PASS;
- v2 startup admission fail-closed: unchanged `recovery_release_inventory`
  tests (`parses_authentic_signed_release_digests`,
  `signed_digest_paths_must_be_bare_relative_names`,
  `signed_digest_lines_must_be_well_formed`) still pass; the publisher tests
  above add signed-but-malformed rejection at the same shared parser. The
  startup-admission function itself reads installed root paths
  (`/usr/local/...`) and cannot run as a plain unit test; it is covered by
  the real-filesystem journey below — PASS (source tier);
- production exclusion: the existing guarded checks were run, not replaced
  (see gates).

## Gates

- `cargo fmt --all -- --check`: clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  clean.
- `cargo test -p o3k --all-features`: PASS (478 lib tests incl. the 7 new
  ones; all integration suites ok).
- `cargo test --workspace --all-features`: PASS (exit 0; 199 ok suites, 0
  failed).
- `bash tests/a10-production-publisher-disabled.sh` (existing CI release
  guard; builds the release `o3k`, asserts `recovery-migrate-v2` absence, no
  publisher symbols, no fault-injection markers, no fixture key, and the
  optimized-feature build-time rejection): PASS.
- Real-filesystem journey `signed_never_recovered_migration_runs_through_real_cli`
  (ignored; root, private mount namespace, test-only signer): see below.

## Real-filesystem process journey

Command (binaries built as the ubuntu user first; staged
`target/a10-fixture/candidate-o3k` with `a10-process-test-hooks`,
`target/a10-fixture/source-o3k` without it, `o3kd` with
`backup-test-hooks`, `o3k-compute-bin`/`o3k-network-bin` from
`target/debug`):

```
sudo -E env O3K_A10_SOURCE_O3K=$PWD/target/a10-fixture/source-o3k \
  O3K_A10_CANDIDATE_O3K=$PWD/target/a10-fixture/candidate-o3k \
  /home/ubuntu/.cargo/bin/cargo test -p o3k --features a10-process-test-hooks \
  --test pp6_c1_reanchor_realfs signed_never_recovered_migration_runs_through_real_cli \
  -- --ignored --nocapture
```

Result: PENDING at the time of writing; the journey now exercises the
authentic seven-entry fixture through the real publisher. See the PR for the
final verdict; a PASS/FAIL update is posted there when the run completes.

## NOT_RUN

- Installed-release / production qualification of the A10.1 path (this is
  source-built fixture evidence with a test-only signer). Authenticated
  installed-release qualification needs a successor candidate: published
  `v0.4.0-rc.25` (`42de13cee64a37d69e900fd4272ff5e849a328b8`) does not
  contain #1206 or this fix, and no tag may be created/published without
  owner authorization through the protected release workflow
  (see `PP6_INSTALLED_RELEASE_QUALIFICATION_PLAN.md`).
- Host power-loss evidence (guest force-restart is not host power-loss
  evidence); the shared runner has forwarding enabled, so the PR #1200
  guest harness refuses provisioning here.
- Protected CI on the pushed head (pending this PR).
