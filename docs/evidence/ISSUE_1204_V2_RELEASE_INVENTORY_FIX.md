# #1204 A10.1 v2 release inventory verifier fix

Source-built fixture evidence only, from the retained PP.6 rc.25 Stage 1
failure documented in `PP6_RC25_STAGE1_QUALIFICATION.md` §"Newly found
product defect (FAIL, retained)". It is not installed-release or production
qualification.

## Environment

- Filesystem containing `/var/lib`: `/dev/sda1`, ext4 (statfs `ext2/ext3`
  magic), mounted at `/`.
- Kernel: 6.8.0-142-generic x86_64; 16 cores.
- Toolchain: cargo/rustc 1.97.1 (debug/unoptimized profile).
- Runner: root via `sudo -n`; each namespace run uses the harness's private
  mount namespace with disposable fixture bind mounts.
- Executables: Cargo-built `o3k` (feature `a10-process-test-hooks`) as
  `target/a10-fixture/candidate-o3k` (the CLI under test) and
  `target/a10-fixture/source-o3k` (separately built non-feature source
  executable for `O3K_A10_SOURCE_O3K`); `o3kd`, `o3k-compute-bin`,
  `o3k-network-bin` from this checkout's `target/debug`.
- Protected commit: `2e08a727d0437c2090f6116ea95b11f9109c701a`
  (branch `pp6/rc25-stage1-evidence`).

## Root cause

`verify_active_v2_release_inventory` parsed the signed
`migration-v2-release-digests-<digest>.txt` with `parse_release_sums`, which
hard-requires `./`-prefixed paths, while the authentic manifest produced by
`packaging/make-provenance-sigstore.sh` (`sha256sum <asset>` from the dist
root) uses bare asset names. Every authentic line was rejected with "release
checksum inventory is malformed". The strict 6-asset length equality would
additionally have rejected the authentic 7-entry manifest (it includes
`provenance.json`) even with a lenient parser.

## Fix

`bins/o3k/src/recovery_release_inventory.rs`:

- new `parse_signed_release_digests` for the signed digest manifest: exactly
  two whitespace-separated columns, 64 lowercase hex digest, bare relative
  asset paths (empty/absolute/`./`-prefixed/`.`/`..`/empty components
  rejected), duplicate paths rejected;
- the asset-set check now requires every required asset to be present and
  tolerates extra signed assets;
- `parse_release_sums` is unchanged and remains used only for the installed
  bundle `SHA256SUMS` (strict `./` format).
- The A10.1 migration publisher uses this same strict signed-manifest parser
  for both source and candidate provenance, and requires the required assets
  while permitting additional signed assets such as `provenance.json`.

## Harness correction (not a product change)

With the verifier fixed, an installed consumer (o3kd, `o3k doctor/upgrade/
rollback` as the service user) at a fully published-but-inactive v2
generation now runs the complete generation verification — including SHA-256
over the four installed executables — before denying at the compute-posture
gate ("installed compute admission is incomplete"). In this unoptimized
debug build that denial costs ~26 s CPU-bound (`perf`: >85 % in sha2 x86
block functions), far over the harness's `timeout 4`, so the first fix-after
run failed at the `v2-generation-verified-before-guard-release` consumer
denial with a false "stayed alive / advertised readiness". The denial itself
was verified correct against the preserved fixture. The deny helper bound in
`assert_incomplete_v2_consumers_denied` was raised `timeout 4` -> `timeout
120` with a comment; no assertion or grep pattern was weakened (a consumer
that advertises readiness still trips the 124 liveness failure).

## Fail-before (protected commit, pre-fix tree)

Command:

```
sudo -E env O3K_A10_SOURCE_O3K=$PWD/target/a10-fixture/source-o3k \
  cargo test -p o3k --features a10-process-test-hooks \
  --test pp6_c1_reanchor_realfs signed_never_recovered_migration_runs_through_real_cli \
  -- --ignored --nocapture
```

Result: FAILED (finished in 308.78s). Log:
`/tmp/issue1204-fail-before.log` (sha256
`9f464390e7b328debffbc0360619d6d7b77f987a01b5bea1edfd1dbafc0a4952`).

Excerpt:

```
PASS selector rename-before-directory-fsync: exact signed event visible; v1 policy/high-water/manifest preserved

thread 'signed_never_recovered_migration_runs_through_real_cli' (2448135) panicked at bins/o3k/tests/pp6_c1_reanchor_realfs.rs:1814:5:
post-selector process restart did not exact-forward from staged authenticated inputs: stdout= stderr=C1_REANCHOR_NAMESPACE_READY
installation policy migration failed: Persistence("exact-forward generation verification failed")
```

The interruption boundary itself behaved correctly; the post-selector
exact-forward retry failed inside `verify_v2_selected_generation`
(`recovery_migration_publisher.rs:2341-2346`), which discards the inner
verifier reason ("release checksum inventory is malformed" from
`parse_release_sums`, confirmed at the rc.25 campaign with a temporary
diagnostic patch, since reverted).

## Fix-after

Same command on the fixed tree. Result: **PASS** (`test result: ok. 1
passed; 0 failed; 5 filtered out; finished in 6951.88s`). Log:
`/tmp/issue1204-fix-after2.log` (sha256
`c426d1a7c3a4cc6ab5479c41ecda5e33b30613f794ad84dbd1af03196593338d`), 33 PASS
lines, including:

- `PASS selector rename-before-directory-fsync: exact signed event visible; v1 policy/high-water/manifest preserved`
- `PASS signed NEVER_RECOVERED v1-to-v2 migration, restart exact-forward completion, and idempotent replay`
- all 20 `PASS A10 publication crash/restart boundary: <point>` lines, each
  retrying to `V2Complete` and replaying byte-identically;
- `PASS incomplete-generation consumer denial: o3kd, o3k doctor/upgrade/rollback, o3k-compute at <point>` at every v2-selector fault point, including `v2-generation-verified-before-guard-release`;
- `PASS A10 direct compute invocation denied during D8; publisher resumed`.

(An intermediate fix-after run without the harness bound correction failed
at exactly one assertion — the `v2-generation-verified-before-guard-release`
consumer denial timeout described above; its diagnosis and correction are
part of this fix, not a product change.)

## Unit tests and gates

- `cargo test -p o3k recovery_release_inventory`: 3 passed, 0 failed
  (`parses_authentic_signed_release_digests`,
  `signed_digest_paths_must_be_bare_relative_names`,
  `signed_digest_lines_must_be_well_formed`).
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  clean (run after the test-file edit).
- `cargo test -p o3k --all-features` and `cargo test --workspace
  --all-features`: all suites ok, 0 failed (workspace run repeated after the
  test-file edit).

## PR review follow-up

Review found that the migration publisher had two separate exact-six-asset
checks for source and candidate releases. Both now share the signed-manifest
parser and permit authenticated extra entries; the source/candidate realfs
fixture includes `provenance.json` to cover that case. After this follow-up,
`cargo fmt --all -- --check`, workspace Clippy, and
`cargo test --workspace --all-features` pass. The latter does not run the
ignored root/private-mount-namespace realfs migration test, so the fixture
change is compiled but that host gate has not been rerun here.

## NOT_RUN

- Installed-release / production qualification of the A10.1 path (this is
  source-built fixture evidence with a test-only signer).
- Consumer-deny latency was measured only in this unoptimized debug build; a
  release-profile installed host hashes far faster.
