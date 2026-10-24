# #1084 authenticated backup artifact — Phase-8 Slice F evidence

Date: 2026-10-24. Branch: `pp6/1084-artifact`.

Current state: the Slice F implementation is committed at
`50113f7a4efba261ee8af08abeee726b1d04fd6f` (tracked tree clean at run time),
and this document is bound to that run in `FINAL-COMMIT-BINDING` below. This
document was amended after the bound run; the binding names the implementation
commit whose tree was tested. Per-run fields (artifact digest, ids, timestamps)
are facts of that run and vary on re-execution.

## FINAL-COMMIT-BINDING

Status: **COMPLETE** for the artifact campaign run recorded below. The document
was then amended in a follow-up commit; the binding refers to the implementation
commit named in `final_commit`, whose tracked tree was clean at run time.

Commands run on the final implementation commit (from the repository root):

```bash
git status --porcelain --untracked-files=no
git rev-parse HEAD
sha256sum tests/pp6_backup_artifact.sh tests/pp6_backup_handoff.sh
cargo fmt --all -- --check
cargo clippy -p o3k -p o3k-store -p o3kd --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p o3k -p o3k-store -p o3kd --all-features
cargo test --workspace --all-features
bash -n tests/pp6_backup_artifact.sh tests/pp6_backup_handoff.sh
shellcheck -S warning tests/pp6_backup_artifact.sh tests/pp6_backup_handoff.sh
bash tests/pp6_backup_artifact.sh        # run 1
bash tests/pp6_backup_artifact.sh        # run 2
bash tests/pp6_backup_handoff.sh
bash tests/adr-governance.sh
bash tests/supply-chain-governance.sh
```

Recorded runs: the artifact campaign was executed three times (the bound run
recorded here plus two consecutive re-runs on the delivered tree) and the
handoff campaign was re-run on the delivered tree; every run produced the row
outcomes below. The per-run fields printed in the verdict JSON (artifact
digest, backup id, data-directory identities) differ between runs by
construction; the row matrix does not.

Recorded result:

```text
final_commit: 50113f7a4efba261ee8af08abeee726b1d04fd6f
clean_tree_at_run: yes (tracked tree clean; only unrelated untracked build/campaign dirs)
harness_sha256: 92e64bb9ccb4846550aeca1675b14f681de6dcd958b0c4e98c0d59aaca890214
handoff_harness_sha256: bc79562028ff5c3097da706b93f4063db19ea51b1b65b67a8682d5c5b2d3caff
artifact_campaign: 44 PASS rows / 1 NOT-COVERED row / 0 FAIL rows
handoff_campaign: 19 PASS rows / 7 documented rows / 0 FAIL rows
workspace_gate: cargo fmt clean; workspace clippy -D warnings clean; cargo test --workspace --all-features exit 0 (145 suites)
verdict:
{
  "backup_digest": "d17f29fe439ac2ffec1e444d653ca75cfba19d6db4069b38ef20b2efb263e355",
  "backup_id": "00f3b95b-81bc-4fdd-9e36-e760df5ffed6",
  "backup_installation_id": "e951cb8e47034d2939880b809a5f6d31",
  "backup_site_id": "49fbf3953a4e06f1d2ac75108456186c",
  "backup_size_bytes": 1261601,
  "campaign": "tests/pp6_backup_artifact.sh",
  "executed_rows": 44,
  "failed_rows": 0,
  "harness_sha256": "92e64bb9ccb4846550aeca1675b14f681de6dcd958b0c4e98c0d59aaca890214",
  "host_identity_hash": "8110f5814f95639d2d88a1e379a827e065c9c072b52b54c92f4ce2b1051f54bb",
  "issue": 1084,
  "matrix": {
    "FAIL": 0,
    "NOT-COVERED": 1,
    "PASS": 44
  },
  "max_migration_checksum": "7a2333035bc23d000c129d6d87d236b119a69bbc2de5bda6e41618c6b1488fc0",
  "max_migration_version": 53,
  "not_covered_rows": 1,
  "o3k_binary_sha256": "2624568d23a53888df96b1d919864a213ddaa91c990a9dea75e6698635ec9d81",
  "o3kd_binary_sha256": "5cb9597cd7af9127b683458ab8b2d63fb1865ccfa22b2a914ead897eb4c81967",
  "passed_rows": 44,
  "profile": "o3k-demo-v1",
  "release_artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "rustc_version": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
  "schema_version": 53,
  "slice": "F",
  "source_sha": "50113f7a4efba261ee8af08abeee726b1d04fd6f",
  "sqlite_version": "3.46.0",
  "state_inventory_sqlite_version": "3.46.0",
  "working_tree_dirty": false
}

```

Note: `release_artifact_sha256` is the campaign fixture's placeholder value
(`aa…`), not a real release tarball digest; the evidence campaigns run from a
source build with a labelled fixture release manifest. A real installed release
records the digest verified by the installer/upgrade path.

The recorded `harness_sha256` / `handoff_harness_sha256` values are byte-identical
to the delivered campaign scripts at the bound commit and at the PR head.

Post-binding delta: PR head `3f7b2d1f` adds `packaging/backup-trust.example.json`
to the release-bundle file lists (`packaging/make-release.sh`,
`tests/packaging-bundle.sh`) and touches no product code or harness;
`tests/packaging-bundle.sh`, `packaging-safety` and `packaging-sbom` pass at
head. The implementation binding above does not change.

This document reports executable, real-process evidence for the signed backup
artifact lifecycle only. The implementation is authored by the same agent that
authored this campaign; see the *No independent review yet* non-claim under
**Honest non-claims** below.

## Environment

| Item | Value |
| --- | --- |
| campaign harness | `tests/pp6_backup_artifact.sh` |
| harness SHA-256 | `92e64bb9ccb4846550aeca1675b14f681de6dcd958b0c4e98c0d59aaca890214` |
| build | `cargo build -p o3k -p o3kd --features o3kd/backup-test-hooks,o3k/backup-test-hooks` |
| `o3k` binary SHA-256 | `2624568d23a53888df96b1d919864a213ddaa91c990a9dea75e6698635ec9d81` |
| `o3kd` binary SHA-256 | `5cb9597cd7af9127b683458ab8b2d63fb1865ccfa22b2a914ead897eb4c81967` |
| rustc | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| SQLite (from the published manifest) | `3.46.0` |
| SQLite generator version (baseline `state_inventory_v1.json`) | `3.46.0` |
| schema version | `53` |
| product/deployment profile | `o3k-demo-v1` (SQLite TestLab/portable path) |
| host identity hash | `8110f5814f95639d2d88a1e379a827e065c9c072b52b54c92f4ce2b1051f54bb` |

The host identity hash is `SHA-256(hostname + "\n" + uname -srm)`. It is a
host-label stabilizer only; the backup site/installation identities are derived
from the canonical data directory and differ per campaign run (they are listed
in the verdict JSON for the recorded run).

## Fixtures (no secret values are reproduced here)

Everything lives in a fresh `mktemp -d` tree, mode `0700`.

The installer ships `packaging/backup-trust.example.json` to
`<prefix>/share/o3k/backup-trust.example.json` (mode `0644`, no key material) as
the field-by-field template operators copy to `/etc/o3k/backup-trust.json` as
`root:o3k 0640` (or `0600`). The example is capture-only: it names
`recipient.x25519_public_key` and no private-key path. The X25519 private key is
recovery-host-only (`0600`, or `0400`) and is needed only by
`o3k backup verify`. The installer never creates the trust document itself; the
`/etc/o3k` directory it may create is `0755` (readable/traversable, **not**
group- or other-writable), and the installer never creates a
group/other-writable trust document or key path.

| Fixture | Generation | Posture |
| --- | --- | --- |
| offline Ed25519 signing key | `openssl genpkey -algorithm ED25519` in the test tree; never passed to `o3k`/`o3kd` | `0600`; only the harness reads it |
| foreign Ed25519 key (negative test) | second `openssl genpkey -algorithm ED25519` | `0600` |
| X25519 recipient keypair | `openssl genpkey -algorithm X25519`; the raw 32-byte private half feeds the trust document, the public half is the fingerprint asserted in the signing request. A second keypair is the `case-17` substitution fixture. | `0600` |
| trust document | `o3k-backup-trust-v1` JSON: site/installation identities derived as `SHA-256(domain ‖ 0x00 ‖ canonical data dir)[:16]`, profile `o3k-demo-v1`, `artifact_signing.key_id=signing-1`, custody record `2-of-3` purpose `artifact-signing` with a mandatory `expires_at`, `revoked_key_ids=[]`, recipient key id `recovery-1`, private-key path and declared `x25519_public_key`. Loading is lazy: the document is read without opening the private key, and the public/private match is proved only when verification loads the private key. | TestLab `0600`; packaged `root:o3k 0640` (or `0600`), parent dirs `0700` |
| installed release manifest | `<prefix>/share/o3k/release-manifest.json`: `version=0.4.0`, `profile_id=o3k-demo-v1`, `source_commit=0123…4567`, `release_artifact_sha256="a"×64`, `schema_version=53` | `0600` |
| artifact-signing public key | DER tail 32 bytes of the Ed25519 key; embedded in the trust document | public |
| private seed / recipient bytes | extracted only for the secret scan (hex); never written to any captured output | not logged |

`release_artifact_sha256="a"×64` is a fixture constant: the installed manifest
is a synthetic bundle identity, not a real release tarball digest. A production
installation gets that field from the installer/upgrade engine's verified
tarball digest (`bins/o3k/src/upgrade/release_identity.rs`). In this campaign
the trust document named by `O3K_BACKUP_TRUST_CONFIG` is a **fixture trust
document**; the success JSON's "configured trust document" wording is the same
code path production runs against the root-owned installed document.

### Offline signing procedure

`o3k backup create` carries `signing_input_base64url` in the signing request.
The harness decodes it, verifies `signing_input_sha256`, and signs the exact
bytes with `openssl pkeyutl -sign -rawin -inkey <key>`. OpenSSL 3.0.13 supports
Ed25519 raw signing. If that is unavailable the harness falls back to python3
`cryptography` (`Ed25519PrivateKey.sign`); both are present on the recording
host and OpenSSL is the path actually used. The harness then writes
`signing-response.json` (`request_sha256` = SHA-256 of the request file,
`key_id`, 128 lowercase hex signature, `signed_at`) with mode `0600`.

### Test-only crash hooks (feature `backup-test-hooks`)

All hooks are compiled only with `--features o3k/backup-test-hooks`; a release
or default build contains no environment-controlled process exit and no
production semantics change.

| Environment variable | Exit | Location | Meaning |
| --- | --- | --- | --- |
| `O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_CAPTURED=1` | 86 | `bins/o3k/src/backup_create.rs` after the durable `captured` write | crash before staging |
| `O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_STAGED=1` | 87 | `bins/o3k/src/backup_create.rs` after the durable `staged` write | crash before the signing wait |
| `O3K_BACKUP_TEST_EXIT_AWAITING_SIGNATURE=1` | 91 | `bins/o3k/src/backup_artifact.rs` inside the signing wait, after the `awaiting-signature` line | crash during the wait with the store lock and the marker held |
| `O3K_BACKUP_TEST_EXIT_AFTER_FINALIZE=1` | 90 | `bins/o3k/src/backup_artifact.rs` after finalize removes `artifact.unsigned`, before the `publishing` journal write | crash in the finalize/journal window (F9) |
| `O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_PUBLISHING=1` | 88 | `bins/o3k/src/backup_artifact.rs` after the durable `publishing` write | crash before publication |
| `O3K_BACKUP_TEST_EXIT_AFTER_PUBLICATION=1` | 89 | `bins/o3k/src/backup_artifact.rs` after `published` + staging/marker cleanup | crash before the success document |
| `O3K_BACKUP_TEST_AWAIT_TIMEOUT_SECONDS=<n>` | — | `bins/o3k/src/backup_create.rs` bounded await policy | shorten the wait so the safe abort is observable (`case-4e`) |
| `O3K_BACKUP_TEST_AWAIT_POLL_MS=<n>` | — | same | poll interval for the response file |
| `O3K_BACKUP_TEST_STOP_AFTER_STAGING=1` | — | `bins/o3k/src/backup_create.rs` after the durable `staged` write | harness-only one-shot phase 1 (`signing-required`, exit 3); used by `tests/pp6_backup_handoff.sh`, which exercises the handoff/lock matrix and not the Option A wait |
| `O3K_BACKUP_TEST_SKIP_MARKER_CLEANUP=1` | — | same | keep the denial marker on the one-shot path (`case-l1`) |

The existing handoff hooks/barriers (`94`–`99`, executor barrier) are unchanged
and remain covered by `tests/pp6_backup_handoff.sh`.

## What this proves

- Real `o3kd` → real `o3k backup create` authenticated handoff; the capture
  process then holds the store lock **and** the denial marker while it captures
  a quiesced SQLite snapshot, assembles the encrypted v1 artifact (manifest,
  HPKE-wrapped content key, AES-256-GCM members, unsigned Ed25519 slot) and
  writes the offline signing request. It emits one stable
  `o3k backup create: awaiting-signature <operation-id>` line (operation id
  only, no path) and stays in the
  wait (ADR-0190 Option A: "the controller remains stopped throughout
  signing"), so no replacement controller can start.
- The waiting process verifies the detached response against the fixture trust
  document (`O3K_BACKUP_TRUST_CONFIG` in this campaign; production uses the
  root-owned installed `/etc/o3k/backup-trust.json`), publishes
  `<destination>/backup-<operation id>.o3k` with an atomic no-replace
  publication, removes the marker and exits 0. A request that expires first
  performs the **safe abort** (staging tree removed, journal `aborted`, marker
  removed, exit 3 `signing-request-expired`).
- A crash during the wait leaves the marker and the `staged` journal; the same
  command resumes the wait/publication without recapturing, and a controller
  restart is refused until verified publication (or the safe abort) removes the
  marker.
- `o3k backup verify --artifact` takes the same lifetime store lock (D4), so it
  refuses to inspect the store while a controller or a capture owns the data
  directory (`controller-active`, exit 2), authenticates the published bytes
  against the installed exact release and removes its private plaintext
  staging. The `controller-active` refusal itself is integration-covered only
  (`bins/o3k/tests/backup_verify.rs::rejects_verification_while_the_store_lock_is_held`);
  every verify row in the matrix runs with no live controller, so it is not a
  matrix row.
- The publication boundary rejects tampering, a pre-existing destination
  (including a symlinked or non-regular entry), destination symlink swaps,
  wrong/foreign/short/mismatched signatures, an expired request, and a revoked
  key, with stable exit codes; post-publication state is recovered
  destination-first even when the staging tree is already gone.
- Crash/restart behavior at `captured`, `staged` (during the wait),
  `publishing` and post-publication is observable and recoverable (or refused)
  exactly as the journal contract states; journal phases only move forward.
- The source database is byte-identical across capture, publication and verify;
  only the operation journal (and transient WAL/lock/socket entries) appears in
  the data directory.
- D9 `source_bytes`/`reserved_bytes` reported by the capture equal an
  independent measurement taken after the WAL checkpoint (main database, any
  remaining non-empty `-wal` sidecar — normally absent/zero after a truncating
  checkpoint — the installation metadata members and the bounded
  capture/request metadata allowance) and `max(2×S + 1 GiB, 6 GiB)` with no
  truncation; the same reservation is re-checked before finalize and before
  publication and never lowered to fit. Only the reported numbers are a matrix
  row (`case-10`); the pre-finalize/pre-publication re-checks are
  unit-only (`backup_reservation::tests::boundary_recheck_never_truncates_the_remaining_reservation`)
  and no matrix row consumes the filesystem between checks.
- A seeded non-terminal Operation makes the manifest record
  `in_flight_operations=recorded_unknown` (with the stable ids in the capture
  metadata member) instead of claiming `drained`. This is matrix row `case-23`
  when `sqlite3` is installed (the harness seeds the row directly in SQLite);
  without `sqlite3` the row is NOT-COVERED and the claim rests on the unit
  tests `backup_artifact::tests::{non_terminal_operations_are_recorded_as_unknown,capture_records_in_flight_operation_identities}`.
- The harness custodian compares the signing request's
  `recipient_public_key_sha256` with the trusted trust document before it signs
  (the two-of-three custody check is simulated at the helper boundary) and
  writes `signing-response.json` through a private temp file plus rename. An
  altered request is refused by the custodian and rejected independently by
  phase 2 (`case-27`).
- The committed D13 inventory covers 17 repositories: SQLite 78 tables /
  86 indexes / 2 triggers (166 objects), PostgreSQL 78 tables / 83 indexes /
  2 triggers / 2 functions (165 objects). Capture enumerates the snapshot's
  live
  `sqlite_master` and fails closed (exit 2 `store-catalog-mismatch`) on an
  extra, missing or redefined object before staging the artifact. The
  `store-catalog-mismatch` classification is unit-only
  (`backup_artifact::tests::snapshot_catalog_rejects_an_extra_index`,
  `..._an_extra_table`, `..._a_changed_definition`); the campaign has no
  matrix row for it because a catalog mutation would require seeding a
  non-baseline schema.
- The campaign independently verifies the published bytes: local JCS + exact
  D1 input + OpenSSL Ed25519, recomputed member SHA-256 digests, and HPKE
  content-key unwrap plus AES-256-GCM decryption bound to the signed capture
  record and the harness-measured source database (see the F15 non-claim for
  the exact scope and limits).

## Matrix (recorded from the current campaign run)

Columns: `exit` is the process status of the decisive invocation (the injected
crash exit for crash rows); `journal` is the durable phase observed afterwards;
`marker` is the count of `.o3k-backup-in-progress-*`; `lock` is whether the
cooperative store lock is held by another process when the row is recorded;
`published` is the presence of the final artifact; `verification` is
`o3k backup verify` or the refusal classification.

| # | Case | Result | Exit | Journal | Marker | Lock | Published | Verification |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `case-1a` Option A wait (barrier-frozen; independent D9 measurement) | PASS | wait | staged | 1 | held | no | — |
| 2 | `case-10` D9 reservation | PASS | 0 | published | 0 | free | yes | source 3,298,472 B (db + wal + 2 MiB metadata bound); reserved 6,442,450,944 B |
| 3 | `case-1b` signature while waiting → publish → verify | PASS | 0 | published | 0 | free | yes | verified, exit 0, `release_match=true` |
| 4 | `case-1c` single-byte ciphertext-body flip | PASS | 2 | published | 0 | free | yes | `corrupt-artifact` |
| 5 | `case-2` crash during the wait (hook 91) → restart denied → resume | PASS | 91 | published | 0 | free | yes | restart exit 1 (marker); resume published, no recapture |
| 6 | `case-3` replay after publication (L5) | PASS | 0 | published | 0 | free | yes | destination re-verified; idempotent exit 0, one artifact |
| 7 | `case-4a` wrong signature | PASS | 2 | staged | 1 | free | no | `signature-invalid`; staging kept |
| 8 | `case-4b` wrong key id | PASS | 2 | staged | 1 | free | no | `signing-response-mismatch` |
| 9 | `case-4c` short signature | PASS | 2 | staged | 1 | free | no | `signing-response-invalid` |
| 10 | `case-4d` mismatched request digest | PASS | 2 | staged | 1 | free | no | `signing-response-mismatch` |
| 11 | `case-4e` wait timeout → safe abort | PASS | 3 | aborted | 0 | free | no | `signing-request-expired`; staging + marker removed |
| 12 | `case-5a` crash after `captured` (hook 86) | PASS | 86 | captured | 1 | free | no | retry exit 3 `backup-operation-incomplete` |
| 13 | `case-5b` crash after `staged` (hook 87) | PASS | 87 | published | 0 | free | yes | replay resumed the wait and published without recapture |
| 14 | `case-5c` crash after `publishing` (hook 88) | PASS | 88 | published | 0 | free | yes | replay finished publication, one artifact |
| 15 | `case-5d` crash after publication (hook 89) | PASS | 89 | published | 0 | free | yes | retry exit 0 `published-replay`; one artifact |
| 16 | `case-5e` crash between finalize and `publishing` (hook 90) | PASS | 90 | published | 0 | free | yes | retry re-verified `artifact.partial` and published |
| 17 | `case-6` pre-existing final artifact | PASS | 2 | published | 0 | free | yes | `artifact-destination-exists` on the first attempt; untouched; after clearing it the journal replay published and verified |
| 18 | `case-7` destination symlink swap | PASS | 2 | published | 0 | free | yes | `destination-symlink`; restored and retried |
| 19 | `case-8` modes/cleanup | PASS | — | — | — | free | yes | staging 0700, files 0600, artifact 0600, verify staging removed |
| 20 | `case-9` secret scan | PASS | — | — | — | free | yes | no secret/path match in outputs or artifact |
| 21 | `case-11` replacement controller during the wait | PASS | 0 | published | 0 | free | yes | restart DENIED (exit 1); published; restart then ready + SIGTERM 0 |
| 22 | `case-18` symlink at the final name (F37) | PASS | 2 | published | 0 | free | yes | `artifact-destination-exists`; link never followed; retry published |
| 23 | `case-19` stale empty `artifact.partial` (M5) | PASS | 0 | published | 0 | free | yes | atomic temp+rename; retry published |
| 24 | `case-20` post-publication crash: final present, staging gone (F2) | PASS | 0 | published | 0 | free | yes | destination digest matched; classified complete |
| 25 | `case-21` concurrent phase-2 invocations (F20) | PASS | 0/0/2 | published | 0 | free | yes | one published; the other `controller-active` |
| 26 | `case-22` create with missing trust config (P2) | PASS | 2 | — | 0 | free | no | `trust-config-unavailable` before the handoff; daemon stayed ready, SIGTERM exit 0 |
| 27 | `case-23` seeded non-terminal Operation (M4) | PASS | 0 | published | 0 | free | yes | `consistency.in_flight_operations=recorded_unknown` |
| 28 | `case-12missing-trust` | PASS | 3 | — | — | free | yes | `trust-config-unavailable` |
| 29 | `case-12identity` | PASS | 2 | — | — | free | yes | `identity-mismatch` |
| 30 | `case-12release` | PASS | 2 | — | — | free | yes | `release-mismatch` |
| 31 | `case-12revoked` | PASS | 2 | — | — | free | yes | `revoked-signing-key` |
| 32 | `case-12truncated` | PASS | 2 | — | — | free | yes | `corrupt-artifact` |
| 33 | `case-12oversize` | NOT-COVERED | — | — | — | — | — | unreachable for a schema-valid manifest; see below |
| 34 | `case-13` canonical-state immutability | PASS | — | published | 0 | free | yes | source DB SHA-256 identical before/after |
| 35 | `case-14` forged `publishing` journal | PASS | 2 | publishing | 1 | free | no | `staged-artifact-invalid`; forged bytes never published |
| 36 | `case-15` forged journal `backup_id` traversal | PASS | 2 | staged | 1 | free | no | `backup-operation-journal-invalid`; no escaped path |
| 37 | `case-16` symlinked staged artifact | PASS | 2 | staged | 1 | free | no | `staged-artifact-invalid`; `O_NOFOLLOW` refuses the link |
| 38 | `case-17` recipient-key substitution | PASS | 2 | published | 0 | free | yes | request fingerprint; swapped trust rejected; original published and verified |
| 39 | `case-1d` independent artifact verification (signature/D1/member digests) | PASS | 0 | published | 0 | free | yes | local JCS + OpenSSL Ed25519 over D1; recomputed member digests |
| 40 | `case-1d-decrypt` independent HPKE/AES-GCM decryption leg | PASS | 0 | published | 0 | free | yes | HPKE unwrap + AES-GCM decrypt bound to the capture record and source DB (NOT-COVERED, never PASS, when python `cryptography` is unavailable) |
| 41 | `case-1e` independent check rejects the tampered artifact | PASS | 2 | published | 0 | free | yes | independent member SHA-256 recomputation flags the flipped byte; nothing published |
| 42 | `case-24` validly signed (re-signed) manifest missing `metadata/capture.json` (F10) | PASS | 2 | published | 0 | free | yes | `missing-required-member` before any decrypt; the manifest was re-signed over the mutated content, so this is not a signature failure |
| 43 | `case-25` fake daemon answers the handoff (M1) | PASS | 2 | — | 0 | free | no | `daemon-identity-mismatch`; Python peer rejected |
| 44 | `case-26` validly signed partial from a different manifest (M2) | PASS | 2 | staged | 1 | free | no | `signing-request-mismatch`; request and staging kept |
| 45 | `case-27` custodian refuses an altered recipient fingerprint (L11) | PASS | 2 | staged | 1 | free | no | custodian helper exit 1, no response written; phase 2 `signing-request-mismatch` |

Totals: **45 matrix rows: 44 PASS + 1 NOT-COVERED, 0 FAIL** when both python
`cryptography` and `sqlite3` are available. The row set is conditional on those
two tools:

- without python `cryptography`, `case-1d-decrypt` becomes NOT-COVERED
  (45 rows: 43 PASS + 2 NOT-COVERED) and no decryption claim is made;
- without `sqlite3`, `case-23` (seeded non-terminal Operation) becomes
  NOT-COVERED (45 rows: 43 PASS + 2 NOT-COVERED) and the
  `in_flight_operations=recorded_unknown` claim rests on the unit tests named
  above.

No unexecuted row is reported as PASS, and the harness prints its own
PASS/FAIL/NOT-COVERED accounting.

### Row notes and deliberate test mechanics

- `case-1a` uses the executor's two-way barrier so the harness can apply the
  outstanding WAL frames with `PRAGMA wal_checkpoint(TRUNCATE)` and measure the
  database *after* that setup action but *before* the executor opens the store.
  This is what makes `case-10` and `case-13` deterministic: the D9 measurement
  and the before/after hash then refer to the same bytes.
- `case-1a` runs `backup create` in the background and inspects the live wait:
  the request file exists, the journal is `staged`, the marker is present, the
  store lock is held by the waiting process, one `awaiting-signature` line is on
  stderr, and nothing is published. The harness then signs; the *same* process
  verifies, publishes and removes the marker (`case-1b`).
- `case-1d` re-verifies the published artifact without product verifier code:
  it parses the frozen layout, checks the manifest bytes are canonical JCS,
  rebuilds the exact D1 input (domain prefix, u64be JCS length, canonical
  manifest without `authentication.signature`, per-member u32be name + SHA-256),
  verifies with `openssl pkeyutl -verify -rawin -pubin`, and recomputes every
  member digest. The decryption leg is a **separate row** (`case-1d-decrypt`):
  when python `cryptography` is present it unwraps the HPKE content key,
  decrypts every member, compares the `database/o3k.sqlite` plaintext with the
  signed `metadata/capture.json` `snapshot_sha256`, binds the capture record's
  source-before/after digests to a fresh hash of the source database, and
  compares the decrypted snapshot's catalog and `_sqlx_migrations` rows with the
  source. When `cryptography` is unavailable the decrypt row is NOT-COVERED and
  `case-1d` still asserts only the signature/D1/digest legs; the detail string
  reports the actual `decrypt=` result. `VACUUM INTO` rebuilds the file, so byte
  equality with the source database is neither expected nor claimed.
- `case-1e` runs the same independent check against the single-byte tampered
  copy from `case-1c`; the member SHA-256 recomputation must fail.
- `case-4e` uses `O3K_BACKUP_TEST_AWAIT_TIMEOUT_SECONDS=1` instead of editing
  the request: the real request TTL is 24h, so the bounded-wait hook makes the
  safe abort observable. The observed contract is recoverable exit 3
  (`signing-request-expired`); the staging tree and the marker are removed
  because no publication is pending.
- `case-4a`–`case-4d` write the mutated response out of tree and move it into
  place atomically: the executor polls for the file, so it must never observe
  the valid response between two writes.
- `case-5b`: the injected crash lands deliberately between the durable `staged`
  write and the signing wait. The marker stays, so controller startup remains
  denied; the replay resumes the wait and, after verified publication, removes
  it. `case-2` covers the same state reached by dying *inside* the wait.
- `case-6` records the **decisive** invocation's exit code (2,
  `artifact-destination-exists`) together with the **state after the retry**
  (journal `published`, marker `0`, published `yes`). The first attempt leaves
  the journal `publishing`, the marker `1` and the pre-existing file untouched;
  after the operator removes the colliding entry, the same request publishes
  without a second signature and removes the marker.
- `case-27` alters the request's `recipient_public_key_sha256` and rebinds the
  journal's `request_sha256` so the request-digest check passes. The harness
  custodian refuses to sign (exit 1, no `signing-response.json`), and the
  product's phase 2 independently rejects the request as
  `signing-request-mismatch` (exit 2). Both legs are asserted.
- `case-7` replaces the destination directory with a symlink while the capture
  is in its wait (reached through hook 91). The resumed invocation fails closed
  with `destination-symlink`; the staging tree is preserved in the renamed real
  directory, and restoring the path lets the same request publish.
- `case-8` records the staging modes observed while the capture waits (0700
  directory, 0600 files including the request and `operation.lock`), plus the
  published artifact mode (0600) and the absence of `.o3k-verify-staging-*`
  after a successful verify.
- `case-11` starts a replacement `o3kd` while the capture waits: it must exit
  non-zero with either the interrupted-marker denial or the store lock, and must
  never serve. Only after verified publication does a new controller reach
  `/readyz` and exit 0 on SIGTERM.
- `case-18` places a symlink at the final publication name; the publication
  check opens it `O_NOFOLLOW`, classifies it as `artifact-destination-exists`
  (exit 2), never follows or replaces it, and the same request publishes once
  the entry is removed.
- `case-19` creates an empty, 0600 `artifact.partial` in the members directory
  while the capture waits; the retry replaces it atomically (temp name +
  rename) and publishes. The injection happens only after the stable
  `awaiting-signature` line, because `complete_staged` clears stale finalize
  debris before emitting that line; injecting earlier races the cleanup.
- `case-1d`/`case-1e` use the same tampered file: `case-1e` flips one byte
  inside the first member's ciphertext body (not the trailing tag), so the
  independent SHA-256 recomputation and the AEAD both fail.
- The happy-path executor wait is bounded by `wait_bounded` (exit marker plus
  deadline); no harness path performs an unbounded `wait`.
- `case-20` simulates the post-publication crash on the already published `case-1`
  artifact: journal rewritten to `publishing` with the artifact digest, staging
  tree absent, marker recreated. The replay opens the destination inode
  `O_NOFOLLOW`, requires a regular file whose digest equals the journal digest,
  marks the operation published and removes the marker.
- `case-21` launches two replays at once. What is observable is the lifetime
  store lock: one publishes, the other exits 2 `controller-active` before
  touching the tree. The staging-directory `operation.lock`
  (`operation-busy`, exit 3) is the second line of defense for the same
  operation from an unrelated data directory; it is unit-covered by
  `backup_artifact::tests::operation_lock_is_exclusive_and_released_on_drop`.
- `case-23` seeds a `running` Operation row directly in SQLite (the daemon is
  stopped first) and asserts the published manifest says
  `in_flight_operations=recorded_unknown`. The stable ids are recorded in the
  encrypted `metadata/capture.json` member, which the campaign does not
  decrypt; that binding is unit-covered by
  `backup_artifact::tests::capture_records_in_flight_operation_identities`.
- `case-9` scans every captured `*.json`, `*.stderr`, `*.log` and `*.txt` for
  the Ed25519 seed hex, the raw X25519 recipient bytes hex, the signing-key path
  and the recipient-key path, and scans the published artifact bytes for the
  same markers. None matched. The trust document itself intentionally names the
  recipient key path and was excluded as an input fixture; it is encrypted into
  the artifact and not emitted on stdout/stderr.
- `case-11` starts a fresh `o3kd` on the same data directory after phase 1,
  asserts `/readyz` and the daemon's "backup operation has not reached a
  terminal phase" warning, then a clean SIGTERM exit 0, then completes phase 2.

## Security review round 1

A hostile review confirmed three exploitable defects (F1, F2, F3) and several
lower-severity hardening gaps. Every item below is implemented and covered by a
regression test that fails against the pre-review code. The accepted CLI surface
and the frozen v1 artifact format are unchanged.

| Finding | Fix (file) | Regression test |
| --- | --- | --- |
| F1 (High) `publishing` replay trusted journal bytes | `bins/o3k/src/backup_artifact.rs` `complete_staged` / `verify_publishable_staged_artifact` / `bins/o3k/src/backup.rs` `verify_signed_artifact_integrity`: both `staged` and `publishing` now parse the canonical signed artifact through a `O_NOFOLLOW` descriptor, validate schema/JCS/limits, bind site/installation/profile/release/key ids, consult trust+revocation fail-closed, verify Ed25519 over the D1 input and re-digest every member before comparing the journal digest and publishing | `case-14` (harness); `backup_artifact::tests::symlinked_staged_artifact_is_never_published` |
| F2 (High) trust/release config substitution | `bins/o3k/src/backup_trust.rs` root posture (`default_trust_config_path_for`, `install_prefix_for`, `environment_overrides_allowed`), private-file mode (`0600`), `bins/o3k/src/upgrade/release_identity.rs` bounded `O_NOFOLLOW` manifest read used by backup verify, `o3k version` and the upgrade engine; `main.rs` / `upgrade/runner.rs` ignore `O3K_UPGRADE_PREFIX` as root; `backup_create.rs` / `backup_verify.rs` ignore `O3K_DATA_DIR` as root | `backup_trust::tests::{root_ignores_every_environment_override,rejects_group_or_world_writable_configuration_and_key}`; `release_identity::tests::release_manifest_read_fails_closed_on_unsafe_entries` |
| F3 (High) journal `backup_id` traversal | `crates/o3k-store/src/backup_journal.rs` contract identifier grammar; `backup_artifact.rs` publication name derived from the operation UUID, `final_name` `/` check | `backup_journal::tests::identifiers_reject_path_traversal_and_empty_values`; `case-15` (harness) |
| F4/F13 symlink publication and hash-then-rename race | `open_staged_signed_artifact` (`O_NOFOLLOW`+`fstat`), `hash_fd`, `link_staged_inode` (`linkat` of the verified inode, `AT_EMPTY_PATH` with descriptor-relative `/proc/self/fd` fallback), `existing_destination` hashes through the opened descriptor | `case-16` (harness); `backup_artifact::tests::publication_is_no_replace_and_replay_safe` |
| F5 plaintext snapshot left in staging | `backup_create.rs` unlinks `<staging>/o3k.sqlite` immediately after `stage_capture` (failure included) and fails closed if it cannot; `backup_artifact.rs` removes the staging tree on `signing-request-expired` | `backup_create::tests::two_phase_flow_publishes_a_verified_artifact`; `case-4e` (staging removed) |
| F6 journal read posture | `backup_journal.rs` validates the directory (`0700`, trusted owner) and each record fd (`O_NOFOLLOW`, regular, `0600`, trusted owner, ≤256 KiB) | `backup_journal::tests::{symlinked_and_over_permissive_records_are_rejected,oversized_records_are_rejected_before_parsing}` |
| F9 finalize/journal crash window | `backup_artifact.rs` `staged` retry detects `artifact.partial` and re-verifies it fully; hook 90 exercises the window | `case-5e` (harness) |
| F10 member staging directory fsync | `backup_artifact.rs` `stage_capture` fsyncs `members-*` before the signing request is written/synced | covered by the happy-path campaign |
| F11 clock-inconsistent response | `backup_artifact.rs` `verify_signing_response` requires `created_at <= signed_at <= expires_at`; expiry is host-clock based, with no HSM time attestation. `expires_at` is inside the persisted request bytes, so it is bound by `request_sha256` (verified: the digest is computed over the whole request file). | `backup_artifact::tests::signing_response_is_bound_to_the_request_and_the_trust_key` |
| F12 mandatory custody expiry | `backup_trust.rs` requires `custody.expires_at` (`trust-custody-incomplete`) | `backup_trust::tests::rejects_expired_or_incomplete_custody_records` |
| F15 recipient key zeroization | `backup_trust.rs`: raw bytes in `Zeroizing`; the hpke `X25519HkdfSha256::PrivateKey` is `x25519_dalek::StaticSecret` (`ZeroizeOnDrop`), so no serialized private copy survives; documented in the module | `backup_trust::tests::loads_the_recipient_key_from_raw_bytes_and_hex` |
| F16 trust template | `packaging/backup-trust.example.json` (placeholders, no keys, public-key-only capture) installed to `<prefix>/share/o3k/`; installer documents `root:o3k 0640` (or `0600`) and never creates `/etc/o3k` with permissive modes | `packaging/install.sh`; ownership list in `packaging/uninstall.sh` |
| F17 harness negatives | `case-14`, `case-15`, `case-16`, `case-17`; `case-17` asserts the request exposes `recipient_public_key_sha256` and that a swapped recipient is rejected by phase 2 and `o3k backup verify` | `tests/pp6_backup_artifact.sh` |

### F7/F8 design note (recipient binding)

The signing request now carries `recipient_public_key_sha256` (SHA-256 of the
configured X25519 recipient public key). The trust document may declare
`recipient.x25519_public_key`. Loading is lazy: `BackupTrustConfig::load` never
opens the private key. When the public key is configured the capture path uses
it and reads no private key material, even if `x25519_private_key_file` names
an absent path. When only the private key is configured, deriving the public
half opens it on demand. Verification loads the private key and proves it
matches the declared public key; a capture-only document may omit it, and
verification then fails closed with `trust-recipient-key-unavailable`.

The frozen v1 artifact manifest does **not** bind the recipient public key: the
format is fixed by the accepted contract
(`contracts/control-plane-backup-v1.proposed.schema.json`) and adding a manifest
field would be a contract amendment. Substitution is mitigated by the
custodian-visible request fingerprint and the trust-document check; a
public-key-only verification mode remains a documented follow-up because verify
still needs the recovery key to decrypt members.

### Harness key handling

The harness passes `-inkey <path>` to OpenSSL, so the key path (not the key) is
visible in the process argument vector for the duration of the signing command.
This is a campaign-fixture exposure only (the harness runs on a disposable
recording host in a private temporary directory); the product never reads the
artifact-signing custody key. Verification does read the separate X25519
recovery private key on the recovery/operator host, as documented below.

## Security review round 2

The second security review found one blocking packaging defect (H1), a
pre-existing root override gap (H2), two medium recovery-boundary defects (M1,
M2), a contract member-set gap (F10), and several small hardening items. All
are implemented; the accepted CLI surface and the frozen v1 artifact format are
unchanged.

| Finding | Fix (file) | Regression test |
| --- | --- | --- |
| **H1 root-owned trust anchor unusable by the service user** | `bins/o3k/src/backup_trust.rs`: trust document may be owned by root or the effective uid; modes `0600` or `0640` (the latter only when the owning group is root or one of the process's groups); group/other write and other read always rejected. Private recipient key stays `0600`/`0400`. `load` no longer opens the private key; the public/private match is checked when `load_recipient_private_key` runs. `O3K_BACKUP_TRUST_CONFIG` / `O3K_INSTALL_PREFIX` are honored only for a non-installed data directory (`/var/lib/o3k` ignores them regardless of euid). | `backup_trust::tests::{root_owned_0640_for_a_service_user_and_group_write_rejection,accepts_the_service_group_mode_and_rejects_writable_or_other_readable,capture_loads_with_a_configured_public_key_and_no_private_key_file,installed_data_dir_ignores_the_environment_overrides_regardless_of_euid}` |
| **H2 root upgrade path/URL overrides** | `bins/o3k/src/upgrade/runner.rs`: `upgrade_overrides_allowed(euid)` gates `O3K_UPGRADE_PREFIX/BIN_DIR/CONFIG_DIR/DOWNLOAD_DIR/RELEASES_URL/DOWNLOAD_BASE`; euid 0 uses canonical paths and URLs. Release-signature verification remains a follow-up (the upgrade contract does not define it yet). | `upgrade::runner::tests::upgrade_path_and_url_overrides_are_ignored_for_root` |
| **M1 daemon not authenticated by the executor** | `crates/o3k-store/src/backup_control.rs::verify_daemon_peer` checks `SO_PEERCRED` uid and `/proc/<pid>/exe` dev+ino against the sibling `o3kd` and the data-dir owner; `backup_create.rs` connects, authenticates the peer and only then sends the request (round 3), before `receive_handoff` (`daemon-identity-mismatch` / `daemon-identity-unavailable`, exit 2) and compares the received data-dir fd dev+ino with the canonical directory (`handoff-directory-mismatch`, exit 2; `access_lock.rs::data_dir_matches`). | `backup_control::tests::daemon_peer_requires_the_expected_uid_and_executable`; `access_lock::tests::data_directory_identity_is_compared_by_dev_and_ino`; `case-25`; `backup_create::tests::impostor_daemon_never_receives_the_request` |
| **M2 staged partial not bound to its request** | `backup_artifact.rs::complete_staged`: the signed-recovery branch reads the persisted request (journal `request_sha256`, site/installation/key id, manifest digest, signing-input digest, recipient fingerprint) and requires the signed artifact's unsigned-manifest digest and D1 input to equal it before publishing; mismatch is exit 2 `signing-request-mismatch` and keeps staging. | `backup_artifact::tests::staged_recovery_binds_the_signed_manifest_to_the_persisted_request`; `case-26` |
| **F10 required member set** | `bins/o3k/src/backup.rs`: one `REQUIRED_ARTIFACT_MEMBERS` constant (`database/o3k.sqlite`, `metadata/capture.json`, `release/release-manifest.json`, `trust/backup-trust.json`) used by `validate_manifest` and `verify_artifact_stream`; missing member is the typed `missing-required-member` class (exit 2). | `backup::tests::every_required_member_is_enforced_with_a_typed_failure`; `case-24` |
| **F3 verify host boundary and live-store mutation** | `backup_verify.rs` copies the main database and a non-empty WAL sidecar into its private `0700` staging under the store lock and opens the copy read-only (`immutable=1` when no non-empty WAL); the live store is never opened. Docs state that full verification decrypts members, requires the recovery private key, and must run on the operator/recovery host; signature/D1/member-digest authenticity is independently checkable without decryption. | `backup_verify::tests::verification_reads_a_private_copy_including_a_non_empty_wal`; campaign `case-13` |
| **L3 blocking opens** | `O_NONBLOCK` added beside `O_RDONLY\|O_NOFOLLOW` for trust/key, staged/destination artifacts, request/response, journal and release-manifest reads; post-open `fstat` type checks remain. | `backup_artifact::tests::destination_artifact_requires_owner_mode_and_never_blocks_on_a_fifo` |
| **L4 published digest** | `backup_artifact.rs::mark_published` persists the verified `artifact_sha256` in the terminal record. | `backup_create::tests::two_phase_flow_publishes_a_verified_artifact` (journal assertion) |
| **L5 wedged published retry** | A journal at `published` re-verifies the destination and exits 0 idempotently (clearing marker/staging debris), or rejects `published-artifact-missing` / `published-artifact-changed` (exit 2). | `backup_create::tests::{two_phase_flow_publishes_a_verified_artifact,published_operation_with_a_missing_destination_is_rejected}`; `case-3`, `case-5d` |
| **L9 installer temp manifest** | `packaging/install.sh` creates the augmented manifest under `$PREFIX/share/o3k` (root-owned, `mktemp` `O_EXCL`), never `TMPDIR`. | `bash -n`; installer review |
| **L10 destination posture** | `backup_artifact.rs::existing_destination` requires a regular file owned by the effective uid with no group/other permission bits (normally `0600`; a stricter owner-only mask such as `0400` from a hardening pass or umask is accepted so a replay cannot be wedged); other postures are exit 2 `artifact-destination-posture-invalid`. `backup.rs::create_private_file` `fchmod`s each new staging file to exactly `0600` and surfaces a failure. | `backup_artifact::tests::destination_artifact_requires_owner_mode_and_never_blocks_on_a_fifo` |
| **L11 custodian fingerprint check** | `tests/pp6_backup_artifact.sh::sign_request` compares the request's `recipient_public_key_sha256` with `recipient.x25519_public_key` from the configured trust document before signing; a mismatch is refused and no response is written. The helper writes the response through a private temp file and `os.replace`. The product additionally retries an unparsable response until the deadline (safe abort) so a non-atomic writer cannot wedge it. | `case-27`; `backup_artifact::tests::signing_wait_retries_a_partially_written_response` |

### Verify host boundary (non-claim)

`o3k backup verify` performs full decryption and therefore requires the X25519
recovery private key; the controller-side capture path needs only the public
key. The campaign's independent check verifies the Ed25519 signature, exact D1
input and every member ciphertext digest without decrypting. A public-key-only
verify mode is a follow-up requiring a contract decision and is not claimed
here.

## Contract review round 1

The contract/correctness review of the accepted Option A mode and the
publication/recovery paths found one contract violation (F1: the exclusion was
released after capture, allowing a controller restart during the signing
window), one correctness defect (F2: a crash after publication with the staging
tree already removed could not be recovered), one wedged-retry defect (M5), and
several truthfulness/hardening gaps. Every item below is implemented; the
accepted CLI surface (`create --destination --operation-id`,
`verify --artifact`), the frozen v1 artifact format and the exit codes `0/2/3/4`
are unchanged.

| Item | Fix (file) | Regression test |
| --- | --- | --- |
| **F1 / Option A exclusion through publication** | `bins/o3k/src/backup_create.rs`: the capture process retains the `StoreAccessLock` and the denial marker after staging and calls `complete_staged` in the same process; `bins/o3k/src/backup_artifact.rs` `complete_staged` emits `o3k backup create: awaiting-signature <operation-id>`, polls for `signing-response.json` until the request TTL, then verifies → finalizes → publishes → removes the marker, or performs the safe abort (staging removed, journal `aborted`, marker removed, exit 3 `signing-request-expired`). Phase 2 (same `--destination/--operation-id`) detects the journal before any controller contact, acquires the lifetime lock (`WouldBlock` → exit 2 `controller-active`), re-creates the marker if an operator removed it and resumes the wait/publication. | `case-1a`, `case-1b`, `case-11`, `case-2`, `case-4e`; `backup_create::tests::{phase_one_waits_for_the_signature_and_publishes,phase_two_without_a_signature_safely_aborts,phase_two_requires_the_lifetime_store_lock}` |
| **F2 / P0-2 post-publication recovery** | `backup_artifact.rs` `complete_staged` observes the destination **before** requiring the staging tree: `existing_destination` (`O_NOFOLLOW`, `fstat` regular) → full verification → digest equals `record.artifact_sha256` → `published`, staging removed, marker removed, exit 0. Only when the destination is absent does the staged file drive publication. | `case-20`; `backup_create::tests::two_phase_flow_publishes_a_verified_artifact` (post-publication replay step) |
| **M5 / P0-3 stale `artifact.partial`** | `bins/o3k/src/backup.rs` `finish_signed_artifact` builds into `artifact.partial.tmp-<uuid>` and renames atomically; on any failure the temporary and the partial are removed; a stale entry is removed first only after proving it is this operation's private regular file. `backup_artifact.rs` `remove_stale_finalize_outputs` clears `artifact.partial`/`artifact.partial.tmp-*` whenever `artifact.unsigned` is still present. | `case-19`; `backup::tests::finalize_replaces_a_stale_partial_instead_of_wedging` |
| **M4 / F9 truthful `in_flight_operations`** | `backup_artifact.rs` `snapshot_in_flight_operations` / `query_in_flight_operations` read `operations` from the quiesced snapshot under the store lock (`succeeded`/`failed` are terminal); the manifest records `recorded_unknown` and the ids go into `metadata/capture.json`. | `case-23`; `backup_artifact::tests::{non_terminal_operations_are_recorded_as_unknown,capture_records_in_flight_operation_identities}` |
| **M3 / F5b D9 measurement and footprint** | `backup_create.rs` measures after the truncating WAL checkpoint (main DB + non-empty `-wal` + release/trust members + a 2 MiB capture/request metadata allowance; the accepted formula is unchanged) and fails closed with exit 3 `space-unavailable`; `backup_reservation::ensure_reserved_space` re-checks the remaining reservation before finalize and before publication; `backup.rs` deletes each member ciphertext as soon as it is copied into the unsigned artifact and `artifact.unsigned` right after the partial is durable. | `case-10`, `case-4e`; `backup_reservation::tests::boundary_recheck_never_truncates_the_remaining_reservation` |
| **F12 verify store-access guard** | `bins/o3k/src/backup_verify.rs` acquires `StoreAccessLock` before reading the store; `WouldBlock` → exit 2 `controller-active`; the lock is held for the migration read and released before artifact verification. Deriving migration identity from installed metadata is impossible (the release manifest carries `schema_version` but no migration checksums), so the lock option was chosen. | `case-12*` (no controller); `bins/o3k/tests/backup_verify.rs::rejects_verification_while_the_store_lock_is_held` |
| **F11 data-directory resolution** | New `bins/o3k/src/backup_data_dir.rs` shared by `create` and `verify`: root uses `/var/lib/o3k`; non-root uses `O3K_DATA_DIR`, else the bounded `O3K_DATA_DIR=` assignment in `/etc/o3k/o3kd.env` (no shell evaluation), else the packaged `/var/lib/o3k` when it exists and is owned by the effective uid (round 3), else `./data`. | `backup_data_dir::tests::{parses_the_single_assignment_and_ignores_everything_else,rejects_ambiguous_or_unsafe_values,precedence_matches_the_documented_rule,readable_environment_file_wins_over_the_packaged_directory,packaged_directory_is_used_when_the_environment_file_yields_nothing,packaged_directory_is_not_used_when_it_is_not_owned_by_the_caller,environment_file_posture_requires_a_trusted_owner_and_no_group_write}` |
| **P2 pre-handoff config preflight** | `backup_create::preflight_before_handoff` loads the trust document and release identity read-only and applies the D9/member bounds before `connect_control`; a configuration failure is rejected (exit 2) without stopping the daemon. `verify` has no preflight and maps the shared `BackupTrustError::is_recoverable` classification to exit 3 (missing or unreadable configuration), keeping exit 2 for a present-but-untrusted document. | `case-22`; `backup_create::tests::missing_configuration_is_rejected_before_the_handoff`; `backup_verify::tests::reports_a_missing_trust_document_as_recoverable` |
| **F19 post-publication cleanup reported** | `backup_artifact.rs` `finish_publication`: an unprovable staging/marker removal is exit 4 `post-publication-cleanup-failed`/`marker-removal-failed`; a directory-sync failure on the success path emits the stable warning `o3k backup create: warning post-publication-sync-failed`. | success path: `case-1`/`case-5d`; failure branches: `backup_artifact::tests::{post_publication_staging_cleanup_failure_is_an_unknown_outcome, post_publication_marker_removal_failure_is_an_unknown_outcome}` (unit-only; no real-process seam) |
| **F20 concurrent phase 2** | `backup_artifact.rs` `OperationLock` (`flock LOCK_EX|LOCK_NB` on `<staging>/operation.lock`, mode 0600, released on every return) → exit 3 `operation-busy`; the lifetime store lock remains the primary exclusion. | `case-21`; `backup_create::tests::phase_two_requires_the_lifetime_store_lock`; `backup_artifact::tests::operation_lock_is_exclusive_and_released_on_drop` |
| **F37 final-name entry classification** | `existing_destination` classifies a symlink or non-regular entry at the final name as `artifact-destination-exists` (exit 2), never exit 4. | `case-18`; `backup_artifact::tests::{destination_symlink_is_a_rejected_precondition,destination_directory_is_a_rejected_precondition}` |
| **F31 exit-4 journal state** | `backup_create.rs` records the journal as `aborted` before returning `source-modified-during-capture`, `snapshot-hash-failed`, `source-rehash-failed`, `capture-outcome-unknown` and the other post-marker capture failures, so a retry does not mistake the attempt for an unfinished capture. | **Not separately tested end-to-end**: no deterministic seam forces those failure reasons without new production hooks. The shared helper is unit-covered by `backup_create::tests::capture_failure_helper_records_the_terminal_aborted_phase`; the reasons themselves are not claimed as real-process evidence. |
| **L2 rustdoc attribution** | `bins/o3kd/src/composition/mod.rs`: the marker denial doc is on `deny_interrupted_backup_markers`; `warn_pending_backup_operations` has its own diagnostic-only doc. | — |
| **L3 single migration mapping** | `backup_artifact.rs` capture calls `backup_verify::migration_checksum`; one documented mapping for both paths. | `backup_artifact::tests::snapshot_facts_reuse_the_verify_mapping` |
| **L5 member path grammar** | `backup.rs` `validate_path` rejects empty/`.`/`..` and any segment beginning with `.` or `-`. The frozen contract schema (`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`) also rejects a leading `.`, but permits a leading `-`; rejecting `-` is deliberately stricter (defense in depth) and no artifact member uses such a name. | `backup::tests::member_path_grammar_rejects_hidden_and_option_like_segments` |
| **L6 forward-only journal** | `crates/o3k-store/src/backup_journal.rs` `advance_backup_operation` reads the on-disk phase, refuses regressions (`backup-operation-phase-regression`) and treats an already-durable phase as idempotent; every `update_journal`/abort/`mark_published` call uses it. | `backup_journal::tests::{transitions_only_move_forward,advance_is_idempotent_and_refuses_to_regress}` |
| **L7 typed verification classification** | `bins/o3k/src/backup.rs` `ArtifactVerifyClass`/`ArtifactVerifyError`: the reason code and exit status come from the typed class, never from wording; `backup_verify.rs` maps class → exit/reason. | `backup_verify::tests::reason_mapping_is_stable_for_every_failure_class` (asserts the exact strings); `bins/o3k/tests/backup_verify.rs` |
| **L8 / F30 harness dirty detection** | `tests/pp6_backup_artifact.sh` uses `git status --porcelain --untracked-files=no` scoped to the change set, so unrelated untracked build directories do not mark the campaign dirty. | verdict `working_tree_dirty` field |
| **F34 CI cannot regenerate the baseline** | `crates/o3k-store/src/state_inventory.rs` `regeneration_requested` refuses `O3K_REGENERATE_INVENTORY=1` whenever `CI` is set. | `state_inventory::tests::regeneration_is_refused_in_ci` |

## Final review round: D13 catalog completeness and F15 harness independence

| Item | Change | Evidence |
| --- | --- | --- |
| **F4a / D13 catalog completeness** | `crates/o3k-store/src/state_inventory.rs` now emits tables, indexes and triggers from both migration trees, plus PostgreSQL functions. Indexes/triggers are assigned to the repository owning their `ON <table>`; the two generic operation-integrity functions are assigned to `operations` through the reviewed `GENERIC_FUNCTION_OWNERS` list (an unlisted function fails generation). The SQLite catalog is generated by applying the migration tree in an in-memory store and reading `sqlite_master`, so SQLite's `ALTER TABLE ... ADD COLUMN` rewrites and the runtime `operations` rebuild are reflected in the baseline digests. | `state_inventory::tests::{baseline_inventory_includes_indexes_triggers_and_functions, baseline_comparison_detects_added_indexes_and_triggers, generation_rejects_an_index_owned_by_an_unregistered_table, generation_rejects_a_function_without_a_reviewed_owner, index_trigger_and_function_normalization_is_deterministic}`; committed baseline regenerated |
| **F4b / live catalog comparison** | `snapshot_facts` enumerates the snapshot's live `sqlite_master` (tables/indexes/views/triggers), excludes `sqlite_*` internal names, compares names and normalized definition digests against every baseline entry in both directions, and fails closed with exit 2 `store-catalog-mismatch` before staging the artifact. `_sqlx_migrations` remains compared because the baseline claims it. | `backup_artifact::tests::{snapshot_catalog_rejects_an_extra_index, snapshot_catalog_rejects_an_extra_table, snapshot_catalog_rejects_a_changed_definition, snapshot_facts_read_store_identity_and_repository_emptiness}` |
| **F15 harness independent verification** | `tests/pp6_backup_artifact.sh` independently rebuilds D1 (local JCS), verifies Ed25519 with OpenSSL, recomputes member digests, and decrypts HPKE/AES-GCM members with python `cryptography`; the database plaintext is bound to the signed capture record and the harness-measured source database. `case-1d` is the positive row and `case-1e` the tampered negative row. | `case-1d`, `case-1e` |
| **Nits** | `main.rs` Backup help text describes the in-process Option A wait and crash re-run; the stale raw-key trimming comment in `bins/o3k/tests/backup_verify.rs` is corrected; the happy-path executor wait is explicitly bounded by `wait_bounded`; this document uses "fixture trust document" for `O3K_BACKUP_TRUST_CONFIG`. | `cargo fmt`/clippy/tests; `bash -n` and shellcheck at `-S warning` (info/style notes suppressed) |

Catalog counts in the regenerated baseline (17 repositories): SQLite 78
tables, 86 indexes, 2 triggers (166 objects); PostgreSQL 78 tables, 83
indexes, 2 triggers, 2 functions (165 objects). The extra table in each
backend is the framework-owned `_sqlx_migrations`; the second SQLite trigger
(`resources_delete_generic_operations`) and the `operations` table definition
come from the runtime schema rebuild that `SqliteStore::connect` applies after
SQLx migrations.

Known verification limits are listed in the F15 and D13 non-claims above: no
live PostgreSQL catalog comparison, no views/sequences/constraints, no
no-table repository entry (SPEC/schema conflict), and `VACUUM INTO` snapshot
bytes are not the source database bytes.

## Contract/correctness review round 3

| Item | Change | Evidence |
| --- | --- | --- |
| M-1 per-member bound before capture | `backup_create::ensure_member_bound` rejects `database + wal` or any metadata source above 1 GiB (`member-bound-exceeded`, exit 2) in the read-only preflight and again after the checkpoint before `backup_to_file`; `bins/o3k/src/backup.rs` exposes the shared `MAX_MEMBER_BYTES`. | `backup_create::tests::{oversized_snapshot_member_is_rejected_before_the_handoff, member_bound_counts_the_database_and_wal_sidecar}`; `tests/pp6_backup_handoff.sh case-m1` |
| L-1 typed signature/schema classes | Missing, malformed and non-verifying Ed25519 signatures are `signature-invalid`; semantic `validate_manifest` failures are `schema-invalid` in both `verify_artifact_stream` and `verify_signed_artifact_integrity`. | `bins/o3k/tests/backup_verify.rs::{rejects_a_forged_manifest_signature_as_signature_invalid, rejects_a_semantically_invalid_signed_manifest_as_schema_invalid}` |
| L-2 `sqlite_sequence` false mismatch | The expected catalog map skips SQLite-internal `sqlite_*` names, matching the live-catalog exclusion. | `state_inventory::tests::catalog_comparison_ignores_expected_sqlite_internal_objects` |
| L-3 journal re-read under the lock | Phase 2 re-reads the operation journal after `StoreAccessLock::acquire`; a record that advanced to `published` follows the L5 idempotent replay instead of failing as unavailable staging. | `backup_create::tests::phase_two_reloads_the_journal_after_acquiring_the_lock` |
| L-6 durable finalize | `finish_signed_artifact` fsyncs the `members-*` directory after the finalize rename and after removing `artifact.unsigned`. | `backup::tests::unsigned_stage_finishes_with_a_detached_signature_only_after_verification` (exercise path); a staging-sync fault is not separately injectable |
| L-8 metadata bound | `reservation_with_metadata_bound` propagates `source-bound-exceeded` instead of falling back to the lower reservation. | `backup_create::tests::metadata_bound_propagates_the_source_limit` |
| P2 read-only preflight | The trust document, release identity, member bound and D9 reservation are validated before the controller is contacted; the under-lock reload remains the captured-member authority. | `backup_create::tests::missing_configuration_is_rejected_before_the_handoff`; `tests/pp6_backup_handoff.sh case-p2` |
| D10/D13 PostgreSQL baseline binding | `state_inventory_v1.json` now binds `postgres_major` (16; SPEC-0050 / PP6 D10), the SQLite generator version (`SELECT sqlite_version()` from the linked library; `3.46.0`) and the SHA-256 of every file in both migration trees. The generator emits them, the drift gate compares them (a SQLite library change forces a reviewed regeneration), and `baseline_binding()` exposes them while `baseline_state_inventory()` keeps the manifest entry shape. | `state_inventory::tests::{baseline_binding_covers_every_migration_file, changing_a_migration_file_fails_the_drift_gate}` |

## Security/correctness review round 3 (final)

The third round found one high-severity packaging defect (the installed service
user could not resolve the packaged data directory), two medium findings
(symlinked-installation override bypass, verifier open on a FIFO) and several
low hardening items. All are implemented; the accepted CLI surface and the
frozen v1 artifact format are unchanged.

| Item | Fix (file) | Regression test |
| --- | --- | --- |
| **High packaged service-user data-dir resolution** | `bins/o3k/src/backup_data_dir.rs`: the non-root rule is now `O3K_DATA_DIR` → `O3K_DATA_DIR=` from `/etc/o3k/o3kd.env` → the packaged `/var/lib/o3k` when it exists, is a directory and is owned by the effective uid → `./data`. An environment file that exists but cannot be read (the packaged `root:root 0600` case) yields no value instead of failing, and an unsafe posture still fails closed. `resolve_non_root_data_dir`/`packaged_data_dir` are the exported helpers shared by `create` and `verify`; `packaging/install.sh` prints the resolution rule. | `backup_data_dir::tests::{readable_environment_file_wins_over_the_packaged_directory, packaged_directory_is_used_when_the_environment_file_yields_nothing, packaged_directory_is_not_used_when_it_is_not_owned_by_the_caller}` |
| **Medium symlinked installation bypass** | `bins/o3k/src/backup_trust.rs::is_installed_data_dir` compares the data directory against the canonical form of `/var/lib/o3k` as well as the literal path (fallback to the literal when resolution fails), so an installation whose packaged directory is a symlink cannot re-enable `O3K_BACKUP_TRUST_CONFIG`/`O3K_INSTALL_PREFIX`. | `backup_trust::tests::installed_data_dir_detection_survives_a_symlinked_packaged_directory` |
| **Medium verifier open can block on a FIFO** | `bins/o3k/src/backup_verify.rs::open_artifact` adds `O_NONBLOCK` beside `O_NOFOLLOW`; the existing `fstat` regular-file check then rejects a FIFO swapped in after path validation without blocking. | `backup_verify::tests::artifact_open_never_blocks_on_a_fifo` |
| **Low authenticate the daemon before the request** | `crates/o3k-store/src/backup_control.rs`: `connect_control` (connect only) and `send_request_and_read_accept` (frame exchange) are split; `connect_and_request` remains as their composition. `bins/o3k/src/backup_create.rs` resolves the expected uid/executable, connects, calls `verify_daemon_peer`, and only then sends the request, so an impostor never triggers the daemon's drain. An unreadable expected daemon path (or unreadable peer identity) is `daemon-identity-unavailable` (exit 2) and a proven different peer is `daemon-identity-mismatch` (exit 2). Consequence for the handoff campaign: `case-a` now exercises the client-side ordering (a relocated executor is refused with `daemon-identity-unavailable` when it has no sibling `o3kd`, and `daemon-identity-mismatch` when it has a non-matching one, with no request frame reaching the daemon); the daemon-side executor identity check stays unit-covered. | `backup_create::tests::{impostor_daemon_never_receives_the_request, unreadable_expected_daemon_path_is_identity_unavailable}`; `case-25`; handoff `case-a` |
| **Low environment-file posture** | `backup_data_dir::env_file_data_dir` `fstat`s the opened descriptor and requires a regular file owned by root or the effective uid with no group/other write bit (`data-dir-env-unsafe` otherwise); the posture is checked on the inode actually read, not on the pre-open `lstat`. | `backup_data_dir::tests::environment_file_posture_requires_a_trusted_owner_and_no_group_write` |
| **Low classification documentation** | `backup_trust.rs` (`is_recoverable`) and `backup_artifact.rs` (`From<BackupTrustError>`, module configuration section) state the actual split: `create`'s read-only preflight rejects configuration failures as exit 2 (exit 3 only for a configuration that disappears before the under-lock reload); `verify` reports recoverable configuration failures as exit 3. | documentation; `case-22` (create exit 2) and `case-12missing-trust` (verify exit 3) |
| **Low installer/module wording and a distinct reason** | `backup_trust.rs` module docs and `packaging/install.sh` describe `root:o3k 0640` as the packaged trust-document mode and `0600` as the euid-owned TestLab mode; a root-owned document without the group-read bit is `trust-config-unreadable-by-service-user` (recoverable class, exit 3 in `verify`, exit 2 in the `create` preflight). | `backup_trust::tests::root_owned_document_without_group_read_names_the_service_user_reason` |
| **Very low producer mode** | `bins/o3k/src/backup.rs::create_private_file` `fchmod`s the created file to exactly `0600` and surfaces a failure (removing the partial file); `backup_artifact.rs::existing_destination` accepts any owner-only mode (`mode & 0o077 == 0`, owner == euid) so a restrictive umask or hardening pass cannot wedge a replay. | `backup_artifact::tests::destination_artifact_requires_owner_mode_and_never_blocks_on_a_fifo` |
| **Harness** | `tests/pp6_backup_artifact.sh` gained `resign_artifact` (rebuild + re-sign a mutated manifest) and `case-24` now re-signs the member-stripped manifest, so the row proves a *validly signed* artifact missing a required member is `missing-required-member`, not `signature-invalid`. The `case-12oversize` rationale now states why the 5 GiB branch is unreachable for a schema-valid manifest. `tests/pp6_backup_handoff.sh` states that it is not the custody evidence script. | `case-24`; `backup::tests::the_complete_size_bound_is_unreachable_for_a_schema_valid_manifest` |

## Executed vs documented-not-executed

Executed real-process rows: **44 PASS of 45 matrix rows** (1 NOT-COVERED,
0 FAIL), produced by `tests/pp6_backup_artifact.sh` on the final tree. The
matrix grew by five rows over the round-1 campaign: `case-24`, `case-25`, `case-26`, `case-27` and
`case-1d-decrypt` (39 + 5 = 44 PASS rows; the single NOT-COVERED row,
`case-12oversize`, is unchanged and makes 45 matrix rows). The PASS count is
conditional on tooling: without python `cryptography`, `case-1d-decrypt` is
NOT-COVERED (43 PASS, 2 NOT-COVERED); without `sqlite3`, `case-23` is
NOT-COVERED (43 PASS, 2 NOT-COVERED). The campaign prints its own
PASS/FAIL/NOT-COVERED accounting and exits non-zero on any failure.

Not executed end-to-end (`NOT-COVERED`, exact reason and coverage):

- **Oversized artifact (`artifact-too-large`, exit 2).** Rebuilding and
  re-signing a mutated manifest is now feasible (`resign_artifact` in the
  harness, used by `case-24`), so tooling is no longer the blocker: the 5 GiB
  complete-size branch is unreachable for a *schema-valid* manifest.
  `validate_manifest` bounds each member's plaintext at 1 GiB
  (`MAX_MEMBER_BYTES`), the total plaintext at 4 GiB
  (`MAX_TOTAL_PLAINTEXT`) and the manifest at 16 MiB, and it runs before the
  complete-size check, so the largest declarable artifact is ~4 GiB + 16 MiB.
  A re-signed manifest that declares more is rejected earlier as
  `schema-invalid` (member metadata or total-size bound); the only remaining
  path into the check is an over-long declared manifest length, i.e. a
  malformed header rather than a signed artifact. The invariant is asserted by
  `backup::tests::the_complete_size_bound_is_unreachable_for_a_schema_valid_manifest`,
  and the stable mapping is unit-covered by
  `backup_verify::tests::reason_mapping_is_stable_for_every_failure_class`
  (`ArtifactVerifyClass::ArtifactTooLarge` → exit 2 `artifact-too-large`).
  This is **not** an exit-4 row: oversize is a rejected precondition.
- **Exit-4 post-publication cleanup (unit-only).** The
  `post-publication-cleanup-failed` and `marker-removal-failed` branches are
  exercised at the helper level by
  `backup_artifact::tests::{post_publication_staging_cleanup_failure_is_an_unknown_outcome,
  post_publication_marker_removal_failure_is_an_unknown_outcome}`. The campaign
  has no deterministic real-process seam for "artifact published, cleanup
  fails"; no real-process exit-4 cleanup row is claimed.
- **F31 capture-failure reasons (not separately tested).** No deterministic
  seam forces `source-modified-during-capture`, `snapshot-hash-failed` or
  `capture-outcome-unknown` without new production hooks; the handoff campaign
  likewise records source mutation during capture as a documented-coverage row
  (`case-m`) because the transferred flock excludes all writers. The shared
  `mark_operation_aborted` journal effect is unit-covered
  (`backup_create::tests::capture_failure_helper_records_the_terminal_aborted_phase`);
  the individual reasons are not claimed as real-process evidence.

Unit/integration coverage that the campaign does not reproduce as a separate
real-process row (listed so the evidence boundary is explicit):

- `backup_verify::tests::{success_json_is_bounded_and_carries_the_expected_fields,
  reason_mapping_is_stable_for_every_failure_class,
  artifact_path_validation_rejects_relative_missing_symlinks_and_directories,
  migration_checksum_binds_sqlx_bytes_as_lowercase_sha256,
  missing_local_store_fails_closed_as_expected_release_unavailable}`
- `bins/o3k/tests/backup_verify.rs::rejects_verification_while_the_store_lock_is_held`
- `backup_data_dir::tests::{parses_the_single_assignment_and_ignores_everything_else,
  rejects_ambiguous_or_unsafe_values, precedence_matches_the_documented_rule,
  installed_environment_file_parses_when_present,
  readable_environment_file_wins_over_the_packaged_directory,
  packaged_directory_is_used_when_the_environment_file_yields_nothing,
  packaged_directory_is_not_used_when_it_is_not_owned_by_the_caller,
  environment_file_posture_requires_a_trusted_owner_and_no_group_write}`
- `backup_trust::tests::{installed_data_dir_detection_survives_a_symlinked_packaged_directory,
  root_owned_document_without_group_read_names_the_service_user_reason}`
- `backup_verify::tests::artifact_open_never_blocks_on_a_fifo`
- `backup_create::tests::{impostor_daemon_never_receives_the_request,
  unreadable_expected_daemon_path_is_identity_unavailable}`
- `backup::tests::the_complete_size_bound_is_unreachable_for_a_schema_valid_manifest`
- `backup_artifact::tests::{operation_lock_is_exclusive_and_released_on_drop,
  signing_request_validation_binds_identity_digests_and_expiry,
  signing_response_is_bound_to_the_request_and_the_trust_key,
  config_loads_the_installed_release_and_binds_the_data_directory,
  snapshot_facts_read_store_identity_and_repository_emptiness,
  snapshot_facts_reuse_the_verify_migration_mapping,
  non_terminal_operations_are_recorded_as_unknown,
  capture_records_in_flight_operation_identities,
  destination_symlink_is_a_rejected_precondition,
  destination_directory_is_a_rejected_precondition,
  publication_is_no_replace_and_replay_safe,
  naming_and_prefix_resolution_are_stable,
  post_publication_staging_cleanup_failure_is_an_unknown_outcome,
  post_publication_marker_removal_failure_is_an_unknown_outcome,
  signing_wait_retries_a_partially_written_response,
  repository_table_mapping_covers_the_committed_baseline}`
- `backup_create::tests::{invalid_configuration_fails_before_capture,
  published_operation_is_refused_before_controller_contact,
  incomplete_operation_is_recoverable_without_a_controller,
  two_phase_flow_publishes_a_verified_artifact,
  phase_one_waits_for_the_signature_and_publishes,
  phase_two_without_a_signature_safely_aborts,
  phase_two_requires_the_lifetime_store_lock,
  capture_failure_helper_records_the_terminal_aborted_phase}`
- `backup::tests::{unsigned_stage_finishes_with_a_detached_signature_only_after_verification,
  unsigned_stage_rejects_a_wrong_key_id_and_a_tampered_payload,
  finalize_replaces_a_stale_partial_instead_of_wedging,
  member_path_grammar_rejects_hidden_and_option_like_segments}`
- `backup_reservation::tests::{reservation_boundaries_follow_d9,
  space_boundaries_never_truncate_the_reservation,
  boundary_recheck_never_truncates_the_remaining_reservation,
  measures_regular_files_in_a_real_directory,
  rejects_symlinked_or_non_regular_sources,
  reports_stable_reason_strings}`
- `backup_trust::tests` (file posture, key derivation, revocation, custody
  expiry, identity binding, default path precedence)
- `o3k-store backup_journal::tests` (atomic records, pending scan, invalid
  records, symlinked directory, phase stability, forward-only transitions)
- `o3k-store state_inventory::tests::regeneration_is_refused_in_ci`
- `bins/o3kd composition::tests::pending_backup_operation_journal_does_not_deny_startup`
- `bins/o3k/tests/backup_create_hooks.rs::crash_during_the_signing_wait_keeps_the_marker_and_staged_request`

The handoff journey, its 19 executed cases and its 7 documented-coverage rows
remain covered by `tests/pp6_backup_handoff.sh` (still passing; see below). That
campaign uses the harness-only `O3K_BACKUP_TEST_STOP_AFTER_STAGING=1` so its
rows keep their one-shot phase-1 shape; it exercises the handoff, lock and
failure-injection matrix, not the Option A wait (which is proven by the artifact
campaign).

## Secret-scan result

PASS (`case-9`). The scan covered all captured stdout/stderr/log files and the
published artifact bytes. Neither the Ed25519 private seed (hex), the X25519
recipient private bytes (hex), the signing-key path, nor the recipient-key path
appeared. Decrypted plaintext is only ever written under
`<data_dir>/.o3k-verify-staging-*` (0700) and is removed before success; the
campaign asserts that no such directory remains after `o3k backup verify` and
that the published artifact is 0600.

## Validation performed

```text
cargo fmt --all -- --check                                        # PASS
cargo clippy -p o3k -p o3k-store -p o3kd --all-targets --all-features -- -D warnings  # PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings                 # PASS
cargo test -p o3k -p o3k-store -p o3kd --all-features             # PASS (0 failures)
cargo test --workspace --all-features                             # PASS (0 failures)
bash -n tests/pp6_backup_artifact.sh tests/pp6_backup_handoff.sh  # PASS
shellcheck -S warning tests/pp6_backup_artifact.sh tests/pp6_backup_handoff.sh  # PASS (no findings)
bash tests/pp6_backup_artifact.sh        # PASS (three recorded runs): 45 matrix rows, 44 PASS, 1 not-covered, 0 failures
bash tests/pp6_backup_handoff.sh         # PASS: 19 executed, 7 documented, 0 failures
bash tests/adr-governance.sh             # PASS
bash tests/supply-chain-governance.sh    # PASS
git diff --check                                                  # PASS
```

Shellcheck is run at `-S warning` (severity warning and above); the `info` and
`style` notes are suppressed and are not part of the gate. Both campaigns
produce no finding at that level; `bash -n` parses both scripts.

The artifact campaign produced the matrix above (`NOT-COVERED=1`, `FAIL=0`,
`PASS=44` of 45 matrix rows) in every recorded run; the per-run artifact digest,
backup id, data-directory identities and size differ by construction. The
round-2 regression rows (`case-24`, `case-25`, `case-26`) and the
round-2/cleanup additions (`case-27`, `case-1d-decrypt`) are included in those
runs; round 3 re-signed the `case-24` manifest so that row proves the
required-member ordering with a valid signature, and re-ran both campaigns on
the final tree.

The campaign is re-runnable and deterministic in its assertions: crashes use
process-exit hooks, the only barriers are the executor's two-way file barrier
and bounded readiness/exit/file polls, and the signing wait is bounded by the
request TTL (or a feature-gated test timeout). The runs recorded above were
executed on the tree of the commit named as `final_commit` in
`FINAL-COMMIT-BINDING`; that commit is the binding for these results, and the
tracked tree was clean at run time (untracked build/campaign directories
excluded, as the harness's own `git status --porcelain --untracked-files=no`
check records). The handoff campaign's 19 executed rows and 7
documented-coverage rows are unchanged and passing. Per-run randomness is
confined to the artifact content key, timestamps and the temporary
data-directory identities (and therefore the artifact digest).

## Findings and residuals (contract review round 1 applied)

- **Exclusion now spans publication (was a contract violation).** Before this
  round the executor released the store lock and removed the marker as soon as
  the artifact was staged, so a controller could start during the signing
  window (ADR-0190 Option A says it stays stopped). The marker and the lock now
  last until verified publication or the safe abort. The consequence is
  intended and recorded: a signing delay extends API downtime.
- **A request that expires while waiting is a safe abort (exit 3, not 2).** No
  publication is pending, so the staging tree and the marker are removed. The
  task brief allowed "exit 2/4 per implementation"; the accepted contract uses
  the recoverable class and that is recorded honestly.
- **`controller-active` is the observable phase-2 exclusion.** Because phase 2
  takes the same lifetime store lock, a concurrent replay is normally rejected
  with exit 2 `controller-active` before it can reach the per-operation
  `operation.lock`. The operation lock (`operation-busy`, exit 3) remains a
  defense-in-depth guard for two invocations that reach the same staging tree
  from unrelated data directories; the campaign cannot deterministically create
  that race, so only the lock acquisition path is exercised by unit tests.
- **A stale `artifact.partial` is only replaced when it is this operation's
  private regular file.** A symlinked, non-regular or over-permissive entry
  fails closed (`artifact-finalize-failed`/`staged-artifact-invalid`) instead of
  being removed, which keeps an untrusted entry from being silently deleted.
  The operator must inspect and remove such an entry.
- **Verifier migration identity sourcing.** `o3k backup verify` reads the
  migration inventory from the local canonical store because the installed
  release manifest carries only `schema_version`. It therefore takes the D4
  store-access lock and refuses to run while a controller (or a capture waiting
  for its signature) owns the data directory. Deriving the identities from
  installed metadata would need a release-signed migration inventory in the
  installation manifest; that is a follow-up, not a restore-time claim.
- **Data-directory resolution is shared but not unified with `o3k-config`.**
  `create`/`verify` resolve root → `/var/lib/o3k`, non-root → `O3K_DATA_DIR` →
  `/etc/o3k/o3kd.env` → the packaged `/var/lib/o3k` when it exists and is owned
  by the effective uid → `./data`. The packaged step exists because the
  installed environment file is `root:root 0600` and unreadable to the `o3k`
  service user; a present-but-unreadable file therefore falls through instead
  of failing. Other `o3k` subcommands still resolve the data directory through
  `o3k-config`; aligning them is out of scope here.
- **Crash injection is exit-based.** The artifact campaign uses hard
  `std::process::exit` hooks, not SIGKILL; it exercises journal durability and
  replay ordering, not filesystem-level torn writes. The handoff campaign keeps
  its SIGKILL coverage for the lock-transfer window.
- **D9 enforcement is preflight plus boundary re-checks, not a quota.** See the
  non-claim below.
- **`recorded_unknown` is truthful, not a drain proof.** If the quiesced
  snapshot contains a non-terminal Operation, the manifest says
  `recorded_unknown` and the ids are preserved in the capture metadata; the
  artifact does not claim the operation was resolved.
- **Round-2 residuals.** (1) Release-signature verification for upgrades is
  not implemented; H2 only stops root from being redirected through
  `O3K_UPGRADE_*`. (2) `verify` still performs full decryption and therefore
  needs the recovery private key; a public-key-only verification mode is a
  follow-up contract decision. (3) The `O3K_BACKUP_TEST_DAEMON_EXE` override
  exists only in `backup-test-hooks` builds for the in-process fake-daemon
  tests; a production binary never reads it. (4) For the installed
  `/var/lib/o3k` directory the trust/install overrides are ignored even for
  root; this is deliberately stricter than the minimum review request and
  keeps TestLab overrides for non-installed directories. (5) The verify copy
  includes the main database and a non-empty `-wal`; SQLite recreates the
  `-shm` index in the private staging directory.

## Contract decisions required

These are places where the accepted contract text and this implementation (or
the frozen schema) do not fully coincide, or where a boundary is deliberately
narrower than a reader might assume. Each needs a human decision before the
corresponding claim can be widened; none is silently resolved here.

- **D9 staging quota vs. preflight + boundary re-checks.** The accepted D9 text
  says "enforce as staging quota". The implementation measures the source after
  the truncating checkpoint, computes `max(2×S + 1 GiB, 6 GiB)` (cap 9 GiB), and
  re-checks `f_bavail × f_frsize` before capture, before finalize and before
  publication. It fails closed (`space-unavailable`, exit 3) and never
  truncates, but it is **not** a filesystem quota: a concurrent writer can
  consume space between checks. A human contract decision is required either to
  accept this enforcement model as satisfying D9 or to amend the D9 wording.
- **D2 trust-root lifecycle/rotation.** Only a static configured trust document
  with a static `revoked_key_ids` list is implemented. There is no root rotation,
  key ceremony, revocation-distribution endpoint, sequence/`next_update`
  tracking, or two-of-three root-signing workflow. Those D2 mechanisms remain a
  contract/implementation gap, not a tested behavior.
- **Required-member set (four members, v1).** The accepted v1 schema
  (`contracts/control-plane-backup-v1.proposed.schema.json`) constrains member
  *shape* but not member *names*; the implementation requires all four listed
  capture members (`database/o3k.sqlite`, `metadata/capture.json`,
  `release/release-manifest.json`, `trust/backup-trust.json`) to be present
  through `REQUIRED_ARTIFACT_MEMBERS`; a missing one is the typed
  `missing-required-member` (exit 2). It does not reject additional
  schema-valid members (up to the contract's 64-member limit). The presence
  requirement is deliberately stricter than the schema: it makes "a validly
  signed artifact that omits a member" a rejection rather than an accepted
  artifact with fewer members (`case-24`). A human decision is required to make the four-member set
  normative in the contract (schema `minContains`/member-name enumeration, or
  the v1 text) before it is described as a contract requirement rather than an
  implementation choice.
- **Trust-document format and mode (`0640` root:service-group vs `0600`).**
  SPEC-0050 §8 requires root-owned installation configuration, but the packaged
  service user is `o3k`, so a `root:root 0600` document is unreadable to it.
  The accepted implementation posture is "owned by root **or** the effective
  uid; mode `0600`, or `0640` when the owning group is root or one of the
  process's groups; never group/other writable; never other readable", with
  `root:o3k 0640` as the packaged mode and `0600` as the euid-owned TestLab
  mode. A root-owned `0600` document for a non-root caller is reported as
  `trust-config-unreadable-by-service-user`. Whether the contract should name
  `0640` plus a service group as the packaged posture (and whether the file
  format should record a service-group name) is a human decision, not a
  resolved part of the accepted text.
- **D13 no-table repositories.** The contract schema requires `minItems: 1` for
  both object arrays, and the committed baseline has no repository with zero
  tables. A genuinely empty repository cannot be represented without inventing a
  synthetic object or amending the schema; this remains a SPEC/schema conflict.
- **D13 object kinds.** The accepted text lists tables, views, sequences,
  indexes, constraints, functions and triggers. The implementation covers
  tables, indexes, triggers (both backends) and PostgreSQL functions; views,
  sequences and explicit named constraints are absent, and PostgreSQL
  `ALTER TABLE ... ADD COLUMN` effects are not merged into textual definitions.
  A human decision is required on whether v1 must cover those kinds or whether
  the narrower catalog is the accepted boundary.
- **§4 private-recovery-key boundary.** Full `o3k backup verify` decrypts every
  member and therefore must run on the recovery/operator host that holds the
  X25519 private key. The campaign's independent check shows that
  signature/D1/member-digest authenticity is verifiable with the public key
  alone, but a supported public-key-only verify mode is a follow-up contract
  decision, not an implemented mode.
- **#1084 remains open.** This document is Slice F implementation and campaign
  evidence only. Issue closure still needs the remaining slices, human
  exact-commit review, and the supported-profile gates; nothing here closes it.

## Security/correctness review round 5 (final)

- **Help text** now describes the in-process Option A wait (the first invocation
  does not exit; re-run only after a crash).
- **D9 depth-8 bound enforced** in member-path validation (`validate_path`),
  with the existing unit tests; deeper signed members are rejected.
- **Verify failure-path cleanup**: a failed removal of the private staging tree
  (which holds the database copy) now returns exit 4 `verification-cleanup-failed`
  instead of a recoverable/rejected code.
- **Replay success JSON** omits `source_bytes` (it is not re-measured) instead of
  reporting a misleading zero.
- **Evidence**: the bound verdict block is valid verbatim JSON; the harness-digest
  note and verify-boundary wording are corrected; the post-binding packaging
  delta is recorded; the required-member wording now states presence (not
  exact-set) and the D13 object-kind decision is registered.
- **Packaging fixture**: `tests/packaging-account-refusal.sh` stages the trust
  template, and `tests/packaging-bundle.sh` asserts the installed template and
  its `.o3k-installed` entry.
- Comments corrected (linkat publication, D8 out of scope, replay publication
  still requires the store lock).

## Honest non-claims

- **No restore.** This slice produces and publishes the encrypted artifact.
  Restore, restore journaling, fencing and replacement-host recovery are
  separate contracts and are not implemented or tested here.
- **No PostgreSQL.** Every row ran on the SQLite portable/TestLab default.
  `store.backend` is always `sqlite`. PostgreSQL is a production-oriented
  target without an adapter/conformance suite in this slice.
- **No production/HSM custody qualification.** The Ed25519 and X25519 keys are
  generated in a temporary directory on the recording host. The trust document
  describes a `2-of-3` custody process, but the tool (and this evidence) cannot
  attest that two custodians approved, that the offline workstation was
  uncompromised, or that an HSM/custody appliance was used. Custody remains an
  operator process.
- **Not "supported PP.6 operational recovery".** That statement requires the
  #944 runbook and exact-release verification evidence in the supported
  deployment profile. This document proves the artifact lifecycle and its
  failure matrix only.
- **No Kubernetes/HA, edge-profile, cross-cloud or footprint claim.** The
  evidence is one host running the SQLite demo/TestLab profile.
- **D9 enforcement scope.** The accepted reservation (`max(2×S + 1 GiB,
  6 GiB)`, cap 9 GiB) is a preflight plus boundary re-check against
  `f_bavail × f_frsize`: once before capture (after the WAL checkpoint), once
  before finalize and once before publication, each never lowering the reserve.
  It is **not** a filesystem quota and does not prevent another process from
  consuming the space between checks; a shortfall fails closed with exit 3
  `space-unavailable` and nothing is truncated.
- **Option A wait semantics.** While waiting for the detached signature the
  controller cannot start (the denial marker and the store lock are held), so
  signing delays extend API downtime and may extend the recovery point
  interval. The wait is bounded by the request's `expires_at` (24 h from the
  snapshot) plus an optional implementation timeout; expiry is host-clock
  based, with no HSM time attestation, and the tool cannot observe whether the
  custodian process actually happened.
- **Verify locking.** `o3k backup verify` needs the same exclusive store lock as
  the controller, so it is refused (exit 2 `controller-active`) while a
  controller is running. It does not hot-read a live store; operators stop the
  controller (or use the maintenance window) before verifying. It copies the
  main database and a non-empty WAL sidecar into its private `0700` staging and
  opens the copy read-only. The live database file is opened read-only to make
the copy but is never opened as a SQLite store, checkpointed, migrated or
mutated. The lock is held for the copy and released before artifact
verification.
- **Independent harness verification scope (F15).** The campaign now rebuilds the
  exact D1 input from the published bytes with a local JCS implementation
  (byte-checked against the artifact's stored canonical manifest), verifies the
  Ed25519 signature with `openssl pkeyutl -verify -rawin -pubin`, recomputes
  every member's SHA-256 over ciphertext+tag, and, when python `cryptography` is
  available, performs the HPKE X25519/HKDF-SHA256 key unwrap and AES-256-GCM
  member decryption independently of the product verifier. The decrypted
  `database/o3k.sqlite` is bound to the signed capture record's
  `snapshot_sha256`, the record's `source_db_sha256_before`/`_after` are bound
  to the harness-measured source database, and the decrypted snapshot's catalog
  and `_sqlx_migrations` lineage must equal the source database's. Limits: the
  HPKE/AES-GCM primitives come from the python `cryptography` library rather
  than a second from-scratch implementation; the snapshot is produced by
  `VACUUM INTO` and is **not** byte-identical to the source database, so the
  harness does not claim `SHA-256(decrypted database) == source database hash`
  (it claims equality with the signed capture record's snapshot digest plus
  logical schema/migration equivalence to the source); and if `cryptography` is
  unavailable the campaign records `decrypt=unavailable` and the
  `case-1d-decrypt` row is NOT-COVERED while the signature/D1/digest legs still
  PASS in `case-1d`. A NOT-COVERED decryption leg is never reported as PASS.
- **#1084 is not closed by this evidence.** This document records Slice F
  implementation and campaign evidence only; issue closure requires the
  remaining slices, human review at an exact commit, and the supported-profile
  gates.
- **D4 exclusion is continuous but operator-visible.** The lock and denial
  marker are held across the signing wait and publication (Option A), so a
  systemd-managed controller restart during that window is downtime, not a
  transparent handoff. The wait is bounded by the request TTL.
- **D9 is preflight plus re-checks, not a filesystem quota** (see above); a
  concurrent writer can still consume space between checks.
- **D13 catalog coverage and the no-table SPEC/schema conflict.** The generated
  inventory now covers SQLite tables/indexes/triggers and PostgreSQL
  tables/indexes/triggers/functions, and capture compares the snapshot's live
  `sqlite_master` (tables/indexes/views/triggers) against the baseline. It does
  not emit views, sequences, explicit named constraints, PostgreSQL
  `ALTER TABLE ADD COLUMN` effects, or a live PostgreSQL catalog comparison.
  The contract requires `minItems: 1` for both object arrays, so a repository
  with no table cannot be represented without either inventing a synthetic
  object or amending the schema; the registry therefore keeps its current shape
  (every repository owns at least one table) and this remains a SPEC/schema
  conflict rather than an implemented no-table repository entry.
- **D2 trust-root rotation/lifecycle is not implemented.** Trust is a static
  configured document with a static `revoked_key_ids` list; there is no
  root-rotation, key-ceremony, or revocation-distribution workflow.
- **Oversized artifacts are exit 2, not exit 4.**
  `artifact-too-large` is a rejected precondition (exit 2) and is
  NOT-COVERED end-to-end because producing a validly signed manifest declaring
  more than 5 GiB would require a bespoke artifact assembler; only the unit
  mapping test covers it. The exit-4 cleanup classifications
  (`post-publication-cleanup-failed`, `marker-removal-failed`) are unit-only;
  no real-process exit-4 cleanup row is claimed.
- **Packaged service-user path is unit-tested only.** The `/var/lib/o3k`
  fallback (owned-directory check), detection of an installation whose
  `/var/lib/o3k` is a symlink, the `root:o3k 0640` trust posture and
  `trust-config-unreadable-by-service-user` are covered by unit tests with
  temporary fixtures. No test creates a real `/var/lib/o3k`, runs as the
  packaged `o3k` account, or exercises the installed systemd unit; the campaign
  runs as an ordinary user with `O3K_DATA_DIR` and `O3K_BACKUP_TRUST_CONFIG`
  pointing into a temporary tree. Do not read this as installed-host evidence.
- **No independent review yet.** The implementation, the campaign and this
  document were produced by the same agent. This is interim evidence pending
  human exact-head review; it is not an independent verification.

## Machine-readable verdict

The authoritative run is recorded in `FINAL-COMMIT-BINDING` (clean commit
`50113f7a`). The JSON below is an earlier pre-binding run on the uncommitted
working tree, kept to show per-run variation: the same matrix and row outcomes
with different artifact digest, backup id, data-directory identities and size.
The harness prints the same object on stdout between the markers
`O3K_PP6_VERDICT_JSON_BEGIN` and `O3K_PP6_VERDICT_JSON_END`.

`source_sha` / `working_tree_dirty` are **per-run facts about the tree that was
tested**, not an exact-commit claim; see `FINAL-COMMIT-BINDING`.

```json
{
  "backup_digest": "dff4e3cdce0e16110b785b8cbd963075a8dbd33da626d821d0fc2d151008e411",
  "backup_id": "c8ec240e-f12e-40b9-bbdf-8dedd6417418",
  "backup_installation_id": "b21e49612359e5534387aa9dc80e6dde",
  "backup_site_id": "4a49afa56cce12f81425b3059ab2b38b",
  "backup_size_bytes": 1261601,
  "campaign": "tests/pp6_backup_artifact.sh",
  "executed_rows": 44,
  "failed_rows": 0,
  "harness_sha256": "f5d4a8e05ef4fcd66e6acf5c5b5683bdb6640cea4d686989ca6333db484071e1",
  "host_identity_hash": "8110f5814f95639d2d88a1e379a827e065c9c072b52b54c92f4ce2b1051f54bb",
  "issue": 1084,
  "matrix": {
    "FAIL": 0,
    "NOT-COVERED": 1,
    "PASS": 44
  },
  "max_migration_checksum": "7a2333035bc23d000c129d6d87d236b119a69bbc2de5bda6e41618c6b1488fc0",
  "max_migration_version": 53,
  "not_covered_rows": 1,
  "o3k_binary_sha256": "15b0917a7949bb5adb91a4b3299e9aae3935a71f47f48997bc2120f23ace36f3",
  "o3kd_binary_sha256": "787bfa105c987edd3dd17628c444770aa0269766a5292e62b9d7f6a673a38c66",
  "passed_rows": 44,
  "profile": "o3k-demo-v1",
  "release_artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "rustc_version": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
  "schema_version": 53,
  "slice": "F",
  "source_sha": "ffa0955b36cf6df98eff49c0a15f8d0dbfe8179b",
  "sqlite_version": "3.46.0",
  "state_inventory_sqlite_version": "3.46.0",
  "working_tree_dirty": true
}
```

The verdict now also binds the migration identity of the captured source:
`schema_version` (53), `max_migration_version` (53) and
`max_migration_checksum` (SHA-256 of the highest applied SQLx checksum blob,
the same mapping as the artifact's `store.migrations`). The baseline binding
independently records the SQLite generator version (`3.46.0`).
