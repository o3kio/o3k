# #1084 authenticated backup artifact — Phase-8 Slice F evidence

Date: 2026-10-24. Branch: `pp6/1084-artifact`. Branch head:
`41f9c24bce8c8a5b8d97b1a9fdd4af24ba3322dd` (`fix(pp6): address security and
contract review rounds on signed backup artifacts`), on top of
`521cc6fc…` and `20b54afe…`. The working tree is dirty: this final-review round
(D13 catalog kinds/live comparison, F15 harness independence and the small
nits) is uncommitted. `source_sha` in the verdict is the branch head, not a
clean-tree claim; exact-commit binding remains with the parent/reviewer after
commit.

This document reports executable, real-process evidence for the signed backup
artifact lifecycle only. The implementation is authored by the same agent that
authored this campaign; see **Interim review status**.

## Environment

| Item | Value |
| --- | --- |
| campaign harness | `tests/pp6_backup_artifact.sh` |
| harness SHA-256 | `7ed481acd9a66c727abb6f2192642a9f8227f241b4b9b1b4fbb7d7d201699a9c` |
| build | `cargo build -p o3k -p o3kd --features o3kd/backup-test-hooks,o3k/backup-test-hooks` |
| `o3k` binary SHA-256 | `107f8e949663d0cdf0e1331d19b9c0e4d2d86aaf11ebf6b967bc42a004f21d1c` |
| `o3kd` binary SHA-256 | `28f042563ab8578ea0cd9ed857a2ca2b3f7436f602fed5f01f6d09589939515c` |
| rustc | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| SQLite (from the published manifest) | `3.46.0` |
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
the field-by-field template operators copy to the root-owned
`/etc/o3k/backup-trust.json`. The installer never creates the trust document
itself and never makes `/etc/o3k` group/other-accessible.

| Fixture | Generation | Posture |
| --- | --- | --- |
| offline Ed25519 signing key | `openssl genpkey -algorithm ED25519` in the test tree; never passed to `o3k`/`o3kd` | `0600`; only the harness reads it |
| foreign Ed25519 key (negative test) | second `openssl genpkey -algorithm ED25519` | `0600` |
| X25519 recipient keypair | `openssl genpkey -algorithm X25519`; the raw 32-byte private half feeds the trust document, the public half is the fingerprint asserted in the signing request. A second keypair is the `case-17` substitution fixture. | `0600` |
| trust document | `o3k-backup-trust-v1` JSON: site/installation identities derived as `SHA-256(domain ‖ 0x00 ‖ canonical data dir)[:16]`, profile `o3k-demo-v1`, `artifact_signing.key_id=signing-1`, custody record `2-of-3` purpose `artifact-signing` with a mandatory `expires_at`, `revoked_key_ids=[]`, recipient key id `recovery-1`, private-key path and declared `x25519_public_key` (the loader proves the two match) | `0600`, parent dirs `0700` |
| installed release manifest | `<prefix>/share/o3k/release-manifest.json`: `version=0.4.0`, `profile_id=o3k-demo-v1`, `source_commit=0123…4567`, `release_artifact_sha256="a"×64`, `schema_version=53` | `0600` |
| artifact-signing public key | DER tail 32 bytes of the Ed25519 key; embedded in the trust document | public |
| private seed / recipient bytes | extracted only for the secret scan (hex); never written to any captured output | not logged |

`release_artifact_sha256="a"×64` is a fixture constant: the installed manifest
is a synthetic bundle identity, not a real release tarball digest. A production
installation gets that field from the installer/upgrade engine's verified
tarball digest (`bins/o3k/src/upgrade/release_identity.rs`).

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
  `o3k backup create: awaiting-signature <request-path>` line and stays in the
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
  staging.
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
  independent measurement taken after the WAL checkpoint (main database, a
  non-empty `-wal` sidecar, the installation metadata members and the bounded
  capture/request metadata allowance) and `max(2×S + 1 GiB, 6 GiB)` with no
  truncation; the same reservation is re-checked before finalize and before
  publication and never lowered to fit.
- A seeded non-terminal Operation makes the manifest record
  `in_flight_operations=recorded_unknown` (with the stable ids in the capture
  metadata member) instead of claiming `drained`.
- The committed D13 inventory covers 17 repositories: SQLite 78 tables /
  86 indexes / 2 triggers (166 objects), PostgreSQL 78 tables / 83 indexes /
  2 triggers / 2 functions (165 objects). Capture enumerates the snapshot's
  live
  `sqlite_master` and fails closed (exit 2 `store-catalog-mismatch`) on an
  extra, missing or redefined object before staging anything.
- The campaign independently verifies the published bytes: local JCS + exact
  D1 input + OpenSSL Ed25519, recomputed member SHA-256 digests, and HPKE
  content-key unwrap plus AES-256-GCM decryption bound to the signed capture
  record and the harness-measured source database (see the F15 non-claim for
  the exact scope and limits).

## Matrix (recorded from the final campaign run)

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
| 6 | `case-3` duplicate after publication | PASS | 2 | published | 0 | free | yes | `operation-already-published`, one artifact |
| 7 | `case-4a` wrong signature | PASS | 2 | staged | 1 | free | no | `signature-invalid`; staging kept |
| 8 | `case-4b` wrong key id | PASS | 2 | staged | 1 | free | no | `signing-response-mismatch` |
| 9 | `case-4c` short signature | PASS | 2 | staged | 1 | free | no | `signing-response-invalid` |
| 10 | `case-4d` mismatched request digest | PASS | 2 | staged | 1 | free | no | `signing-response-mismatch` |
| 11 | `case-4e` wait timeout → safe abort | PASS | 3 | aborted | 0 | free | no | `signing-request-expired`; staging + marker removed |
| 12 | `case-5a` crash after `captured` (hook 86) | PASS | 86 | captured | 1 | free | no | retry exit 3 `backup-operation-incomplete` |
| 13 | `case-5b` crash after `staged` (hook 87) | PASS | 87 | published | 0 | free | yes | replay resumed the wait and published without recapture |
| 14 | `case-5c` crash after `publishing` (hook 88) | PASS | 88 | published | 0 | free | yes | replay finished publication, one artifact |
| 15 | `case-5d` crash after publication (hook 89) | PASS | 89 | published | 0 | free | yes | retry exit 2 `operation-already-published` |
| 16 | `case-5e` crash between finalize and `publishing` (hook 90) | PASS | 90 | published | 0 | free | yes | retry re-verified `artifact.partial` and published |
| 17 | `case-6` pre-existing final artifact | PASS | 2 | publishing | 1 | free | yes | `artifact-destination-exists`; untouched; retry verified |
| 18 | `case-7` destination symlink swap | PASS | 2 | published | 0 | free | yes | `destination-symlink`; restored and retried |
| 19 | `case-8` modes/cleanup | PASS | — | — | — | free | yes | staging 0700, files 0600, artifact 0600, verify staging removed |
| 20 | `case-9` secret scan | PASS | — | — | — | free | yes | no secret/path match in outputs or artifact |
| 21 | `case-11` replacement controller during the wait | PASS | 0 | published | 0 | free | yes | restart DENIED (exit 1); published; restart then ready + SIGTERM 0 |
| 22 | `case-18` symlink at the final name (F37) | PASS | 2 | published | 0 | free | yes | `artifact-destination-exists`; link never followed; retry published |
| 23 | `case-19` stale empty `artifact.partial` (M5) | PASS | 0 | published | 0 | free | yes | atomic temp+rename; retry published |
| 24 | `case-20` post-rename crash: final present, staging gone (F2) | PASS | 0 | published | 0 | free | yes | destination digest matched; classified complete |
| 25 | `case-21` concurrent phase-2 invocations (F20) | PASS | 0/0/2 | published | 0 | free | yes | one published; the other `controller-active` |
| 26 | `case-22` create with missing trust config (F22) | PASS | 3 | — | 0 | free | no | `trust-config-unavailable` |
| 27 | `case-23` seeded non-terminal Operation (M4) | PASS | 0 | published | 0 | free | yes | `consistency.in_flight_operations=recorded_unknown` |
| 28 | `case-12missing-trust` | PASS | 3 | — | — | free | yes | `trust-config-unavailable` |
| 29 | `case-12identity` | PASS | 2 | — | — | free | yes | `identity-mismatch` |
| 30 | `case-12release` | PASS | 2 | — | — | free | yes | `release-mismatch` |
| 31 | `case-12revoked` | PASS | 2 | — | — | free | yes | `revoked-signing-key` |
| 32 | `case-12truncated` | PASS | 2 | — | — | free | yes | `corrupt-artifact` |
| 33 | `case-12oversize` | NOT-COVERED | — | — | — | — | — | see below |
| 34 | `case-13` canonical-state immutability | PASS | — | published | 0 | free | yes | source DB SHA-256 identical before/after |
| 35 | `case-14` forged `publishing` journal | PASS | 2 | publishing | 1 | free | no | `staged-artifact-invalid`; forged bytes never published |
| 36 | `case-15` forged journal `backup_id` traversal | PASS | 2 | staged | 1 | free | no | `backup-operation-journal-invalid`; no escaped path |
| 37 | `case-16` symlinked staged artifact | PASS | 2 | staged | 1 | free | no | `staged-artifact-invalid`; `O_NOFOLLOW` refuses the link |
| 38 | `case-17` recipient-key substitution | PASS | 2 | published | 0 | free | yes | request fingerprint; swapped trust rejected; original published and verified |
| 39 | `case-1d` independent artifact verification | PASS | 0 | published | 0 | free | yes | local JCS + OpenSSL Ed25519 over D1, recomputed member digests, HPKE/AES-GCM decrypt bound to capture record and source DB |
| 40 | `case-1e` independent check rejects the tampered artifact | PASS | 2 | published | 0 | free | yes | independent member SHA-256 recomputation flags the flipped byte; nothing published |

Totals: **39 executed rows PASS, 1 NOT-COVERED, 0 FAIL**. No unexecuted row is
reported as PASS.

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
  verifies with `openssl pkeyutl -verify -rawin -pubin`, recomputes every
  member digest, and (when python `cryptography` is present) unwraps the HPKE
  content key and decrypts every member. The `database/o3k.sqlite` plaintext is
  compared with the signed `metadata/capture.json` `snapshot_sha256`; the
  capture record's source-before/after digests are compared with a fresh hash
  of the source database; and the decrypted snapshot's catalog and
  `_sqlx_migrations` rows are compared with the source. `VACUUM INTO` rebuilds
  the file, so byte equality with the source database is neither expected nor
  claimed.
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
- `case-6` also confirms the replay path: after the colliding file is removed,
  the journal `publishing` record plus the staged signed artifact publish
  without a second signature (and the marker is removed).
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
- `case-20` simulates the post-rename crash on the already published `case-1`
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
| F16 trust template | `packaging/backup-trust.example.json` (placeholders, no keys) installed to `<prefix>/share/o3k/`; installer documents the fields and never creates `/etc/o3k` with permissive modes | `packaging/install.sh`; ownership list in `packaging/uninstall.sh` |
| F17 harness negatives | `case-14`, `case-15`, `case-16`, `case-17`; `case-17` asserts the request exposes `recipient_public_key_sha256` and that a swapped recipient is rejected by phase 2 and `o3k backup verify` | `tests/pp6_backup_artifact.sh` |

### F7/F8 design note (recipient binding)

The signing request now carries `recipient_public_key_sha256` (SHA-256 of the
configured X25519 recipient public key). The trust document may declare
`recipient.x25519_public_key`; when both halves are present the loader proves
they match, and the capture path uses the declared public key without reading
private key material. A capture-only document may omit
`x25519_private_key_file`; verification still requires it to decrypt members.

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
custody key.

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
| **F1 / Option A exclusion through publication** | `bins/o3k/src/backup_create.rs`: the capture process retains the `StoreAccessLock` and the denial marker after staging and calls `complete_staged` in the same process; `bins/o3k/src/backup_artifact.rs` `complete_staged` emits `o3k backup create: awaiting-signature <request-path>`, polls for `signing-response.json` until the request TTL, then verifies → finalizes → publishes → removes the marker, or performs the safe abort (staging removed, journal `aborted`, marker removed, exit 3 `signing-request-expired`). Phase 2 (same `--destination/--operation-id`) detects the journal before any controller contact, acquires the lifetime lock (`WouldBlock` → exit 2 `controller-active`), re-creates the marker if an operator removed it and resumes the wait/publication. | `case-1a`, `case-1b`, `case-11`, `case-2`, `case-4e`; `backup_create::tests::{phase_one_waits_for_the_signature_and_publishes,phase_two_without_a_signature_safely_aborts,phase_two_requires_the_lifetime_store_lock}` |
| **F2 / P0-2 post-rename recovery** | `backup_artifact.rs` `complete_staged` observes the destination **before** requiring the staging tree: `existing_destination` (`O_NOFOLLOW`, `fstat` regular) → full verification → digest equals `record.artifact_sha256` → `published`, staging removed, marker removed, exit 0. Only when the destination is absent does the staged file drive publication. | `case-20`; `backup_create::tests::two_phase_flow_publishes_a_verified_artifact` (post-rename replay step) |
| **M5 / P0-3 stale `artifact.partial`** | `bins/o3k/src/backup.rs` `finish_signed_artifact` builds into `artifact.partial.tmp-<uuid>` and renames atomically; on any failure the temporary and the partial are removed; a stale entry is removed first only after proving it is this operation's private regular file. `backup_artifact.rs` `remove_stale_finalize_outputs` clears `artifact.partial`/`artifact.partial.tmp-*` whenever `artifact.unsigned` is still present. | `case-19`; `backup::tests::finalize_replaces_a_stale_partial_instead_of_wedging` |
| **M4 / F9 truthful `in_flight_operations`** | `backup_artifact.rs` `snapshot_in_flight_operations` / `query_in_flight_operations` read `operations` from the quiesced snapshot under the store lock (`succeeded`/`failed` are terminal); the manifest records `recorded_unknown` and the ids go into `metadata/capture.json`. | `case-23`; `backup_artifact::tests::{non_terminal_operations_are_recorded_as_unknown,capture_records_in_flight_operation_identities}` |
| **M3 / F5b D9 measurement and footprint** | `backup_create.rs` measures after the truncating WAL checkpoint (main DB + non-empty `-wal` + release/trust members + a 2 MiB capture/request metadata allowance; the accepted formula is unchanged) and fails closed with exit 3 `space-unavailable`; `backup_reservation::ensure_reserved_space` re-checks the remaining reservation before finalize and before publication; `backup.rs` deletes each member ciphertext as soon as it is copied into the unsigned artifact and `artifact.unsigned` right after the partial is durable. | `case-10`, `case-4e`; `backup_reservation::tests::boundary_recheck_never_truncates_the_remaining_reservation` |
| **F12 verify store-access guard** | `bins/o3k/src/backup_verify.rs` acquires `StoreAccessLock` before reading the store; `WouldBlock` → exit 2 `controller-active`; the lock is held for the migration read and released before artifact verification. Deriving migration identity from installed metadata is impossible (the release manifest carries `schema_version` but no migration checksums), so the lock option was chosen. | `case-12*` (no controller); `bins/o3k/tests/backup_verify.rs::rejects_verification_while_the_store_lock_is_held` |
| **F11 data-directory resolution** | New `bins/o3k/src/backup_data_dir.rs` shared by `create` and `verify`: root uses `/var/lib/o3k`; non-root uses `O3K_DATA_DIR`, else the bounded `O3K_DATA_DIR=` assignment in `/etc/o3k/o3kd.env` (no shell evaluation), else `./data`. | `backup_data_dir::tests::{parses_the_single_assignment_and_ignores_everything_else,rejects_ambiguous_or_unsafe_values,precedence_matches_the_documented_rule}` |
| **F22 classification alignment** | `backup_trust::BackupTrustError::is_recoverable` is the single predicate: `ConfigUnavailable`, `RecipientKeyUnavailable`, `IdentityUnavailable` are exit 3 in both `create` and `verify`; `ArtifactConfig::load_from` maps missing release/identity material to recoverable. | `case-22`; `case-12missing-trust`; `backup_create::tests::invalid_configuration_fails_before_capture` |
| **F19 post-publication cleanup reported** | `backup_artifact.rs` `finish_publication`: an unprovable staging/marker removal is exit 4 `post-publication-cleanup-failed`/`marker-removal-failed`; a directory-sync failure on the success path emits the stable warning `o3k backup create: warning post-publication-sync-failed`. | covered by `case-1`/`case-5d` (success path) and the `finish_publication` failure branches |
| **F20 concurrent phase 2** | `backup_artifact.rs` `OperationLock` (`flock LOCK_EX|LOCK_NB` on `<staging>/operation.lock`, mode 0600, released on every return) → exit 3 `operation-busy`; the lifetime store lock remains the primary exclusion. | `case-21`; `backup_create::tests::phase_two_requires_the_lifetime_store_lock`; `backup_artifact::tests::operation_lock_is_exclusive_and_released_on_drop` |
| **F37 final-name entry classification** | `existing_destination` classifies a symlink or non-regular entry at the final name as `artifact-destination-exists` (exit 2), never exit 4. | `case-18`; `backup_artifact::tests::{destination_symlink_is_a_rejected_precondition,destination_directory_is_a_rejected_precondition}` |
| **F31 exit-4 journal state** | `backup_create.rs` records the journal as `aborted` before returning `source-modified-during-capture`, `snapshot-hash-failed`, `source-rehash-failed` and `capture-outcome-unknown`, so a retry reports the real state instead of `backup-operation-incomplete`. | covered by the `mark_operation_aborted` call sites; the marker still denies startup |
| **L2 rustdoc attribution** | `bins/o3kd/src/composition/mod.rs`: the marker denial doc is on `deny_interrupted_backup_markers`; `warn_pending_backup_operations` has its own diagnostic-only doc. | — |
| **L3 single migration mapping** | `backup_artifact.rs` capture calls `backup_verify::migration_checksum`; one documented mapping for both paths. | `backup_artifact::tests::snapshot_facts_reuse_the_verify_mapping` |
| **L5 member path grammar** | `backup.rs` `validate_path` rejects segments starting with `.` or `-`; `contracts/control-plane-backup-v1.proposed.schema.json` uses the same rule. | `backup::tests::member_path_grammar_rejects_hidden_and_option_like_segments` |
| **L6 forward-only journal** | `crates/o3k-store/src/backup_journal.rs` `advance_backup_operation` reads the on-disk phase, refuses regressions (`backup-operation-phase-regression`) and treats an already-durable phase as idempotent; every `update_journal`/abort/`mark_published` call uses it. | `backup_journal::tests::{transitions_only_move_forward,advance_is_idempotent_and_refuses_to_regress}` |
| **L7 typed verification classification** | `bins/o3k/src/backup.rs` `ArtifactVerifyClass`/`ArtifactVerifyError`: the reason code and exit status come from the typed class, never from wording; `backup_verify.rs` maps class → exit/reason. | `backup_verify::tests::reason_mapping_is_stable_for_every_failure_class` (asserts the exact strings); `bins/o3k/tests/backup_verify.rs` |
| **L8 / F30 harness dirty detection** | `tests/pp6_backup_artifact.sh` uses `git status --porcelain --untracked-files=no` scoped to the change set, so unrelated untracked build directories do not mark the campaign dirty. | verdict `working_tree_dirty` field |
| **F34 CI cannot regenerate the baseline** | `crates/o3k-store/src/state_inventory.rs` `regeneration_requested` refuses `O3K_REGENERATE_INVENTORY=1` whenever `CI` is set. | `state_inventory::tests::regeneration_is_refused_in_ci` |

## Final review round: D13 catalog completeness and F15 harness independence

| Item | Change | Evidence |
| --- | --- | --- |
| **F4a / D13 catalog completeness** | `crates/o3k-store/src/state_inventory.rs` now emits tables, indexes and triggers from both migration trees, plus PostgreSQL functions. Indexes/triggers are assigned to the repository owning their `ON <table>`; the two generic operation-integrity functions are assigned to `operations` through the reviewed `GENERIC_FUNCTION_OWNERS` list (an unlisted function fails generation). The SQLite catalog is generated by applying the migration tree in an in-memory store and reading `sqlite_master`, so SQLite's `ALTER TABLE ... ADD COLUMN` rewrites and the runtime `operations` rebuild are reflected in the baseline digests. | `state_inventory::tests::{baseline_inventory_includes_indexes_triggers_and_functions, baseline_comparison_detects_added_indexes_and_triggers, generation_rejects_an_index_owned_by_an_unregistered_table, generation_rejects_a_function_without_a_reviewed_owner, index_trigger_and_function_normalization_is_deterministic}`; committed baseline regenerated |
| **F4b / live catalog comparison** | `snapshot_facts` enumerates the snapshot's live `sqlite_master` (tables/indexes/views/triggers), excludes `sqlite_*` internal names, compares names and normalized definition digests against every baseline entry in both directions, and fails closed with exit 2 `store-catalog-mismatch` before staging. `_sqlx_migrations` remains compared because the baseline claims it. | `backup_artifact::tests::{snapshot_catalog_rejects_an_extra_index, snapshot_catalog_rejects_an_extra_table, snapshot_catalog_rejects_a_changed_definition, snapshot_facts_read_store_identity_and_repository_emptiness}` |
| **F15 harness independent verification** | `tests/pp6_backup_artifact.sh` independently rebuilds D1 (local JCS), verifies Ed25519 with OpenSSL, recomputes member digests, and decrypts HPKE/AES-GCM members with python `cryptography`; the database plaintext is bound to the signed capture record and the harness-measured source database. `case-1d` is the positive row and `case-1e` the tampered negative row. | `case-1d`, `case-1e` |
| **Nits** | `main.rs` Backup help text describes the two-phase signed flow; the stale raw-key trimming comment in `bins/o3k/tests/backup_verify.rs` is corrected; the happy-path executor wait is explicitly bounded by `wait_bounded`; this document uses "fixture trust document" for `O3K_BACKUP_TRUST_CONFIG`. | `cargo fmt`/clippy/tests; `bash -n` and shellcheck (pre-existing warnings only) |

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

## Executed vs documented-not-executed

Executed real-process rows: 39 PASS rows (one per matrix row except
`case-12oversize`), produced by `tests/pp6_backup_artifact.sh` on the final
tree. The campaign prints its own PASS/FAIL/NOT-COVERED accounting and exits
non-zero on any failure.

Not executed end-to-end (`NOT-COVERED`, exact reason and coverage):

- **Oversized artifact (`artifact-too-large`).** The verifier applies the
  5 GiB manifest-bounded size check only after a valid Ed25519 signature over
  the manifest. Producing that input would require the harness to reimplement
  artifact assembly and sign a malicious manifest; that is not a real operator
  path and would be evidence of a bespoke tool rather than of the product.
  The stable mapping is unit-covered by
  `backup_verify::tests::reason_mapping_is_stable_for_every_failure_class`
  (`ArtifactVerifyClass::ArtifactTooLarge` → exit 2 `artifact-too-large`).

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
  installed_environment_file_parses_when_present}`
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
  repository_table_mapping_covers_the_committed_baseline}`
- `backup_create::tests::{invalid_configuration_fails_before_capture,
  published_operation_is_refused_before_controller_contact,
  incomplete_operation_is_recoverable_without_a_controller,
  two_phase_flow_publishes_a_verified_artifact,
  phase_one_waits_for_the_signature_and_publishes,
  phase_two_without_a_signature_safely_aborts,
  phase_two_requires_the_lifetime_store_lock}`
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

The handoff journey, its 17 executed cases and its 7 documented-coverage rows
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
cargo check -p o3k -p o3k-store --all-features                    # PASS
cargo clippy -p o3k -p o3k-store -p o3kd --all-targets --all-features -- -D warnings  # PASS
cargo test -p o3k -p o3k-store -p o3kd --all-features             # PASS (0 failures)
bash -n packaging/install.sh packaging/uninstall.sh \
        tests/pp6_backup_artifact.sh tests/pp6_backup_handoff.sh   # PASS
bash tests/pp6_backup_artifact.sh        # PASS (run 1): 39 executed, 1 not-covered, 0 failures
bash tests/pp6_backup_artifact.sh        # PASS (run 2): same matrix and row outcomes
bash tests/pp6_backup_handoff.sh         # PASS: 17 executed, 7 documented, 0 failures
git diff --check                                                  # PASS
```

The two artifact-campaign runs produced the same matrix
(`NOT-COVERED=1`, `FAIL=0`, `PASS=39`) and the same per-row outcomes; only the
per-run artifact digest, backup id, data-directory identities and size differ
by construction. Shellcheck reports only pre-existing warnings (unused
campaign variables and the cleanup trap's indirect reachability); `bash -n`
passes.

The campaign is re-runnable and deterministic in its assertions: crashes use
process-exit hooks, the only barriers are the executor's two-way file barrier
and bounded readiness/exit/file polls, and the signing wait is bounded by the
request TTL (or a feature-gated test timeout). The artifact and handoff
campaigns above are the final invocations of the final tree (security-review
round 1 and contract/correctness-review round 1 included) and produced the
recorded matrix outcomes. The handoff campaign's 17 executed rows and 7
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
  `/etc/o3k/o3kd.env` → `./data`. Other `o3k` subcommands still resolve the
  data directory through `o3k-config`; aligning them is out of scope here.
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
  controller (or use the maintenance window) before verifying.
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
  unavailable the campaign records `decrypt=unavailable` and retains the
  signature/digest checks only.
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
- **Exit-4 real-process coverage remains NOT-COVERED for oversized artifacts.**
  The verifier's `artifact-too-large` check runs only after a valid Ed25519
  signature over a manifest declaring more than 5 GiB; producing that input
  would require a bespoke artifact assembler and is covered only by the unit
  mapping test.
- **No independent review yet.** The implementation, the campaign and this
  document were produced by the same agent. This is interim evidence pending
  human exact-head review; it is not an independent verification.

## Machine-readable verdict

Generated by the final campaign run (`tests/pp6_backup_artifact.sh`); values
that are per-run by construction are the ones from that run. The block below is
run 1; run 2 produced the same matrix and row outcomes with a different artifact
digest, backup id, data-directory identities and size. The harness prints the
same object on stdout between the markers
`O3K_PP6_VERDICT_JSON_BEGIN` and `O3K_PP6_VERDICT_JSON_END`.

```json
{
  "backup_digest": "0e16cbbbfe92faea5261f4f04db02445bf869d56996bb786a716907f1379fa09",
  "backup_id": "98e4bb27-2f04-4e6b-998c-0bfaac22663c",
  "backup_installation_id": "60f8b6fcd49aa27140b79e307f6ea558",
  "backup_site_id": "48488118d24d983de0604c13355304c6",
  "backup_size_bytes": 1261601,
  "campaign": "tests/pp6_backup_artifact.sh",
  "executed_rows": 39,
  "failed_rows": 0,
  "harness_sha256": "7ed481acd9a66c727abb6f2192642a9f8227f241b4b9b1b4fbb7d7d201699a9c",
  "host_identity_hash": "8110f5814f95639d2d88a1e379a827e065c9c072b52b54c92f4ce2b1051f54bb",
  "issue": 1084,
  "matrix": {
    "FAIL": 0,
    "NOT-COVERED": 1,
    "PASS": 39
  },
  "not_covered_rows": 1,
  "o3k_binary_sha256": "107f8e949663d0cdf0e1331d19b9c0e4d2d86aaf11ebf6b967bc42a004f21d1c",
  "o3kd_binary_sha256": "28f042563ab8578ea0cd9ed857a2ca2b3f7436f602fed5f01f6d09589939515c",
  "passed_rows": 39,
  "profile": "o3k-demo-v1",
  "release_artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "rustc_version": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
  "schema_version": 53,
  "slice": "F",
  "source_sha": "41f9c24bce8c8a5b8d97b1a9fdd4af24ba3322dd",
  "sqlite_version": "3.46.0",
  "working_tree_dirty": true
}
```
