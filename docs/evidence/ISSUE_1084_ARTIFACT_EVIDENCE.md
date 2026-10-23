# #1084 authenticated backup artifact — Phase-8 Slice F evidence

Date: 2026-10-24. Branch: `pp6/1084-artifact`. Baseline commit:
`20b54afea966dbfc286e04545a5a8af6987ce2c8` (`feat(pp6): backup trust config,
D9 reservations, D13 inventory, release identity`). The working tree is dirty:
the two-phase offline signing implementation, the durable journal, the verify
command, the D9/D13/release-identity foundations and this evidence slice are
not yet committed. `source_sha` in the verdict below is the baseline commit,
not a clean-tree claim.

This document reports executable, real-process evidence for the signed backup
artifact lifecycle only. The implementation is authored by the same agent that
authored this campaign; see **Interim review status**.

## Environment

| Item | Value |
| --- | --- |
| campaign harness | `tests/pp6_backup_artifact.sh` |
| harness SHA-256 | `776f308ff475e26e768b5fd4c3208a034716ee6b8b6a15983e33c782e64c5e06` |
| build | `cargo build -p o3k -p o3kd --features o3kd/backup-test-hooks,o3k/backup-test-hooks` |
| `o3k` binary SHA-256 | `ce0785089e9028a2dc50d04f405af57fc8d5a6437ebd7a7616e8a72787caab75` |
| `o3kd` binary SHA-256 | `88668ef13fc6d569478a7f35cc8fe6f86992a8162527840ada5a7021ba1fc72c` |
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

| Fixture | Generation | Posture |
| --- | --- | --- |
| offline Ed25519 signing key | `openssl genpkey -algorithm ED25519` in the test tree; never passed to `o3k`/`o3kd` | `0600`; only the harness reads it |
| foreign Ed25519 key (negative test) | second `openssl genpkey -algorithm ED25519` | `0600` |
| X25519 recipient key | `openssl rand -out … 32` (32 raw bytes; the trust loader derives the public key) | `0600` |
| trust document | `o3k-backup-trust-v1` JSON: site/installation identities derived as `SHA-256(domain ‖ 0x00 ‖ canonical data dir)[:16]`, profile `o3k-demo-v1`, `artifact_signing.key_id=signing-1`, custody record `2-of-3` purpose `artifact-signing`, `revoked_key_ids=[]`, recipient key id `recovery-1` | `0600`, parent dirs `0700` |
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
| `O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_STAGED=1` | 87 | `bins/o3k/src/backup_create.rs` after the durable `staged` write | crash before marker removal |
| `O3K_BACKUP_TEST_EXIT_AFTER_JOURNAL_PUBLISHING=1` | 88 | `bins/o3k/src/backup_artifact.rs` after the durable `publishing` write | crash before the no-replace rename |
| `O3K_BACKUP_TEST_EXIT_AFTER_PUBLICATION=1` | 89 | `bins/o3k/src/backup_artifact.rs` after `published` + staging removal | crash before the success document |

The existing handoff hooks/barriers (`94`–`99`, executor barrier,
`O3K_BACKUP_TEST_SKIP_MARKER_CLEANUP`) are unchanged and remain covered by
`tests/pp6_backup_handoff.sh`.

## What this proves

- Real `o3kd` → real `o3k backup create` authenticated handoff; phase 1 captures
  a quiesced SQLite snapshot, assembles the encrypted v1 artifact (manifest,
  HPKE-wrapped content key, AES-256-GCM members, unsigned Ed25519 slot), writes
  the offline signing request, journals `staged`, removes the denial-only
  marker, publishes nothing, and exits 3 `signing-required`.
- The same command with the same destination and operation id verifies the
  detached response against the installed trust document and publishes
  `<destination>/backup-<operation id>.o3k` with an atomic no-replace rename,
  exiting 0. Without a response the retry is idempotent and costs no capture.
- `o3k backup verify --artifact` authenticates the published bytes against the
  installed exact release and removes its private plaintext staging.
- The publication boundary rejects tampering, a pre-existing destination,
  destination symlink swaps, wrong/foreign/short/mismatched signatures, an
  expired request, and a revoked key, with stable exit codes.
- Crash/restart behavior at `captured`, `staged`, `publishing` and
  post-publication is observable and recoverable (or refused) exactly as the
  journal contract states.
- The source database is byte-identical across phase 1 + phase 2 + verify; only
  the operation journal (and transient WAL/lock/socket entries) appears in the
  data directory.
- D9 `source_bytes`/`reserved_bytes` reported by phase 1 equal an independent
  measurement and `max(2×S + 1 GiB, 6 GiB)` with no truncation.

## Matrix (recorded from the final campaign run)

Columns: `exit` is the process status of the decisive invocation (the injected
crash exit for crash rows); `journal` is the durable phase observed afterwards;
`marker` is the count of `.o3k-backup-in-progress-*`; `lock` is whether the
cooperative store lock is held by another process when the row is recorded;
`published` is the presence of the final artifact; `verification` is
`o3k backup verify` or the refusal classification.

| # | Case | Result | Exit | Journal | Marker | Lock | Published | Verification |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `case-1a` phase 1 (barrier-frozen, independent D9 measurement) | PASS | 3 | staged | 0 | free | no | — |
| 2 | `case-10` D9 reservation | PASS | 3 | staged | 0 | free | no | source 1,201,227 B; reserved 6,442,450,944 B = max(2S+1 GiB, 6 GiB) |
| 3 | `case-1b` offline sign → phase 2 | PASS | 0 | published | 0 | free | yes | verified, exit 0, `release_match=true` |
| 4 | `case-1c` single-byte ciphertext flip | PASS | 2 | published | 0 | free | yes | `corrupt-artifact` |
| 5 | `case-2` idempotent phase-1 re-run | PASS | 3 | staged | 0 | free | no | journal bytes and staged artifact digest unchanged |
| 6 | `case-3` duplicate after publication | PASS | 2 | published | 0 | free | yes | `operation-already-published`, one artifact |
| 7 | `case-4a` wrong signature | PASS | 2 | staged | 0 | free | no | `signature-invalid` |
| 8 | `case-4b` wrong key id | PASS | 2 | staged | 0 | free | no | `signing-response-mismatch` |
| 9 | `case-4c` short signature | PASS | 2 | staged | 0 | free | no | `signing-response-invalid` |
| 10 | `case-4d` mismatched request digest | PASS | 2 | staged | 0 | free | no | `signing-response-mismatch` |
| 11 | `case-4e` expired request | PASS | 3 | staged | 0 | free | no | `signing-request-expired` (recoverable; staging kept) |
| 12 | `case-5a` crash after `captured` (hook 86) | PASS | 86 | captured | 1 | free | no | retry exit 3 `backup-operation-incomplete` |
| 13 | `case-5b` crash after `staged` (hook 87) | PASS | 87 | published | 1 | free | yes | replay published, no re-capture; marker retained |
| 14 | `case-5c` crash after `publishing` (hook 88) | PASS | 88 | published | 0 | free | yes | replay finished publication, one artifact |
| 15 | `case-5d` crash after publication (hook 89) | PASS | 89 | published | 0 | free | yes | retry exit 2 `operation-already-published`, one artifact |
| 16 | `case-6` pre-existing final artifact | PASS | 2 | publishing | 0 | free | yes | `artifact-destination-exists`; untouched; retry verified |
| 17 | `case-7` destination symlink swap | PASS | 2 | staged | 0 | free | no | `destination-symlink`; nothing outside; retry verified |
| 18 | `case-8` modes/cleanup | PASS | — | — | — | free | yes | staging 0700, files 0600, artifact 0600, verify staging removed |
| 19 | `case-9` secret scan | PASS | — | — | — | free | yes | no secret/path match in outputs or artifact |
| 20 | `case-11` replacement controller on staged journal | PASS | 3 | published | 0 | free | yes | ready + SIGTERM 0; phase 2 verified |
| 21 | `case-12missing-trust` | PASS | 3 | — | — | free | yes | `trust-config-unavailable` |
| 22 | `case-12identity` | PASS | 2 | — | — | free | yes | `identity-mismatch` |
| 23 | `case-12release` | PASS | 2 | — | — | free | yes | `release-mismatch` |
| 24 | `case-12revoked` | PASS | 2 | — | — | free | yes | `revoked-signing-key` |
| 25 | `case-12truncated` | PASS | 2 | — | — | free | yes | `corrupt-artifact` |
| 26 | `case-12oversize` | NOT-COVERED | — | — | — | — | — | see below |
| 27 | `case-13` canonical-state immutability | PASS | — | published | 0 | free | yes | source DB SHA-256 identical before/after |

Totals: **26 executed rows PASS, 1 NOT-COVERED, 0 FAIL**. No unexecuted row is
reported as PASS.

### Row notes and deliberate test mechanics

- `case-1a` uses the executor's two-way barrier so the harness can apply the
  outstanding WAL frames with `PRAGMA wal_checkpoint(TRUNCATE)` and measure the
  database *after* that setup action but *before* the executor opens the store.
  This is what makes `case-10` and `case-13` deterministic: the D9 measurement
  and the before/after hash then refer to the same bytes.
- `case-4e`: the implementation has a fixed 24-hour TTL and no clock hook, so
  the harness rewrites `expires_at` in the request and the matching
  `request_sha256` in the journal before signing. The observed contract is
  recoverable exit 3 (`signing-request-expired`), not exit 2; the staging
  directory is preserved for inspection.
- `case-5b`: the injected crash lands deliberately between the durable `staged`
  write and marker removal. Publication succeeds from the staged files, but the
  marker remains and continues to deny replacement-controller startup until an
  operator removes it. This is the documented denial authority, not a hidden
  success path.
- `case-6` also confirms the replay path: after the colliding file is removed,
  the journal `publishing` record plus the staged signed artifact publish
  without a second signature.
- `case-7` replaces the destination directory with a symlink before phase 2.
  `validate_destination` fails closed with `destination-symlink`; the staging
  tree is preserved in the renamed real directory.
- `case-8` records the staging modes observed while phase 1 is staged (0700
  directory, 0600 files including the request), plus the published artifact
  mode (0600) and the absence of `.o3k-verify-staging-*` after a successful
  verify.
- `case-9` scans every captured `*.json`, `*.stderr`, `*.log` and `*.txt` for
  the Ed25519 seed hex, the raw X25519 recipient bytes hex, the signing-key path
  and the recipient-key path, and scans the published artifact bytes for the
  same markers. None matched. The trust document itself intentionally names the
  recipient key path and was excluded as an input fixture; it is encrypted into
  the artifact and not emitted on stdout/stderr.
- `case-11` starts a fresh `o3kd` on the same data directory after phase 1,
  asserts `/readyz` and the daemon's "backup operation has not reached a
  terminal phase" warning, then a clean SIGTERM exit 0, then completes phase 2.

## Executed vs documented-not-executed

Executed real-process rows: the 26 PASS rows above (the campaign is the
executor; see `tests/pp6_backup_artifact.sh`).

Not executed end-to-end (`NOT-COVERED`, exact reason and coverage):

- **Oversized artifact (`artifact-too-large`).** The verifier applies the
  5 GiB manifest-bounded size check only after a valid Ed25519 signature over
  the manifest. Producing that input would require the harness to reimplement
  artifact assembly and sign a malicious manifest; that is not a real operator
  path and would be evidence of a bespoke tool rather than of the product.
  The stable mapping is unit-covered by
  `backup_verify::tests::reason_mapping_is_stable_for_every_failure_class`
  (`"backup artifact exceeds the configured size limit"` → exit 2
  `artifact-too-large`).

Unit/integration coverage that the campaign does not reproduce as a separate
real-process row (listed so the evidence boundary is explicit):

- `backup_verify::tests::{success_json_is_bounded_and_carries_the_expected_fields,
  reason_mapping_is_stable_for_every_failure_class,
  artifact_path_validation_rejects_relative_missing_symlinks_and_directories,
  migration_checksum_binds_sqlx_bytes_as_lowercase_sha256,
  data_dir_precedence_mirrors_the_capture_executor,
  missing_local_store_fails_closed_as_expected_release_unavailable}`
- `backup_artifact::tests::{signing_request_validation_binds_identity_digests_and_expiry,
  signing_response_is_bound_to_the_request_and_the_trust_key,
  config_loads_the_installed_release_and_binds_the_data_directory,
  snapshot_facts_read_store_identity_and_repository_emptiness,
  publication_is_no_replace_and_replay_safe,
  naming_and_prefix_resolution_are_stable,
  repository_table_mapping_covers_the_committed_baseline}`
- `backup_create::tests::{invalid_configuration_fails_before_capture,
  published_operation_is_refused_before_controller_contact,
  incomplete_operation_is_recoverable_without_a_controller,
  two_phase_flow_publishes_a_verified_artifact}`
- `backup::tests::{unsigned_stage_finishes_with_a_detached_signature_only_after_verification,
  unsigned_stage_rejects_a_wrong_key_id_and_a_tampered_payload}`
- `backup_reservation::tests::{reservation_boundaries_follow_d9,
  space_boundaries_never_truncate_the_reservation,
  measures_regular_files_in_a_real_directory,
  rejects_symlinked_or_non_regular_sources,
  reports_stable_reason_strings}`
- `backup_trust::tests` (file posture, key derivation, revocation, custody
  expiry, identity binding, default path precedence)
- `o3k-store backup_journal::tests` (atomic records, pending scan, invalid
  records, symlinked directory, phase stability)
- `bins/o3kd composition::tests::pending_backup_operation_journal_does_not_deny_startup`
- `tests/backup_create_hooks.rs::skip_marker_cleanup_keeps_marker_after_staging`

The handoff journey, its 17 executed cases and its 7 documented-coverage rows
remain covered by `tests/pp6_backup_handoff.sh` (still passing; see below).

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
cargo build -p o3k -p o3kd --features o3kd/backup-test-hooks,o3k/backup-test-hooks
bash -n tests/pp6_backup_artifact.sh
shellcheck -S warning tests/pp6_backup_artifact.sh
bash tests/pp6_backup_artifact.sh        # clean PASS (26 executed, 1 not-covered)
bash -x tests/pp6_backup_artifact.sh     # clean PASS (diagnostic trace)
bash tests/pp6_backup_artifact.sh        # clean PASS (recorded verdict)
bash tests/pp6_backup_handoff.sh         # PASS: 17 executed, 7 documented, 0 failures
cargo fmt --all -- --check
cargo clippy -p o3k -p o3k-store -p o3kd --all-targets --all-features -- -D warnings
git diff --check
```

The campaign is re-runnable and deterministic in its assertions: crashes use
process-exit hooks, the only barrier is the executor's two-way file barrier,
and every wait is a bounded readiness/exit/file poll. An earlier exploratory
invocation was discarded because the harness was being edited while Bash was
still reading it; the three invocations listed above are of the final harness
and produced identical matrix outcomes. Per-run randomness is confined to the
artifact content key, timestamps and the temporary data-directory identities
(and therefore the artifact digest).

## Findings and residuals (no production semantics changed)

- **No production defect was found.** The observed behaviors match the
  documented contract, including exit-code boundaries.
- **Marker after a crash between `staged` and marker removal.** A real process
  death in that microsecond window leaves the marker; phase 2 can still publish
  from the staged files, but a replacement controller stays denied until an
  operator removes the marker. `case-5b` records this explicitly. If this is not
  the intended operator experience, it needs a small follow-up (for example,
  letting phase 2 remove the marker for the same operation before publishing).
  It is not changed here because doing so would change production semantics.
- **Expired-request recovery is exit 3, not exit 2.** The request TTL is a
  recoverable condition and keeps staging. The task brief allowed "exit 2/4 per
  implementation"; the implementation's accepted contract is exit 3 and is
  recorded honestly.
- **Verifier migration identity sourcing.** `o3k backup verify` reads the
  migration inventory from the local canonical store because the installed
  release manifest does not carry it; it fails closed with
  `expected-release-unavailable` if the store or schema does not match the
  release. This is documented in `bins/o3k/src/backup_verify.rs` and is not a
  restore-time replacement for release-signed migration identity.
- **Crash injection is exit-based.** The artifact campaign uses hard
  `std::process::exit` hooks, not SIGKILL; it exercises journal durability and
  replay ordering, not filesystem-level torn writes. The handoff campaign keeps
  its SIGKILL coverage for the lock-transfer window.
- **The D9 measurement is a preflight, not a quota.** The reservation is
  checked against `f_bavail * f_frsize` before capture; it is not enforced as an
  ongoing disk quota during the artifact lifecycle.

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
- **No independent review yet.** The implementation, the campaign and this
  document were produced by the same agent. This is interim evidence pending
  human exact-head review; it is not an independent verification.

## Machine-readable verdict

Generated by the final campaign run (`tests/pp6_backup_artifact.sh`); values
that are per-run by construction are the ones from that run. The harness prints
the same object on stdout between the markers
`O3K_PP6_VERDICT_JSON_BEGIN` and `O3K_PP6_VERDICT_JSON_END`.

```json
{
  "backup_digest": "7c7c63ac4810cd85fe366e167992165d5c3d4009d0bac56ad8ca8421daff6267",
  "backup_id": "4091fff9-4392-477b-a345-f9037d2e068a",
  "backup_installation_id": "a95fb75f841ba8cc21982fba07758c93",
  "backup_site_id": "c33c9932d920c9b0c93c118c970765f4",
  "backup_size_bytes": 1232909,
  "campaign": "tests/pp6_backup_artifact.sh",
  "executed_rows": 26,
  "failed_rows": 0,
  "harness_sha256": "776f308ff475e26e768b5fd4c3208a034716ee6b8b6a15983e33c782e64c5e06",
  "host_identity_hash": "8110f5814f95639d2d88a1e379a827e065c9c072b52b54c92f4ce2b1051f54bb",
  "issue": 1084,
  "matrix": {
    "FAIL": 0,
    "NOT-COVERED": 1,
    "PASS": 26
  },
  "not_covered_rows": 1,
  "o3k_binary_sha256": "ce0785089e9028a2dc50d04f405af57fc8d5a6437ebd7a7616e8a72787caab75",
  "o3kd_binary_sha256": "88668ef13fc6d569478a7f35cc8fe6f86992a8162527840ada5a7021ba1fc72c",
  "passed_rows": 26,
  "profile": "o3k-demo-v1",
  "release_artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "rustc_version": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
  "schema_version": 53,
  "slice": "F",
  "source_sha": "20b54afea966dbfc286e04545a5a8af6987ce2c8",
  "sqlite_version": "3.46.0",
  "working_tree_dirty": true
}
```
