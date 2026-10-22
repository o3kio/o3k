# #1084 authenticated backup handoff — Slice D capture evidence

Date: 2026-10-22. Scope: PP.6 authenticated backup handoff, real-process
integration campaign (Slice D of the `#1084-handoff` branch work). Slices A–C
(control protocol, store-lock handoff, daemon/CLI wiring) were implemented
before this document; this is the evidence for the cross-process behavior of
those slices, not a design record.

**What this proves:** the authenticated handoff and provisional capture work
end-to-end between real `o3kd` and real `o3k` processes, survive deterministic
failure injection at every crash surface, and recover through the bounded
restart path.

**What this does NOT prove (explicit non-claims):**

- This is a **provisional capture only**. There is no artifact signing, no
  trust/publication chain, and no supported PP.6 backup claim.
- No PostgreSQL exclusion claim: every case ran on the SQLite
  portable/TestLab default.
- No provider/execution claim: no compute, network, or storage provider
  mutation was requested; the matrix exercises the control plane and the
  store-access lock only.
- **#1084 is not closed.** Human exact-head review, protected checks, and
  protected merge/main verification remain required.

## Baseline identity

| Item | Value |
| --- | --- |
| Repository / branch | o3k, `pp6/1084-handoff` |
| Worktree HEAD (baseline; Slice A–D uncommitted on top) | `2a481ca7c085d3515c14e12dfe92ce4217c84775` |
| `o3kd` binary SHA-256 (debug, hooks features) | `019653c4ead0abcd79cc3332c5654827a8607b3a99ead4f8d238f95a97dbfee9` |
| `o3k` binary SHA-256 (debug, hooks features) | `ca6e97cb8038e6fff5531f48439c3fa99a54194bcec61eeafb32c21f1eed2593` |
| Toolchain | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Build command | `cargo build -p o3kd -p o3k --features o3kd/backup-test-hooks,o3k/backup-test-hooks` |

Both binaries were copied into a private per-run installation directory
(`mktemp -d`, 0700) so the daemon's sibling-`o3k` executable-identity check was
exercised against a clean installation layout rather than the build tree.

## Harness

`tests/pp6_backup_handoff.sh` (executable, re-runnable, `set -euo pipefail`,
trap-based cleanup that kills every daemon it started). It exits 0 only when
every executed check passed and prints a per-case matrix summary. Determinism
sources: the feature-gated crash hooks below, a two-way file barrier on each
side of the handoff, and `kill`/`SIGKILL`. The only sleeps are bounded
readiness polls.

Test-only hooks used (all behind `backup-test-hooks`, off by default; never
enabled in release/production builds):

| Hook | Side | Effect |
| --- | --- | --- |
| `O3K_BACKUP_TEST_EXIT_BEFORE_HANDOFF=1` | daemon | exit 98 after drain proof, before descriptor transfer |
| `O3K_BACKUP_TEST_EXIT_AFTER_ACK=1` | daemon | exit 99 after the executor's ack |
| `O3K_BACKUP_TEST_DAEMON_BARRIER_READY_FILE` / `_WAIT_FILE` | daemon | create ready file after successful handoff, wait for go file before exit (SIGKILL window) |
| `O3K_HANDOFF_TEST_EXIT_AFTER_SEND_BEFORE_ACK_READ=1` | o3k-store (sender) | exit 96 after descriptor send, before ack read |
| `O3K_HANDOFF_TEST_SLEEP_AFTER_SEND_MS=<n>` | o3k-store (sender) | bounded post-send delay so the receiver's ack deterministically lands before the sender dies (added by Slice D) |
| `O3K_HANDOFF_TEST_EXIT_BEFORE_ACK=1` | o3k-store (receiver) | exit 97 after validation, before ack write |
| `O3K_BACKUP_TEST_EXIT_BEFORE_RECEIVE=1` / `_AFTER_RECEIVE=1` | executor | exit 95 / 94 around `receive_handoff` |
| `O3K_BACKUP_TEST_SKIP_MARKER_CLEANUP=1` | executor | keep the interrupted-backup marker on success |
| `O3K_BACKUP_TEST_BARRIER_READY_FILE` / `_WAIT_FILE` | executor | create ready file after lock receipt, wait for go file before marker write (added by Slice D) |

Slice D production-code deltas (additive, test-only): the three hooks marked
"added by Slice D", plus one one-line Cargo fix — `bins/o3kd`'s
`backup-test-hooks` feature now enables `o3k-store/backup-test-hooks`, because
the daemon-side after-send crash hook (96) lives in the shared o3k-store
handoff primitive and previously would not have been compiled into `o3kd`.
No production semantics were changed.

## Authority and writer inventory (drained-before-transfer)

Reuse of the ISSUE_1084_OWNED_WRITER_REVIEW disposition table; the
"Disposition at handoff" column is what this campaign observes in real
processes. Every owner below is drained or excluded **before** the store lock
leaves the daemon (`ControllerDrainProof`), and the API admission layer is
closed by the same graceful-shutdown path as SIGTERM before the proof exists.

| Owner | Writers | Disposition at handoff (observed) |
| --- | --- | --- |
| API admission | HTTP mutations, audit and Operation writes | Graceful shutdown ends the serve before `composition.shutdown()`; concurrent mutation workload observed rejected (connection refused after listener close); in-flight handlers drained |
| Composition | heartbeat, event/console consumers, reconcilers | `controller writers drained` logged; task abort+join bounded before proof |
| Composition optional workers | fabric/storage recovery, control server, probes | Same join set (none enabled in this profile: both flags false in the drain verdict) |
| NodeRegistry / network guards / storage fence | child tasks, lease renewal/relinquishment, fence assert/end | Not enabled in this minimal profile; drain-internal failure classes mapped to their unit/integration tests (matrix case-d) |
| Local LVM runner | provider subprocesses | Not instantiated by this profile |
| Inline remote providers | agent/network/Cinder dispatch | Not configured; durable UnknownOutcome preservation unit-covered |
| SQLite store | submitted statements, connection workers | `controller session drained` logged after controller-session drain and pool close |
| Backup control thread | dedicated accept thread | Performs no canonical writes by design; after one acceptance it retires and the daemon proceeds to drain |

Direct libvirt and Ceph runners remain outside this composition; no remote
execution can write the canonical controller database.

## State machine (real-process log evidence)

Journey run, `o3kd` JSON log (timestamps from the 2026-10-22 campaign run):

```text
16:58:31.611794Z o3kd listening
16:58:36.046317Z backup handoff request accepted; draining controller for lock transfer
16:58:36.046665Z backup handoff admitted, shutting down for lock transfer
16:58:36.084356Z controller session drained
16:58:36.084412Z controller writers drained
16:58:36.085471Z store lock ownership transferred to the backup executor; source exiting
```

Mapping to the SPEC-0050 phase names:

| Phase | Evidence |
| --- | --- |
| AUTHORIZED | `backup handoff request accepted; draining controller for lock transfer` (after SO_PEERCRED + exe identity + installation/site token + PID-reuse revalidation) |
| ADMISSION_CLOSED | `backup handoff admitted, shutting down for lock transfer` — the backup notify drives the same graceful-shutdown path as SIGTERM; the mutation workload observed rejections from this point |
| WRITERS_DRAINED | `controller session drained` + `controller writers drained` (drain verdict with `fabric_recovery_enabled=false`, `storage_recovery_enabled=false` for this minimal profile) |
| LOCK_HANDOFF | `store lock ownership transferred to the backup executor; source exiting` (SCM_RIGHTS `O3KLOCK1`/`LOCKACK1`) |
| EXECUTOR_OWNS | executor writes `.o3k-backup-in-progress-<op>` marker, checkpoint(TRUNCATE), `VACUUM INTO` snapshot, hash verification, metadata, no-replace rename |
| SOURCE_EXIT | daemon exit status 0 (journey), executor exit 0 with bounded JSON |

Wall-clock from acceptance to lock transfer in this run: ~39 ms of drain
(small TestLab database, minimal profile). All drain steps retain their own
5 s bounds independently of this observation.

## Journey results (Section 1 of the harness)

Seeded state: 3 durable networks `pp6-seed-1..3` via
`POST /v2.0/networks` (X-Subject-Token from `POST /v3/auth/tokens` with the
bootstrap password), plus a background workload creating and deleting
additional networks for the duration of the backup.

| Check | Result |
| --- | --- |
| `o3k backup create` exit code | 0 |
| Bounded JSON contract | `status=provisional-capture-complete`, `source_unchanged=true`, `provisional=true`, `operation_id` matches, provisional note present |
| Concurrent workload during backup | 5 successful mutations before shutdown began, 5 deterministic rejections after (no success at or after the first rejection) |
| Daemon exit | 0 (SOURCE_EXIT after ack) |
| Artifact | `<dest>/provisional-backup-<op>/o3k.sqlite` + `metadata.json`, staging dir renamed away |
| Metadata | all 12 fields present; `format=o3k-provisional-backup-v1`; before/after source hashes equal; `snapshot_sha256` matches the file; mode 0600 |
| Snapshot | `PRAGMA integrity_check` = ok, `PRAGMA foreign_key_check` empty, 53 `_sqlx_migrations` rows (sqlite3 CLI on the snapshot, in addition to the store's own `verify_sqlite_snapshot`) |
| Restart on same data dir | daemon starts (marker was removed), `/readyz` ready, all 3 seeded networks visible via the API, clean SIGTERM exit 0 |

Admission-gate note (honest limitation): the middleware's 503 + `Retry-After: 1`
response is not observable in this real-process wiring, because `o3kd` begins
the API exclusion inside `composition.shutdown()`, which runs **after** the
axum serve has ended; from outside, the observable rejection is connection
refused once the listener closes (plus `/readyz` going not-ready). The
503+Retry-After gate semantics are unit-covered by
`o3k_api::backup_admission_tests::exclusive_backup_admission_keeps_liveness_and_rejects_other_requests`.

## Failure-injection matrix (Section 2 of the harness)

Per-case recorded fields: last confirmed owner, lock state, durable-op
classification, canonical write occurred?, provider mutation?, recovery
classification, artifact published? "n/a" = not applicable to the case.

| Case | Injection | Last confirmed owner | Lock state after | Controller readiness | Canonical write? | Artifact? | Recovery | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| a | exe-identity mismatch (copied `o3k`) | daemon (never left) | daemon-held (flock NB refused) | healthy (`/readyz` 200), SIGTERM exit 0 | none | none | rejected pre-drain, exit 2 `unauthorized-peer` | **PASS (executed)** |
| b | garbage 64-byte frame | daemon | daemon-held | healthy, SIGTERM exit 0 | none | none | in-band `O3KBKRJ`+2 (Malformed); daemon unaffected | **PASS (executed)** |
| b | zero-length request | daemon | daemon-held | healthy | none | none | connection closed, logged Malformed | **PASS (executed)** |
| c | two concurrent `backup create` | first executor (after handoff) | executor-held during capture; released at exit | daemon SOURCE_EXIT 0 | none during capture | exactly one (`provisional-backup-<op1>`) | loser exit 2 `controller-unavailable` (control socket retired after the single accept; in-band `AlreadyActive` unit-covered) | **PASS (executed)** |
| c2 | daemon hook 98 (die after accept, pre-transfer), then restart and retry same op id | daemon, then no one | released at daemon exit | restart refused initially? no — marker absent, restart ok | none | none from first attempt; retry succeeded | duplicate detection is **per-daemon-lifetime**; a fresh daemon has no accepted ids and the aborted op never transferred the lock, so retry is safe. Residual risk recorded below | **PASS (executed)** |
| d | drain-internal classes (API drain timeout; network lease cleanup; storage renewal; unknown provider outcome; SQLite rollback pending) | n/a | n/a | n/a | n/a | n/a | **NOT RE-EXECUTED HERE** — mapped to existing deterministic coverage (table below) | DOCUMENTED |
| e | executor hook 95 (die before descriptor receipt) | daemon | daemon-held until its exit; free after | daemon exit 1 | none | none | daemon exits 1 without transfer (peer dead at revalidation / handoff); restart ok | **PASS (executed)** |
| f | executor hook 94 (die after receipt + ack) | executor, then released | free after executor exit | daemon SOURCE_EXIT 0 | none | none (executor died pre-marker) | restart ok | **PASS (executed)** |
| g | daemon hooks: sleep-after-send + exit 96 (die after send, before ack read) | executor (descriptors received; ack landed in the deterministic sleep window) | executor-held through capture | daemon exit 96 | none during capture | **yes**, valid artifact | capture does not depend on sender survival; ownership continuity | **PASS (executed)** |
| h | executor hook 97 (die before ack write) | daemon | daemon-held until exit (fail-closed, `mem::forget` of returned guard path not needed — retained in proof) | daemon exit **1**, never 0, no success log | none | none | `UnknownOutcome`; restart ok | **PASS (executed)** |
| i | SIGKILL (9) of the daemon after transfer, while it still exists (daemon-side barrier) | executor | executor-held through capture | daemon exit 137 | none during capture | yes, valid artifact | capture completed exit 0; marker removed; restart ok | **PASS (executed)** |
| j | start second `o3kd` on the same data dir while the executor owns the lock | executor | executor-held (competitor refused) | competitor exit 1 at the store lock, never served | **none** (competitor failed before store open) | yes (main capture) | systemd units use this same binary/startup path (`packaging/o3kd.service`) | **PASS (executed)** |
| k | third-party `flock` on `.o3k-store.lock` and the data dir while executor owns the lock | executor | executor-held | n/a (no controller start) | none | yes | `open()` succeeds (advisory lock does not block open); nonblocking exclusive `flock` refused with EWOULDBLOCK on **both** the lock file and the directory | **PASS (executed)** |
| l1 | `O3K_BACKUP_TEST_SKIP_MARKER_CLEANUP=1` (capture succeeds, marker kept) | executor, then none | free | **restart REFUSED** exit 1 with `interrupted backup marker(s) present` | none | yes | operator removes marker → restart + SIGTERM exit 0 | **PASS (executed)** |
| l2 | pre-existing `<dest>/provisional-backup-<op>` (finalize rename collides) | executor, then none | free | daemon already SOURCE_EXIT | none published; pre-existing dir untouched; staging preserved for inspection | none (no-replace preserved existing) | exit 3 `finalize-rename-failed`; marker kept; restart ok after marker removal | **PASS (executed)** |
| m | source mutation during capture | n/a | n/a | n/a | n/a | n/a | **NOT real-process reproducible**: the transferred flock excludes all writers and `backup_to_file` holds a `BEGIN IMMEDIATE` writer exclusion; residual path enforced by the SHA-256 before/after check (exit 4 `unknown`) | DOCUMENTED |
| n1 | executor pointed at a copy of the data dir (different installation binding) | daemon | daemon-held | healthy | none | none | exit 2 `controller-unavailable` (no live socket in the copy); in-band `identity-mismatch` unit-covered | **PASS (executed)** |
| n3 | second daemon instance while the first lives | first daemon | first-daemon-held | competitor exit 1 at the store lock (control bind never reached) | none | n/a | covered above | **PASS (executed)** |
| n4 | stale control socket after SIGKILL | replacement daemon | replacement-held | replacement starts ready, SIGTERM exit 0 | none | n/a | socket file survived the kill (no destructors); replacement validated owner/type and rebound | **PASS (executed)** |

### Case-d existing coverage map (never reported as executed here)

| Drain-internal classification | Existing deterministic coverage |
| --- | --- |
| API drain timeout | `o3k_api::backup_admission_tests::backup_admission_times_out_when_an_api_request_does_not_drain` |
| Admission-gate 503 + Retry-After semantics | `o3k_api::backup_admission_tests::exclusive_backup_admission_keeps_liveness_and_rejects_other_requests` |
| Network lease cleanup failure | `bins/o3kd/src/composition/network.rs`: `failed_real_relinquishment_blocks_network_drain`, `failed_relinquishment_cannot_be_counted_as_drained`, `cancelled_realm_cleanup_is_owned_by_registry` |
| Storage renewal failure | `bins/o3kd/src/composition/storage.rs`: `failed_storage_renewal_is_not_repolled_or_unlocked`, `cancelled_acquisition_is_recorded_and_keeps_execution_lock`, `storage_end_waits_for_in_flight_database_renewal` |
| Unknown provider outcome | `crates/o3k-reconciler/src/storage_workflow.rs`: `unknown_provider_outcome_requires_observe_before_retry`; `crates/o3k-reconciler/src/tests.rs`: `unknown_outcome_is_observed_without_duplicate_create` |
| SQLite rollback pending | `crates/o3k-store/src/tests.rs`: `terminal_writer_drain_joins_cancelled_sqlite_transaction_and_rejects_new_writes`; `bins/o3kd/src/composition/drain_tests.rs`: `cancelled_controller_session_drain_retains_lifetime_lock` |
| Configured worker drain (real process) | `bins/o3kd/tests/shutdown.rs`: `configured_network_and_storage_workers_drain_in_real_daemon` |

## Residual risks and honest gaps

1. **Cross-restart operation replay (case c2).** Duplicate-operation
   detection is per-daemon-lifetime (in-memory per listener). A daemon that
   accepted an operation and then died before transferring the lock leaves no
   durable record of that acceptance, so a restarted daemon re-accepts the
   same operation id. This is safe for the current provisional milestone
   because the aborted operation never took ownership (no marker, no
   artifact, no lock transfer); it is recorded here as the residual risk a
   future signed-operation journal must close.
2. **Admission-gate 503 not real-process observable** (see Journey note). The
   gate exists and is unit-tested; o3kd's wiring closes admission after the
   serve ends, so external observers see connection refusal. If a future
   change moves exclusion earlier, the 503 path becomes externally testable.
3. **Case-m (source mutation during capture)** cannot be reproduced with real
   processes because the mechanism under test is exactly what excludes the
   mutation; coverage is the store's writer-exclusion unit tests plus the
   executor's hash-mismatch exit-4 path.
4. **Hook-enabled binaries.** All executed cases used binaries built with
   `backup-test-hooks`. Hooks only *add* hard exits/barriers; the
   authentication, drain, and handoff logic under test is the production code
   path, and the journey itself (seed → workload → backup → restart) used no
   crash hooks.
5. **Timing note for case g.** Without the Slice-D post-send sleep hook, the
   after-send crash races the receiver's ack write at microsecond scale
   (either "capture proceeds" or a clean EPIPE exit-3 failure, both safe).
   The hook removes the race so the ownership-continuity branch is
   deterministic.

## Validation (all green on baseline `2a481ca`)

- `tests/pp6_backup_handoff.sh`: full run **PASS — 17 executed checks, 7
  documented-coverage rows, 0 failures**, re-runnable end to end in ~2
  minutes on the baseline host; trap cleanup leaves no daemon or executor
  process and removes the temporary installation.
- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p o3kd -p o3k -p o3k-store --all-targets --all-features -- -D warnings` — exit 0, no warnings.
- `cargo test -p o3kd -p o3k -p o3k-store --all-features` — every test
  binary `ok`, 0 failed (including the real-process `bins/o3kd/tests/shutdown.rs`
  SIGTERM/SIGINT/lock-exclusion tests, the `backup_control.rs` authenticated-
  request wiring test, the `backup_create_hooks.rs` crash-injection tests, and
  the o3k-store handoff/pool suites).

## Provenance

Repository sources only: Slices A–C as present in the worktree
(`crates/o3k-store/src/backup_control.rs`, `crates/o3k-store/src/access_lock.rs`,
`bins/o3kd/src/composition/backup.rs`, `bins/o3kd/src/composition/mod.rs`,
`bins/o3kd/src/main.rs`, `bins/o3k/src/backup_create.rs`), ADR-0189 and
SPEC-0050, and the ISSUE_1084_OWNED_WRITER_REVIEW disposition table. No Go
implementation, private source, or external test material was used.
