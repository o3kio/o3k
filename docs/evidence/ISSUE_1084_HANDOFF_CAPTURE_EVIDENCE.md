# #1084 authenticated backup handoff — Slice D capture evidence

> **Superseded status note (2026-10-24, updated):** the provisional capture
> described here has been replaced by the authenticated artifact flow on branch
> `pp6/1084-artifact`. Under ADR-0190 Option A the capture process now keeps the
> store lock and the denial marker while it waits for the offline signature and
> publishes in the same invocation (exit 0); an expired request is a safe abort
> (exit 3 `signing-request-expired`); a re-run after a crash during the wait
> resumes the wait/publication. See
> `docs/evidence/ISSUE_1084_ARTIFACT_EVIDENCE.md`.
>
> The handoff campaign described below still runs
> `O3K_BACKUP_TEST_STOP_AFTER_STAGING=1`, a feature-gated harness control that
> keeps phase 1 one-shot (stage, `signing-required`, exit 3, marker removed) so
> each row can observe the post-capture state without a signing wait. That hook
> is never enabled in a production build and does not change the product
> semantics; the Option A wait itself is proven by
> `tests/pp6_backup_artifact.sh` (`case-1`, `case-2`, `case-11`, `case-4e`).
> The measurements below remain valid for the revision they name.

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
| Worktree HEAD | `b92f4ce9b317e469174fd73f746c3ad3f6a3d866` (Slices A–D committed); review-rounds-1/2 production fixes uncommitted on top |
| `o3kd` binary SHA-256 (debug, hooks features) | `ed848c3a086e3bdf4351b420291fa17de3c9d4bcb03ae30500122163890ad338` |
| `o3k` binary SHA-256 (debug, hooks features) | `87f135aa8258c7b4cdb2c5fc31e70e21ba04548a441bda826ef4720f3ce354b5` |
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
readiness/deadline polls (`wait_ready`, `wait_log`, `reap_exit`, the case-b
rejection-count poll, the case-i/j/k barrier polls) plus a one-second
workload ramp at journey start that paces the concurrent mutation loop; no
assertion depends on that ramp. On `INT`/`TERM` the harness exits 130/143 so
the `EXIT` trap runs cleanup exactly once with a deterministic status.
Foreground competitor/restart `o3kd` invocations run under `timeout 30` so a
blocking regression fails the case instead of hanging the harness.

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

Journey run, `o3kd` JSON log (timestamps from the post-review-fix verification
run of 2026-10-22):

```text
21:37:10.343289Z o3kd listening
21:37:14.839878Z backup handoff request accepted; draining controller for lock transfer
21:37:14.840381Z backup handoff admitted, shutting down for lock transfer
21:37:14.951630Z controller session drained
21:37:14.951709Z controller writers drained
21:37:14.952839Z store lock ownership transferred to the backup executor; source exiting
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

Wall-clock from acceptance to lock transfer in this run: ~113 ms of drain
(small TestLab database, minimal profile; the earlier baseline observation was
~39 ms — the difference is host load, and every drain step retains its own
5 s bound independently of this observation).

## Journey results (Section 1 of the harness)

Seeded state: 3 durable networks `pp6-seed-1..3` via
`POST /v2.0/networks` (X-Subject-Token from `POST /v3/auth/tokens` with the
bootstrap password), plus a background workload creating and deleting
additional networks for the duration of the backup.

| Check | Result |
| --- | --- |
| `o3k backup create` exit code | 0 |
| Bounded JSON contract | `status=provisional-capture-complete`, `source_unchanged=true`, `provisional=true`, `operation_id` matches, provisional note present |
| Concurrent workload during backup | 5 successful mutations before shutdown began, 6 deterministic rejections after (no success at or after the first rejection) |
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
| c | two concurrent `backup create` | first executor (after handoff) | executor-held during capture; released at exit | daemon SOURCE_EXIT 0 | none during capture | exactly one (`provisional-backup-<op1>`) | loser exit 2 either way: in-band `backup-already-active` (`O3KBKRJ` AlreadyActive) when the second connect lands during the drain window — the daemon now keeps accepting post-handoff and rejects in-band — or `controller-unavailable` (exit 2) when it lands after daemon exit (stale socket) | **PASS (executed)** |
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
| n4 | stale control socket after SIGKILL | replacement daemon | replacement-held | replacement starts ready, SIGTERM exit 0 | none | n/a | socket file survived the kill (no destructors); this case asserts replacement readiness + clean SIGTERM only — the owner/type check + rebind itself is unit-covered (`bind_refuses_non_socket_at_socket_path`, `stale_socket_file_is_replaced_at_bind`) | **PASS (executed)** |

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

## Review round 1 (pre-merge)

A round-1 review of PR #1168 (2026-10-22, pre-merge) found 15 production-code
findings and 5 test-harness findings. All 20 are fixed; the production fixes
landed in `crates/`/`bins/` and the harness fixes in
`tests/pp6_backup_handoff.sh` (this document and the matrix summary were
refreshed in the same round).

Production findings fixed (verified against the worktree diff on top of
`b92f4ce9`):

1. Peer executable identity compared by device+inode from `fs::metadata` of
   `/proc/<pid>/exe` (no path-string comparison).
2. Peer revalidation rechecks the peer uid on every `revalidate_peer` call
   (PID-reuse defense), not only at accept time.
3. Shrinking read/write deadlines on the control socket so a stalled peer
   fails fast instead of holding the drain.
4. Bounded serve drain (`SERVE_DRAIN_BOUND`, 15 s) on the backup-initiated
   shutdown path.
5. `serve_result` is checked on the backup path (a serve error can no longer
   be silently treated as a clean drain).
6. Non-Linux unused-binding fix.
7. A handoff that was requested but whose accepted request never arrived
   exits 1 (previously exit 0).
8. `WriteZero`/`Interrupted` transfer errors classified as `UnknownOutcome`
   (fail-closed) instead of a definite outcome.
9. Post-accept in-band `AlreadyActive` rejection loop: after one acceptance
   the daemon keeps accepting and answers concurrent executors with the
   bounded `O3KBKRJ` AlreadyActive frame (exit 2) until it exits (case-c
   drain-window behavior above).
10. Non-UTF-8 interrupted-backup marker name still denies startup (raw-byte
    prefix comparison, no `to_str`).
11. Destination validated through an opened dir-fd plus revalidation, and a
    destination overlapping the data dir is rejected (precondition exit 2).
12. `HANDOFF_RECEIVE_TIMEOUT` (120 s) bounds the receiver-side handshake.
13. Uniform keep-staging on post-lock failure: once the interrupted-backup
    marker is written it is kept (with the staging dir) so an operator can
    inspect the interrupted capture; the marker blocks daemon preflight until
    cleared.
14. Debug-only `compile_error!` guard on `backup-test-hooks`
    (`not(debug_assertions)`), in both `bins/o3kd` and `o3k-store`.
15. Exit-code documentation corrected to match the implemented contract.

Harness findings fixed:

- **F1** (case-b): the `sleep 0.5` wait for the zero-length rejection is a
  bounded rejection-count poll (10 s deadline); the header wording now scopes
  "no sleeps as synchronization" to the readiness/deadline polls and names
  the one-second workload ramp as pacing only.
- **F2** (cases j, k, l1, l2): the post-handoff daemon reap now asserts exit
  status 0 (`reap_exit ... && [[ exit_status == 0 ]]`); a daemon that hangs
  after lock transfer fails the case instead of passing.
- **F3** (cases j, l1, n3): foreground competitor/restart `o3kd` invocations
  run under `timeout 30`; exit 124 (timeout kill) is treated as failure, so
  a blocking regression fails instead of hanging the harness.
- **F6**: `INT`/`TERM` re-raise as exit 130/143 with the `EXIT` trap running
  cleanup exactly once (previously `trap cleanup EXIT INT TERM` continued
  with an unclear status).
- **F7** (case-n4): the result string now states exactly what is asserted
  (replacement readiness + clean SIGTERM exit 0) and points at the unit
  coverage for the owner/type check and rebind
  (`bind_refuses_non_socket_at_socket_path`,
  `stale_socket_file_is_replaced_at_bind`).

## Review round 2 (pre-merge)

A round-2 review of PR #1168 (2026-10-23, pre-merge) found 7 Low/Nit
findings — 6 production and 1 documentation; all are fixed in the same
uncommitted worktree state on top of the round-1 fixes (the documentation
finding is this section). The baseline binary hashes above predate this
round; the round-2 validation rebuilt both binaries.

Operator-visible behavior note: the 15 s `SERVE_DRAIN_BOUND` added in round 1
caps not only the backup-initiated shutdown drain but also the connection
drain of an **ordinary SIGTERM** — a stalled client can no longer hold the
serve past that bound. This is a deliberate operator-visible behavior change.
Also note that on expiry only the listener closes: axum 0.8 detaches
connection tasks, so stalled handlers run until process exit.

Production findings fixed (verified against the worktree diff on top of the
round-1 fixes):

1. Backup-control accept loops (the main accept loop and the post-accept
   in-band `AlreadyActive` rejection loop) now sleep 1 s before retrying a
   non-timeout `Io` accept error (e.g. EMFILE), so a persistent error can no
   longer hot-spin the accept thread at 100% CPU while flooding the log.
2. `ConnectionReset` and `BrokenPipe` lock-handoff transfer errors are
   classified as `UnknownOutcome` (post-send ambiguity — the executor may
   already hold duplicate descriptors) instead of `TransferRejected`; the
   classification unit test covers both kinds.
3. The provisional-capture snapshot write is now dir-fd-anchored end to end:
   after the staging `mkdirat`, the staging directory is itself opened with
   `openat(O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` under the held destination
   dir-fd and `/proc/self/fd/<staging-fd>/o3k.sqlite` is handed to
   `backup_to_file` as the destination. Proc magic links are resolved by the
   kernel against the open descriptor, so the store's internal
   `create_dir_all`/`canonicalize`/`hard_link` re-resolution follows the
   verified staging directory and a path-component swap between validation
   and capture cannot redirect the snapshot; the staging fd stays alive
   until the call returns. The module doc no longer overclaims — it now
   states the capture path is dir-fd-anchored and scopes the remaining
   string-path steps (metadata, hashing) to the verified euid-owned staging
   directory.
4. The `SERVE_DRAIN_BOUND` and shutdown-path comments (and the matching
   operator-facing warn line) now state that dropping the axum 0.8 serve
   future closes only the listener; stalled connection handlers run until
   process exit.
5. Non-Linux build fix: the off-Linux `_backup_control` binding now carries
   an explicit type (`Option<()>`; `composition::backup::BackupControl` is
   itself Linux-gated, so it cannot be named there), resolving the E0282
   inference error.
6. `AcceptedBackupRequest::revalidate_peer`'s doc now records that the
   canonical executable path is compared alongside the executable dev+ino
   and the uid.

## Review round 3 (pre-merge)

Commit state first: the round-1 and round-2 fixes are no longer uncommitted —
they landed as `e05d0701` ("fix(pp6): address pre-merge review rounds 1-2 on
the backup handoff") on top of `b92f4ce9`, and the tree was clean at that
head when this round started. The round-3 fixes below were applied on top of
`e05d0701` (uncommitted at the time of writing).

A round-3 review of PR #1168 (2026-10-23, pre-merge) found 2 Low and 2 Nit
findings; all are fixed:

1. **(Low) All post-capture steps are now dir-fd-anchored.** The round-2 fix
   anchored only the `backup_to_file` destination; the snapshot hash, the
   `metadata.json` write, and the staging fsync still used the swappable
   destination string path, so an attacker who swapped a writable ancestor
   after revalidation and restored it before the final rename could divert
   the metadata and produce a success-flagged artifact missing
   `metadata.json`. Those steps now run through the staging fd magic link
   (`/proc/self/fd/<staging-fd>/o3k.sqlite`,
   `/proc/self/fd/<staging-fd>/metadata.json`, and `fsync` on the staging fd
   directly); the staging fd is kept alive until after the final rename, and
   string paths remain only for logging and the `renameat` leaf names. The
   module doc states this exactly.
2. **(Low) EPIPE-safe result emission.** `run_backup_create` used
   `println!`/`eprintln!`, which panic (exit 101, outside the SPEC-0050 §8
   0/2/3/4 contract) when stdout is closed, e.g. `o3k backup create ... |
   head -0`. Both emissions are now `writeln!` on `io::stdout()`/`io::stderr()`
   with errors handled: a failed stdout write exits with the already-computed
   contract code, and the stderr reason line is best-effort. Regression
   coverage: `backup_create_closed_stdout_keeps_contract_exit_code` in
   `bins/o3k/tests/cli.rs` spawns the real binary with a reader-less stdout
   pipe and asserts exit 2 (a rejected precondition), not 101.
3. **(Nit) Publication durability.** After the final
   `renameat_with(RENAME_NOREPLACE)`, the destination directory is fsynced
   best-effort (`let _ = sync_dir(&destination_dir)`), mirroring the
   existing data-dir sync, so the published directory entry survives power
   loss.
4. **(Nit) This section** records the commit state and the round-3 fixes.

## Validation

Round 3 (this round's fixes):

- `cargo fmt -p o3k -- --check` (after `cargo fmt -p o3k`) — clean; a
  workspace-wide `cargo fmt --all -- --check` afterwards is also clean.
- `cargo clippy -p o3k --all-targets --all-features -- -D warnings` — exit 0,
  no warnings.
- `cargo test -p o3k --all-features` — exit 0, 0 failed (including the
  end-to-end provisional-capture test on the now fully fd-anchored
  post-capture path, the crash-hook tests, and the new closed-stdout
  contract test).
- `tests/pp6_backup_handoff.sh` — **PASS — 17 executed checks, 7
  documented-coverage rows, 0 failures** (exit 0).

Round 2 (this round's fixes):

- `tests/pp6_backup_handoff.sh` re-run after the round-2 fixes (worktree =
  `b92f4ce9` + uncommitted round-1 + round-2 fixes): **PASS — 17 executed
  checks, 7 documented-coverage rows, 0 failures** (exit 0), including the
  full journey with the dir-fd-anchored snapshot capture.
- `cargo fmt -p o3kd -p o3k -p o3k-store -- --check` — clean.
- `cargo clippy -p o3kd -p o3k -p o3k-store --all-targets --all-features -- -D warnings` — exit 0, no warnings.
- `cargo test -p o3kd -p o3k -p o3k-store --all-features` — exit 0; 744
  passed, 0 failed across 57 test binaries (including
  `backup_create::tests::provisional_capture_completes_end_to_end`, which
  exercises the `/proc/self/fd/<staging-fd>` capture path end to end, and the
  extended `handoff_transfer_error_classification_tests`).

Round 1 (pre-merge):

- `tests/pp6_backup_handoff.sh`: re-run **twice** after the round-1
  production and harness fixes (worktree = `b92f4ce9` + uncommitted round-1
  fixes). Both full runs **PASS — 17 executed checks, 7 documented-coverage
  rows, 0 failures**, re-runnable end to end in ~2 minutes on the baseline
  host; trap cleanup leaves no daemon or executor process and removes the
  temporary installation. The run observations quoted above (state-machine
  timestamps, drain wall-clock, workload counts) are from the second of
  those runs; binary SHA-256s are from the same build. `bash -n` and
  `shellcheck -S warning` are clean on the updated harness.
- Original full run (baseline `2a481ca`, Slices A–D uncommitted): **PASS —
  17 executed checks, 7 documented-coverage rows, 0 failures**.
- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p o3kd -p o3k -p o3k-store --all-targets --all-features -- -D warnings` — exit 0, no warnings.
- `cargo test -p o3kd -p o3k -p o3k-store --all-features` — every test
  binary `ok`, 0 failed (including the real-process `bins/o3kd/tests/shutdown.rs`
  SIGTERM/SIGINT/lock-exclusion tests, the `backup_control.rs` authenticated-
  request wiring test, the `backup_create_hooks.rs` crash-injection tests, and
  the o3k-store handoff/pool suites). (The three `cargo` results are from the
  baseline validation of Slices A–D; the round-1 production fixes on top were
  validated by the fixing change.)

## Provenance

Repository sources only: Slices A–C as present in the worktree
(`crates/o3k-store/src/backup_control.rs`, `crates/o3k-store/src/access_lock.rs`,
`bins/o3kd/src/composition/backup.rs`, `bins/o3kd/src/composition/mod.rs`,
`bins/o3kd/src/main.rs`, `bins/o3k/src/backup_create.rs`), ADR-0189 and
SPEC-0050, and the ISSUE_1084_OWNED_WRITER_REVIEW disposition table. No Go
implementation, private source, or external test material was used.
