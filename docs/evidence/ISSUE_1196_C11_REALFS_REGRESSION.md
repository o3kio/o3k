# #1196 C1.1 real-filesystem regression rerun

This is source-built fixture evidence only. It is not installed-release or
production qualification.

## Environment

- Filesystem containing `/var/lib`: `/dev/sda1`, ext4, mounted at `/`.
- Runner: root via `sudo -n`.
- Isolation: each test uses the harness's private mount namespace and bind
  mounts a unique disposable fixture into canonical paths.
- Executable: Cargo-built `o3k` binary from this checkout.
- Command: `sudo -n cargo test -p o3k --test pp6_c1_reanchor_realfs -- --ignored --nocapture`.
- Full output: [`ISSUE_1196_C11_REALFS_REGRESSION.log`](ISSUE_1196_C11_REALFS_REGRESSION.log).

## Individual test bodies

| Test | Result |
|---|---|
| `rotation_over_real_protected_directories_resumes_and_preserves_exactly` | PASS |
| `rotate_then_real_designate_then_startup_observation_accepts_the_new_designation` | PASS |
| `crash_before_and_after_every_boundary_resumes_exact_forward_driver_level` | PASS |
| `startup_observation_rejects_mixed_generations` | PASS |
| `revocation_refresh_resumes_after_archive_and_is_repeatable` | PASS |

Result: 5 passed, 0 failed, 0 ignored (all five ignored-by-default privileged
tests were explicitly run).

## Findings and correction

Four test bodies previously returned successfully when the root fixture could
not be created, falsely reporting PASS; the fifth panicked without a useful
prerequisite disposition. All five now fail with an explicit `NOT_RUN` reason
when a root fixture cannot be created.

The root run first reproduced `installation policy is unavailable`. The
fixture presented its C1 release manifest before invoking first-install
provisioning, so the startup selector gate correctly rejected the generation
whose policy did not yet exist. After resolving that ordering, the run
revealed two further admission errors: first-install policy provisioning was
gated on the selector it publishes, and recovery trust/re-anchor maintenance
was gated on operational admission, which intentionally denies designated
installations. The corresponding commands perform their own root, signature,
protected-path, D8/lock, and exact-forward checks. The CLI-level operational
selector gates were removed from those maintenance/bootstrap paths; they do
not open the canonical store or grant operational readiness.

No test assertion was weakened. The suite verifies protected-byte preservation,
foreign marker preservation, exact-forward retries, mixed-generation denial,
and startup denial after designation. These results do not replace installed
C1/C1.1 qualification from authenticated release artifacts.
