# #1089 PP.6 resource-pressure and operator-error matrix

Status: coverage map for [#1089](https://github.com/o3kio/o3k/issues/1089),
recorded 2026-10-16. This is not acceptance evidence and does not close #1089.
Each row names the test or CI lane that exercises a case and its state:

- **Merged**: on `main` and run by CI.
- **This branch**: added by the `pp6/decision-followups` branch, not yet merged.
- **Open PR**: in an open pull request.
- **Partial**: some of the criterion is covered; the gap is stated.
- **Gated**: blocked on ADR-0189/SPEC-0050 acceptance.

## Criterion 1: store pressure and availability

| Case | Backend | Evidence | State |
| --- | --- | --- | --- |
| WAL filesystem full (`SQLITE_FULL`) on a real ext4 loop mount | SQLite | `tests/sqlite-disk-pressure.sh`, `crates/o3k-store/tests/sqlite_disk_pressure.rs` (#1128) | Merged |
| Unavailable store path fails closed, no parent created | SQLite | `crates/o3k-store/tests/sqlite_unavailable.rs` (#1129) | Merged |
| Lock/busy: a cancelled write must not leave the writer lock held | SQLite | `crates/o3k-store/tests/sqlite_cancellation.rs` (#1132, fixes #1126) | Open PR |
| Connection loss and reconnect after server stop/start | PostgreSQL 16.4 container | `crates/o3k-store/tests/postgres_outage.rs` (#1128) | Merged |
| Client pool exhaustion and recovery | PostgreSQL (CI service, shared-DB advisory lock) | `crates/o3k-store/tests/postgres_resource_pressure.rs` (#1128) | Merged |
| Server connection exhaustion (SQLSTATE 53300) and recovery | PostgreSQL 16.4 container | `crates/o3k-store/tests/postgres_server_pressure.rs` (#1128) | Merged |
| Tablespace full (SQLSTATE 53100) and recovery | PostgreSQL 16.4 container | `crates/o3k-store/tests/postgres_tablespace_pressure.rs`, `.github/workflows/pp6-postgres-tablespace-pressure.yml` (#1128) | Merged |
| WAL disk full (SQLSTATE 53100) and restart recovery | PostgreSQL 16.4 container | `crates/o3k-store/tests/postgres_wal_pressure.rs`, `tests/postgres-wal-pressure.sh` (#1128) | Merged |

## Criterion 2: operator error, restart and unknown outcome

| Case | Evidence | State |
| --- | --- | --- |
| Backup destination full or unavailable | No backup implementation exists | Gated |
| Malformed configuration: positional argument, malformed TOML file, invalid listen address, PostgreSQL backend without URL, weak signing key. Each exits before serving, echoes no secret, and leaves the data directory unchanged | `bins/o3kd/tests/pp6_config_input_process.rs` | This branch |
| Invalid CloudProfile writes: malformed body, unknown field, ID mismatch, invalid profile, stale and reused generation, missing content type, unavailable store; state and audit unchanged | `rejected_cloud_profile_writes_preserve_profile_and_audit`, `cloud_profile_write_reports_unavailable_store_as_503` in `bins/o3kd/src/native_adapters/composition_profile.rs` (from #1106) | This branch |
| Capacity rejection leaves Placement, network pool and volume state consistent | `unavailable_and_insufficient_hosts_are_skipped` (`o3k-scheduler`), `exhausted_network_pool_preserves_state_and_allows_retry_after_release` (`o3k-network`), `native_volume_capacity_failure_is_durable_and_skips_follow_up_work` (`o3k-api`) (#1129) | Merged |
| Repeated/replayed operator action across processes, including concurrent, in-flight, terminal and restart replay | `bins/o3kd/tests/p12_7_cross_process_replay.rs` (SQLite in the test suite; PostgreSQL in the mandatory "P12.7 cross-process native replay conformance" CI step) | Merged |
| Compute timeout replay keeps identity and does not re-dispatch | `native_compute_create_after_delete_same_key_fails` in `bins/o3kd/src/native_adapters/tests.rs` (#1129) | Merged |
| Process restart preserves canonical state | `p15_3_placement_process.rs`, `p15_4_cloud_profile_process.rs`, `p15_5_building_block_process.rs`, `cross_process_restart_replay_{sqlite,postgres}` | Merged |
| Lost response / unknown outcome is observed before retry | `production_mtls_unknown_final_removal_is_not_superseded` and `production_mtls_unknown_final_removal_store_reopen_sqlite` (`bins/o3kd/src/composition/network.rs`, #1129); `create_timeout_is_unknown_and_reconcile_observes_before_retry` (`o3k-compute`); `failed_realization_is_unknown_until_observation_resolves_it` (`o3k-network`) | Merged |
| Interrupted delete leaves a repairable orphan, not a lost resource | `fault_pause_interrupted_delete_orphan_is_repaired_and_reuse_is_restored` (`bins/o3kd/tests/pp5_interrupted_delete_process.rs`) | Merged |

## Criteria 3–6

| Criterion | State | Notes |
| --- | --- | --- |
| 3. Bounded error identity, canonical invariants, safe retry per case | Partial | Asserted per test above. The six evidence lanes also write one normalized `o3k.pp6.evidence.v1` envelope per run (this branch); the per-case assertions themselves stay in each lane's own artifact. |
| 4. No unowned mutation and foreign-state preservation under interruption/retry | Partial | The store-pressure lanes record `foreign_state` as not exercised: they invoke no provider. Provider-backed interruption cases are the unknown-outcome and interrupted-delete tests above. |
| 5. Secret checks and run binding (source, harness, backend/version, profile, fixture) | This branch | `scripts/validate_pp6_evidence.py` maps each of the six lanes onto one envelope binding case, passing disposition, source (and execution) commit, backend kind and version, product profile (`o3k-small-edge-v1` or `o3k-demo-v1`), fixture identity and foreign state, and scans the full artifact for credential shapes. CI runs it after every lane and uploads the envelope. Validated against real artifacts from the client-pool, SQLite WAL and PostgreSQL WAL lanes. |
| 6. PostgreSQL cases fail, never silently pass, when the backend is unavailable | Met for the lanes | Each lane provisions or requires its PostgreSQL instance and fails without it: an `expect` on `O3K_DATABASE_URL`, a `docker` error, or `tests/postgres-wal-pressure.sh` exiting before emitting evidence. |

## Remaining work for #1089

1. Merge #1132, then the lock/busy row is covered.
2. Backup destination cases, once ADR-0189/SPEC-0050 are accepted and #1084 exists.
3. Memory and file-descriptor pressure are not covered.
