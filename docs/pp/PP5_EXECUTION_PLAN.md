# PP.5 execution plan — O3K Small Edge v1 lifecycle, failure and soak hardening

Status: proposed execution plan. Not acceptance evidence.
Program: [#968](https://github.com/o3kio/o3k/issues/968)
Phase: PP.5 · Gate: [#974](https://github.com/o3kio/o3k/issues/974)
Carried-in debt: [#1035](https://github.com/o3kio/o3k/issues/1035) (first priority), [#1033](https://github.com/o3kio/o3k/issues/1033)
Predecessor: PP.4 Core [#973](https://github.com/o3kio/o3k/issues/973) — closed COMPLETE
Excluded from acceptance: Araf [#1029](https://github.com/o3kio/o3k/issues/1029)

## 1. Scope and authority

PP.5 hardens the **already-delivered** O3K Cloud Kernel for the bounded
single-site `o3k-small-edge-v1` profile. It adds no topology, scheduling,
lifecycle, or reconciliation authority. It reuses, without duplication:

| Authority | Location |
| --- | --- |
| LocationRegistry / failure-domain topology | `crates/o3k-kernel/src/location.rs` |
| BuildingBlock lifecycle | `crates/o3k-kernel/src/building_block.rs` |
| ResourceProvider / Placement | `crates/o3k-placement/src/lib.rs` |
| CloudProfile | `crates/o3k-kernel/src/composition.rs` |
| node/agent identity + epoch fencing | `crates/o3k-provider/src/node.rs`, `crates/o3k-compute-agent/src/lib.rs` |
| IAM / `AuthContext` | `crates/o3k-kernel/src/auth_context.rs` |
| Operations / durable workflow state | `crates/o3k-reconciler/src/lib.rs`, `crates/o3k-store` |
| PKI / enrollment | `bins/o3kd/src/native_adapters/bootstrap.rs` |
| Native O3K API | `crates/o3k-native-api` |
| Bounded OpenStack compatibility projections | `crates/o3k-api` |

PP.5 is hardening + evidence, not architecture. Where a requirement would need
a new canonical authority, work stops and reports (see §10).

## 2. Accepted baseline

* public release `v0.4.0-rc.24`; runtime source `7830d62e…`; PP.4 certification head `77ac5c6f…`
* merged main `dc92cb57` — PP.4 Core: prove the bounded demo-v1 profile on Ubuntu and Debian (#973)
* Ubuntu 24.04 PASS, Debian 12 PASS; PP.4 issue #973 CLOSED COMPLETE
* `o3k-demo-v1` (single host) is the PP.4 profile; `o3k-small-edge-v1` (1–20 hosts, multi-host) is the PP.5 profile
* PostgreSQL is the declared production-oriented backend (`docs/specs/SPEC-0024-product-profiles-and-claims.md:281`)

## 3. Gap review — PP.5 requirements vs delivered P15/P15.7 capability

The multi-host lifecycle the PP.5 brief describes **already exists** as the
protected P15.7 real-host journey, `scripts/p15-7-real-host-journey.sh`
(launched by `.github/workflows/real-host-validation.yml`). PP.5 must extend
it, not rebuild it.

### 3.1 Already delivered (reuse; do not re-implement)

| PP.5 campaign step | Status | Evidence |
| --- | --- | --- |
| authenticated host / BuildingBlock joins | delivered | journey `:539-607`; `bins/o3kd/src/native_adapters/bootstrap.rs` |
| canonical topology + ResourceProvider capacity | delivered | journey `:704-722`; `crates/o3k-placement` |
| constrained workload placement | delivered | journey `:778-858` |
| add capacity | delivered | journey `:803-806` (block-c) |
| drain a BuildingBlock | delivered | `BuildingBlockState::Draining` (`building_block.rs:23`); journey `:922-948` |
| reject new placement onto draining capacity | delivered | Placement `Enabled`-only filter (`o3k-placement/src/lib.rs:470,603`); inventory never reopens a draining provider (`crates/o3k-compute/src/inventory.rs:78`); journey `:950-985` |
| report resident workload/storage/attachment blockers | delivered | `DrainBlocker{Workload,LocalStorage,Attachment}` (`building_block.rs:47`); journey `:936-947` |
| remove a host | delivered | `Draining→Removed` (`building_block.rs:192`); journey `:1019-1021` |
| rejoin / replace | delivered (replace = new identity) | journey `:1022-1025`; same-identity rejoin after removal is deliberately refused (`bootstrap.rs:476`) |
| restart relevant services/control plane/PostgreSQL | delivered | journey `:1086-1129` |
| teardown + owned-leak assertion | delivered | journey `:269-392`; `leak_check` counters `:1156` |
| `o3k-server:%` zero-endpoint assertion | delivered (elsewhere) | `tests/p13_2d_server_lifecycle.sh:98`; `tests/pp4-core-campaign/in-vm-core-post.sh:94-118` |
| PostgreSQL as the journey backend | delivered | journey `execution.database_backend = postgres`; `postgres:16.4` container |
| SQLite parity check | delivered (narrow) | journey `:1137` re-runs `p15_1_topology_process` + `p15_5_building_block_process` only |

### 3.2 Genuine gaps PP.5 must close

1. **Interrupted-terminal-delete orphan endpoint (#1035).** The request path
   releases server-owned endpoints (`crates/o3k-api/src/compute.rs:1175`), and a
   delete *replay* retries it (`crates/o3k-compute/src/actions.rs:420-441`), but
   the periodic sweep only lists **non-terminal** lifecycle operations
   (`crates/o3k-compute/src/construction.rs:817`). A crash between the durable
   terminal delete and the release leaves an ACTIVE `o3k-server:` endpoint that
   blocks network teardown, and nothing repairs it.
2. **Exact release-artifact install.** The journey builds `o3kd`/`o3k`/`o3k-compute`
   from the local tree (`scripts/bootstrap-disposable-testlab.sh:458-465`).
   SPEC-0048 §6 requires "target hosts must not compile O3K from source".
3. **Declared scale beyond 4 hosts.** The journey's four block ids are
   hardcoded (`:208-218`); no path to 5–20 hypervisors.
4. **Deliberate durable-workflow interruption.** The journey restarts the
   control plane only after workloads have settled (`:1017` then `:1086`).
   Nothing kills a control plane mid-create/delete/drain, and no compute,
   network, or storage lifecycle operation is fault-injected.
5. **Soak / endurance.** No soak harness exists anywhere in `tests/` or `scripts/`.
6. **Evidence binding.** `p15-7-scale-composition-evidence.json` binds source SHA
   and profile only. It does **not** bind a release artifact digest, SBOM,
   provenance, signature, harness SHA, host/environment identity, database
   backend identity, campaign configuration, or a declared scale/soak matrix.
7. **PostgreSQL conformance is a soft skip.** `crates/o3k-store/src/conformance.rs:1968-1981`
   returns `Ok` with a printed message when `O3K_DATABASE_URL` is unreachable,
   so a local `cargo test -p o3k-store` can pass without exercising PostgreSQL.
8. **Host-reboot contract undecided (#1033).** `packaging/install.sh` and the
   TestLab bootstrap set no `libvirt-guests` posture; the accepted contract for
   rebooting a host with running tenant domains is not written down.

## 4. Declared scale and soak matrix

Fixed **now**, before any execution, so the result cannot choose the target.
Changing a tier requires an explicit replan recorded on #974; a failed tier
never silently lowers the declared envelope.

### 4.1 Scale tiers

| Tier | Hypervisors | Purpose | Required |
| --- | --- | --- | --- |
| `S3` | 3 | multi-host lifecycle correctness (smallest multi-host site) | yes |
| `S10` | 10 | representative mid-scale tier inside the `small-edge-cloud` 1-20 envelope; full lifecycle + failure matrix | yes |
| `S20` | 20 | `o3k-small-edge-v1` declared envelope maximum; capacity + soak | yes |

Rationale for `{3, 10, 20}`: it brackets the single profile envelope now
declared for this profile — `small-edge-cloud.target_hypervisors: {minimum: 1,
maximum: 20}` (`compatibility/product-profiles.yaml`) and `o3k-small-edge-v1`
`target_envelope: 1-20` (SPEC-0048 §4.2) — with `S3` the smallest multi-host
site, `S10` a mid-scale tier inside the envelope, and `S20` the envelope
maximum. The former profile-vs-spec envelope conflict was resolved by aligning
the profile record to SPEC-0048; see §10.1.

### 4.2 Soak tiers

| Tier | Duration | Scale | Load | Required |
| --- | --- | --- | --- | --- |
| `K-min` | 2 h | `S10` | continuous create/delete churn, 2 control-plane restarts, 1 PostgreSQL restart, 1 BuildingBlock drain/ready cycle | yes |
| `K-full` | 12 h | `S20` | same churn at envelope maximum, ≥ 3 restarts | yes |

Soak acceptance is judged on: zero canonical identity duplication, zero
quota/allocation leakage, zero owned-resource leakage, bounded resident memory
and file descriptors, and continued convergence of native + selected
compatibility projections. Soak never claims HA, SLA, or uptime.

## 5. Decomposition

| # | Workstream | Issue | Blocks |
| --- | --- | --- | --- |
| 1 | Reconcile server-owned endpoints orphaned by an interrupted terminal delete | #1035 | everything |
| 2 | Small Edge host-reboot contract: drain / bounded guest stop / operator policy — decide and document, then test to the accepted contract | #1033 | failure matrix |
| 3 | PostgreSQL hardening for the Small Edge lifecycle path (hard-fail conformance arm, DB backend in evidence, #1035 path under real PostgreSQL) | new | #1035 evidence, campaign |
| 4 | PP.5 multi-host campaign harness: exact release-artifact install, declared scale tiers, lifecycle matrix, zero-leak teardown | new | acceptance run |
| 5 | Failure / recovery boundary matrix: durable-workflow interruption, compute/network/storage lifecycle interruption, replay, fencing, idempotency | new | acceptance run |
| 6 | Scale + soak harness and `K-min`/`K-full` execution | new | acceptance run |
| 7 | Evidence binding v2: artifact digest + SBOM + provenance + signature + harness SHA + host identity + DB backend + campaign config + declared matrix, fail-closed | new | acceptance run |
| 8 | PP.5 acceptance run from exact artifacts; limitations; close #974 | #974 | — |

## 6. Acceptance matrix

Every row runs on exact release artifacts at the declared tier, and must
preserve canonical identity, tenant isolation, foreign state, resource
ownership, quotas/allocations, retry/idempotency semantics, readiness
independence, and bounded compatibility claims.

```text
A  install exact release artifacts (no source build)
B  initialize control plane
C  authenticated host / BuildingBlock joins
D  canonical topology and ResourceProvider capacity
E  constrained workload placement
F  add capacity
G  drain a BuildingBlock
H  reject new placement onto draining capacity
I  report resident workload/storage/attachment blockers honestly
J  remove
K  rejoin / replace
L  restart services / control plane / PostgreSQL
M  verify canonical identities survive
N  verify native + selected compatibility projections converge
O  teardown
P  verify no O3K-owned resource leakage (incl. zero durable `o3k-server:%` endpoints)
Q  interrupted terminal delete leaves an orphan; the sweep repairs it (#1035)
R  durable-workflow interruption mid-create / mid-delete / mid-drain recovers
S  soak `K-min` and `K-full`
```

## 7. Evidence binding

Every PP.5 evidence artifact must bind, and its validator must fail closed on
any missing field:

* exact source SHA and exact public release artifact (`version`, `tag_object`, archive sha256);
* SBOM digest, provenance, and signature verification result;
* harness SHA (`campaign_tree_digest`);
* host/environment identity per host (distro, kernel, arch, KVM);
* database backend **identity**, not just its name (PostgreSQL server version, migrations applied, container/instance identity);
* campaign configuration: declared scale tier, declared soak tier, tier parameters;
* the declared matrix from §4 as executed, with per-tier verdicts.

### 7.1 PostgreSQL proof status

PostgreSQL is a declared production-oriented backend (SPEC-0024 §281), and the
#1035 path must not be proven on SQLite alone.

Proven, against the host PostgreSQL 16.15 at `127.0.0.1:5432`
(`O3K_DATABASE_URL=postgres://o3k:password@127.0.0.1:5432/o3k_test`):

| Claim | Status |
| --- | --- |
| real PostgreSQL migrations apply (`migrations_postgres/`, 33 files) | proven — `PostgresStore::connect` runs `sqlx::migrate!` |
| store conformance suite runs against PostgreSQL | proven — `conformance::tests::test_postgres_conformance` executes, does not skip |
| canonical resource/operation/lifecycle concurrency + fencing | proven — `postgres_p12_4` (6), `postgres_p13_b1` (4) |
| quota, topology, governance, metering, audit repositories | proven — full `-p o3k-store --all-features` green |
| network realm cleanup / fingerprint parity under PostgreSQL | proven — `postgres_p13_f2_r1`, `p13_r2a_fingerprint_parity` (needs `O3K_DATABASE_URL_PARITY`) |
| storage attachment path under PostgreSQL | proven — `postgres_p13_4_storage` |

**Closed in this run — the #1035 sweep itself now runs against PostgreSQL.**
The endpoint-lifecycle harness
(`bins/o3kd/src/composition/pp4_endpoint_lifecycle.rs`) is now
backend-parameterized (`HarnessBackend::Sqlite` / `::Postgres`), and three
PostgreSQL lanes are marked `#[ignore = "requires O3K_DATABASE_URL (PostgreSQL)"]`
and fail closed when the backend is unset or unreachable:

| #1035 PostgreSQL lane | Result |
| --- | --- |
| `postgres_interrupted_delete_orphan_is_repaired_and_reuse_is_restored` | pass |
| `postgres_orphan_endpoint_re_attached_by_live_server_is_skipped_and_released_on_delete` | pass |
| `postgres_concurrent_sweeps_and_delete_replay_converge_once` | pass |

Command (observed 3 passed, 0 failed):
`O3K_DATABASE_URL=postgres://o3k:password@127.0.0.1:5432/o3k_test cargo test -p o3kd --all-features --lib pp4_endpoint_lifecycle -- --ignored --nocapture`

SQLite parity for the same semantics is unchanged and green (15 passed,
3 ignored) via `cargo test -p o3kd --all-features --lib pp4_endpoint_lifecycle`.

The 14 required #1035 points are proven on both backends: create with an
O3K-owned endpoint; durable terminal-successful delete; interruption before
release; orphan present before reconciliation; restart reconstructed from
durable state (new connection, same database, no clean); shipped reconciler
removes it; idempotent (`released`/`discovered` → 0, no double delete); the
freed address is reusable; project endpoint count is exact (no leaked
allocation); caller-supplied and foreign endpoints survive **non-vacuously**
(the sweep demonstrably repaired an orphan in the same pass); concurrent sweeps
converge; a delete replay racing the sweep stays correct.

Still open, and required before PP.5 acceptance:

* the SQLite→PostgreSQL migration path does not exist (SPEC-0024 §297); PP.5
  tests fresh PostgreSQL deployments only.
* the harness shares one database (`o3k_test`) and cleans it at test start,
  following the existing `postgres_p12_4` convention. `o3k-store`'s
  `prepare_shared_postgres_test_database` resets the `public` schema under a
  session advisory lock; other PostgreSQL test files reset it without that
  lock, so the two must not run concurrently (recorded in §8.1 item 6).

The soft-skip hole is closed: `O3K_DATABASE_URL` configured but unreachable now
**fails** the conformance suite instead of silently passing, so
`cargo test -p o3k-store` can no longer claim PostgreSQL without exercising it.

## 8. Merge boundary and defect handling

At every merge boundary: `BLOCKER = 0`, `HIGH = 0`, `MEDIUM = 0`.

For every defect:

```text
reproduce -> classify product vs harness/environment -> create/update owning issue
-> repair at the correct architectural layer -> add regression
-> rerun affected campaign -> rerun required global gates
```

A harness/evidence defect is repaired and the affected evidence rerun; it is
never waived because the system looks healthy.

### 8.1 Defects discovered during the PP.5 gap review

1. **`bins/o3k/tests/cli.rs` hid the cause of its own failures.** `run()`
   mapped *any* failure to execute the binary to a synthetic exit code `99`,
   so all eight CLI tests failed with `left: 99, right: 0` and no diagnosable
   error. Reproduced on a clean tree (`git stash`), so it is pre-existing and
   not caused by #1035. Repaired: a failure to execute now panics with the
   underlying `io::Error` and the binary path.
2. **PostgreSQL conformance was a soft skip.** `test_postgres_conformance`
   returned `Ok` with a printed message whenever the database was unreachable,
   so a local `cargo test -p o3k-store` passed without touching PostgreSQL.
   Repaired: a configured `O3K_DATABASE_URL` that cannot be prepared now fails
   the suite; only the unconfigured local default may skip.
3. **A timing-flaky create-convergence test (issue #1040).** `o3k-compute`'s
   `create_convergence_sweep_survives_empty_registry_until_agent_registers`
   armed one 10 s deadline *before* its first wait loop and reused it in the
   second, so under full-workspace parallel load the second loop could inherit
   an exhausted budget. Observed once in a full-workspace run; passing in
   isolation and on re-run.
   **Classification: test-only timing bug — production semantics are sound.**
   Evidence: `crates/o3k-reconciler/src/lib.rs` returns
   `Ok(OperationState::Running)` for `ProviderError::NotFound` without
   consuming the retry budget, and
   `crates/o3k-compute/src/construction.rs::spawn_create_convergence_reconciler`
   is an unbounded periodic sweep with no internal deadline — the only deadline
   in the design was the one the test invented. Repaired by re-arming the
   deadline per wait loop; no timeout inflation, no retries, no weakened
   assertion. The real flake was not reproduced on demand (25 isolation runs,
   25 runs under 12 CPU burners, and 6 full-lib-suite runs all passed); the
   fix is verified against a deterministic reproduction of the exact budget
   arithmetic plus green validation, and that limit is recorded rather than
   hidden.
5. **PostgreSQL `list_resources_by_kind` silently dropped `DELETED`
   tombstones.** `crates/o3k-store/src/postgres/compute.rs` filtered
   `UPPER(observed_state) != 'DELETED'`; the SQLite adapter has always returned
   every row of the kind. The filter arrived with the PostgreSQL adapter
   (`cc189b4a`) and diverged from the pre-existing SQLite behaviour, while the
   method's own doc comment promises "all resources of one kind across
   projects". Callers already filter for themselves (for example
   `bins/o3kd/src/composition/mod.rs:225` `placement_consumer_ids`), and
   `DELETED` tombstones are deliberate (issue #89). Consequence: on PostgreSQL
   the #1035 repair scan found nothing and orphaned endpoints were never
   repaired — the whole sweep was inert on the production backend.
   Repaired by removing the filter and aligning the ordering with SQLite
   (`ORDER BY id`), documenting the contract on
   `ComputeRepository::list_resources_by_kind`, and pinning it with a shared
   conformance test (`conformance::test_list_resources_by_kind_includes_deleted_tombstones`)
   that runs on **both** backends. Fail-before proven: with the filter restored,
   `test_postgres_conformance` fails with *"list_resources_by_kind must return
   DELETED tombstones"*.
6. **The #1035 sweep could release an endpoint a live server depends on.**
   The reserved-name rule answers "who may release this name", not "is this
   endpoint still in use". A tenant may attach any project-visible port to a
   new server (`crates/o3k-api/src/compute.rs`), including a deleted server's
   orphaned `o3k-server:` endpoint, so the sweep's stale create intent could
   name an endpoint a running guest now uses — violating both "never delete
   caller-supplied endpoints" and "never repair live servers". Found by two
   independent reviewers. Repaired in
   `repair_orphaned_server_endpoints`: the pass now skips every endpoint a
   non-terminal server still references (from the same durable scan), counts it
   as `skipped_attached`, and takes the project scope from the resource row
   rather than the derived create intent. Regression:
   `orphan_endpoint_re_attached_by_live_server_is_skipped_and_released_on_delete`
   (SQLite) and its PostgreSQL variant. Fail-before proven: with the guard
   disabled the test fails with `released:1, skipped_attached:0`.
7. **Shared-database PostgreSQL tests can race the schema reset.** Not a
   product defect and not introduced here, but it bounds how the new lanes may
   run: `prepare_shared_postgres_test_database` resets `public` under a session
   advisory lock, while other PostgreSQL test files (for example
   `crates/o3k-store/tests/postgres_p13_f1.rs`) reset the same schema without
   that lock. Two harnesses sharing `O3K_DATABASE_URL` can therefore wipe each
   other mid-run. The new lanes follow the locking convention; the un-locked
   files are recorded as an open item rather than changed here.
4. **Stale build artifacts from a relocated checkout.** `target/debug`
   contained 1163 dep-info files and 111 test binaries compiled from a
   previous checkout path `/root/o3k-rust`, which no longer exists. Their
   cargo fingerprints still matched (identical sources), so cargo reused them
   instead of rebuilding, and every absolute path baked in at compile time
   (`env!("CARGO_MANIFEST_DIR")`, `env!("CARGO_BIN_EXE_o3k")` targets) pointed
   at a missing directory. This is the real cause of the two failures below,
   and it is environmental, not a product or test-isolation defect:

   | Symptom | Real cause |
   | --- | --- |
   | `bins/o3k` CLI tests failed with a synthetic exit `99` | the test harness could not execute a binary resolved through the dead path |
   | `o3k-service-sdk` mTLS test failed instantly with `cannot read server certificate: No such file or directory` | the binary was built from `/root/o3k-rust/crates/o3k-service-sdk`, so its fixture path did not resolve |

   Both pass in isolation because `cargo test -p <pkg>` recompiles against the
   current path. Repaired by purging `target/debug` and rebuilding; the PP.5
   gate is not trustworthy on this host until that is done. Any campaign
   evidence produced before the purge must be re-derived.
5. **Docker port publishing is disabled on the campaign host.** Containers
   start, but `-p 127.0.0.1:PORT:5432` produces no mapping
   (`NetworkSettings.Ports == {}`) and the port is refused from the host. The
   P15.7 journey's disposable PostgreSQL container is therefore unreachable,
   and its `O3K_P15_7_PG_CONTAINER` reachability gate cannot be satisfied as
   written. The PP.5 campaign must use the host PostgreSQL
   (`127.0.0.1:5432`, database `o3k_test`) instead, or the journey's container
   assumption must be adapted — a decision for workstream 4.

## 9. Non-claims

PP.5 does not claim HA, SLA, automatic evacuation or live migration, arbitrary
datacenter scale, multi-region, cells/sharding, blanket OpenStack
compatibility, Araf readiness, or GA/PP.7 certification. No row in §6 may be
reported as passing on the strength of a source build, a skipped test, or
evidence from another profile.

## 10. Open decisions requiring an explicit answer

### 10.1 Hypervisor envelope conflict — RESOLVED

`small-edge-cloud.target_hypervisors` is now `{minimum: 1, maximum: 20}`,
aligned with SPEC-0048 §4.2's `1–20` target envelope
(`compatibility/product-profiles.yaml`). The former profile-vs-spec envelope
conflict is closed; SPEC-0048 is unchanged as the authority.

| Source | Envelope | Authority level |
| --- | --- | --- |
| `compatibility/product-profiles.yaml` `small-edge-cloud` | `minimum: 1, maximum: 20` | compatibility profile (aligned to SPEC-0048 in this change set) |
| `compatibility/product-profiles.yaml` `o3k-small-edge-v1` / SPEC-0048 §4.2 | `1-20` | normative spec + frozen profile |
| issue #974 title/body | `3-20` | issue acceptance criteria |

Per the authority order in `AGENTS.md`, SPEC-0048 outranks the compatibility
profile record and remains the normative authority; the alignment edit in this
change set brings the profile record into the `1–20` envelope rather than
amending SPEC-0048. All three declared envelopes now sit within `1–20`. §4.1
tests `{3, 10, 20}` inside that envelope.

### 10.2 Host-reboot contract (#1033) — DECIDED

Decided and documented in `docs/operations/pp5-host-maintenance.md`. The
supported planned-maintenance contract is **drain-first**:

```text
Ready -> Draining -> reject new placement -> expose resident blockers
      -> operator explicitly resolves workloads or accepts downtime
      -> host reboot / maintenance -> host returns
      -> reconcile the same canonical identity
```

O3K performs no live migration and no automatic evacuation, so it reports
resident workloads instead of pretending to move them. Verified: no O3K
install, packaging or service unit mutates host-global shutdown policy
(`libvirt-guests` / `ON_SHUTDOWN`); host shutdown posture stays operator-owned.

The disposable TestLab keeps a **bounded ACPI wait then force-destroy**
sequence (`tests/pp4-core-campaign/host-run.sh`) purely as an anti-hang control
for minimal guest images. That is a test-environment control and is never
evidence of workload HA or graceful production evacuation; the two are labelled
separately in the contract document and in campaign evidence.

Host reboot remains **unused as a PP.5 acceptance signal** until the S5
maintenance journey passes.

## 11. Araf boundary

Araf stays outside PP.5 acceptance entirely. Araf work remains under #1029.

## 12. Execution environment and status

### 12.1 Campaign host

The PP.5 campaign host is a nested-virtualisation-capable machine:

| Property | Value |
| --- | --- |
| CPUs | 16 |
| RAM | 62 GiB (60 GiB available) |
| `/dev/kvm` | present |
| libvirt / QEMU | 10.0.0 / 8.2.2 |
| cached images | `noble-server-cloudimg-amd64.img` (Ubuntu 24.04), `debian-12-genericcloud-amd64.qcow2` |
| PostgreSQL | 16.15 on `127.0.0.1:5432` (user `o3k`, database `o3k_test`) |
| docker | usable for containers, but **port publishing is disabled** — see §8.1 item 5 |
| pre-existing unrelated domains | `p14-openstack-source`, `p14-openstack-source-legacy-2025.1` — **must never be touched** |
| cached campaign inputs | Ubuntu 24.04 cloud image `612b2c0c…`, CirrOS 0.6.3 `7d635585…` (both match the pinned digests) |

Every guest is a genuine nested-KVM libvirt domain, so "multi-host" here means
independent kernels with independent `o3k-compute` agents, not processes on one
kernel. The `S20` tier (20 guests) needs a declared resource budget per guest;
the host above supports it at ~2 vCPU / 2 GiB per guest.

### 12.2 First installation

The first execution step is a **5-host first installation** (`S5`), deliberately
below the declared `S3`/`S10`/`S20` tiers: prove that five genuine nested-KVM
hosts can be provisioned, joined, given canonical topology and ResourceProvider
capacity, and torn down with zero owned leakage, *before* scaling. `S5` is a
stepping stone, not a tier substitution — the declared tiers in §4.1 remain the
acceptance targets.

### 12.3 Status

| Item | Status |
| --- | --- |
| #1035 reconciler implementation | delivered (bounded sweep, repair-only, reserved-name ownership, live-attachment guard) |
| #1035 SQLite regressions | delivered — 15 passed, 3 ignored |
| PostgreSQL proof for the #1035 sweep | **delivered** — 3 PostgreSQL lanes pass; 14 required points proven on both backends (§7.1) |
| PostgreSQL `list_resources_by_kind` parity defect | repaired + pinned by a both-backend conformance test (§8.1 item 5) |
| #1035 live-endpoint safety gap | repaired + regression on both backends (§8.1 item 6) |
| PostgreSQL conformance hardening | delivered (soft skip closed) |
| #1040 create-convergence flake | classified test-only, repaired (§8.1 item 3) |
| PP.5 evidence validator + CI gate | delivered — 26 validator cases, `rust`-job step, fail-closed `pp5-evidence-certify` workflow |
| PostgreSQL provider modes (`external` / `disposable`) | delivered in the P15.7 journey config layer; external-mode fault injection via a run-owned proxy |
| 5-host first installation | **provisioning proven** — 5 genuine nested-KVM hosts up with `/dev/kvm`, `svm`, 2 vCPU / ~1967 MiB, SSH reachable |
| 5-host O3K lifecycle campaign | not yet run — the journey still carries 4 canonical block identities; the 5th is a separate increment |
| declared tiers `S3`/`S10`/`S20`, `K-min`/`K-full` | not started (deliberate — this run is the S5 foundation) |
| #1033 host-reboot contract | **decided and documented** (`docs/operations/pp5-host-maintenance.md`); S5 maintenance journey not yet run |

### 12.4 #1035 follow-ups (recorded, not silently deferred)

1. **Sweep cost under churn.** `repair_orphaned_server_endpoints` enumerates
   every `compute_instance` resource per pass and, for each terminally deleted
   one, asks the network layer to release the endpoints named by its create
   intent. Released endpoints resolve as `absent` cheaply, but the pass is
   O(historically deleted servers) per tick, growing with churn. The soak
   workstream (workstream 6) must measure this cost under sustained churn and,
   if it is material, replace the per-server lookups with one bounded batch
   query per project. Correctness does not depend on this; cost does.
2. **Create-compensation crash window.** #1035 covers the interrupted
   *delete*. A terminally failed *create* compensates its endpoint on the
   request path (`crates/o3k-api/src/compute.rs`), and a crash before that
   compensation has the same orphan shape. It is deliberately out of #1035's
   scope and needs its own decision, because a failed create's endpoint may
   still be needed by reconciliation until the operation is proven terminal.
3. **Terminal-write atomicity — the sweep's discriminator has a converse
   gap.** `OperationJournal::finish_lifecycle` writes
   `update_operation(..., Succeeded)` and then `update_resource(observed_state
   = DELETED)` as two separate, non-transactional statements. A crash between
   them leaves the delete durably terminal **and** `observed_state` not yet
   `DELETED`. That is inside #1035's stated window ("delete becomes durably
   terminal-successful -> process dies before endpoint cleanup"), but the sweep
   keys on `observed_state == DELETED` and the lifecycle sweep only re-drives
   *non-terminal* operations, so the orphan is stranded until a human replays
   the delete. Found independently by two reviewers.
   **Deliberately not repaired in this change set**, because every candidate fix
   is a canonical-contract decision rather than a local repair: (a) make the two
   writes one transaction (needs new store surface, and the local-completion
   path in `crates/o3k-compute/src/actions.rs` writes in the same order, so both
   must change together); or (b) reorder to resource-then-operation so the
   existing non-terminal re-drive closes the window (changes the meaning of
   "operation terminal" for every consumer). Reported as its own defect rather
   than silently redesigned. The same split also means a crashed delete can
   leave a server that reads `ACTIVE` while its guest is gone — a larger
   projection problem than the endpoint orphan.
4. **Does a `DELETED` server still count as a drain blocker?**
   `bins/o3kd/src/native_adapters/building_block.rs::derived_blockers` counts
   any `compute_instance` whose create intent names the block's provider, and
   it does not check `observed_state`, while `finish_lifecycle` leaves
   `desired_state` intact on delete. On SQLite (which always returned
   tombstones) that means a deleted workload may still be reported as a
   resident workload blocker. This is pre-existing and unchanged by the parity
   fix, but it bears directly on the drain contract's promise to "report
   resident blockers honestly", so the S5 drain journey must establish
   empirically whether a deleted workload clears the blocker, and a defect gets
   its own issue if it does not.
5. **Shared-database PostgreSQL reset races.** See §8.1 item 7.
6. **`PostgresStore::connect` backfill validation can fail on a dirty shared
   database.** Its canonical-network backfill validates existing rows before
   any test-level cleanup runs, so a row left behind by an interrupted run can
   fail `connect` itself (observed: a stale `p9-intent` row whose payload id
   contradicted its row id). CI is unaffected because it uses a fresh database;
   shared-host runs are. Recorded as an open item.
