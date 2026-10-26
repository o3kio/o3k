# Plan: o3k doctor — first operator diagnostic CLI

Issue: [#617](../../../issues/617)

## Design

New workspace binary crate `bins/o3k` producing the `o3k` binary whose only
subcommand today is `doctor`. No general CLI framework: argument handling is a
plain match on the first argument (`doctor`, `--version`, `--help`); future
subcommands slot into the same crate without redesign. This satisfies the
preferred UX `sudo o3k doctor` directly.

Doctor is strictly read-only: it opens SQLite in read-only mode, uses
`systemctl` only for state queries, `virsh` only for `uri`/`list`, `ip` only
for `link` listings, and never mutates anything. `o3k repair` is explicitly
out of scope (separate reviewed feature later).

Under the accepted D8 recovery boundary, the CLI first acquires the existing
exclusive store-access guard without creating directories or lock files. It
checks recovery quarantine while holding that guard and retains it through
diagnostic runtime shutdown. A missing, unsafe or busy guard, or recovery
quarantine, produces an unhealthy report containing one `database.accessible`
failure and exits 1 before any diagnostic probe. This includes `--json` output.
Doctor therefore requires offline exclusive access to inspect the canonical
store; it cannot run store diagnostics alongside `o3kd`.

### Check engine

- `Context` carries resolved paths/addresses (data dir, config dir, API
  listen addr, compute health addr, env-file key/values kept in memory only)
  plus trait-based seams for process execution, HTTP, and database access so
  every check is unit-testable deterministically without root or shell shims.
- Each check is an `async fn(&Context) -> CheckResult` producing
  `PASS | WARN | FAIL | NOT_APPLICABLE`, a `summary`, optional `details`, and
  `recommended_actions` (safe read-only next commands) on WARN/FAIL.
- Checks run serially in a fixed order; output order is deterministic.
- Testing/sandbox overrides (process environment, not user-facing flags)
  redirect doctor at a disposable sandbox for rootless process tests and
  acceptance fixtures: `O3K_DOCTOR_CONFIG_DIR`, `O3K_DOCTOR_DATA_DIR`,
  `O3K_DOCTOR_PREFIX`. Production runs use the installed defaults.

### Check IDs

| Category | Section (human) | Check IDs |
| --- | --- | --- |
| host | Host | `host.os_supported`, `host.kvm_device`, `host.disk_space` |
| services | Services | `services.o3kd_unit`, `services.compute_unit` |
| control | Control plane | `control.healthz`, `control.readyz` |
| database | Database | `database.accessible`, `database.integrity`, `database.wal_mode`, `database.permissions` |
| identity | Identity | `identity.configured`, `identity.authenticated` |
| compute | Compute agent | `compute.agent_registered`, `compute.agent_epoch`, `compute.agent_capabilities`, `compute.placement_consistent` |
| libvirt | Libvirt/KVM | `libvirt.compute_access`, `libvirt.control_isolation`, `libvirt.domains_consistent` |
| network | Networking/DHCP | `network.bridge_state`, `network.tap_state`, `network.dhcp_state`, `network.ownership_records` |
| cloud | Cloud/API | `cloud.api_discovery`, `cloud.testvm_status` |
| security | Security boundaries | `security.config_permissions`, `security.tls_identity` |
| release | Installed release | `release.version`, `release.ownership_manifest`, `release.binary_hashes` |

### Output contract

`contracts/o3k-doctor-output.schema.json` — `version`, `overall_status`
(`healthy | warning | unhealthy`), `timestamp`, `checks[]` with
`id/category/status/summary/details/recommended_actions`. Exit codes:
0 = healthy, 1 = warning or unhealthy, 2 = usage/configuration error.
No secrets ever appear in output (enforced by a sentinel redaction test).

### Supporting changes

- `bins/o3k-compute` `/readyz` is extended additively to self-report
  `agent_id`, `agent_epoch`, `software_version`, and `capabilities`
  (max_vcpus/max_memory_mib/max_disk_gb) so doctor can compare the live
  agent epoch against the control plane's persisted epoch (stale-epoch
  detection) and verify capability state. Loopback-only, no secrets.
  Direction semantics: a persisted epoch NEWER than the agent report is a
  stale epoch (FAIL); older records are superseded connection history and
  stay healthy, so a freshly restarted agent never trips the check.
- The compute-identity libvirt probe runs `runuser` with the
  unit's `SupplementaryGroups=libvirt kvm` so it reproduces the real
  agent's socket access; the control-identity probe keeps no extra groups.
- `packaging/install.sh` additionally installs `bin/o3k`,
  `share/o3k/release-manifest.json` (bundle `manifest.json`), and
  `share/o3k/SHA256SUMS` (bundle `SHA256SUMS`), tracked in the ownership
  manifest; `packaging/uninstall.sh` whitelist extended accordingly.
- `packaging/make-release.sh` stages `bin/o3k`;
  `scripts/build-release-binaries-debian12.sh` builds `--bin o3k`.

## Files expected to change

- `Cargo.toml` — workspace member `bins/o3k`.
- `bins/o3k/**` — new crate (lib + thin main + tests).
- `bins/o3k-compute/src/main.rs` — additive `/readyz` fields (+ tests).
- `packaging/install.sh`, `packaging/uninstall.sh`, `packaging/make-release.sh`.
- `scripts/build-release-binaries-debian12.sh`.
- `tests/doctor-process.sh` (new), `tests/ci-workflow.sh` (if CI list changes),
  `tests/packaging-safety.sh`, `tests/operational-outcomes.sh`,
  `tests/installer-negative.sh` (new-file expectations).
- `contracts/o3k-doctor-output.schema.json` (new), `docs/plan/o3k-doctor.md`
  (this file).

## Contracts/specs affected

- `contracts/o3k-doctor-output.schema.json` (new).
- No OpenStack compatibility profile, product-profile, or capability-inventory
  changes: doctor adds no public API surface and no profile claims.

## Required evidence tier

1. Domain/unit: deterministic per-check tests incl. the full negative matrix.
2. Process-level: `tests/doctor-process.sh` against a fake sandbox.
3. Portable integration: real binary against the portable testbed.
4. Real-host gate: clean Ubuntu 24.04 and Debian 12 installed via the public
   one-line path → HEALTHY → stop compute → FAIL → restart → HEALTHY →
   disposable negative fixtures → cleanup → uninstall/purge, with committed
   evidence artifacts, followed by the release/publish step so the public
   `get.o3k.io` path carries doctor.
