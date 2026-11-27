# Issue #1241 — Early Access stabilization plan

Status: Active execution plan; not qualification evidence. Updated after protected merges of #1245 and #1246; main commit `166ff450f8c721f6ac6396eee77ee324e17c8441` post-merge CI is still running.

## Intent and bounded profile

- **Issue:** [#1241](https://github.com/o3kio/o3k/issues/1241), which remains open through exact-artifact SPEC-0052 acceptance, focused independent human security review, and owner GO.
- **Deployment/evidence profile:** `o3k-early-access-v1`; Ubuntu 24.04 LTS x86_64, one active controller, PostgreSQL 16, KVM/libvirt, one to three hypervisors.
- **Canonical domains:** Cloud Kernel/IAM, compute, network, storage, placement, operations/reconciliation, installer and release governance.
- **Compatibility adapter:** existing advertised OpenStack compatibility operations only; no profile expansion.
- **Authority mode:** O3K-implemented Cloud Kernel and resources; host compute/network/storage components remain bounded execution providers; EA installation uses authenticated `early-access-v1` / `installation-local` authority. C1 remains separate and unchanged.
- **Public actions/resources:** canonical init/join, host enrollment and lifecycle, IAM-scoped resource lifecycle, operation replay/reconciliation, and currently advertised VM/network/storage actions. No new route is planned.

## Normative sources consulted

- `README.md`, `docs/PROJECT_CHARTER.md`, `docs/CLEAN_IMPLEMENTATION.md`, `docs/ARCHITECTURE.md`, `docs/NORMATIVE_SOURCES.md`, `docs/TEST_STRATEGY.md`, and the supplied `AGENTS.md`.
- ADR-0191 and SPEC-0052, especially the exact-artifact and all-16-check acceptance gate.
- ADR-0165/0166/0167/0160/0162/0163; SPEC-0020/0021/0022/0024/0025; `compatibility/product-profiles.yaml`; `contracts/execution-boundaries.md`; and `contracts/core-architecture-boundaries.toml`.
- Constraints carried into execution: O3K remains canonical resource authority; auth must precede provider mutation; existing profiles and C1 are preserved; release claims bind to executable evidence; protected review/CI and owner GO remain required; no HA/DR/production certification claim.

## Execution scope

- **Cargo packages/binaries:** release build targets `o3kd`, `o3k`, `o3k-compute-bin` with `libvirt`, and `o3k-network-bin`; focused review/test targets include `o3k-store` and `o3k-image`. No guest-side source builds.
- **Expected repository files:** existing EA installer and release files under `packaging/`, `.github/workflows/release.yml`, operator/release docs, and a campaign-owned `tests/ea-qualification/` harness plus `docs/evidence/` records. Rust source changes are limited to a reproduced blocker and its regression test. Unrelated untracked files in the shared worktree are out of scope.
- **Provider/database assumptions:** real KVM/libvirt and authenticated host agents; PostgreSQL 16 on the control-plane guest; tenant workloads use nested KVM. SQLite remains the portable default outside this selected EA profile.
- **Cross-service dependencies/compensation:** canonical enrollment and Placement before scheduling; persist operations before provider effects; observe after uncertain outcomes; cleanup only O3K-owned resources and preserve foreign state.
- **Evidence tier:** exact authenticated release candidate; real nested-host installation and workload paths; campaigns A–E; machine-readable, redacted, replayable evidence bound to release version/source/artifact/SBOM/provenance/signature and environment. Candidate evidence does not transfer to changed artifact bytes.
- **Required tests/checks:** installer contract and negative tests, package-level regression tests for any changed Rust code, worker snapshot checks, bundle/signature verification, package checks before the workspace gate, protected CI and release workflow, then all SPEC-0052 campaigns against the exact artifact.
- **Known uncertainties:** focused independent human review has been requested against protected main `166ff450f8c721f6ac6396eee77ee324e17c8441`; post-merge CI is still running; no authenticated RC artifact or §8 campaign evidence exists yet. A separate integrated review found that packaged `o3kd` cannot execute the native LVM path under its installed service identity; this is an open storage acceptance blocker and requires implementation of the already-accepted ADR-0169 executor boundary.
- **Non-goals:** PP.5/PP.6/PP.7 certification, S5/S10/S20/K-min/K-full, five-host support, HA, automatic evacuation, live migration, advanced DR, broad OpenStack parity, and unrelated feature work.

## Smallest falsification checks and scope widening

- Current source checks: `bash tests/ea-installer-contract.sh`; `cargo test -p o3k-store --all-features deleted_executable_identity_fails_closed`; `cargo test -p o3k-image --all-features`.
- Expand code scope only when a concrete failing test, review finding, contract mismatch, protected CI failure, or real-host acceptance failure identifies the affected boundary. Do not serialize or disable tests to conceal a concurrency issue.
- Provisioning and campaign evidence are kept separate from release evidence until the exact signed candidate is installed and verified.
