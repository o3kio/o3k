# Owner-directed Early Access roadmap reset — implementation plan

Date: 2026-11-25  
Issue: replacement adoption epic for #968, #974, #975 and #976 (created after this plan)  
Owner direction: this task's explicit O3K project-owner decision, 2026-11-25

## Selected profile and authority

- Product/deployment profile: `o3k-early-access-v1` (new bounded profile), Ubuntu 24.04 LTS x86_64, one active controller, PostgreSQL 16, KVM/libvirt, one to three hypervisors initially; expansion to five requires separate evidence and owner decision.
- Canonical domain: O3K Cloud Kernel with existing IAM, compute, network, storage, topology, Placement, BuildingBlock, operation and reconciliation authorities.
- Compatibility adapter: only already advertised native O3K CLI/API and compatibility operations in the selected existing manifests; no endpoint additions in this work.
- Authority mode: `o3k-implemented` for canonical resources; host execution providers remain bounded execution providers. EA installation-local trust authorizes only the EA installation identity/profile. C1 remains the authority for recovery-qualified installations.
- Cross-service workflow: reuse existing Operations, ownership, provider mappings and compensation; no new scheduler/store/service.

## Normative inputs already consulted

- `README.md`, `docs/PROJECT_CHARTER.md`, `docs/CLEAN_IMPLEMENTATION.md`, `docs/ARCHITECTURE.md`, `docs/NORMATIVE_SOURCES.md`, and `docs/TEST_STRATEGY.md`.
- ADR-0163, ADR-0165, ADR-0166, ADR-0167; SPEC-0020, SPEC-0021, SPEC-0022, SPEC-0024, SPEC-0025; `compatibility/product-profiles.yaml`; `contracts/execution-boundaries.md`; `contracts/core-architecture-boundaries.toml`.
- Existing C1/recovery authorities: ADR-0189, ADR-0190, SPEC-0050 and the PP.6 evidence matrix. Existing install authority: `contracts/installer-v1.yaml` and `docs/INSTALLER.md`.
- Constraints carried forward: profile-specific claims; PostgreSQL/HA support claims require evidence; preserve Cloud Kernel authority; no generic fallback/skip flag; no C1 downgrade; no release or real-host evidence inferred from architecture or source tests.

## Packages, files and symbols expected to change

- Governance/contracts: new owner-directed ADR and EA specification; `docs/NORMATIVE_SOURCES.md`; `compatibility/product-profiles.yaml`; `AGENTS.md`; `docs/ROADMAP.md`; `README.md`; `docs/INSTALLER.md`; release/issue/evidence documentation and `docs/operator/` guides.
- C1 admission boundary: `bins/o3k/src/recovery_identity.rs`, `bins/o3k/src/recovery_installation.rs`, `bins/o3k/src/upgrade/release_identity.rs`, `bins/o3k/src/main.rs`; related C1 install/startup and restore tests.
- Packaging/release: `packaging/make-release.sh`, `packaging/install.sh`, `packaging/get-o3k.sh`, release manifest/bundle contracts and validators, `.github/workflows/release.yml` only where it can preserve protected release controls.
- Executables: affected Cargo packages are `o3k`, `o3kd`, and `o3k-compute` as consumers of the shared install/startup gate.
- Tests: exact-profile manifest/installer tests, C1 preservation and anti-downgrade tests, EA rejection of recovery operations, restart/reconciliation tests where portable; full real-host acceptance requires a provisioned Ubuntu 24.04/PostgreSQL 16/KVM environment and authenticated EA artifact.

## Evidence/public reference inputs

- No source implementation is used as reference. The current repository contracts, accepted ADRs/specs, existing C1 implementation, public OpenStack contract, Sigstore/SLSA release artifacts and the exact published O3K artifact are the permitted inputs.
- Preserve the published immutable v0.4.0 artifact, its test-only declaration and its pinned C1 authority; do not create/relabel evidence or change that tag.

## Required acceptance and tests

1. Validate normative-source/profile/issue traceability before code.
2. Add focused negative and fail-before tests for ambiguous profile state, corrupted/removed/copied recovery state, prohibited C1-to-EA transitions, EA restore/activation denial, and authenticated fresh-install admission.
3. Preserve/run the existing C1 ceremony and C1 designated-startup suites.
4. Run package-level checks for the affected Rust crates and packaging tests, then the repository-mandated fmt, clippy and workspace tests.
5. Real-host gate requires exact authenticated EA artifact and covers the sixteen owner-listed acceptance items. No real-host result is inferred from CI, source fixtures, or the current C1 bundle.

## Dependencies and assumptions

- PostgreSQL 16 is operator-managed infrastructure; the installer may install/configure the supported local package/service when selected by the explicit EA profile, but must not silently initialize/overwrite foreign PostgreSQL state.
- Controller/compute/host services reuse current process contracts. No HA, automatic evacuation, live migration, SLA, generic DR, or >3-host support is claimed; five hosts follow only after evidence.
- Signed release artifact verification (Sigstore, SBOM and provenance) remains the root for executing release content. Installation-local trust is bound to the authenticated EA artifact and canonical fresh installation identity; it does not replace release authenticity.
- Existing C1 release trust, policy, journal, recovery designation, activation and qualified recovery behavior must remain separately selected and fail closed.

## Known uncertainties / independent review

- The current source does not implement the requested EA trust profile or PostgreSQL install path. Security-sensitive format and lifecycle changes require focused independent technical/security review before release promotion; agent review is advisory and is not independent human approval.
- No provisioned dedicated real-host campaign runner or exact authenticated v0.4.1 artifact has been established in this working session. These are hard blockers for the real-host acceptance gate and publication.
- GitHub issue mutations are authorized by the owner decision, but PP parents close only after this replacement contract and the parent/child traceability mapping are recorded. Child defects are not closed merely by transfer.

## Non-goals

- Complete PP.5, PP.6, PP.7, S10/S20/K-min/K-full or full disaster-recovery certification.
- Production/GA/HA/SLA, automatic evacuation, live migration, general disaster recovery, broad OpenStack parity, arbitrary 1–20 host support, or fixed footprint claims.
- Replacing the v0.4.0 artifact or pinned signing authority; modifying protected branch controls; fabricating review, evidence or test results; closing unresolved defects.
