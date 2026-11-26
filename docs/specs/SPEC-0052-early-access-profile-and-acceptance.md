# SPEC-0052 — O3K Early Access profile and acceptance

Status: Accepted owner-directed profile contract; implementation, independent security review, and release evidence remain gated
Authority: [ADR-0191](../adr/ADR-0191-owner-directed-early-access-adoption-and-installation-trust.md)
Date: 2026-11-25
Release target: `v0.4.1` (subject to versioning conventions and protected release workflow)
Parent: new Early Access adoption epic replacing the PP release dependency

## 1. Purpose and claim boundary

This specification defines a bounded O3K Core Early Access deployment and its
minimum evidence gate. Early Access is availability for selected adopters,
development/test use, and replaceable non-critical semi-production workloads.
It is not general availability, full production certification, or blanket
OpenStack parity.

The profile is not supported for customer deployment until every blocker in
§8 passes against the exact authenticated release artifact and an owner records
GO. Repository tests, simulated providers, an earlier release, a source build,
or another profile do not substitute for real-host evidence.

## 2. Deployment profile

| Dimension | Initial supported value |
|---|---|
| Product profile | `o3k-early-access-v1` |
| OS | Ubuntu 24.04 LTS, x86_64 |
| Controller | Single active controller |
| Database | PostgreSQL 16, operator-managed or explicitly installed/configured by the EA installer |
| Compute | KVM/libvirt |
| Hypervisors | One to three initially; five only after new evidence and owner decision |
| Interfaces | Native O3K CLI and API; existing advertised operations only |
| Capabilities | Normal supported compute, storage, networking, IAM, and canonical resource lifecycle |
| Operator | Customer/operator-managed infrastructure and access |
| Workloads | Development, test, and selected replaceable non-critical semi-production workloads |

The control plane must not treat PostgreSQL, the hypervisor, or a provider as
canonical cloud-resource authority. Existing Cloud Kernel and execution
boundaries remain normative.

Explicitly unsupported claims and behaviors include HA, multiple active
controllers, automatic evacuation, live migration, enterprise SLA, general
disaster recovery, tested restoration of tenant workload bytes, arbitrary
1–20-host support, five-host support before its gate, and broad OpenStack
parity.

## 3. Release artifact and command

The public release contains prebuilt binaries and a small installer. Target
hosts do not compile O3K. Before extracting or executing bundled payloads, the
installer authenticates the exact release artifact through the release
verification contract: signed digest, Sigstore identity/transparency proof,
SBOM, provenance, manifest, executable hashes, safe archive structure, and
binary-set consistency.

The operator-facing command for an accepted release is:

```sh
curl -fsSL https://github.com/o3kio/o3k/releases/download/v0.4.1/install.sh | sudo sh -
```

The published wrapper is version-pinned. It must reject unsupported hosts,
ambiguous pre-existing state, signature/provenance/manifest mismatch, partial
installation, foreign PostgreSQL state that it cannot safely adopt, failed
migrations, and health/readiness timeout with deterministic messages. Cleanup
may remove only resources created by the current install transaction and must
preserve foreign state and operator workload data.

An install supports a documented explicit profile selection. It cannot infer
Early Access from missing C1 files or a bypass flag. Once installed, normal
daemon/host restarts use the local installation authority and must not request
a new manual signature ceremony.

## 4. Installation identity and security modes

### 4.1 Exclusive release selection

Authenticated release metadata selects exactly one tuple:

```text
early-access-v1 / installation-local
recovery-qualified-v1 / C1 project-policy authority
```

Unknown values, missing values, duplicate selectors, ambiguous fields, or
authority/profile mismatch fail closed. The profile and authority are also
bound in the durable root-owned installation identity and trusted runtime
configuration. Runtime startup verifies the exact release identity, profile,
authority, backend, canonical installation/site identity, and state root
before accepting API traffic or dispatching reconciliation/provider work.

### 4.2 EA fresh-install admission

EA admission requires an explicit authenticated EA release and a fresh target.
The installer generates a unique canonical installation/site ID and
installation-local trust with a cryptographically secure random source. Trust
material is not derived from public identity, is not included in release
artifacts, is not readable by unprivileged users, and is bound to the profile,
backend, release identity, and installation directories. Publication uses
atomic no-follow file operations, restrictive ownership/modes, and the
existing install ledger/ownership model.

The local authority verifies the installation identity/profile and local
EA-specific integrity records. It never signs recovery designation,
restore-activation, recovery-journal, reanchor, release, or cross-installation
authority. Compromise of the host root remains in the host's trust domain;
this local trust is not a remote custodian or hardware-root guarantee.

### 4.3 Anti-downgrade and ambiguous state

EA admission is permanently refused when any evidence of an existing C1 or
prior O3K installation is present, including valid, missing, partial,
malformed, corrupt, unreadable, copied, or mismatched C1 state. Inputs include
the release manifest, C1 policy/state/trust paths, recovery-state/journal
directories, durable profile marker, installation ledger, existing data root,
and service/configuration footprint. A failed read is not equivalent to
absence. The checks run before mutation and fail closed on races/concurrent
installers.

EA and C1 cannot transition in place. A recovery target cannot be admitted as a
fresh EA install. Copied state fails installation/site identity and
filesystem-object binding. The supported recovery boundary is clean rebuild
with explicit operator data preservation; it does not recover controller
state or external workload data.

No local software can distinguish a deliberately erased entire host from a
never-installed host without an external or hardware monotonic authority. The
supported guarantee is therefore enforced by refusing ordinary installer
cleanup/reinstall when durable state or installation footprints exist, and by
requiring an explicit documented destructive rebuild that retains no claim of
recovery. This limitation must be explained to operators and reviewed before
release.

### 4.4 Recovery denial on EA

Advanced restore designation, restore activation, recovery journal transitions,
reanchor, and recovery-qualified CLI commands are unavailable in EA. The
runtime returns stable unsupported-profile errors before any target/provider
mutation. Missing/corrupt EA trust fails closed; it never falls through to C1
or another mode. Existing C1 startup/recovery behavior remains unchanged.

## 5. Bootstrap and services

After artifact authentication, the installer must:

1. validate Ubuntu 24.04, architecture, KVM/libvirt capability and disk/resource prerequisites before mutation;
2. safely install/configure PostgreSQL 16 without overwriting foreign clusters or roles;
3. configure a least-privilege O3K database role/database, apply supported migrations, and verify PostgreSQL readiness;
4. establish local installation identity/trust and TLS/IAM material under existing ownership and secret-handling contracts;
5. enable the existing control-plane and compute services;
6. perform canonical `o3k init` and authenticated `o3k join` using existing topology, Placement, BuildingBlock, and agent identity authorities;
7. wait for controller, compute-agent and canonical cloud readiness; report the actionable failing component without exposing credentials;
8. preserve installation identity and credentials on idempotent rerun and ordinary service/host restart.

No installer-generated substitute topology, fake readiness, separate resource
store, or source compilation is allowed. Failure cleanup removes only resources
created by the attempted transaction, retains durable ownership records needed
for safe retry, and does not delete tenant data or foreign PostgreSQL state.

## 6. Supported lifecycle and operator data boundary

The profile includes only lifecycle operations already implemented and
advertised by the accepted compatibility/product manifests. Protected actions
continue to use O3K IAM/AuthContext, resource ownership, authorization,
Operations/idempotency, audit, scheduling, and reconciliation. Providers never
authorize callers or allocate public O3K IDs.

Guest disks and external storage payloads are outside the O3K control-plane
database. The install guide must require operators to protect workload data
using the backend's own supported procedures. A clean rebuild must explicitly
preserve/reconcile external data mappings only under the existing authority
model; the guide must not imply that reinstall restores workloads.

## 7. Governance and issue classification

The Early Access adoption epic replaces #968 as the release-governance root.
Every former PP requirement is mapped to exactly one current disposition:

- **EA release blocker** — required to admit customer workloads under this profile;
- **Known EA limitation** — behavior intentionally unsupported and documented;
- **Future operational hardening** — valuable operational improvement not required by the bounded initial profile;
- **Future scalability qualification** — additional host-count, soak, capacity or K-min/K-full evidence;
- **Advanced disaster recovery** — backup/restore activation, fencing and workload recovery beyond clean rebuild;
- **Future feature development** — product capability not required for the accepted EA baseline.

Transfer preserves issue implementation, evidence, status, owner, and blocker
relationships. No issue closure changes evidence state. Defects remain open
until fixed; parent PP issues close as superseded with `not_planned` only after
the new epic and traceability matrix are recorded.

## 8. Bounded Early Access acceptance gate

All checks below are mandatory and bind the exact release version, source SHA,
artifact digest, SBOM/provenance/signature identity, installer digest, host,
profile, database and test harness. Evidence must be redacted and replayable.

1. **Release authentication:** verify release signature/provenance/Sigstore, manifest, bundle and each executable; reject changed digest, wrong identity and malformed bundle.
2. **Fresh install:** install on clean Ubuntu 24.04 from the authenticated public artifact without target source compilation.
3. **PostgreSQL:** prove PostgreSQL 16 readiness, least-privilege role, migrations, restart persistence and no unintended cluster/role mutation.
4. **Services:** prove controller, compute service, agent identity and canonical readiness.
5. **Single-host VM lifecycle:** tenant create, boot, connectivity, stop/start/reboot, delete and canonical cleanup.
6. **Three-host placement:** repeat lifecycle and prove placement across three enrolled hypervisors; five-host claim remains deferred until separately qualified.
7. **Networking:** tenant isolation and required east-west/external connectivity; prove teardown and no foreign network mutation.
8. **Storage:** creation, attachment, detachment, deletion, data-path checks and zero owned-resource leaks.
9. **Restart/reconciliation:** controller and compute restarts converge without duplicates or manual signing.
10. **Database outage:** PostgreSQL outage/restart produces bounded failure, resumes safely, and reconciles without state corruption or duplication.
11. **Host lifecycle:** join, drain, remove and replace a host; no unsafe evacuation assumption or foreign-state deletion.
12. **Negative security:** basic IAM project/scope denial, TLS validation, agent identity/fencing, stale/revoked identity rejection and secret redaction.
13. **Cross-profile security:** EA restore/activation rejection; missing/altered/corrupt/copied C1 inputs never admit EA; copied recovery state and unsupported profile transitions reject before mutation; C1 recovery tests still pass.
14. **Authority/leaks:** zero O3K-owned resource leaks and zero foreign-state mutations across success, failure, restart and cleanup scenarios.
15. **Diagnostics/docs:** operator can diagnose failures from redacted diagnostics without source access; docs accurately state profile, limits, security and escalation path.
16. **Rebuild/data protection:** documented, tested clean rebuild; external workload-data protection and recovery limitations explicit; no implication that rebuild restores tenant data.

Any unresolved critical security defect, data corruption, mandatory lifecycle
failure, loss/duplication of canonical identity, provider mutation before
authorization, owned-resource leak, foreign-state mutation, or secret leak is
NO-GO. Tests that cannot run remain `NOT_RUN`; evidence from one host-count or
profile does not establish another.

## 9. Release publication

Release title: **O3K v0.4.1 — Early Access**. The release page, artifact and
docs must distinguish Early Access from GA and full production certification.
Publication requires:

- all §8 evidence passing on the exact signed artifact;
- focused independent technical/security review of the EA/C1 boundary and
  remediation of findings;
- protected PR review and required CI;
- explicit owner GO and protected release workflow;
- immutable v0.4.0 artifact and test-only declaration unchanged.

No customer deployment is authorized before this gate. A missing testbed or
artifact is a blocker, not a waiver.

## 10. Required operator/customer material

Publish an installation guide, supported profile, supported workload types,
known limitations, security model, upgrade and rebuild policy, workload-data
protection requirements, onboarding checklist, issue-reporting process, and
maintainer support process. Include explicit statements that EA has no HA,
automatic evacuation, live migration, enterprise SLA, or general DR.

## 11. Future milestone boundaries

- Scalability qualification: S10, S20, K-min, K-full and any five-host expansion.
- Operational hardening: broader upgrade/rollback, diagnostics, metrics and
  pressure matrices.
- Advanced DR: authenticated backup/restore, restore fencing/activation, PKI
  recovery/rotation, external workload-data coordination.
- Feature tracks after EA baseline: Araf dashboard, Fabric integration,
  Volvisor integration, deployment automation, diagnostics, customer features.

These are not unconditional dependencies of a supported EA release. The owner
may prioritize them without changing the existing profile unless a new
accepted ADR or profile amendment makes them mandatory.
