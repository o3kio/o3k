# ADR-0191 — Owner-directed Early Access adoption and installation trust

Affected-services: cloud-kernel, iam, compute, network, storage, installer, operations, governance

Status: Accepted — owner-directed decision; implementation, independent security review and release evidence remain gated  
Date: 2026-11-25  
Human decision: O3K project owner, explicit decision supplied 2026-11-25  
Supersedes: PP.5/PP.6/PP.7 as mandatory release prerequisites for the Early Access objective; supersedes only the C1 fresh-install requirement where this ADR explicitly defines the EA profile  
Amends: ADR-0163, ADR-0189, ADR-0190, SPEC-0024, SPEC-0050  
Related: ADR-0165, ADR-0166, ADR-0167, ADR-0160, ADR-0162, SPEC-0020, SPEC-0021, SPEC-0022, SPEC-0024, SPEC-0025

## Context

The project owner has changed the immediate objective from comprehensive
production-readiness certification to a usable, bounded O3K Core baseline for
selected early adopters, development and test workloads, and replaceable
non-critical semi-production workloads. PP.5, PP.6 and PP.7 requirements are
not the mandatory release gate for this objective. This roadmap change does
not imply that unexecuted evidence passed.

The current installed-release C1 ceremony requires project-centralized
installation-policy signing and offline custodians before ordinary fresh
installation. That is a recovery trust requirement being applied to the
ordinary install path. It prevents the project from distributing a practical
Early Access install while adding no recovery qualification to an EA profile
that explicitly does not support restore activation.

## Decision

### 1. Product objective and bounded profile

O3K remains one Cloud Operating System with the existing Cloud Kernel and
canonical service/resource authority. Establish the `o3k-early-access-v1`
deployment/evidence profile:

- Ubuntu 24.04 LTS x86_64;
- one active controller;
- PostgreSQL 16;
- KVM/libvirt;
- one to three hypervisors initially; five only after evidence and a separate
  owner claim decision;
- native O3K CLI and API plus only the already advertised compatibility
  operations;
- normal supported compute, storage, networking, IAM, and resource lifecycle;
- operator-managed infrastructure;
- selected development, test, and replaceable non-critical customer workloads.

The profile makes no HA, automatic evacuation, live migration, enterprise SLA,
general disaster-recovery, broad OpenStack parity, or production certification
claim. Customer deployment is prohibited until the bounded acceptance gate in
SPEC-0052 passes.

### 2. Keep authority and topology unchanged

Use existing IAM/AuthContext, ownership, service registry, Operations,
Placement, topology, BuildingBlock, provider, reconciliation, audit, and
compensation contracts. `o3kd` remains the cloud authority. Agents remain
bounded execution components. No new service, store, scheduler, or parallel
canonical state is introduced. PostgreSQL is an explicit selected EA backend;
this ADR does not imply PostgreSQL HA support.

### 3. Select installation security explicitly

Release metadata must declare exactly one immutable installation security
profile and authority model, authenticated by the release verification path:

- `early-access-v1` + `installation-local`; or
- `recovery-qualified-v1` + existing C1 project-policy authority.

There is no implicit mode and no automatic conversion. The authenticated
release manifest, a root-owned installation identity record, and durable
state must agree on profile, authority, backend, canonical installation/site
identity, release identity, and paths. Unknown, missing, duplicated,
conflicting, copied, or corrupt state fails closed before API readiness,
reconciliation, or provider mutation.

For an explicitly selected EA fresh install, the installer creates
installation-local trust and a canonical random installation/site identity
under the existing ownership and safe-publication rules. The trust material is
root-owned and mode-restricted; it is bound to the authenticated EA release
manifest and local profile record. It is not a project-maintainer key and is
not a replacement for Sigstore, SBOM, provenance, TLS, IAM, or agent identity.
The exact key format, directory binding, permission model, and recovery-denial
checks are specified by SPEC-0052 and must pass focused independent security
review before release promotion.

The ordinary EA install must not require a project-maintainer private key,
offline signing workstation, or two-of-three project custodians. The installer
never chooses EA because C1 files are absent, never has a generic
security-disable flag, and never uses an environment-variable bypass.

### 4. Preserve C1 and prevent profile downgrade

The existing C1 implementation remains the only authority for
recovery-qualified installations. Its existing signed policy/state/trust,
journal, ownership, concurrency, restore designation and activation behavior
must remain intact. v0.4.0 remains immutable, test-use-only, and pinned to its
existing C1 authority.

EA admission is permitted only for a demonstrably fresh target. Any observed
C1 manifest authority, policy/state/trust artifact (including malformed or
partial state), recovery directory/journal, existing installation identity,
existing O3K data root, or ambiguous nonempty installation footprint blocks EA
admission. Modifying, removing, corrupting, copying or failing to read C1 state
does not select EA. C1-to-EA, EA-to-C1 in-place, and recovery-target-to-fresh
transitions are unsupported and fail closed. An operator may rebuild a host
only through the documented destructive/rebuild boundary after preserving
external workload data; that procedure does not claim to recover it.

EA does not support advanced restore designation, restore activation,
recovery journal transitions, re-anchoring, or any command/path that grants
recovery mutation authority. Those operations return explicit unsupported
profile errors before target mutation. EA recovery activation and copied-state
cross-profile tests are release blockers.

### 5. Early Access adoption gate replaces PP release dependency

The new Early Access adoption epic and SPEC-0052 own the release gate. Work
from #974/#975 is reclassified and transferred without erasing implementation
or evidence. PP parent issues #968, #974, #975 and #976 may be closed only as
superseded after the new epic/spec and full parent/child traceability are
recorded. Their closure is not certification; unexecuted tests remain
NOT_RUN/PENDING, and unresolved defects remain open in the new or follow-up
issues.

The minimum EA gate is the sixteen checks enumerated in SPEC-0052: authenticated
artifact integrity; fresh Ubuntu install; PostgreSQL 16 readiness; service
health; single-host lifecycle; three-host lifecycle/placement; network
connectivity; storage lifecycle; restart/reconciliation; PostgreSQL outage and
restart; host join/drain/remove/replace; IAM/TLS/agent negative tests; EA
recovery denial and cross-profile tests; zero owned-resource leaks and zero
foreign-state mutations; redacted diagnostics/operator documentation; and a
tested clean rebuild plus external workload-data protection guidance.

Any unresolved critical security defect, data corruption, failure of a
mandatory lifecycle scenario, violation of canonical resource ownership, leak,
or foreign-state mutation is NO-GO. S10, S20, K-min, K-full and comprehensive
disaster-recovery certification are future milestones, not hidden PASS results.

### 6. Approval and release governance

- The project owner sets roadmap, priorities, scope, and release maturity.
- Routine code changes use protected PR review and required CI; this ADR does
  not alter branch protection or required checks.
- Architecture changes require an explicit accepted ADR.
- Security architecture changes require focused independent technical/security
  review. Agent and automated findings are useful input but do not count as an
  independent human review.
- Release publication requires a passing SPEC-0052 evidence gate and explicit
  owner GO through the protected release workflow.
- ADR-0190's interim PP.6 single-maintainer substitution does not apply to the
  EA security review and cannot be used to claim independent review.

### 7. Release and ecosystem direction

Target `v0.4.1` subject to versioning conventions and protected release
workflow. The title is **O3K v0.4.1 — Early Access**. It must distinguish EA
availability from general availability and full production certification.
Do not retag or replace v0.4.0.

Once the EA baseline passes, Araf planning may depend on the accepted EA API
baseline rather than PP.7. Separate follow-up tracks cover Araf dashboard,
Fabric, Volvisor, customer deployment automation, diagnostics, recovery and
scalability hardening, and customer-driven features. Advanced future work must
not become an unconditional dependency of an already supported EA release.

## Consequences

- Adoption and real-world feedback become the near-term product objective;
  comprehensive certification is decomposed into later profiles and
  milestones.
- An explicit profile and trust mode become part of authenticated release and
  installation identity. This is security-sensitive and requires independent
  review before a public EA artifact.
- Existing C1 installations retain their recovery authority and cannot be
  silently reclassified.
- An EA install is not a recovery-qualified installation. Operators must
  protect guest disks and external storage independently and must use the
  documented clean rebuild process when controller state is lost.
- This ADR changes governance and claims, not test results. All unexecuted
  evidence remains outstanding.

## Acceptance record

The project owner supplied this explicit roadmap, profile, C1 separation,
approval model, acceptance-gate, and release-direction decision on
2026-11-25. Acceptance is not independent security review or release approval.
Implementation conformance, independent review findings, protected CI, exact
artifact evidence, and release GO remain separate gates.
