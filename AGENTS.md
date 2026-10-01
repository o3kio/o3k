# AGENTS.md — mandatory instructions for coding agents

This file is the top-level operating contract for every LLM or automated coding
agent working in O3K Rust.

## Mission

Build O3K as a small, understandable, secure, testable, and extensible
**Cloud Operating System**.

O3K must:

1. preserve selected, evidence-backed OpenStack compatibility;
2. converge on a shared O3K Cloud Kernel instead of reproducing historical
   OpenStack project topology internally;
3. support a native TestLab/cloud and small edge-cloud path;
4. support selected external OpenStack service testbeds;
5. make future first-class O3K services cheaper to build by reusing common IAM,
   authorization, resource ownership, service-registry, operation, audit/event,
   quota/limit, and reconciliation contracts.

Correct end-to-end behavior and honest profile-specific claims matter more than
endpoint count.

"Cloud Operating System" is an architecture/product-direction statement, not a
production-readiness or full-parity claim.

## Authority order

When instructions conflict, use this order:

1. security, licensing, privacy, and clean-implementation rules;
2. accepted ADRs in `docs/adr/`;
3. normative specs in `docs/specs/`;
4. public contracts under `contracts/` and `proto/`;
5. official OpenStack documentation and published specifications for OpenStack
   compatibility questions;
6. public OpenStack client/SDK/Terraform/Tempest behavior;
7. O3K Rust contracts/tests/black-box evidence;
8. public Go O3K as a non-normative secondary reference;
9. issue acceptance criteria;
10. tests;
11. existing implementation.

Do not silently resolve a conflict. Stop, describe it in the issue/PR, and
propose the smallest corrective change.

## Normative source ownership

Read `docs/NORMATIVE_SOURCES.md` before changing architecture, IAM,
authorization, service topology, workflows, compatibility manifests, execution
protocols, product profiles, or deployment claims.

Important authority:

- ADR-0165 — O3K Cloud OS / Cloud Kernel;
- ADR-0166 + SPEC-0020 — O3K IAM / Keystone compatibility;
- ADR-0167 — Kubernetes-native control-plane deployment; PostgreSQL and durable
  work ownership/fencing are required before any Kubernetes HA claim;
- ADR-0163 + SPEC-0024 — deployment/evidence profiles and claims;
- ADR-0160 + SPEC-0025 — topology/dependency/rewrite convergence;
- SPEC-0021 — cross-service workflows/compensation;
- SPEC-0022 — OpenStack compatibility baseline/evidence;
- execution/core architecture contracts.

Summary documents explain intent. They do not redefine normative contracts.

Runtime/release claims require executable evidence even when architecture/specs
are accepted.

## Mandatory reading order

Before editing code, read:

1. `README.md`;
2. `docs/PROJECT_CHARTER.md`;
3. `docs/CLEAN_IMPLEMENTATION.md`;
4. `docs/ARCHITECTURE.md`;
5. `docs/NORMATIVE_SOURCES.md`;
6. `docs/TEST_STRATEGY.md`;
7. the relevant ADR/SPEC/compatibility profile/product profile/execution
   contract;
8. the assigned issue.

For product scope, IAM, topology, provider boundaries, cross-service workflows,
hosted services, or runner changes, also read:

- `docs/adr/ADR-0165-o3k-cloud-operating-system-and-cloud-kernel.md`;
- `docs/adr/ADR-0166-o3k-iam-and-keystone-compatibility-boundary.md`;
- `docs/adr/ADR-0167-kubernetes-native-control-plane-deployment.md`;
- `docs/adr/ADR-0160-service-topology-and-execution-boundaries.md`;
- `docs/adr/ADR-0162-contract-first-staged-runner-validation.md`;
- `docs/adr/ADR-0163-product-profiles-and-deployment-posture.md`;
- `docs/specs/SPEC-0020-keystone-trust-catalog-and-auth-context.md`;
- `docs/specs/SPEC-0021-cross-service-workflows-and-compensation.md`;
- `docs/specs/SPEC-0022-service-api-baseline-and-evidence-gates.md`;
- `docs/specs/SPEC-0023-external-cinder-service-under-test.md` when relevant;
- `docs/specs/SPEC-0024-product-profiles-and-claims.md`;
- `docs/specs/SPEC-0025-rust-rewrite-and-architecture-convergence.md`;
- `compatibility/product-profiles.yaml`;
- `contracts/execution-boundaries.md`;
- `contracts/core-architecture-boundaries.toml`.

ADR-0161 is superseded by ADR-0166 and must not be used as current authority.

## Cloud Kernel invariants

### OpenStack is compatibility, not the internal architecture

Do not make historical OpenStack service names define a new O3K process, crate,
store, or domain boundary without an independent architectural reason.

Conceptually:

```text
Keystone  -> O3K IAM adapter
Glance    -> O3K Image adapter
Nova      -> O3K Compute adapter
Neutron   -> O3K Network adapter
Placement -> O3K Capacity adapter
Cinder    -> O3K Volume adapter
```

Keep OpenStack JSON, headers, microversions, policy names, and error/catalog
shapes at protocol/compatibility edges.

### O3K IAM is canonical

Keystone-compatible authentication/catalog behavior maps into O3K IAM.

All first-class services consume one normalized typed `AuthContext`.

Protected operations should be expressible through:

```text
Principal × Action × Resource × Context -> Allow | Deny
```

A service must not:

- parse Keystone wire credentials as domain state;
- invent a parallel tenant-isolation model;
- treat a syntactically valid token as authorization;
- omit required durable owner/security-scope state;
- authorize after provider mutation;
- reveal cross-tenant existence through idempotency behavior.

### O3K owns O3K resource authority

For O3K-owned resources, the control plane owns:

- public O3K ID;
- resource type;
- owner/security scope;
- desired state;
- operation identity/phase;
- capacity/scheduling;
- compensation/reconciliation;
- provider mapping.

Execution providers own bounded mutation/observation only.

### Existing clouds are not ordinary providers

An external OpenStack cloud, vSphere/vCenter, Proxmox, KubeVirt, or public cloud
may already own scheduling, quotas, policy, resource identity, and lifecycle.

Do not force such a system through a libvirt-like provider abstraction.

A delegated/federated connector requires a separate accepted authority model.

### New first-class services reuse the kernel

A new O3K service should reuse shared:

- IAM/principals;
- authorization;
- ownership;
- service registration;
- quota/limit hooks where selected;
- operations/idempotency/reconciliation;
- audit/event identity;
- standard health/failure identity.

Do not create a parallel cloud framework inside a new service.

## Issue-driven rule

- One issue is the unit of intent.
- One PR should normally close one coherent issue.
- Do not implement untracked features.
- Do not expand scope because a nearby improvement looks easy.
- Missing requirements become an issue/spec amendment.
- An endpoint outside the accepted compatibility profile must not be added
  opportunistically.
- Do not create micro-issues for acceptance criteria already owned by a coherent
  issue.

## Required agent plan

Before code changes, record:

- issue being solved;
- selected deployment/evidence profile;
- canonical O3K service/domain involved;
- OpenStack compatibility adapter involved, if any;
- authority mode: `o3k-implemented`, `external-hosted`, execution provider, or
  explicitly accepted delegated/federated;
- files expected to change;
- contracts/specs affected;
- public reference inputs/pinned revisions/provenance;
- public operations/actions/resources involved;
- database/execution assumptions;
- cross-service dependencies/compensation;
- required evidence tier;
- tests to add first;
- known uncertainties;
- explicit non-goals.

## Product-profile rules

- O3K has one product identity: O3K Cloud OS.
- Do not conflate deployment/evidence profiles.
- External-hosted services retain their own DB/message bus/processes/backend/
  migrations/upgrades/operations.
- Hosting an endpoint does not mean O3K implements it.
- The small edge target is approximately 10–20 hypervisors, not a production
  claim without evidence.
- "Connect to another OpenStack" must be decomposed into explicit trust,
  hosted-service, external-identity, service-consumption, delegation/federation,
  or resource-sharing behavior.
- SQLite is the supported minimal TestLab/portable default.
- PostgreSQL is a production-oriented target until a real adapter/conformance
  suite exists.
- Kubernetes is a first-class control-plane deployment target (ADR-0167):
  Kubernetes APIs do not become Cloud Kernel/domain dependencies; CRDs are not
  the canonical tenant-resource database; pod-local filesystem state is
  non-authoritative; no Kubernetes HA claim before PostgreSQL plus durable
  work-ownership/fencing evidence.
- Approximately 50 MB is a target, not a guarantee.
- Architecture examples of database/Kubernetes/AI/etc. are not support claims.
- The current `v0.2.0-alpha.1` libvirt TestLab gate must not be expanded by
  Cloud Kernel work unless a human-approved release replan explicitly says so.

## Service and process rules

- `o3kd` initially owns Cloud Kernel/service semantics, authorization, desired
  state, scheduling, operations, compensation, and reconciliation.
- `o3k-compute`, `o3k-network`, and `o3k-storage` are execution boundaries, not
  independent sources of public cloud truth.
- Logical/domain/provider separation precedes process separation.
- Do not introduce a daemon because OpenStack has a similarly named service.
- A new daemon requires an accepted ADR covering privilege, identity, protocol,
  failure domain, deployment, restart, and cleanup.
- Never use a display name where a durable principal/scope/service/resource/
  provider ID is required.
- Native Volume/Cinder work does not block the first ephemeral-root guest.
- External Cinder remains external and is not the native O3K storage
  implementation.

## Compatibility-profile rules

- O3K targets operation-level OpenStack profiles, not blanket service parity.
- Every public compatibility operation requires a profile record with service
  ownership, method/path, API version/microversion, auth action/scope, request/
  response/error contract, state transition, dependencies, provider capability,
  tests, and known deviations.
- A route without the required profile record is unsupported even if partial
  implementation exists.
- Compatibility catalogs advertise only implemented/enabled/verified profiles.
- Distinguish upstream reference maximum, O3K advertised range, implemented
  range, and verified range.
- Do not advertise native Volume/Cinder, advanced networking, metadata HTTP,
  PostgreSQL, broad microversions, cross-cloud support, or fixed footprint
  before gates pass.
- Official OpenStack specs/public client behavior remain normative for
  compatibility behavior.
- Compatibility requirements do not override accepted O3K internal architecture
  unless an ADR explicitly changes it.

## Evidence-ladder rules

Work proceeds in this order unless an accepted issue justifies otherwise:

1. ADR/SPEC/contract/profile validation;
2. domain/IAM/store/migration/policy tests;
3. provider/external-service conformance;
4. portable simulated-profile integration;
5. process-level public-client tests;
6. execution component or hosted-service real-host gate;
7. full native/testbed/edge gate;
8. restart/failure matrix;
9. release gate.

Rules:

- protected full-profile runner is a final verifier, not requirements discovery;
- do not modify the full runner to hide a missing contract/portable test;
- fake/skipped/ready/repository-only results are not real-host evidence;
- evidence from one profile is not automatically evidence for another.

## Implementation rules

- Prefer explicit typed domain values over strings/maps.
- Model lifecycle transitions as validated state machines.
- Keep HTTP/OpenStack representations outside the core domain.
- Keep provider/external client types outside the core domain.
- Use one typed `AuthContext`.
- Express protected operations with shared action/resource/ownership semantics.
- Preserve original actor/scope and authenticated service principal for
  cross-service work.
- Persist intent/phase before external side effects where recovery requires it.
- Use deterministic operation/idempotency identity for retriable mutations.
- Define compensation for cross-service mutations.
- Treat timeout as unknown outcome.
- Observe before retrying destructive/duplicating mutations.
- Execution providers must never authorize callers or invent public O3K IDs.
- Avoid `unsafe`; each use requires a dedicated ADR/safety contract/tests/human
  review.
- Avoid global mutable state.
- Never log secrets/tokens/private keys/connection info/user-data/unredacted
  provider payloads.
- Every background task has shutdown/retry/backoff/reconnect/observability
  behavior.
- New dependencies require justification/license/maintenance/minimal features.

## Clean implementation restrictions

Agents must not:

- copy/translate/structurally reproduce non-public source;
- use internal SAP/CobaltCore/NeoNephos/customer/employer material as
  implementation input;
- claim behavior from memory when a public spec/test is available;
- use another implementation's private tests/schemas/migrations/architecture;
- add generated code without committed source contract;
- remove attribution/license notices.

Public OpenStack docs/APIs/SDK behavior/standards and independently written
black-box tests are allowed.

The public Apache-2.0 Go O3K repository may be used only under ADR-0151 as a
non-normative secondary reference. Record exact inspected paths/commit/public
sources.

## Test-first acceptance

A change is incomplete until it has appropriate:

- domain invariant tests;
- IAM/authorization tests where relevant;
- protocol/contract tests;
- provider/external fake/conformance tests;
- compensation/failure tests;
- regression tests;
- process tests;
- component/hosted/full-profile tests required by evidence tier.

Mocks that merely repeat implementation expectations are not evidence.

Do not mock away the exact authority/execution boundary an issue is supposed to
prove.

## Commands required before completion

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Run any additional contract/profile/component/integration commands named by the
issue.

## PR response format

Every agent-authored PR description includes:

- **Issue**
- **Intent**
- **Design**
- **Product/deployment profile**
- **Authority model**
- **OpenStack compatibility impact**
- **Database/footprint**
- **Contracts**
- **Workflow/compensation**
- **Tests**
- **Evidence**
- **Risks**
- **Provenance**
- **Follow-ups**

When public Go O3K is consulted, additionally record exact repository commit,
paths/artifacts inspected, reuse status, and Apache-2.0 attribution handling.

## Definition of done

- acceptance criteria satisfied;
- product profile/authority mode/compatibility profile/evidence tier identified;
- tests fail-before/fix-after when practical;
- formatting/lint/unit/relevant integration tests pass;
- contracts/traceability/docs updated;
- no unrelated change;
- no unexplained TODO/panic/unwrap/ignored production error;
- product/compatibility evidence updated when behavior/claims change;
- no release/database/edge/cross-cloud/future-service/footprint claim exceeds
  evidence;
- reviewer can understand the change without reconstructing agent reasoning.

## Agent Context and Token Efficiency

The mandatory reading and evidence rules above remain authoritative, but agents must avoid turning them into repeated full-repository discovery. Planning may explore broadly enough to establish the correct architecture and normative inputs; execution starts from the bounded plan.

### Search and reading discipline

- Prefer `rg`, `git grep`, targeted directory listings, symbol search, and bounded file reads over recursive `find`, `ls -R`, or broad source dumps.
- Respect `.gitignore` and `.rgignore`. Never search `target/`, generated Tempest workspaces/results, coverage/artifacts, worktrees, caches, or local agent-tool state unless the assigned issue explicitly requires those artifacts.
- Normative ADRs/specs/contracts and compatibility profiles must remain searchable. Read the mandatory sources required by the issue, then carry their relevant constraints into the plan instead of repeatedly reopening every document during execution.
- Do not re-read unchanged files merely to recover context. Re-open the smallest relevant section or inspect `git diff` after edits.
- Do not dump full Cargo/test/Tempest/runner logs into model context. Capture noisy output and inspect the first actionable failures, selected matches, or a bounded tail.
- Run expensive repository-discovery commands such as broad `cargo metadata`, dependency trees, or workspace-wide searches once per planning phase unless the workspace actually changes.

### Planner/executor handoff

The **Required agent plan** must additionally make execution scope explicit:

- affected Cargo package(s) and binaries;
- exact files/symbols expected to change;
- normative documents already consulted and the constraints they impose;
- smallest tests/checks that can falsify the implementation;
- conditions that justify widening scope.

An implementation agent must begin from this handoff. It must not independently rescan all O3K crates, ADRs, specs, and compatibility material when the planning agent has already identified the relevant subset. Expand scope only when code, contract, or test evidence demonstrates that the plan was incomplete.

### Validation ladder

O3K has a large workspace. During implementation, prefer package-level feedback before the mandatory completion gate:

```bash
# Examples; substitute the affected package(s).
cargo check -p <affected-package>
cargo test -p <affected-package> --all-features
cargo clippy -p <affected-package> --all-targets --all-features -- -D warnings
```

For a cross-crate change, validate the smallest affected dependency/consumer set first. Run process, compatibility, provider, Tempest, or real-host evidence only when the issue's evidence tier requires those boundaries.

Before completion, still run every command in **Commands required before completion** plus the issue-specific evidence commands. Context/token efficiency changes the order and repetition of validation; it never relaxes the definition of done, authority order, mandatory reading, clean-implementation rules, or evidence requirements.

## Repository Development Memory (OKF)

O3K keeps repository-local development continuity under `.okf/`. This is an
evidence-routing layer, not a new authority source. It never overrides accepted
ADRs, normative specs, contracts, compatibility profiles, tests, issues, PRs, or
Git history. Read `docs/OKF_MEMORY.md` for the protocol and trust boundaries.

### Consumption

For questions about recent progress, prior development runs, validation commands
already executed, or where a workstream was last observed:

1. read `.okf/index.md`;
2. identify the stable workstream, normally `issue-<number>`;
3. read `.okf/current/workstreams/<workstream>.md` when it exists;
4. follow only the newest relevant immutable run record(s);
5. follow linked issue/PR/ADR/spec/test sources before making semantic claims.

Do not recursively ingest `.okf/`. Do not use an OKF run or projection to claim
that a feature is complete, an architecture is accepted, a blocker is resolved,
or a release/profile gate passed unless the authoritative source and required
executable evidence establish that claim.

### Production

For a substantive issue-driven development session, start deterministic memory
capture before implementation:

```bash
python3 scripts/okf-memory.py start --workstream issue-<number>
```

When practical, run validation commands through the helper so their exit status
is captured without storing noisy stdout/stderr:

```bash
python3 scripts/okf-memory.py exec -- cargo test -p <affected-package> --all-features
```

For long work use `checkpoint` at a meaningful boundary. Before a handoff,
harness/model switch, or session end, run:

```bash
python3 scripts/okf-memory.py end
python3 scripts/okf-memory.py check
```

Generated `Development Run` files under `.okf/workstreams/*/runs/` are
append-only evidence records and must not be hand-edited after commit. Files
under `.okf/current/workstreams/` are deterministic projections and may only be
regenerated with `scripts/okf-memory.py refresh` or by `checkpoint`/`end`.

The helper may observe and transform repository facts; it must not generate
LLM-authored interpretations, next-step plans, completion percentages, root
causes, or architectural summaries as persistent memory.
