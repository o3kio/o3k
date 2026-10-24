# PP.6 PR A — fresh-host preflight (#1085 / #1086 / #975)

Protected base: `b50f537557bcc313a3663900b90572bd7b6f98f4` (PRs #1167–#1171
inspected; writer drain, authenticated descriptor handoff, authenticated artifact,
SQLite conformance and PostgreSQL capture are present). All owning issues stay
open. The accepted technical revision remains
`9ce23ff81218e8e35d917ef6ee4478ae69e8f28e`. Proposed conformance amendments
remain proposed.

Profile: `o3k-small-edge-v1`, PostgreSQL 16; SQLite Demo/TestLab is separately
bounded. Domain: Cloud Kernel recovery/installation, `o3k-implemented` authority;
no OpenStack adapter or public API changes. Public action is only the accepted
host-local `o3k restore preflight --artifact ABSOLUTE_FILE --target EMPTY_TARGET`.

Affected packages/binaries: `o3k` operator CLI. Expected files: new
`restore_preflight.rs`, `restore_pg_validation.rs`, contained catalog SQL and
supporting tests; `lib.rs` / `main.rs` module and command registration. Existing
artifact verification, canonical inventory, release reader, store-access lock
and capacity primitives are reused. No backup format, canonical state, provider
contract, daemon, migration or controller-store lock is introduced.

Consulted authorities: README, PROJECT_CHARTER, CLEAN_IMPLEMENTATION,
ARCHITECTURE, NORMATIVE_SOURCES, TEST_STRATEGY; ADR-0160/0162/0163/0165/0166/0167,
SPEC-0020/0021/0022/0024/0025, product profiles and execution/core architecture
contracts; ADR-0189/0190, SPEC-0050 and PP6_TECHNICAL_CONTRACT_APPROVAL D10/D12.
They require canonical whole-store state, no provider execution, exact migration
checksums, isolated unprivileged executable-definition validation before selected
target mutation, root-owned recovery configuration, and inactive recovery until
separate fencing/PKI gates. No accepted decision is reopened.

Implementation policy: pre-provisioned root-configured empty target and private
local-ext4 recovery directory; target directory is opened without following any
component and held using the existing directory-flock startup exclusion. A
procedural recovery-directory reservation is separate and creates no tenant
state. Preflight writes only disposable private staging outside the target and
removes it before success. Target PostgreSQL checks are read-only, after isolated
D10. Expected migrations come from compiled exact release migrations, never a
source/live database or the artifact. Root-owned configuration binds target,
backend, pinned validator image and selected database; no passwords/keys in argv,
environment or logs. The installed trust document supplies recovery key handles.

Evidence ladder: contract checks, failure-first path/config/policy and process
regressions, real disposable PostgreSQL 16 isolated validation with altered
executable definitions, signed-artifact preflight and unchanged-target evidence,
then workspace formatting, Clippy and normal parallel tests. Smallest falsifiers:
relative/symlink/foreign/nonempty target, signed altered function/default/trigger,
ACL, extension/schema/table drift, migration loss, wrong PG major and concurrent
reservation. Validate separately migrated catalog definitions and migration rows.

Uncertainties: available isolated runtime/cgroup enforcement, exact-release
installed provenance, production Option B signer trust transport/schema and real
HSM custody; independent database-host ingress authority and BMC/PKI are later
work. Widen scope only for a demonstrated contract/test defect. Missing authorities
are reported, never replaced by fixture evidence.

Non-goals: restore mutation/journal/resume (PR B, after protected PR A merge),
activation, PP.5 deferred campaigns, scale/soak, PP.7, new backup format, new
controller lock, software-key-as-HSM evidence, immutable release retagging.
Provenance: repository accepted contracts and PostgreSQL 16 public documentation;
no public Go or private implementation consulted.

Execution findings: PostgreSQL dump/reparse changes some CHECK-cast parse trees;
reference descriptors therefore come from a trusted PG16 dump/reparse of the
separately migrated baseline. Exact descriptor equality is retained. An
untrusted short TOC record could panic the existing parser; bounded guards and
a regression belong to this D10 boundary. The selected PG target is provisioned
by the operator and inspected only in a read-only transaction. No SQLite
preflight success is exposed by this PG16-first slice.

Supplemental non-independent security review found no confirmed critical/high
flaw after the containment, root-ancestor, no-follow and cleanup controls. It
is not senolcolak's required final-exact-head approval. The process lane uses a
privileged recovery orchestrator container and an ext4 named volume; D10 child
containers receive neither its Docker socket nor its target identity. This is
not independent-machine, installed-release or HSM evidence.
