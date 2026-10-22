# #1084 owned writer review

Scope: PR #1167, based on protected source
`eade817ba9797765ff35e7a85e05e1e27d486afd`. This is the SQLite portable/TestLab
owned-writer prerequisite, not authenticated controller handoff or issue closure.
Authority remains the existing o3kd composition and coordination repository;
there is no OpenStack compatibility change or new provider authority.

## Review correction plan

Affected packages: o3kd, o3k-compute-agent, o3k-store, o3k-storage. Review the composition
shutdown, network guards/registry, storage fence/attempt, NodeRegistry child
tasks, and SQLite connection workers. The consulted ADR-0189, SPEC-0050 and
ADR-0190 require fail-closed bounded drain, continuous lifetime exclusion, and
preservation of unresolved Operation identities. No new decisions or public
commands are introduced. Inputs are this repository and pinned SQLx 0.8.6
source; no Go implementation or private source was consulted.

Small falsifiers: cancel drain while renewal is pending; repeat a failed drain;
cancel initial storage acquisition; fail a child task; cancel an open SQLite
transaction; attempt registration or SQL after terminal drain. Widen scope only
when a child writer or cancellation path escapes those owners. Required
evidence includes unit/failure tests, the normal parallel package suites,
workspace gates and real daemon shutdown tests. External provider outcomes
remain unresolved and require observation; tests do not prove transfer.

## Findings and corrections

- HIGH: cancellation of shutdown released the lifetime lock. An RAII retention
  guard now preserves it and the storage fence until process exit on every
  unsuccessful path, including cancellation. Unexpected Composition drop
  requests task cancellation and retains the lock. Startup errors retain the
  lock until exit rather than exposing partially started workers.
- HIGH: cancelled network cleanup removed pending releases and a later drain
  could succeed. Drain failure/cancellation is sticky and drain calls serialize.
- HIGH: network acquisition remained open behind drain. Admission closes before
  drain; acquisition reservations count live owners, and cancelled unknown
  acquisition poisons the verdict. Successful explicit close retires admission.
- HIGH: compute drain removed join handles before awaiting them. Handles now
  remain in shared registry slots; failed/cancelled drain cannot later succeed.
- HIGH: storage acquisition was unrecorded until after its database call and
  ignored cleanup failures. The execution lock and pending acquisition are now
  recorded before that call. Unknown acquisition retains exclusion and blocks
  drain. Unexpected attempt drop cannot unlock unresolved work.
- MEDIUM: failed joins could be polled a second time. Completed failed handles
  are consumed and their failure remains represented in the owning lifecycle.
- MEDIUM: network join mutex acquisition was unbounded. It shares the terminal
  deadline now. Completed registry entries are reaped during registration.
- HIGH: cancellation of the local LVM runner detached its subprocess. Each
  submitted command is now registered before its caller awaits a result. The
  composition closes command admission and joins commands before ending the
  storage fence. A cancelled caller cannot detach provider mutation from this
  proof. A missed deadline is sticky and retains composition/execution locks.
- HIGH: task cancellation did not prove SQLite connection-worker termination.
  The final store boundary closes shared pool admission and waits for SQLx
  worker shutdown/rollback after controller-session drain. Unsupported store
  adapters reject this proof; this supplies no PostgreSQL exclusion claim.

## Writer inventory and disposition

| Owner | Writers | Disposition at successful boundary |
| --- | --- | --- |
| API admission | HTTP/native/compatibility mutations, audit and Operation writes | Admission excluded and active handlers drained before composition shutdown |
| Composition | Controller heartbeat, event and console consumers, attachment/create/lifecycle/orphan reconciliation | All handles cancelled and joined; errors/timeouts reject proof |
| Composition optional workers | Fabric recovery, inventory publishing, composition/native-storage recovery, control server, inspect and diagnostics probes, external Cinder probes | All enabled handles included in the same join set |
| NodeRegistry | Control-stream processors, stream lease renewal, heartbeat monitor, event projection, artifact-transfer recovery | Child handles retained, registration closed, bounded join checked |
| Network guards | Agent-control and Realm lease renewal and final relinquishment | Admission reservations, joined renewals, awaited close or tracked Drop queue; failure is sticky |
| Storage fence | Initial acquisition, assert_current, periodic renewal, release | Shared attempt serialization; execution lock retained until confirmed release; renewal joined |
| Local LVM runner | Child processes submitted by storage workflows or readiness | Owned command handles joined without abort before the execution fence is released; admission closed |
| Inline remote providers/adapters | Agent/CellHV/network/Cinder dispatch and result persistence | Owned request/worker futures stopped; unknown remote outcomes remain durable for observe-before-retry |
| SQLite store | Submitted statements, connection-return rollback and worker threads | Shared pool closed and connection workers drained before proof |
| Configuration/trust | Startup topology/configuration convergence, bootstrap/trust/config-drive mutation | Startup retains lifetime lock; runtime mutations belong to admitted handlers or owned workflows |

Direct libvirt is rejected by the o3kd configuration contract. Its blocking FFI
workers therefore belong to the separate execution component, not this
controller. Ceph runners are also not instantiated by this composition. Remote
execution cannot write the canonical controller database; unresolved provider
outcomes retain their durable recovery state.

A top-level join alone is not used as connection-worker evidence. The database
pool closes only after all lease cleanup and controller-session writes. A failed
boundary may leave work unresolved but retains exclusion and cannot produce a
proof. No new durable lifecycle authority is introduced.

## Regression evidence

The cancellation regression was run with the cancellation verdict guard
removed: `cancelled_network_drain_cannot_later_report_success` failed because a
second drain incorrectly succeeded. The guard was restored before validation.

Controlled coordination adapters wrap real disposable SQLite coordination:

- Drop during blocked relinquishment and quiescence during an actual renewal.
- Cancel Realm cleanup, then drain its registered fallback.
- Force durable relinquishment failure and reject the drain.
- Stop storage while renewal is in flight; serialize assert_current with end.
- Unknown release/inspection retains execution protection.
- Cancel initial acquisition and fail a renewal task; repeated end cannot
  unlock or repoll a consumed join handle.
- Reject new lease writers after admission closes; successful writer counters
  reach zero and remain zero through repeated drain/rejected admission.
- Preserve a durable UnknownOutcome Operation without an executor; reject a
  Running Operation whose blocking executor refuses cancellation.
- Cancel during controller-session drain and retain the lifetime lock.
- Cancel an LVM caller while its real subprocess is blocked on a Unix socket;
  command drain waits for completion. Deadline failure remains a failure after
  the child exits, and late commands are rejected.
- Cancel a worker inside an actual SQLite transaction; terminal pool drain
  completes rollback and rejects subsequent source writes.

The configured real-process regression enables Fabric recovery and native
storage recovery against disposable SQLite, verifies both enabled-worker flags
in the successful structured drain verdict, and rejects a competing canonical
controller before store startup. Host LVM commands are excluded with a child-only
empty PATH, no tenant/provider mutations are requested, and no remote agent is
contacted. This proves configured worker shutdown, not real LVM/Fabric provider
execution or authenticated descriptor transfer. The other process tests cover
SIGINT/SIGTERM, restart and startup failure.

## Validation

Review corrections passed `cargo fmt --all -- --check`, `git diff --check`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`, and
`cargo test --workspace --all-features` with normal test parallelism: 2,017
passed, zero failed, 57 ignored across 142 test binaries/doc-test groups.
Ignored environment-specific tests are not evidence for those profiles. The
five o3kd real-process shutdown tests passed in that workspace run. The final
test-only correction orders store reopening after proof release and ownership
reacquisition; its targeted regression and workspace Clippy also passed.

The last review pass found no further actionable defect in this PR's scoped
writer ownership/drain paths. This is an agent review result, not a replacement
for the required human exact-head review or protected integration.

## Integration limits

Human exact-head approval, protected checks and protected merge/main
verification remain required. The approval on `bd363d73d3482b75ff99cca43f1dfb9cb83e0687`
predates these review corrections. Authenticated handoff is the next separate
PR after this prerequisite merges. No handoff, PostgreSQL exclusion, #1084
completion, PP.7 or PR #1081 claim is made here.
