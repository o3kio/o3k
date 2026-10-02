# PP.5 harness / recovery architecture review

## Investigation (2026-09-28)

The current protected workflow (`.github/workflows/real-host-validation.yml`)
has one step named `Run P15.7 scale/composition convergence gate`.  Its
journey script performs the S5 checkpoints, then enters the #1035 crash/orphan
leg and the #1033 maintenance leg, and finally emits one aggregate
`p15-7-scale-composition-evidence.json` artifact.  Consequently a downstream
failure is surfaced by CI as a scale/composition failure even when the S5
checkpoint sequence already passed.

The source journey explicitly records the expected S5 topology sequence before
the crash leg (`initial`, `pre-drain`, `post-drain`, `post-remove`,
`post-replacement`, `post-reboot`).  This is evidence that S5 is a separable
contract, not a prerequisite for the destructive #1035 experiment.

The #1035 focused process artifacts in the working tree show the same
classification problem and the scheduling risk.  Successful artifacts record
the repair task entering only after restart/lifecycle work; failed artifacts
stop at `orphan_seen`.  In production, `drive_all_lifecycle_convergence`
iterates every non-terminal lifecycle operation and acquires an operation lease
for each before invoking the orphan sweep.  The sweep therefore has no
independent discovery scheduling bound: a lifecycle backlog, lease wait, or
provider deadline can delay its first opportunity beyond `cadence + repair
lease TTL`.

## Hypotheses

* **H1 — confirmed by code/evidence.**  The S5 topology assertions are emitted
  and validated before the #1035/#1033 legs.  The reported red result is not a
  reliable assertion that S5 itself failed; the later resilience legs can be
  the failing phase.
* **H2 — confirmed by code.**  Orphan repair is currently called at the end of
  general lifecycle convergence.  Its scheduling is therefore coupled to the
  lifecycle backlog and cannot honestly claim an independent periodic bound.
* **H3 — confirmed by workflow/artifact naming.**  The protected step and
  aggregate artifact use `scale/composition` for all three contracts, so a
  #1035 or #1033 failure is classified as a scale failure.

## Decision

The repair algorithm remains owned by `ComputeService`, its durable
`server-endpoint-orphan-repair` lease, `orphan_repair_lock`, and the existing
`PortBindingProjector`.  Only scheduling is separated into a dedicated periodic
task.  The lifecycle convergence driver no longer invokes the repair sweep.
The dedicated task reports tick, lease, scan, ownership/fence, unbind, and
release outcomes as structured fields.  S5, #1035, and #1033 receive distinct
protected result artifacts; the integrated campaign still requires all three
to pass.

The repair bound is stated as separate terms: discovery cadence, stale-lease
takeover, and provider unbind/release deadlines.  No timeout is increased to
mask a missing scheduling guarantee.  The production task uses a five-second
discovery cadence and the existing sixty-second durable lease TTL; a provider
unbind is still bounded by the existing per-dispatch deadline and the release
call is observed separately.  Thus the claim is:

```text
control plane ready
  -> next repair tick <= 5s
  -> stale lease takeover <= 60s (when a prior owner is live/expired)
  -> pre-mutation checkpoint
  -> unbind deadline
  -> release deadline
```

These terms are not collapsed into `cadence + TTL`, and the protected result
artifacts preserve the distinction between a missing tick, a busy lease, an
unresolved ownership fence, and a failed provider call.

The focused protected lanes are `tests/pp5_s5_scale.sh`,
`tests/pp5_1035_crash_recovery.sh`, and `tests/pp5_host_maintenance.sh`; the
crash and maintenance lanes require runner-provided real-host commands rather
than silently falling back to SQLite or a fake provider.  The integrated workflow remains the certification path and writes
`pp5-s5-scale-result.json`, `pp5-1035-crash-recovery-result.json`,
`pp5-host-maintenance-result.json`, and `pp5-overall-result.json`.

## PR #1046 scope decision

**DO NOT SPLIT CURRENT PR.** The exact-head diff contains the #1035 product
fix, PostgreSQL/runner qualification, destructive cleanup, S5 provisioning,
crash evidence state, and host-maintenance harness as a dependency chain. A
mechanical split would either duplicate the product fix or make protected
evidence refer to different SHAs during rebases. No new unrelated feature
should enter #1046; any future split should start after this exact-head gate
with stacks ordered as product correctness, evidence infrastructure, S5
lifecycle, and destructive maintenance.
