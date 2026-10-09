# Fabric v3 validation status and authorized deferral

Status record date: 2026-10-09

## Source identities

```text
product code candidate: 1c2d20f6618ea0549428285641865788e7416662
product tree:           6667b03cae6f218aad16d141b3037ff4cccd39c0
harness:                1c3196824aba88fab943868ea48ffccd4917672f
harness tree:           ef46b3d4ef7ed79cbaebe29dfe30ec219e993d7d
```

The product candidate and harness remain unchanged by this status policy.
The executable campaign remains available at
`tests/fabric-v3-o3k-three-host-campaign.sh`. No guest was provisioned for
this policy update, and no libvirt network or host networking was changed.

## Current acceptance states

| Evidence | State | Meaning |
|---|---|---|
| Product unit/integration validation | `PASS` | Projection, lifecycle, and workspace validation passed on the product candidate. |
| SQLite lifecycle validation | `PASS` | Supported HTTP retirement/read-back regression passed using SQLite. |
| PostgreSQL lifecycle validation | `PASS` | The same lifecycle passed using PostgreSQL. |
| Real-host/nested departure microgate | `DEFERRED_BY_POLICY` | No new campaign is authorized now. This is neither a pass nor a failure. |
| Physical three-host Gate B | `DEFERRED_BY_POLICY` | Physical certification is not performed or claimed. |

The authorized deferral means lack of physical evidence does not block
automated product review or evaluation of PR #1057. It does not turn the
physical gate green, satisfy Gate B, or authorize a physical-certification
claim. The nested microgate and physical Gate B are evaluated independently:
either `FAIL` or `NOT_RUN` blocks review; an explicitly authorized
`DEFERRED_BY_POLICY` state is non-blocking but never satisfies a physical
certification predicate. PR #1058 may carry the harness changes without a
real-host pass.

The management-address preflight attempts remain historical
`ENVIRONMENT_GAP` evidence. They are not product failures and are not
reinterpreted as successful acceptance. The preserved archives are:

| Archive | SHA-256 | Historical result |
|---|---|---|
| `/var/tmp/fabric-v3-minimal-three-host-20261009T134000Z-portstatus-micro.tar.gz` | `2724cfac969b4c9a44e674394581bf961785d004fbf42a301b1c9878a28fd497` | Environment preflight did not permit campaign provisioning. |
| `/var/tmp/fabric-v3-minimal-three-host-20261009T134500Z-portstatus-micro.tar.gz` | `7fc114dfd4c446a64329a7f14f2e5469953a6e9d6f3788b6f9e70aa5fce8bd74` | Runner reported fewer than three unused addresses in `192.168.122.201-239`; no campaign guest was provisioned. |
| `/var/tmp/fabric-v3-minimal-three-host-20261009T135500Z-portstatus-micro2.tar.gz` | `00834c79f66317e11b36cfe9f0e6d4cd57fdfc69366b35b2c3432d8da1b46cbb` | Runner reported fewer than three unused addresses in `192.168.122.201-239`; no campaign guest was provisioned. |

## Gate policy

The acceptance evaluator uses four distinct states:

```text
PASS
FAIL
DEFERRED_BY_POLICY
NOT_RUN
```

Only `PASS` satisfies an evidence predicate. `DEFERRED_BY_POLICY` is
non-blocking for the explicitly authorized current product-review decision,
but remains visible as deferred and cannot satisfy a physical certification
requirement. An unapproved deferral is invalid. A `FAIL` is never converted
into a deferral, and `NOT_RUN` remains not run.

Current decision:

```text
NEUTRON PORT STATUS PROJECTION: PASS
AUTOMATED PRODUCT VALIDATION: PASS
SQLITE: PASS
POSTGRESQL: PASS
REAL-HOST MICROGATE: DEFERRED_BY_POLICY
FABRIC PHYSICAL ACCEPTANCE: DEFERRED_BY_POLICY
MERGE BLOCKED BY PHYSICAL VALIDATION: NO
FINAL PHYSICAL CERTIFICATION CLAIMED: NO
```

Other required CI and review checks remain governed by the normal PR process;
this policy changes only whether physical validation blocks the current review.
At this status snapshot PR #1057's `rust` job is not green because
`Maintainability architecture guardrails` failed; the other reported jobs
passed. The guard findings were previously reproduced on both the product base
and successor, so this is a separate inherited-baseline issue. Accordingly,
physical validation does not block review, but the PR is not represented as
merge-ready while required CI is failing. The guard itself is not weakened by
this policy change.

## Follow-up

Run the preserved Fabric v3 real-host/physical acceptance campaign before the
release milestone that requires physical Fabric certification. Do not claim
Gate A, physical Gate B, or PP.5 physical certification until their complete
required evidence passes.
