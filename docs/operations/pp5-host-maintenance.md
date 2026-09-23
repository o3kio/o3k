# PP.5 Small Edge planned host maintenance

Status: accepted operational contract for the `o3k-small-edge-v1` profile
(issue #1033). This document states what O3K supports for **planned** host
maintenance. It is an operations contract, not a resilience claim.

## Scope

Applies to the bounded single-site Small Edge profile (1–20 hypervisors,
SPEC-0048). It covers a **planned** reboot or maintenance window on a
hypervisor that is already enrolled as a BuildingBlock.

It does not cover unplanned host loss. That is issue #1038.

## What O3K does and does not provide

Provided:

- drain of a BuildingBlock, with new placements rejected on the draining block;
- an honest blocker report for resident workloads, local storage and
  attachments;
- canonical identity that survives the maintenance window;
- reconciliation of the same canonical objects after the host returns.

**Not** provided, and not claimed:

- HA or an availability SLA;
- live migration;
- automatic evacuation of resident workloads;
- survival of tenant workloads across an unplanned hypervisor reboot.

O3K does not move tenant workloads during a drain. It reports them. The
operator resolves them.

## The supported sequence

```text
Ready
  -> Draining                  (operator action on the BuildingBlock)
  -> reject new placement      (Placement must not select the draining provider)
  -> expose resident blockers  (workload / local storage / attachment counts)
  -> operator explicitly resolves each blocker
       (stop or delete the workload, detach or delete the storage)
     -- or --
     operator explicitly accepts downtime for the remainder
  -> host reboot / maintenance
  -> host returns
  -> reconcile the same canonical identity
```

Each step is an operator decision. There is no step in which O3K decides on its
own to destroy, move or discard a tenant workload.

### Why the blocker step is not optional

Because PP.5 claims no evacuation, a drain that reported "no blockers" while
resident workloads still existed would be a false statement about the state of
the site. The blocker projection exists so the operator sees what is actually
still running on the block before taking the host down. See
`bins/o3kd/src/native_adapters/building_block.rs::derived_blockers`.

### Identity that must survive

After the host returns, these must be the same canonical objects as before, not
new ones:

- node / agent identity;
- BuildingBlock identity;
- ResourceProvider identity;
- the resources placed on the provider.

A maintenance window must not mint a duplicate provider, block or agent.

## Installer behaviour

The O3K installer and packaging **must not** silently rewrite host-global
distro shutdown policy (for example `libvirt-guests` `ON_SHUTDOWN` /
`ON_BOOT` behaviour, or `on_shutdown` in `/etc/libvirt/libvirtd.conf`).

Reason: that policy is host-global and affects every guest on the hypervisor,
including ones O3K does not own. Changing it as a side effect of installing O3K
would be an unreviewed, site-wide change to foreign state.

Verified: no O3K install, packaging or service unit mutates that policy
(`packaging/`, `deployments/`, `scripts/` contain no `libvirt-guests` or
`ON_SHUTDOWN` write). Host shutdown posture is therefore operator-owned.

Operators who want a different host shutdown posture set it themselves and own
the consequences for the guests they run.

## TestLab bounded force-shutdown (harness only, never a product path)

The disposable nested TestLab uses deliberately minimal guest images (for
example CirrOS) that ignore the ACPI power button. Waiting on the stock
`libvirt-guests` shutdown path there would hang the harness indefinitely.

The disposable harness may therefore use a bounded sequence:

```text
bounded ACPI shutdown wait
  -> force-destroy the remaining minimal test guests
```

Implemented in `tests/pp4-core-campaign/host-run.sh` (and the equivalent PP.5
campaign harness): issue `shutdown`, poll for a bounded number of attempts,
then `destroy` whatever is still running, and capture the domain list as
evidence.

This is a **test-environment anti-hang control**. It is explicitly *not*:

- evidence of workload HA;
- evidence of graceful production evacuation;
- a production behaviour that any O3K service performs;
- a claim that a tenant workload survives a hypervisor reboot.

Production semantics and the TestLab force mechanism are different things and
must never be presented as the same behaviour in evidence.

## S5 verification

The contract is verified by the S5 maintenance journey, which must prove:

1. workloads are placed on more than one child hypervisor;
2. one BuildingBlock is marked `Draining`;
3. no new placement lands on the draining block;
4. resident workloads appear as blockers;
5. the operator explicitly resolves those workloads;
6. the child hypervisor reboots;
7. O3K reconciles after it returns;
8. node/agent, BuildingBlock and ResourceProvider identities are unchanged;
9. no duplicate canonical objects exist;
10. foreign libvirt state is unchanged.

Until that journey passes, host reboot is not used as a PP.5 acceptance signal.

## Non-goals

- No HA, SLA, live migration or automatic evacuation claim.
- No multi-region, cell or sharding behaviour.
- No claim that tenant workloads survive an unplanned hypervisor reboot
  (issue #1038 owns that analysis).
