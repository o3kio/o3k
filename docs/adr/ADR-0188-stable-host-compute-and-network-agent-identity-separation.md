# ADR-0188 — Stable host, compute-agent, and network-agent identity separation

Status: Accepted
Date: 2026-10-06
Affected-services: compute, network, governance
References: ADR-0186, ADR-0187, ADR-0168, SPEC-0049, contracts/edge-fabric-stretched-l2.md

## Context

Fabric v3 placement and execution cross two independent agent processes. The
compute agent owns VM lifecycle commands; the network agent realizes Fabric
plans. Both processes run on a stable compute host, but they have independent
agent IDs, epochs, transports, restart cycles, and failure modes. Treating a
compute agent ID as a host ID or using its epoch to fence a network command
couples unrelated execution channels and rejects valid deployments where the
IDs differ.

## Decision

The authenticated compute registration's host identity is exposed in the
application registry as the stable `host_id`. It is the join between compute
placement and Fabric host state. Agent identities identify execution
processes only:

```text
stable placement/Fabric identity: host_id
compute execution identity:       compute_agent_id + compute_agent_epoch
network execution identity:       network_agent_id + network_agent_epoch
```

Compute placement remains selected and fenced using the compute agent ID and
epoch. Fabric endpoint binding, Realm participant derivation, transport
identity lookup, and target selection use only the stable `host_id`. Each
participating host resolves independently to one current network-agent control
target containing that host ID, network-agent ID, network-agent epoch, control
endpoint, and TLS server name. Fabric commands carry the network agent's
identity and epoch. Compute commands carry the compute agent's identity and
epoch. The channels meet only through `host_id`.

Missing, malformed, duplicate, disabled, or ambiguous stable-host mappings and
missing network-agent targets fail closed. A draining compute host is not
eligible for new placement; existing Realm reconciliation remains possible
while the compute agent is available and not disabled. Network-agent
availability does not authorize placement evacuation. Fabric transport
identity remains keyed by host ID; any retained legacy agent-ID metadata is
non-authoritative and supplies neither placement nor execution fencing.

Legacy non-Fabric networking retains its existing explicitly configured
compatibility behavior. Fabric v3 does not silently infer that compute and
network agent IDs are equal.

## Consequences

Compute and network agents may be independently restarted or replaced without
rewriting canonical host placement. Network work is fenced against the current
network-agent epoch, and VM work is fenced against the current compute-agent
epoch. Durable Realm plans and provider ownership continue to use stable host
IDs as defined by ADR-0186 and SPEC-0049. The identity separation does not
change the shared `o3kio/fabric` provider contract or claim nested/physical
dataplane acceptance.
