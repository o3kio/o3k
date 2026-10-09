# ADR-0187 — Fabric-owned TAP attachment to compute guests

Status: Accepted
Date: 2026-10-06
Supersedes: ADR-0057 for the TAP ownership and MAC identity at the libvirt boundary
Affected-services: compute, network, governance

## Context

ADR-0057 established that libvirt may consume an already-created O3K TAP. The
original boundary assumed one TAP owner and one MAC identity. Fabric v3 creates
per-Realm TAPs, owns their lifetime, and assigns a provider-local TAP MAC that
is intentionally distinct from the endpoint's canonical guest MAC. The legacy
`HostNetworkManager` also has its own durable ownership manifest and single
managed bridge. Copying Fabric ownership into that manifest, or asking it to
validate a per-Realm bridge, would create competing ownership authorities.

## Decision

Fabric remains the sole creator, mutator, and remover of Fabric endpoint TAPs.
Compute never adopts, repairs, renames, re-bridges, or deletes those TAPs.

For external/Fabric networking, compute requires an explicitly configured,
read-only Fabric attachment resolver. It reads the same provider state root as
the local network agent and, for every attachment, requires all of:

- exactly one current persisted Fabric plan containing the endpoint on the
  configured stable local host, with matching canonical guest MAC and current
  plan generations;
- committed endpoint TAP ownership in Fabric's durable provider state (a
  pending ownership record is not attachable);
- live kernel evidence that the recorded interface is a TAP with the recorded
  provider TAP MAC and is attached to the current Realm bridge.

The resulting bounded attachment evidence separates `tap_mac` from
`guest_mac`. Libvirt targets the Fabric TAP while emitting the canonical guest
MAC in the guest interface XML. A missing or stale plan, ownership record, or
kernel link holds back create/restore; compute does not fall back to
`HostNetworkManager` in external mode. Startup restoration re-reads the
successful create attachment identity from the compute agent's durable command
journal and re-attests each live Fabric TAP before starting a domain.

External mode requires `O3K_COMPUTE_FABRIC_STATE_ROOT` to name the shared
provider state root, `O3K_COMPUTE_FABRIC_HOST_ID` to name the canonical local
Fabric host, and `O3K_COMPUTE_NETWORK_EXTERNAL=true`. The state root must be
the same root configured for the network agent as `O3K_NETWORK_FABRIC_ROOT`.
Missing or invalid configuration prevents compute startup.

When external networking is disabled, the legacy compute-owned path remains
unchanged: `HostNetworkManager` creates, validates, and removes its own TAPs
under ADR-0026, ADR-0058, and ADR-0140. This decision does not broaden that
manager to accept arbitrary external interfaces.

## Consequences

The TAP MAC is host/provider-local and never substitutes for the guest NIC
MAC. Fabric state, the current canonical plan, and live kernel observation
jointly prove attachment; neither interface names nor libvirt XML establish
ownership. A temporarily absent Fabric TAP after restart delays guest start
until Fabric reconciliation recreates it and a fresh read-only attestation
succeeds. Server/domain deletion continues to remove the canonical endpoint
through O3K lifecycle and Fabric reconciliation, not through compute-side TAP
cleanup.

This decision defines an execution-provider attachment boundary. It does not
claim nested or physical host connectivity; those remain subject to the
ADR-0186, SPEC-0049, and stretched-L2 contract evidence gates.
