# Fabric v3 O3K lifecycle integration plan

Status: implementation in progress; supported lifecycle milestone not yet accepted

## Provenance

- Base product SHA: `4cdb50eddc41de8de1b78535950f6f9bf698f0dc`
- Base tree SHA: `08babcd839f3651472bd96b83fea77b16c8fec0b`
- Base branch: `fabric-v3-runtime`
- Remote base visibility: the SHA is not present on the remote; remote `fabric-v3-runtime` is `09ce9255604e943eaf1416d00c88f12e0862626a`, an ancestor of the base.
- New branch: `fabric-v3-o3k-lifecycle-gate-a`, created directly from the base SHA.
- Remote successor SHA: pending implementation commit and push; no acceptance testing before it is remotely resolvable.

## Issue and selected profile

Implement the supported O3K lifecycle integration required by the Fabric v3 Nested Conformance Gate A task. The evidence profile is the nested three-compute conformance profile; physical-host acceptance and PP.5 are explicit non-goals.

## Authority and boundaries

- Canonical service/domain: O3K Network and Compute orchestration in `o3kd`; canonical Network, AddressRealm, endpoint, binding, placement, and operation records remain authoritative.
- OpenStack adapter: Neutron-compatible Network/Subnet/Port API only at the existing API boundary.
- Authority mode: `o3k-implemented` control plane plus execution providers; Linux Fabric remains a bounded plan executor.
- Public operations/resources: network, subnet/AddressRealm, port/endpoint, server attachment, host Fabric enrollment, and internal realm reconciliation.
- Shared provider: pinned `o3kio/fabric` `fabric-plan`/`fabric-linux` contract is consumed as-is. Any material conflict with ADR-0186, SPEC-0049, or the accepted O3K contract is a stop condition.
- Durable state: reuse `o3k-store` SQLite/PostgreSQL abstractions, canonical Network tables, durable VNI binding, operation/journal, and existing generation fences. No second placement or retry authority.
- Cross-service workflow: compute placement/attachment waits on network realization according to existing operation outcome and compensation semantics; ambiguous mutation remains unknown until observed.

## Expected execution scope

- Cargo packages/binaries: `o3k-domain`, `o3k-store`, `o3k-network`, `o3k-network-protocol`, `o3k-api`, and `o3kd` as required by the discovered boundary.
- Expected source areas: canonical Fabric host identity model and repositories/migrations; host-to-agent relationship/target-aware dispatcher; deterministic realm-directory/participant/HER plan derivation; production network and compute lifecycle composition; bounded reconciliation and outcome recording.
- Expected tests: identity validation and persistence (SQLite and PostgreSQL where available), participant/HER derivation, distinct target dispatch and epoch fencing, partial failure/replay, lifecycle composition, deterministic plan identity, and focused nested three-host O3K-driven milestone.
- Normative inputs consulted: ADR-0168, ADR-0186, ADR-0176, SPEC-0033, SPEC-0049, `contracts/edge-fabric-stretched-l2.md`, and the repository authority/test-strategy documents. Constraints carried forward: canonical placement and identity remain in O3K; HER is derived only from the current endpoint directory; VNI is durable and generation fenced; provider observations are not authority; journal before mutation; no Geneve fallback; no secret material in canonical state.
- Public reference/provenance: pinned shared `o3kio/fabric` crates and their contract/version only; no private or non-public source is implementation input.

## Non-goals

No Fabric dataplane redesign, shared-provider semantic change, scheduler redesign, blind failure evacuation, PP.5 execution, Gate B physical acceptance, broad OpenStack parity, or unrelated service work.

## Known uncertainties and widening conditions

The current canonical endpoint rows do not themselves encode accepted compute host and placement generation, while compatibility port records carry a binding host. The implementation must use the existing accepted attachment/placement workflow as the source for that join, or stop if the required generation cannot be established. `AgentNodeSnapshot` is compute-agent lifecycle state and must not be overloaded with Fabric transport identity. Multi-host dispatch must resolve each command target independently and must have no static-endpoint fallback for v3. Scope may widen only where store/protocol/composition evidence proves these boundaries cannot otherwise be implemented safely.

## Validation ladder

First add focused fail-before tests for identity validation/persistence, complete participant/HER derivation, target separation/epoch fencing, and partial multi-host convergence. Then run package-level store/network/API/composition checks, PostgreSQL-required tests when configured, shared fabric conformance, and the narrow nested O3K-driven A/B/C milestone. Run workspace fmt/clippy/test and the broader Gate A suite only after the narrow milestone succeeds. Do not run PP.5 S1-S4.

## Defects and validation notes

- `PRODUCT_DEFECT`: the agent compute provider invokes `resolve` and then
  `resolve_artifacts`; the latter previously called the network resolver again.
  In v3 that repeats realm-plan mutations under the same operation/realm/host
  command identity but a newly computed deadline, which can produce a replay
  fingerprint conflict. Fixed by deriving config-drive network metadata from
  the already-resolved attachment input. A focused regression covers that
  derivation; the multi-host composition test also passes.
- `PRODUCT_DEFECT`: realm reconciliation treated the second endpoint on one
  accepted host as a conflicting host identity. Participant derivation now
  deduplicates matching identities and fails closed only on conflicting
  identity data. The multi-host composition regression now places two
  endpoints on compute-a while retaining endpoints on compute-b and compute-c.
- The first workspace test run failed because the SQLite reopen expectation
  omitted the newly durable port binding generation. Updated the expected
  generation and reran that test successfully.
- `SUPPORTED_API_GAP` remains open: the passing composition test drives
  `DaemonCreateResolver` directly. It does not yet create the network and
  servers through the supported HTTP APIs or prove nested packet delivery.
- `ENVIRONMENT_GAP` remains open: the three nested compute guests are running,
  but the available host SSH identities are not accepted by their installed
  guest keys. No guest credentials or state have been changed.
- Controller restart reconciliation remains unproven: canonical state and VNI
  bindings persist, but this branch does not yet have a durable realm work
  inventory/reconciliation sweep that resumes all affected realms after
  `o3kd` restart.
