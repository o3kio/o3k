# Normative source ownership

This file identifies the authoritative documents for O3K architecture and
product rules. Summaries explain these decisions but do not override them.

## Authority map

| Subject | Normative source | Summary-only documents |
|---|---|---|
| Cloud OS identity, Cloud Kernel, OpenStack compatibility, provider/delegated-cloud authority | `docs/adr/ADR-0165-o3k-cloud-operating-system-and-cloud-kernel.md` | `README.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md` |
| End-to-end edge-to-datacenter scale continuity, deployment building blocks, composable service catalog, and OpenStack ecosystem extension boundary | `docs/adr/ADR-0182-edge-to-datacenter-building-block-cloud-os.md` and `docs/specs/SPEC-0039-edge-to-datacenter-building-block-cloud.md` | `README.md`, `docs/ROADMAP.md`, `docs/PRODUCT_REQUIREMENTS.md` |
| O3K IAM and Keystone compatibility | `docs/adr/ADR-0166-o3k-iam-and-keystone-compatibility-boundary.md` and `docs/specs/SPEC-0020-keystone-trust-catalog-and-auth-context.md` | `README.md`, `docs/ARCHITECTURE.md` |
| Kubernetes-native control-plane deployment and PostgreSQL requirement for HA Kubernetes | `docs/adr/ADR-0167-kubernetes-native-control-plane-deployment.md` | `README.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md` |
| P9 O3K network intent, Routed Fabric, and node-local network execution | `docs/adr/ADR-0168-o3k-routed-fabric-and-network-execution.md` and `docs/specs/SPEC-0026-o3k-routed-fabric-v1.md` | `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/PRODUCT_REQUIREMENTS.md` |
| P11 accepted stretched-L2 v3 fabric (per-realm VXLAN head-end replication over the WireGuard host fabric) | `docs/adr/ADR-0186-stretched-l2-edge-fabric-vxlan-her.md`, `docs/specs/SPEC-0049-stretched-l2-edge-fabric-v3.md`, and `contracts/edge-fabric-stretched-l2.md` (Accepted 2026-09-28; supersedes the v2 P11 fabric authority for implementation). **Host-fabric substrate implementation authority: the shared repository [o3kio/fabric](https://github.com/o3kio/fabric)** (provider contract pinned at v0.1.5, commit bf99a9f2134ae44b5f485fa2efcb37b103c298a2; see [fabric-provider-v1.md](https://github.com/o3kio/fabric/blob/bf99a9f2134ae44b5f485fa2efcb37b103c298a2/contracts/fabric-provider-v1.md) and [change-control.md](https://github.com/o3kio/fabric/blob/bf99a9f2134ae44b5f485fa2efcb37b103c298a2/docs/change-control.md); also consumed by CHV per its ADR-021) | `docs/ROADMAP.md`, `docs/P11_IMPLEMENTATION_PROMPT.md`, `docs/P11_REALM_OVERLAY_IMPLEMENTATION_PROMPT.md`, `crates/o3k-network/tests/fabric_conformance.rs` (CI gate at the pinned tag) |
| Canonical Network / AddressRealm lifecycle | `docs/adr/ADR-0176-canonical-network-and-addressrealm-lifecycle-separation.md`, `docs/specs/SPEC-0033-canonical-network-addressrealm-lifecycle-v1.md` (Accepted 2026-08-24; bounded runtime implementation and evidence are complete for P13.3) | `docs/compatibility/p13-1/p13-2-managed-resource-requirements.yaml` |
| Canonical NetworkPolicy / PolicyRule / PolicyAttachment lifecycle | `docs/adr/ADR-0177-canonical-networkpolicy-and-reusable-policy-set.md`, `docs/specs/SPEC-0034-canonical-networkpolicy-lifecycle-v1.md` (Accepted 2026-08-26 against reviewed proposal baseline 8429a56a32aa1963edd98291000418f02bb87d03; bounded runtime and provider evidence are complete for P13.3) | `docs/compatibility/p13-3/p13-3a-security-group-provider-contract.json` |
| Canonical L3 gateway and Realm connectivity | `docs/adr/ADR-0178-canonical-l3-gateway-and-realm-connectivity.md`, `docs/specs/SPEC-0035-canonical-l3-gateway-lifecycle-v1.md` (Accepted 2026-08-27; bounded runtime and compatibility evidence are defined, but the committed gateway artifacts require rerun after subsequent implementation changes) | `docs/compatibility/p13-3/p13-3c-router-architecture-decision-request.md` |
| Deployment/evidence profiles and claim posture | `docs/adr/ADR-0163-product-profiles-and-deployment-posture.md`, `docs/specs/SPEC-0024-product-profiles-and-claims.md`, and `compatibility/product-profiles.yaml` | `README.md`, `docs/ROADMAP.md` |
| Service topology, persistence authority, process/crate extraction | `docs/adr/ADR-0160-service-topology-and-execution-boundaries.md`, `docs/specs/SPEC-0025-rust-rewrite-and-architecture-convergence.md`, and `contracts/core-architecture-boundaries.toml` | `README.md`, `docs/ARCHITECTURE.md` |
| Cross-service workflows and compensation | `docs/specs/SPEC-0021-cross-service-workflows-and-compensation.md` | `docs/ARCHITECTURE.md`, `docs/TEST_STRATEGY.md` |
| OpenStack compatibility and evidence gates | `docs/specs/SPEC-0022-service-api-baseline-and-evidence-gates.md` | `README.md`, `docs/ROADMAP.md` |
| External OpenStack service-under-test profile | `docs/specs/SPEC-0023-external-cinder-service-under-test.md` | `README.md`, `docs/ARCHITECTURE.md`, `docs/PROJECT_CHARTER.md`, `docs/ROADMAP.md` |
| Federated OIDC identity ingress, external subject binding, scope exchange and browser/BFF boundary | `docs/adr/ADR-0179-o3k-federated-identity-ingress.md` and `docs/specs/SPEC-0036-federated-identity-ingress-v1.md` | `docs/plan/p12-iam-production-federation-plan.md`, `docs/prompts/p12-iam/README.md` |
| Execution authority and protocol invariants | `contracts/execution-boundaries.md` | `docs/ARCHITECTURE.md`, `AGENTS.md` |
| Native persistent Volume/Attachment/Snapshot authority and storage execution | `docs/adr/ADR-0169-native-persistent-storage-and-o3k-storage-boundary.md` and `docs/specs/SPEC-0027-native-persistent-storage-v1.md` | `docs/ROADMAP.md`, `docs/PRODUCT_REQUIREMENTS.md` |

## Accepted P12 sources — active architecture authority

The following P12 sources were accepted on 2026-08-21 (human architecture/
security approval by project-requester, recorded in task instruction). They are now active architecture
authority alongside the accepted foundation sources above. Runtime
implementation and support claims remain gated by the evidence requirements
defined in each source.

| Subject | Normative source |
|---|---|
| Native O3K resource API, resource envelope, identity/versioning/operations/error/pagination/CLI semantics | `docs/adr/ADR-0173-native-o3k-resource-api-and-resource-model.md`, `docs/specs/SPEC-0030-native-o3k-resource-api-v1.md`, `contracts/native-resource-envelope-v1.schema.json` |
| Service Manifest, registry evolution, namespace ownership, external controller/service-principal/delegation/composition model | `docs/adr/ADR-0174-service-manifest-and-resource-provider-controller.md`, `docs/specs/SPEC-0031-service-extension-controller-v1.md`, `contracts/service-manifest-v1.schema.json`, `contracts/controller-protocol-v1.md` |
| Separation of native service identity from OpenStack service/catalog/API compatibility metadata | `contracts/openstack-compatibility-projection-v1.schema.json` under ADR-0174/SPEC-0031; actual advertisement remains gated by SPEC-0022 and compatibility manifests |
| Canonical region and availability-domain location identity/discovery | `docs/adr/ADR-0181-canonical-location-identity.md`, `docs/specs/SPEC-0038-canonical-location-discovery-v1.md`, `contracts/native-location-discovery-v1.schema.json` |
| Authoritative metering definitions and bounded usage aggregation | `docs/adr/ADR-0183-authoritative-metering-and-bounded-usage-aggregation.md`, `docs/specs/SPEC-0046-native-metering-v1.md`, `contracts/native-metering-v1.schema.json` |

## Accepted P13 sources — active architecture authority

The following P13 sources were accepted on 2026-08-24 through explicit human
architecture/security approval by the project-requester, after review findings
were resolved at baseline `7b4a352dd719607e72bfb0cad0749c38fe54686e`.
They are active architecture authority.
Acceptance authorizes P13.1 provider-contract discovery but does not create
runtime compatibility or product-support evidence; those claims remain gated
by SPEC-0032.

| Subject | Normative source |
|---|---|
| OpenStack Ecosystem and Infrastructure-as-Code Compatibility Boundary | `docs/adr/ADR-0175-openstack-ecosystem-and-iac-compatibility-boundary.md`, `docs/specs/SPEC-0032-openstack-terraform-opentofu-compatibility-profile-v1.md`, `contracts/iac-openstack-profile-v1.yaml` |

## Accepted P14.0 sources — active architecture authority

P14.0 is architecture-only. Its accepted boundary is ADR-0180 and SPEC-0037;
runtime implementation and product claims remain evidence-gated by the P14
profile and ordered prompts.

| Subject | Authority |
| --- | --- |
| OpenStack cold migration authority, cutover, and bounded profile | `docs/adr/ADR-0180-openstack-cold-migration-authority-and-cutover.md`, `docs/specs/SPEC-0037-openstack-cold-migration-v1.md`, `docs/prompts/p14/` |

## Accepted end-to-end scale sources — active architecture authority

ADR-0182 and SPEC-0039 define O3K as one Cloud Operating System across the
edge-to-datacenter continuum. They do not promote any untested datacenter-scale
support claim; scale evidence remains profile-specific.

| Subject | Authority |
| --- | --- |
| Edge-to-datacenter building-block continuity, composable service catalog and upstream OpenStack hosted-service extension model | `docs/adr/ADR-0182-edge-to-datacenter-building-block-cloud-os.md`, `docs/specs/SPEC-0039-edge-to-datacenter-building-block-cloud.md` |

## Accepted P15 sources — active architecture authority

ADR-0184 (`docs/adr/ADR-0184-p15-scale-and-composition-foundation.md`) and
SPEC-0047 (`docs/specs/SPEC-0047-p15-scale-and-composition-foundation.md`)
were accepted on 2026-09-12 by explicit human architecture approval recorded
in the PR #938 review. They are now active architecture authority for the P15
program. ADR-0182/SPEC-0039 remain the authoritative strategic E2D decision —
advanced by, not amended by, ADR-0184 — and the gap register
(`docs/architecture/p15-e2d-gap-register.md`) records the post-#928 truth.

| Subject | Authority |
| --- | --- |
| P15 scale/composition architecture and invariants | `docs/adr/ADR-0184-p15-scale-and-composition-foundation.md` |
| P15 phase scope/dependency/acceptance model | `docs/specs/SPEC-0047-p15-scale-and-composition-foundation.md` |
| Post-#928 current-state audit and E2D gap register | `docs/architecture/p15-0-post-araf-current-state-audit.md`, `docs/architecture/p15-e2d-gap-register.md` |
| P15 implementation prompts | `docs/prompts/p15/` |

## Core rules

- O3K owns public identity, ownership, desired state, scheduling, operations,
  reconciliation, and provider mappings for O3K-owned resources.
- OpenStack service names are compatibility concepts, not mandatory internal
  process boundaries.
- O3K is one Cloud Operating System across supported edge and datacenter scale
  profiles; growth must preserve the same cloud authority, IAM, resource/API,
  service-catalog and automation model rather than require replatforming.
- Scale continuity does not require identical internal process topology. Cells,
  sharding, hierarchical scheduling, database topologies and scale-specific
  provider designs are permitted behind stable O3K contracts when evidence
  requires them.
- The service catalog is composable and must identify native O3K versus
  external-hosted ownership. Catalog registration is never proof that O3K
  implements an external service.
- OpenStack compatibility may be used as a bounded ecosystem extension surface
  for upstream services only after exact dependency-contract discovery and
  profile-specific conformance evidence.
- O3K IAM is canonical; Keystone is a compatibility projection.
- ADR-0168/SPEC-0026 establish that O3K Network owns technology-independent
  connectivity intent, with Neutron objects as compatibility projections and
  nftables/eBPF/OVN/overlay mechanisms as execution-provider concerns.
- ADR-0168 activates `o3k-network` only as a bounded node-local execution
  authority; it does not gain tenant authorization, scheduling, public-ID
  allocation, or an independent cloud desired-state database.
- ADR-0170/SPEC-0028 define the superseded P11 v1 authority. They introduced the
  realm bridge/netns, distributed endpoint directory, proxy-MAC remote neighbor
  resolution, and one shared WireGuard host fabric.
- ADR-0171/SPEC-0029 and the realm-overlay contract defined the superseded P11
  v2 authority (Geneve realm encapsulation, known-unicast only, no cross-host
  flooding).
- ADR-0186/SPEC-0049 and the stretched-L2 contract are the active P11 v3
  implementation authority. The WireGuard host-fabric substrate beneath them
  is implemented once in the shared repository o3kio/fabric and consumed by
  git tag (single-tag fleet policy with CHV); its provider contract is
  normative for the substrate, and changes flow through that repository's
  change control — never per-project forks. Acceptance does not create a
  runtime, product, or real-host support claim.
- P11 implementation must follow the v3 authority; the portable realm-scoped
  endpoint-directory/planner semantics and the VNI binding registry from v2 may
  be retained where compatible.
- The accepted successor interprets cross-host tenant addresses as
  `(AddressRealm, IP)`, uses a durable provider mapping from AddressRealm to a
  VXLAN VNI, and makes WireGuard route only unique provider host-fabric
  transport addresses rather than tenant endpoint `/32`s.
- VXLAN in the accepted successor carries realm identity and realizes one
  literal L2 broadcast domain per AddressRealm across enrolled hosts: guest ARP
  is answered by the remote endpoint's actual canonical MAC, and broadcast,
  unknown-unicast, and multicast traverse via bounded head-end replication to
  peers currently hosting realm endpoints only.
- In both P11 designs, same-host/same-realm local L2 is allowed only when
  anti-spoofing and canonical NetworkPolicy are enforced on the TAP/bridge
  path. Packet learning/FDB/ARP observations never become endpoint authority.
- WireGuard is authenticated encrypted host transport, never tenant isolation or
  authorization. Private fabric keys stay host-local.
- Kubernetes is a first-class **control-plane deployment target**, not the Cloud
  Kernel and not the tenant-resource database.
- The Cloud Kernel/domain crates remain independent from Kubernetes APIs.
- PostgreSQL is required before an HA/cloud-native Kubernetes support claim.
  SQLite remains the minimal single-controller/TestLab store.
- Host-local compute/network/storage execution remains outside Kubernetes by
  default.
- Kubernetes CRDs do not become the canonical O3K server/network/volume/
  operation store.
- Existing OpenStack, vSphere, Proxmox, KubeVirt, or public clouds require a
  delegated/federated authority model rather than a libvirt-like provider.
- Accepted P12 documents are active architecture authority for the native API
  and extensible service model. Runtime support claims remain evidence-gated
  by SPEC-0030 §20 and SPEC-0031 §24.

## Claim discipline

Architecture is not release evidence. PostgreSQL/Kubernetes HA, routed
networking, native storage, P11 multi-host networking, P12 native API/service
framework, P13 IaC compatibility, broad federation, complete parity, fixed
footprint/scale claims, larger datacenter scale, and fast-bootstrap timing
claims remain limited to the exact implementation and evidence profiles that
passed their gates.

The current compatibility manifest remains authoritative for which OpenStack
operations are actually advertised. Accepted P12 native contracts do not expand
Keystone, Nova, Neutron, Glance, Placement, or Cinder compatibility by their
presence in the repository; runtime advertisement remains gated by SPEC-0022,
SPEC-0030 §20, and SPEC-0031 §24 evidence gates.

The accepted overlapping-AddressRealm P11 successor must not be claimed as a
supported runtime until a real multi-host gate proves two independent
realms/projects using the same CIDR and overlapping endpoint IPs with zero
cross-realm misdelivery.

P11 must state the exact tested real-hypervisor topology. Simulated agents may
supplement scale/concurrency evidence but do not expand a real-hypervisor
support claim.

The current ephemeral-root libvirt TestLab remains the first-alpha blocking path
unless a later human-approved decision explicitly replans it.
