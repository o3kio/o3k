# PP.4 rebaseline — O3K Core and Araf certification

Status: documented governance rebaseline, 2026-09-21  
Program: [#968](https://github.com/o3kio/o3k/issues/968)  
Core gate: [#973](https://github.com/o3kio/o3k/issues/973)  
Araf gate: [#1029](https://github.com/o3kio/o3k/issues/1029)  
Next hardening phase: [#974](https://github.com/o3kio/o3k/issues/974)

This is a Production Phase release-gate amendment, not a Cloud Kernel
authority change. O3K and Araf remain separate products and authorities. Araf
browser/runtime defects are recorded as client evidence and cannot block O3K
Cloud Kernel lifecycle, compatibility, or scale hardening.

## Gate split

### PP.4 — O3K Demo/Core Acceptance (#973)

PP.4 is the release-blocking gate for beginning PP.5. It proves, on fresh
Ubuntu 24.04 and Debian 12 x86_64 campaigns using exact published O3K
artifacts:

```text
fresh supported host
 -> public one-line O3K install and release verification
 -> canonical init/join
 -> one real BuildingBlock
 -> real Placement/topology
 -> bounded native network
 -> real libvirt/KVM and guest boot
 -> native O3K workload lifecycle
 -> bounded OpenStack-compatible lifecycle
 -> unmodified Horizon compatibility witness
 -> reboot/rerun/reset/reinstall/purge/foreign-state/secret checks
```

Native API proof is first and mandatory. The current native keypair/config-drive,
stable port identity, collision-safe free-IP allocation, and
compensation/replay fixes are part of this gate. `python-openstackclient`
provides exact compatibility assertions; Horizon provides bounded third-party
UI evidence. Both interfaces must observe one canonical server (or the
declared deterministic projection), with identity mapping recorded. No
OpenStack shortcut or same-name second resource satisfies native proof.

Horizon is pinned to one unmodified upstream container artifact for the
campaign: Docker Hub `openstackhelm/horizon:2024.1-ubuntu_jammy-20250523`,
manifest digest
`sha256:53af8d4c6c6b4c9c339f535080e2b56c439f8b36c417a6eba8bbf16afeb04a2b`.
Normal Keystone endpoint/catalog/region/TLS/session configuration is allowed.
The witness is limited to the capabilities advertised by
`o3k-demo-v1`; unsupported services fail truthfully or are absent. O3K Ready
does not depend on Horizon Ready.

### PP.4A — Araf Native Console Certification (#1029)

PP.4A owns the separately versioned Araf candidate and its native O3K console
certification:

- published immutable candidate, exact source/version and artifact digests;
- strict production CSP and compatible JSON Schema runtime;
- CSRF, OIDC/session, secure cookies, and tenant/operator separation;
- browser native create, inspect, lifecycle, and delete against the real O3K
  native API and real libvirt/KVM workload;
- reboot/recovery and Ubuntu/Debian evidence where required;
- no fixtures, fabricated success, or Araf-owned authorization/resource truth.

Failed/consumed Araf `rc.15` and `rc.16` candidates and O3K `rc.16` evidence
remain historical and immutable. The Araf CSP/schema-runtime defect moves to
PP.4A; it is not rewritten as an O3K Core limitation.

PP.4A is required before PP.7 can certify an `O3K + Araf Edge v1` product
promise. It is not required for O3K readiness, PP.4 Core completion, or PP.5
start.

## Client roles and independence

```yaml
Araf:
  role: native next-generation O3K dashboard
  interface: O3K native APIs
  authority: none
  certification: PP.4A (#1029)

Horizon:
  role: external OpenStack compatibility witness
  interface: OpenStack-compatible APIs
  authority: none
  product_dependency: false
```

Araf remains the intended user interface. Horizon is test/demo evidence and is
not the O3K product dashboard. O3K readiness is independent of both clients.

## Dependency graph

```text
PP.4 Core (#973)
   |
   +------> PP.5 (#974)
   |
PP.4A Araf (#1029)
   |
PP.5 + PP.6 (#975) + PP.4A
   |
   v
PP.7 final certification (#976)
```

PP.5 is not started by this document. PP.7 may publish an O3K-core verdict
while PP.4A is incomplete, but must not certify the Araf-integrated product.

## Governance conclusion

The split changes PP release-gate semantics, not Cloud Kernel authority,
IAM, Placement, LocationRegistry, BuildingBlock, CloudProfile, or Araf
authority. A dedicated architecture ADR/spec amendment is not required;
this lightweight PP governance addendum and the issue records are the
traceability artifact. Existing ADRs/SPEC-0048 remain authoritative for
architecture and product-profile boundaries.

## Required status

```text
PP.4 REBASELINE: COMPLETE

#973:
  new core scope: O3K Demo/Core acceptance with native-first lifecycle,
    bounded OpenStack CLI, and pinned unmodified Horizon witness
  Araf removed from core completion gate: YES; historical evidence preserved;
    PP.4A #1029 owns Araf browser/runtime certification
  Horizon added as compatibility witness: YES; external, bounded, non-authoritative

PP.4A:
  issue: #1029
  scope: published Araf candidate, CSP/schema/CSRF/OIDC/session and
    tenant/operator checks; native browser create/inspect/lifecycle/delete;
    reboot/recovery and required OS matrix
  required before PP.7: YES for an Araf-integrated Edge-v1 verdict

#974:
  depends on PP.4 Core: YES
  depends on PP.4A: NO

#976:
  PP.4A dependency: YES when the claimed product includes Araf; otherwise
    PP.7 must state an O3K-core-only verdict

o3k-demo-v1:
  Araf client optional preserved: YES
  Araf O3K readiness dependency: NONE

Horizon:
  product dependency: NO
  compatibility witness: YES
  fork required: NO

BLOCKER: none introduced by the governance split
HIGH: none introduced by the governance split
MEDIUM: none introduced by the governance split
LOW: exact Horizon artifact pin and campaign matrix must be recorded by PP.4 evidence

PP.5 authorized after PP.4 Core: YES (but PP.5 is not started here)
```
