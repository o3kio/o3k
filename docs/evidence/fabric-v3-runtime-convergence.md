# Fabric v3 runtime executor evidence

This record covers the runtime executor refactor on branch `fabric-v3-runtime`.
It does not certify the final PP.5 campaign.

Candidate source SHA: `febd119168f1ba5530df4fb10fa0573121d02c64`.
Base protected `main`: `41fedbfdf982596f6932c5eb6b08e2c36f810067`.

## Authority and provenance

- O3K authority: ADR-0186, SPEC-0049, and `contracts/edge-fabric-stretched-l2.md`.
- Shared executor: `o3kio/fabric` tag `v0.1.5`, resolved at commit
  `bf99a9f2134ae44b5f485fa2efcb37b103c298a2`.
- Open PR #1054 was inspected. Its phase 0/1 dependency and conformance changes
  are already present in this branch; this implementation adds the production
  adapter and does not fork or patch the shared repository.

The shared provider owns WireGuard, per-realm VXLAN, learning bridges, bounded
HER, provider ownership journaling, and substrate cleanup. O3K continues to own
AddressRealm identity, endpoint placement and generations, VNI bindings,
realm/TAP bridges, ingress source-host/VNI admission, anti-spoofing, policy,
public-address behavior, and O3K operation fencing/reconciliation.

## Implementation evidence

`o3k-network` now converts each accepted `NamespacedRoutedFabricPlan` into a
validated `fabric_plan::StretchedL2Plan` and invokes
`fabric_linux::LinuxFabricProvider<RealCommandRunner>` from a separate
`fabric-provider` ownership root. The provider-created consumer veth is
validated and attached to the O3K realm bridge. Provider-derived VXLAN names,
VNI, MTU, and HER membership are mirrored into O3K execution state; O3K's
authenticated ingress and endpoint anti-spoof rules remain in force. Geneve is
rejected during conversion and the production path never calls the legacy local
Geneve/VXLAN substrate.

## Validation

The following focused checks pass on the candidate:

```text
cargo check -p o3k-network --all-features
cargo test -p o3k-network --all-features
cargo test -p o3k-network --test fabric_conformance --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

The provider conformance suite exercises the pinned executor's replay,
generation, ownership, HER, MTU, cleanup, and foreign-state behavior. Adapter
tests cover V3 plan conversion, VNI and Geneve admission, peer preservation,
fencing generation, and MTU propagation.

## Real-host gate

The required independent three-compute-host KVM/libvirt gate is **not green**.
This development host has KVM/libvirt and can provision nested guests, but all
guests share one physical underlay. No independent three-host ARP/MAC, DHCP,
overlap-isolation, encryption-capture, anti-spoof, MTU, restart, and zero-leak
evidence was manufactured or treated as equivalent.

Therefore this record is a focused implementation/conformance record only.
The development host recorded for the attempted gate has Linux
`6.8.0-139-generic`, libvirt `10.0.0`, QEMU `8.2.2`, iproute2 `6.1.0`, and
WireGuard tools `1.0.20210914`. It has one physical underlay; nested guests
would share it and therefore cannot satisfy the independent three-compute-host
requirement. No packet captures or three-host artifacts are claimed here.

The workspace run retained an unrelated focused PP.5 endpoint artifact at
`bins/o3kd/target/pp5/01a10135-abe5-77d1-9e8f-d8fba0e3fce4/pp5-1035-restart-evidence.json`
with SHA-256
`8fd54f379ff494a3698e6c388fca75b5f9b211df77dc318e63a3635d9ae670bb`; it is
not Fabric v3 evidence.
