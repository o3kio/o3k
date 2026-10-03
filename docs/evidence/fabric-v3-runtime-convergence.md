# Fabric v3 runtime executor evidence

This record covers the runtime executor refactor on branch `fabric-v3-runtime`.
It does not certify the final PP.5 campaign.

Candidate implementation SHA: `0005fa2edc04883b588982bc9a957aa4f0933f6a`.
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

## Nested development-host validation

On 2026-10-03 the current development host provisioned three nested KVM
guests with `tests/pp5-small-edge-campaign/provision-hosts.sh`:

```text
run: fabric-v3-20261003-evidence2
host-a: 192.168.122.18
host-b: 192.168.122.4
host-c: 192.168.122.241
kernel: 6.8.0-139-generic
vCPU/memory: 2 / 1967 MiB per guest
/dev/kvm in guest: usable on all three
guest-to-guest reachability: passed
```

Provisioning evidence is retained at
`docs/evidence/artifacts/fabric-v3-20261003-evidence2/evidence.json` (SHA-256
`58bec87347d9a60eadf219ff643fb39471cc5d2a13ec3c77f1be38cbe5f3d90f`) and the
sanitized inventory at
`docs/evidence/artifacts/fabric-v3-20261003-evidence2/inventory.txt` (SHA-256
`5c30893fb2992bfa3bd91fee3304525def14eb202c0e36525d28109324878370`).

The provider smoke was executed on all three guests using the production
`fabric_linux::LinuxFabricProvider<RealCommandRunner>` adapter. Each guest
passed host transport address, per-realm VXLAN (`dstport 4789`, learning
enabled), isolated VXLAN/consumer-veth attachment, and topology cleanup.
The smoke used provider-generated names (`o3k-wg`, `o3k-x-*`, `o3k-b-*`, and
`o3k-p-*`) and confirmed no residual provider objects after each run.
The sanitized command output is retained at
`docs/evidence/artifacts/fabric-v3-20261003-evidence2/provider-smoke.txt`
(SHA-256
`ecbfa4ce0fc6d5d066c60a2d1ffdd80eb9a5fbad21a4067988b75400c463b0b6`).

The first host-b retry encountered the intended O3K fail-closed response after
an interrupted prior smoke left the durable TAP record with MAC
`02:29:48:24:12:14` while the kernel TAP reported a different MAC. No foreign
object was deleted. The recorded ownership journal was checked, the owned TAP
MAC was restored to the journal value, and the smoke was rerun successfully on
host-b and then repeated successfully on all three guests. This is retained as
a negative ownership-safety observation, not as a Fabric v3 pass claim.

The nested guests share this development host's physical libvirt underlay.
They therefore provide substrate and ownership evidence only; they do not
prove the required independent three-compute-host packet gate (real remote
ARP/MAC, DHCP broadcast, overlap isolation, authenticated WireGuard capture,
anti-spoof injection, MTU boundary, restart, and zero-leak cleanup).
