# Fabric v3 runtime executor evidence

This record covers the runtime executor refactor on branch `fabric-v3-runtime`.
It does not certify the final PP.5 campaign.

Candidate implementation SHA: `32b4fb61` (test-tooling follow-up is included in
the final source SHA reported below).
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

## Nested three-host packet follow-up

The retained nested-host run `fabric-v3-gate-20261003` used three freshly
provisioned guests on the development host:

```text
host-a  192.168.122.118
host-b  192.168.122.134
host-c  192.168.122.196
```

The test-only helper
`crates/o3k-network/examples/fabric-regression-3host-helper.rs` encoded the
accepted fixture without changing canonical authority:

```text
Realm A: A1 10.0.0.10 / 02:00:00:00:a1:01 on host-a
          A2 10.0.0.20 / 02:00:00:00:a1:02 on host-b   VNI 101
Realm B: B1 10.0.0.10 / 02:00:00:00:b1:01 on host-c
          B2 10.0.0.20 / 02:00:00:00:b1:02 on host-b   VNI 102
```

`tests/fabric-v3-three-host-gate.sh` applied the production Linux adapter on
all three guests, attached disposable endpoint namespaces to the provider
bridges, and then replayed the same plans after deleting host-b's provider
WireGuard device. The run passed bidirectional A1↔A2 and B1↔B2 ICMP, with
neighbour tables learning the actual remote endpoint MACs, realm-scoped
DHCP-like broadcast delivery, and restart/reconciliation return. Cleanup
removed provider VXLAN, bridge, namespace, WireGuard, nftables, and endpoint
state while preserving the foreign `f3-foreign-can` bridge canary.

The exact corrected command output is retained in
`docs/evidence/artifacts/fabric-v3-three-host-gate-20261003/gate-output-corrected.txt`
(SHA-256 `2ba83ff4b4826a792a1aacf56b9625247ff9d807d14a1a94cdc148a9bb85dbab`).
The earlier `gate-output.txt` and `runtime-snapshot.txt` are retained as
diagnostic artifacts from the first helper revision; that revision over-created
realm state on hosts without a local endpoint and is not used for the corrected
result.
The corrected runtime snapshot at
`docs/evidence/artifacts/fabric-v3-three-host-gate-20261003/runtime-snapshot-corrected.txt`
records per-realm VXLAN (`dstport 4789`, learning enabled), VNI 101/102, HER
FDB membership, authenticated WireGuard peers with `/32` AllowedIPs, and
endpoint anti-spoof rules; its SHA-256 is
`857660f88943d3cd828f6af1c45855327e08eb938e4a05adf8902edd51e8a560`.
The physical-underlay capture contains only UDP/65001 WireGuard packets and
no decoded tenant IPv4 fields; its SHA-256 is
`9c28f2a37b0d7c6d183fedb3d4586ca4458ebd97a7f090210559d8fe5df46e7f`.
Host tool/kernel inventory is retained at
`docs/evidence/artifacts/fabric-v3-three-host-gate-20261003/host-inventory.txt`
(SHA-256 `e80ab93274284234800dedf11e2754f907f33a6fad8658731518a358895591f8`).

This is useful nested packet-path evidence, but all three guests still share
one physical libvirt underlay. The run therefore does not satisfy the required
independent three-compute-host gate. Direct injected wrong-MAC, wrong-IP, and
ARP-sender packets through a live guest TAP were not claimed; the snapshot
records the installed fail-closed nftables rules and counters. MTU boundary
success/oversize behavior and full unknown/stale-VNI traffic injection remain
portable/provider evidence rather than real-host claims.

## Disposable bridge gate tooling

`tests/fabric-v3-bridge-gate.sh` creates two logical host namespaces with
private provider mount namespaces, a veth underlay, the production provider
WireGuard/VXLAN bridges, two overlapping realm bridges, endpoint namespaces,
and a foreign canary. It is bounded to this development host and does not
claim independent compute-host evidence. The provider-only setup/cleanup mode
passed on this candidate:

```text
sudo FABRIC_V3_PROVIDER_ONLY=1 \
  FABRIC_V3_HELPER_BIN=$PWD/target/debug/examples/fabric-regression-helper \
  bash tests/fabric-v3-bridge-gate.sh
```

That run proved provider bridge/VXLAN/HER realization and cleanup while the
foreign canary survived. The full endpoint mode was also run after correcting
the helper's host-relative endpoint directory. WireGuard handshakes and
VXLAN ingress counters were observed, but the remote ARP request did not reach
the endpoint bridge, so the script failed closed at the A1-to-A2 packet gate.
This retained failure is diagnostic evidence only; it is not a Fabric v3
functional pass. `FABRIC_V3_KEEP=1` is available for bounded inspection and
must be followed by explicit removal of the listed disposable namespaces.

### Ingress admission correction and follow-up run

The first full bridge-gate run retained a real packet-path failure. The
provider and WireGuard transport were healthy, but an nftables `vxlan vni`
expression was evaluated at the WireGuard netdev ingress hook, before the
kernel had decapsulated the VXLAN frame. That rejected BUM and unknown-unicast
frames, so a remote ARP request never reached the endpoint bridge. A standalone
VXLAN-over-WireGuard reproduction isolated the failure to that pre-decap
match.

Commit `93b271540b5398e12e2b8b1378aec299bcb9814c4` changes admission to two
bounded stages. The WireGuard netdev rule authenticates the enrolled peer
source and assigns a deterministic mark. A bridge-forward rule then binds
that mark to the current realm VXLAN device and VNI after decapsulation. The
reconciliation fingerprints and owns both tables, rejects foreign markers,
and removes them only after ownership is proven. The netdev hook no longer
matches `vxlan vni` before decapsulation.

The corrected development-host runs were:

```text
provider-realization=passed
endpoint-bridges=not-run
provider-cleanup-and-foreign-canary=passed

provider-realization=passed
endpoint-bridges=passed
remote-arp-mac-and-icmp=passed
bounded-her-fdb=passed
provider-cleanup-and-foreign-canary=passed
```

The full run observed actual endpoint MAC learning for both overlapping
realms, bidirectional A1/A2 and B1/B2 ICMP with 0% loss, bounded HER entries,
and cleanup with the foreign canary preserved. This is a one-physical-host,
two-logical-host development gate. It is retained as focused packet-path
evidence and does not satisfy the independent three-compute-host requirement.
It does not claim DHCP broadcast, underlay capture, injected anti-spoof
rejections, MTU boundary behavior, restart/reconciliation return, or a
three-host zero-leak inventory.
