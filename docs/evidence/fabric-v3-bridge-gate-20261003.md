# Fabric v3 bridge gate witness (development host)

Source SHA for the original diagnostic run: `cfcc1e6159514bbc030c5f6154381ad44b0c41c1`
Harness: `tests/fabric-v3-bridge-gate.sh`  
Helper: `crates/o3k-network/examples/fabric-regression-helper.rs`  
Base: `41fedbfdf982596f6932c5eb6b08e2c36f810067`

The harness created two logical hosts on this single development machine. Each
host had a private `/run/netns` mount, a veth underlay (`10.77.0.1/24` and
`10.77.0.2/24`), the shared WireGuard fabric, one VXLAN and fabric bridge per
realm, and a root-side consumer veth attached to each O3K realm bridge. Realm A
and Realm B both used `10.0.0.0/24`; a foreign namespace was retained as a
cleanup canary.

The provider-only run passed. It observed WireGuard peers, VXLAN UDP/4789 with
learning enabled, bounded HER entries for the current peer, and clean provider
removal; the foreign canary remained. The full endpoint run failed at the first
remote ARP/ICMP assertion. WireGuard capture showed the VXLAN/ARP datagram
arriving at the peer and the authenticated ingress counters incremented, but
the remote ARP request did not reach the endpoint bridge. The harness retained
the failure diagnostics and cleaned all disposable state on the normal run.

This is a development-host negative result. It does not prove the required
three independent KVM/libvirt compute-host gate, and no Fabric v3 convergence
PASS is claimed.

## Follow-up after the ingress admission fix

The failure was reproduced against the provider and narrowed to the
pre-decap nftables rule that matched `vxlan vni` on the WireGuard netdev. That
hook sees the outer UDP frame, so the VNI match dropped BUM before VXLAN
decapsulation. Commit `93b271540b5398e12e2b8b1378aec299bcb9814c4` keeps the
outer hook limited to enrolled-peer authentication and a deterministic mark,
then performs the mark/VNI binding in a bridge-forward hook after decap. The
owned table fingerprints are replayed from durable state and foreign tables
remain untouched.

The provider-only follow-up and full endpoint run on the same development host
both passed:

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

The full run learned the canonical remote endpoint MACs for Realm A and Realm
B (both realms use `10.0.0.0/24`), completed A1↔A2 and B1↔B2 ICMP with 0%
loss, and removed O3K-owned objects while preserving the foreign canary. This
is still one physical host with two logical hosts. It is not independent
three-host evidence and does not claim DHCP, underlay cleartext capture,
anti-spoof injection counters, MTU-boundary, restart, or final zero-leak
certification.
