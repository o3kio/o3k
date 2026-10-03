# Fabric v3 bridge gate witness (development host)

Source SHA: `cfcc1e6159514bbc030c5f6154381ad44b0c41c1`  
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
