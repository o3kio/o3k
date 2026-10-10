# P11 v3 runtime implementation

The Linux fabric executor now realizes the accepted stretched-L2 plan with one
learning VXLAN device per active realm and host. The device uses the durable
realm binding VNI, UDP destination port 4789, and the shared WireGuard fabric
interface. Flood membership is reconciled from the current endpoint directory;
kernel learning and ARP observations are never used as placement authority.

The provider journals VXLAN ownership before mutation, rejects stale v2 Geneve
attachments and VNI collisions, and removes only observed owned objects. The
realm directory resolves remote neighbors to their canonical endpoint MACs.
Root-side TAP rules enforce canonical MAC/IP and ARP sender identity with nft
counters; fabric-side ingress accepts only current remote endpoint identities
and drops the remainder. A provider-owned netdev ingress chain additionally
admits UDP/4789 only when the authenticated WireGuard transport `/32` and
current realm VNI pair are present in the durable plans, so unknown peers,
wrong VNIs, and stale realm membership are dropped before VXLAN delivery.
Existing bridge/veth objects are reused only after their expected VXLAN,
namespace, and bridge-port topology is observed. MTU admission derives IPv4
`fabric_mtu` as `underlay_mtu - 60` and tenant MTU as `fabric_mtu - 50`.

The portable conformance and three-host evidence gates remain required before
this runtime can be used as PP.5 S5 evidence. This document records the
implementation boundary only; it does not claim those gates have passed.

The bounded privileged provider witness is retained in
[`docs/evidence/fabric-v3-single-host-smoke-20261003.md`](evidence/fabric-v3-single-host-smoke-20261003.md).
