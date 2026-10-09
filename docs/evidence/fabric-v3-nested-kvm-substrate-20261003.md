# Fabric v3 nested-KVM substrate witness

This witness records the next-gate environment check. It is deliberately not
the SPEC-0049 three-independent-host runtime gate: all guests share the
`o3k-rust` physical host and its libvirt underlay.

| Field | Value |
| --- | --- |
| Run | `fabricv3-20261003b` |
| Physical host | `o3k-rust` |
| Libvirt network | `default` (`192.168.122.1`) |
| Guest count | 3 |
| Guest kernel | `6.8.0-139-generic` |
| Guest iproute2 | `6.1.0` |
| Guest nftables | `1.0.9` |

Provisioning completed with `3/3` guests passing usable nested-KVM checks:

| Guest | Address | Nested KVM | vCPU | Memory |
| --- | --- | --- | ---: | ---: |
| host-a | `192.168.122.199` | yes | 2 | 1967 MiB |
| host-b | `192.168.122.232` | yes | 2 | 1967 MiB |
| host-c | `192.168.122.237` | yes | 2 | 1967 MiB |

From host-a, one ICMP probe to each of host-b and host-c passed:

```text
nested-host-reachability=passed
```

The guests were provisioned from the verified Noble cloud image and reclaimed
with the ownership-checked `teardown-hosts.sh` path. No guest credentials or
private keys are retained in this witness. No Fabric v3 VXLAN, WireGuard,
guest-TAP, DHCP, ARP, anti-spoof, or underlay-capture claim follows from this
substrate check.
