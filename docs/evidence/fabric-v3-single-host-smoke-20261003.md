# Fabric v3 privileged single-host smoke

This is a bounded provider realization/cleanup witness. It is not the
SPEC-0049 three-independent-host gate and is not PP.5 certification evidence.

| Field | Value |
| --- | --- |
| Source SHA | `e611ea481715f1708d958a1c4246bdb4aad46afc` |
| Branch | `fabric-v3-runtime` |
| Host | `o3k-rust` |
| Kernel | `6.8.0-139-generic` |
| libvirt | `10.0.0` |
| QEMU | `8.2.2` |
| WireGuard tools | `v1.0.20210914` |
| iproute2 | `6.1.0` |
| nftables | `1.0.9` |
| Cloud image fixture | Noble cloud image, SHA-256 `612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354` |

Command:

```text
cargo build -p o3k-network --example linux-fabric-smoke
sudo env O3K_FABRIC_SMOKE_ROOT=<disposable-directory> \
  ./target/debug/examples/linux-fabric-smoke
```

Observed output:

```text
net.ipv4.conf.o3k-u.rp_filter = 0
net.ipv4.conf.o3k-v.rp_filter = 0
net.ipv4.ip_forward = 1
linux-fabric-smoke: host-transport-address=passed
linux-fabric-smoke: vxlan-realization=passed
linux-fabric-smoke: isolated-attachment=passed
linux-fabric-smoke: topology-and-cleanup=passed
```

The smoke plan used realm `00000000-0000-0000-0000-000000001100`, VNI `101`,
local transport `198.18.0.1`, remote transport `198.18.0.2`, fabric MTU `1440`,
and tenant MTU `1390`. The runtime checks observed VXLAN UDP/4789 with learning
enabled, WireGuard transport addressing, realm bridge/TAP/gateway realization,
and successful provider cleanup. Post-run inspection found no O3K network
namespace, link, nftables table, or owned NAT residue. No credentials or key
material are recorded here.

The witness does not include guest ARP/DHCP/ping traffic, independent hosts,
underlay capture, wrong-VNI injection, anti-spoof packet injection, or restart
traffic recovery; those remain required before the real-host convergence gate
can pass.
