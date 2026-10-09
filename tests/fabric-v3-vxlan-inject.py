#!/usr/bin/env python3
"""Send one VXLAN Ethernet/ARP frame through an enrolled WireGuard peer."""

import socket
import struct
import sys


def main() -> None:
    if len(sys.argv) != 6:
        raise SystemExit(
            "usage: fabric-v3-vxlan-inject.py LOCAL_IP REMOTE_IP VNI SOURCE_MAC SOURCE_IP"
        )
    local_ip, remote_ip, raw_vni, raw_mac, source_ip = sys.argv[1:]
    vni = int(raw_vni)
    if not 1 <= vni <= 0xFFFFFF:
        raise SystemExit("VNI must fit 24 bits and be nonzero")
    source_mac = bytes.fromhex(raw_mac.replace(":", ""))
    if len(source_mac) != 6:
        raise SystemExit("SOURCE_MAC must contain six octets")
    destination_mac = bytes.fromhex("ffffffffffff")
    ethernet = destination_mac + source_mac + b"\x08\x06"
    arp = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        + source_mac
        + socket.inet_aton(source_ip)
        + bytes(6)
        + socket.inet_aton("10.0.0.20")
    )
    vxlan = bytes((0x08, 0, 0, 0)) + vni.to_bytes(3, "big") + bytes(1)
    packet = vxlan + ethernet + arp
    transport = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    transport.bind((local_ip, 0))
    transport.sendto(packet, (remote_ip, 4789))
    print(f"sent enrolled WG peer VXLAN VNI={vni} bytes={len(packet)}")


if __name__ == "__main__":
    main()
