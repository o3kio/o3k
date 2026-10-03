#!/usr/bin/env python3
"""Send a minimal valid DHCPDISCOVER from the disposable A1 namespace."""

import socket
import struct
import sys


def checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    words = struct.unpack(f"!{len(header) // 2}H", header)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def main() -> None:
    iface = sys.argv[1] if len(sys.argv) == 2 else "eth0"
    mac = bytes.fromhex("02000000a101")
    transaction_id = 0x4F334B31
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,
        1,
        6,
        0,
        transaction_id,
        0,
        0x8000,
        bytes(4),
        bytes(4),
        bytes(4),
        bytes(4),
        mac + bytes(10),
        bytes(64),
        bytes(128),
    )
    options = bytes.fromhex("63825363") + bytes((53, 1, 1, 55, 3, 1, 3, 6, 255))
    payload = bootp + options
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    source = socket.inet_aton("0.0.0.0")
    destination = socket.inet_aton("255.255.255.255")
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        source,
        destination,
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    frame = bytes.fromhex("ffffffffffff") + mac + b"\x08\x00" + ip + udp
    packet = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    packet.bind((iface, 0))
    packet.send(frame)
    print(f"sent DHCPDISCOVER xid={transaction_id:08x} bytes={len(frame)}")


if __name__ == "__main__":
    main()
