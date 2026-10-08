#!/usr/bin/env python3
"""Typed helpers for the Fabric nested acceptance guest-control contract."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import xml.etree.ElementTree as ET


def link_local(mac: str) -> str:
    raw = bytes.fromhex(mac.replace(":", ""))
    if len(raw) != 6:
        raise ValueError("expected a six-byte MAC address")
    iid = bytes((raw[0] ^ 2, raw[1], raw[2], 0xFF, 0xFE, raw[3], raw[4], raw[5]))
    return str(ipaddress.IPv6Address(b"\xfe\x80" + b"\0" * 6 + iid))


def scoped_target(address: str, bridge: str) -> str:
    parsed = ipaddress.IPv6Address(address)
    if not parsed.is_link_local:
        raise ValueError("guest control target must be IPv6 link-local")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", bridge):
        raise ValueError("invalid scoped Realm bridge name")
    return f"cirros@{parsed}%{bridge}"


def serial_capabilities(xml_path: str) -> dict:
    root = ET.parse(xml_path).getroot()
    devices = root.find("./devices")
    serial = []
    serial_nodes = []
    if devices is not None:
        serial_nodes.extend(("serial", node) for node in devices.findall("./serial"))
        serial_nodes.extend(("console", node) for node in devices.findall("./console"))
    for device_name, node in serial_nodes:
        source = node.find("source")
        serial.append({"device": device_name, "type": node.get("type"), "path": source.get("path") if source is not None else None})
    pty = [item for item in serial if item["device"] == "console" and item["type"] == "pty" and (item.get("path") or "").startswith("/dev/pts/")]
    file_backed = [item for item in serial if item["type"] == "file"]
    channels = devices.findall("./channel") if devices is not None else []
    qga = any((target := node.find("target")) is not None and target.get("name") == "org.qemu.guest_agent.0" for node in channels)
    interface_count = len(devices.findall("./interface")) if devices is not None else 0
    return {
        "serial": serial,
        "serial_pty_interactive": bool(pty),
        "file_backed_serial_read_only": bool(file_backed),
        "qemu_guest_agent_present": qga,
        "vsock_present": devices is not None and devices.find("./vsock") is not None,
        "dedicated_management_nic_present": interface_count > 1,
    }


def failure_class(transport_error: bool, phase_class: str) -> str:
    return "HARNESS_GAP" if transport_error else phase_class


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    mac = sub.add_parser("link-local"); mac.add_argument("mac")
    target = sub.add_parser("target"); target.add_argument("address"); target.add_argument("bridge")
    serial = sub.add_parser("serial"); serial.add_argument("xml")
    classification = sub.add_parser("failure-class"); classification.add_argument("transport_error", choices=("yes", "no")); classification.add_argument("phase_class")
    args = parser.parse_args()
    if args.command == "link-local":
        print(link_local(args.mac))
    elif args.command == "target":
        print(scoped_target(args.address, args.bridge))
    elif args.command == "serial":
        print(json.dumps(serial_capabilities(args.xml), sort_keys=True))
    else:
        print(failure_class(args.transport_error == "yes", args.phase_class))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
