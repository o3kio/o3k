#!/usr/bin/env python3
"""Read-only libvirt inventory and collision-safe nested-host IP preflight."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import select
import socket
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def _run(*args: str) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _pool_config_sha(xml: str) -> str:
    """Fingerprint pool configuration without live capacity telemetry."""
    root = ET.fromstring(xml)
    for name in ("capacity", "allocation", "available"):
        for node in root.findall(f"./{name}"):
            root.remove(node)
    return _sha(ET.tostring(root, encoding="unicode"))


def _names(text: str) -> list[str]:
    """Normalize virsh --name output, which pads rows to a fixed width."""
    return [line.strip() for line in text.splitlines() if line.strip()]


def _network_xml(name: str) -> tuple[str, ET.Element]:
    raw = _run("virsh", "-c", "qemu:///system", "net-dumpxml", name)
    return raw, ET.fromstring(raw)


def _capture_domains() -> list[dict[str, Any]]:
    names = _names(_run("virsh", "-c", "qemu:///system", "list", "--all", "--name"))
    result = []
    for name in sorted(names):
        uuid = _run("virsh", "-c", "qemu:///system", "domuuid", name).strip()
        state = _run("virsh", "-c", "qemu:///system", "domstate", name).strip()
        xml = _run("virsh", "-c", "qemu:///system", "dumpxml", "--inactive", name)
        result.append({"name": name, "uuid": uuid, "state": state, "xml_sha256": _sha(xml)})
    return result


def _capture_networks() -> list[dict[str, Any]]:
    names = _names(_run("virsh", "-c", "qemu:///system", "net-list", "--all", "--name"))
    result = []
    for name in sorted(names):
        info = _run("virsh", "-c", "qemu:///system", "net-info", name)
        xml = _run("virsh", "-c", "qemu:///system", "net-dumpxml", name)
        result.append({"name": name, "info": info, "xml_sha256": _sha(xml)})
    return result


def _capture_pools() -> list[dict[str, Any]]:
    names = _names(_run("virsh", "-c", "qemu:///system", "pool-list", "--all", "--name"))
    result = []
    for name in sorted(names):
        info = _run("virsh", "-c", "qemu:///system", "pool-info", name)
        xml = _run("virsh", "-c", "qemu:///system", "pool-dumpxml", name)
        volume_text = ""
        state_line = next((line for line in info.splitlines() if line.lstrip().startswith("State:")), "")
        if state_line.split(":", 1)[-1].strip().lower() in ("running", "active"):
            volume_text = _run("virsh", "-c", "qemu:///system", "vol-list", name, "--details")
        # Pool allocation changes while run-owned disks exist. Keep immutable
        # pool config/state and volume identity/path/capacity, not free space.
        stable_info = "\n".join(line for line in info.splitlines() if not line.startswith(("Capacity:", "Allocation:", "Available:")))
        volume_rows = []
        for line in volume_text.splitlines()[2:]:
            fields = line.split()
            if len(fields) >= 5:
                volume_rows.append(fields[:4])
        result.append({"name": name, "info": stable_info, "xml_sha256": _pool_config_sha(xml), "volumes": sorted(volume_rows)})
    return result


def _stable_links() -> list[dict[str, Any]]:
    rows = json.loads(_run("ip", "-j", "-d", "link", "show"))
    keep = ("ifname", "address", "broadcast", "mtu", "master", "operstate", "flags", "link_type", "linkinfo")
    volatile_bridge_fields = {"gc_timer", "hello_timer", "tcn_timer", "topology_change_timer"}
    stable_rows = []
    for row in rows:
        stable = {key: row[key] for key in keep if key in row}
        linkinfo = stable.get("linkinfo")
        if isinstance(linkinfo, dict):
            info_data = linkinfo.get("info_data")
            if isinstance(info_data, dict) and linkinfo.get("info_kind") == "bridge":
                linkinfo = dict(linkinfo)
                linkinfo["info_data"] = {
                    key: value for key, value in info_data.items() if key not in volatile_bridge_fields
                }
                stable["linkinfo"] = linkinfo
        stable_rows.append(stable)
    return sorted(stable_rows, key=lambda row: row.get("ifname", ""))


def capture_inventory(network: str) -> dict[str, Any]:
    xml, root = _network_xml(network)
    net = root.find("./ip")
    if net is None or not net.get("address") or not net.get("netmask"):
        raise ValueError(f"libvirt network {network} has no IPv4 address/netmask")
    bridge = root.find("./bridge")
    if bridge is None or not bridge.get("name"):
        raise ValueError(f"libvirt network {network} has no bridge")
    leases = _run("virsh", "-c", "qemu:///system", "net-dhcp-leases", network)
    neighbors = json.loads(_run("ip", "-j", "neigh", "show", "dev", bridge.get("name")))
    return {
        "network": network,
        "network_xml": xml,
        "network_info": _run("virsh", "-c", "qemu:///system", "net-info", network),
        "bridge": bridge.get("name"),
        "bridge_addresses": json.loads(_run("ip", "-j", "-4", "address", "show", "dev", bridge.get("name"))),
        "dhcp_leases": leases,
        "neighbors": neighbors,
        "domains": _capture_domains(),
        "networks": _capture_networks(),
        "pools": _capture_pools(),
        "links": _stable_links(),
    }


def _network_values(root: ET.Element) -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Address, int, int, set[ipaddress.IPv4Address]]:
    node = root.find("./ip")
    if node is None or not node.get("address") or not node.get("netmask"):
        raise ValueError("IPv4 network address and netmask are required")
    address = ipaddress.IPv4Address(node.get("address"))
    netmask = ipaddress.IPv4Address(node.get("netmask"))
    network = ipaddress.IPv4Network(f"{address}/{netmask}", strict=False)
    if network.prefixlen != 24:
        raise ValueError(f"the nested guest network requires a /24; found {network}")
    bridge = root.find("./bridge")
    ip_node = root.find("./ip")
    assert bridge is not None and ip_node is not None
    iface = bridge.get("name")
    if not iface:
        raise ValueError("bridge name is missing")
    host_rows = json.loads(_run("ip", "-j", "-4", "address", "show", "dev", iface))
    host_addresses = {
        ipaddress.IPv4Interface(item["local"] + "/" + str(item["prefixlen"]))
        for row in host_rows for item in row.get("addr_info", []) if item.get("family") == "inet"
    }
    if not any(item.ip == address for item in host_addresses):
        raise ValueError(f"bridge {iface} does not own configured gateway {address}")
    ranges = ip_node.findall("./dhcp/range")
    if len(ranges) != 1 or not ranges[0].get("start") or not ranges[0].get("end"):
        raise ValueError("exactly one bounded DHCP range is required")
    start = int(ipaddress.IPv4Address(ranges[0].get("start")))
    end = int(ipaddress.IPv4Address(ranges[0].get("end")))
    reserved = {address, network.network_address, network.broadcast_address}
    for host in ip_node.findall("./dhcp/host"):
        value = host.get("ip")
        if value:
            reserved.add(ipaddress.IPv4Address(value))
    return network, address, start, end, reserved


def _leased_ips(text: str) -> set[ipaddress.IPv4Address]:
    result: set[ipaddress.IPv4Address] = set()
    for line in text.splitlines():
        ip_match = None
        mac_match = None
        for token in line.split():
            try:
                ip_match = ipaddress.IPv4Address(token)
            except ipaddress.AddressValueError:
                pass
            if len(token.split(":")) == 6 and all(len(part) == 2 for part in token.split(":")):
                mac_match = token
        # `FAILED` pseudo-leases have no MAC and are stale libvirt probe data.
        if ip_match is not None and mac_match is not None:
            result.add(ip_match)
    return result


def _domain_macs(domains: list[dict[str, Any]], network: str, bridge: str) -> set[str]:
    result = set()
    for domain in domains:
        raw = _run("virsh", "-c", "qemu:///system", "dumpxml", "--inactive", domain["name"])
        root = ET.fromstring(raw)
        for interface in root.findall("./devices/interface"):
            source = interface.find("./source")
            if source is None or not (source.get("network") == network or source.get("bridge") == bridge):
                continue
            mac = interface.find("./mac")
            if mac is not None and mac.get("address"):
                result.add(mac.get("address").lower())
    return result


def _arp_in_use(interface: str, source_ip: ipaddress.IPv4Address, source_mac: str, target: ipaddress.IPv4Address, timeout: float = 0.25) -> bool:
    """Probe without adding entries to the host kernel neighbor table."""
    source = bytes.fromhex(source_mac.replace(":", ""))
    target_bytes = target.packed
    frame = b"\xff" * 6 + source + struct.pack("!H", 0x0806)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + source + source_ip.packed + b"\x00" * 6 + target_bytes
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)) as sock:
        sock.bind((interface, socket.htons(0x0806)))
        sock.send(frame + arp)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            ready, _, _ = select.select([sock], [], [], remaining)
            if not ready:
                return False
            packet = sock.recv(2048)
            if len(packet) < 42 or packet[12:14] != b"\x08\x06":
                continue
            payload = packet[14:42]
            htype, ptype, hlen, plen, operation = struct.unpack("!HHBBH", payload[:8])
            sender_ip = ipaddress.IPv4Address(payload[14:18])
            if htype == 1 and ptype == 0x0800 and hlen == 6 and plen == 4 and operation in (1, 2) and sender_ip == target:
                return True


def select_addresses(snapshot: dict[str, Any]) -> dict[str, Any]:
    xml_root = ET.fromstring(snapshot["network_xml"])
    network, gateway, start, end, reserved = _network_values(xml_root)
    bridge = snapshot["bridge"]
    bridge_mac = None
    for row in snapshot["links"]:
        if row.get("ifname") == bridge:
            bridge_mac = row.get("address")
    if not bridge_mac:
        raise ValueError(f"cannot identify bridge MAC for {bridge}")
    excluded = set(reserved)
    excluded.update(_leased_ips(snapshot["dhcp_leases"]))
    for row in snapshot["neighbors"]:
        destination = row.get("dst")
        lladdr = row.get("lladdr")
        state = str(row.get("state", "")).upper()
        if destination and lladdr and state not in ("FAILED", "INCOMPLETE"):
            try:
                excluded.add(ipaddress.IPv4Address(destination))
            except ipaddress.AddressValueError:
                pass
    domain_macs = _domain_macs(snapshot["domains"], snapshot["network"], bridge)
    if domain_macs:
        raise RuntimeError(
            "management network has pre-existing libvirt domains attached; "
            "their static management addresses cannot be ruled out safely"
        )
    candidates = [ipaddress.IPv4Address(value) for value in range(end, start - 1, -1) if ipaddress.IPv4Address(value) in network]
    probes = []
    selected = []
    for candidate in candidates:
        if candidate in excluded:
            probes.append({"ip": str(candidate), "result": "excluded_by_inventory"})
            continue
        if _arp_in_use(bridge, gateway, bridge_mac, candidate):
            probes.append({"ip": str(candidate), "result": "arp_response"})
            excluded.add(candidate)
            continue
        probes.append({"ip": str(candidate), "result": "no_arp_response"})
        selected.append(candidate)
        if len(selected) == 3:
            break
    if len(selected) != 3:
        raise RuntimeError(f"only {len(selected)} unused management addresses were proved in {network} DHCP range")
    return {
        "network": str(network),
        "bridge": bridge,
        "gateway": str(gateway),
        "selected": [str(item) for item in selected],
        "domain_macs_on_network": sorted(domain_macs),
        "probes": probes,
        "selection_method": "live domain/lease/neighbor inventory plus direct ARP probes; historical evidence is not reserved",
    }


def compare_inventory(before: dict[str, Any], after: dict[str, Any], owned_ips: set[str] | None = None) -> list[str]:
    owned_ips = owned_ips or set()
    diffs = []
    for key in ("domains", "networks", "pools", "links"):
        if before.get(key) != after.get(key):
            diffs.append(key)
    # Leases are compared as IP/MAC pairs; their expiration timestamps are
    # naturally volatile. Run-owned campaign addresses are omitted here.
    def leases(snapshot: dict[str, Any]) -> set[tuple[str, str]]:
        pairs = set()
        for line in snapshot.get("dhcp_leases", "").splitlines():
            fields = line.split()
            ip = next((token for token in fields if token.count(".") == 3), None)
            mac = next((token.lower() for token in fields if len(token.split(":")) == 6 and all(len(p) == 2 for p in token.split(":"))), None)
            if ip and mac and ip not in owned_ips:
                pairs.add((ip, mac))
        return pairs
    if leases(before) != leases(after):
        diffs.append("foreign_dhcp_leases")
    return diffs


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    snapshot_parser = sub.add_parser("snapshot")
    snapshot_parser.add_argument("--network", required=True)
    snapshot_parser.add_argument("--output", required=True)
    select_parser = sub.add_parser("select")
    select_parser.add_argument("--snapshot", required=True)
    select_parser.add_argument("--output", required=True)
    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("--before", required=True)
    compare_parser.add_argument("--after", required=True)
    compare_parser.add_argument("--owned-ip", action="append", default=[])
    args = parser.parse_args()
    try:
        if args.command == "snapshot":
            value = capture_inventory(args.network)
            Path(args.output).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
        elif args.command == "select":
            snapshot = json.loads(Path(args.snapshot).read_text())
            value = select_addresses(snapshot)
            Path(args.output).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
        else:
            before = json.loads(Path(args.before).read_text())
            after = json.loads(Path(args.after).read_text())
            diffs = compare_inventory(before, after, set(args.owned_ip))
            print(json.dumps({"unchanged": not diffs, "changed_classes": diffs}, sort_keys=True))
            return 0 if not diffs else 1
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"HARNESS_GAP: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
