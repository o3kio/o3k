#!/usr/bin/env python3
"""Select, observe, and safely remove a run-owned libvirt management network.

This network is out-of-band harness connectivity only. It is not tenant or
Fabric dataplane state, and its selected addresses are never used as packet
acceptance evidence.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import ipaddress
import json
import pathlib
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from typing import Any


OWNERSHIP = "o3k-fabric-v3-retirement-v1"
UUID_NAMESPACE = uuid.UUID("3849b9f8-2a8c-4d3d-955a-546f86f47c4a")
VIRSH = ["virsh", "-c", "qemu:///system"]


class EnvironmentGap(RuntimeError):
    """The host cannot prove a safe management-network allocation."""


def _command(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EnvironmentGap(f"observer failed: {argv[0]} ({type(exc).__name__})") from exc
    if result.returncode:
        raise EnvironmentGap(
            f"observer failed: {argv[0]} exited {result.returncode}: "
            f"{result.stderr.strip()[:500]}"
        )
    return result.stdout


def _names(output: str) -> list[str]:
    return sorted({line.strip() for line in output.splitlines() if line.strip()})


def _domain_record(name: str, xml: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise EnvironmentGap(f"could not parse libvirt domain XML for {name}") from exc
    interfaces: list[dict[str, str | None]] = []
    for interface in root.findall("./devices/interface"):
        mac = interface.find("mac")
        source = interface.find("source")
        target = interface.find("target")
        interfaces.append(
            {
                "type": interface.get("type"),
                "mac": mac.get("address") if mac is not None else None,
                "network": source.get("network") if source is not None else None,
                "bridge": source.get("bridge") if source is not None else None,
                "dev": source.get("dev") if source is not None else None,
                "target": target.get("dev") if target is not None else None,
            }
        )
    return {
        "name": root.findtext("name") or name,
        "uuid": root.findtext("uuid"),
        "interfaces": sorted(interfaces, key=lambda item: json.dumps(item, sort_keys=True)),
    }


def _resource_is_active(info: str, resource_class: str, name: str) -> str:
    fields: dict[str, list[str]] = {}
    for line in info.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip():
            fields.setdefault(key.strip().lower(), []).append(value.strip().lower())
    if resource_class == "storage pool":
        states = fields.get("state", [])
        active = {"running": "yes", "inactive": "no"}.get(states[0]) if len(states) == 1 else None
    else:
        active_values = fields.get("active", [])
        active = active_values[0] if len(active_values) == 1 else None
    if active not in {"yes", "no"}:
        raise EnvironmentGap(f"libvirt {resource_class} active state is missing or invalid for {name}")
    return active


def _pool_record(name: str, xml: str, info: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise EnvironmentGap(f"could not parse libvirt storage pool XML for {name}") from exc
    target = root.find("target/path")
    source = root.find("source")
    return {
        "name": root.findtext("name") or name,
        "uuid": root.findtext("uuid"),
        "type": root.get("type"),
        "target": target.text if target is not None else None,
        "source": {
            "device": source.findtext("device") if source is not None else None,
            "dir": source.findtext("dir") if source is not None else None,
            "name": source.findtext("name") if source is not None else None,
            "hosts": sorted(
                (host.get("name"), host.get("port"))
                for host in (source.findall("host") if source is not None else [])
            ),
        },
        "active": _resource_is_active(info, "storage pool", name) == "yes",
    }


def capture_snapshot() -> dict[str, Any]:
    """Capture only host topology fields needed for collision/foreign checks."""
    networks: list[dict[str, Any]] = []
    for name in _names(_command(VIRSH + ["net-list", "--all", "--name"])):
        xml = _command(VIRSH + ["net-dumpxml", name])
        info = _command(VIRSH + ["net-info", name])
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as exc:
            raise EnvironmentGap(f"could not parse libvirt network XML for {name}") from exc
        networks.append(
            {
                "name": root.findtext("name") or name,
                "uuid": root.findtext("uuid"),
                "active": _resource_is_active(info, "network", name),
                "xml": xml,
            }
        )

    domains: list[dict[str, Any]] = []
    for name in _names(_command(VIRSH + ["list", "--all", "--name"])):
        xml = _command(VIRSH + ["dumpxml", name])
        domains.append(_domain_record(name, xml))

    pools: list[dict[str, Any]] = []
    for name in _names(_command(VIRSH + ["pool-list", "--all", "--name"])):
        xml = _command(VIRSH + ["pool-dumpxml", name])
        info = _command(VIRSH + ["pool-info", name])
        pools.append(_pool_record(name, xml, info))

    def json_command(argv: list[str]) -> Any:
        try:
            return json.loads(_command(argv))
        except json.JSONDecodeError as exc:
            raise EnvironmentGap(f"observer returned malformed JSON: {argv[0]}") from exc

    links = json_command(["ip", "-j", "link", "show"])
    addresses = json_command(["ip", "-j", "address", "show"])
    routes = json_command(["ip", "-j", "-4", "route", "show", "table", "all"])
    neighbors = json_command(["ip", "-j", "-4", "neigh", "show"])
    return {
        "schema": "o3k-fabric-v3-management-host-snapshot-v1",
        "routes": routes,
        "networks": networks,
        "domains": domains,
        "pools": pools,
        "links": links,
        "addresses": addresses,
        "neighbors": neighbors,
    }


def _xml_networks(snapshot: dict[str, Any]) -> list[ipaddress.IPv4Network]:
    result: list[ipaddress.IPv4Network] = []
    for network in snapshot.get("networks", []):
        try:
            root = ET.fromstring(network["xml"])
        except (KeyError, ET.ParseError) as exc:
            raise EnvironmentGap(f"network inventory XML invalid for {network.get('name', 'unknown')}") from exc
        for node in root.findall("./ip"):
            address = node.get("address")
            if not address:
                continue
            try:
                interface = ipaddress.ip_interface(
                    f"{address}/{node.get('prefix', node.get('netmask', '32'))}"
                )
            except ValueError as exc:
                raise EnvironmentGap(f"invalid IPv4 network address in {network.get('name', 'unknown')}") from exc
            if isinstance(interface, ipaddress.IPv4Interface):
                result.append(interface.network)
        for node in root.findall("./route"):
            address = node.get("address")
            if not address:
                continue
            mask = node.get("prefix", node.get("netmask", "32"))
            try:
                route = ipaddress.ip_network(f"{address}/{mask}", strict=False)
                if isinstance(route, ipaddress.IPv4Network):
                    result.append(route)
            except ValueError as exc:
                raise EnvironmentGap(f"invalid IPv4 route in {network.get('name', 'unknown')}") from exc
    return result


def _occupied_networks(snapshot: dict[str, Any]) -> list[ipaddress.IPv4Network]:
    occupied: list[ipaddress.IPv4Network] = _xml_networks(snapshot)
    for route in snapshot.get("routes", []):
        destination = route.get("dst")
        if not destination or destination == "default":
            continue
        try:
            parsed = ipaddress.ip_network(destination, strict=False)
        except ValueError as exc:
            raise EnvironmentGap(f"invalid route destination in host inventory: {destination}") from exc
        if isinstance(parsed, ipaddress.IPv4Network):
            occupied.append(parsed)
    for entry in snapshot.get("addresses", []):
        for address in entry.get("addr_info", []):
            if address.get("family") != "inet":
                continue
            try:
                occupied.append(ipaddress.ip_network(
                    f"{address['local']}/{address['prefixlen']}", strict=False
                ))
            except (KeyError, ValueError) as exc:
                raise EnvironmentGap("invalid IPv4 host address inventory") from exc
    for neighbor in snapshot.get("neighbors", []):
        destination = neighbor.get("dst")
        if destination:
            try:
                occupied.append(ipaddress.ip_network(f"{destination}/32", strict=False))
            except ValueError as exc:
                raise EnvironmentGap("invalid IPv4 neighbor inventory") from exc
    return occupied


def _merged_intervals(networks: list[ipaddress.IPv4Network]) -> list[tuple[int, int]]:
    intervals = sorted((int(net.network_address), int(net.broadcast_address)) for net in networks)
    merged: list[tuple[int, int]] = []
    for start, end in intervals:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _candidate_bases(run_id: str):
    """Return deterministic RFC1918 /29 search space without materializing it."""
    spaces = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16")]
    # A run-specific start makes independent campaigns avoid concentrating on
    # the same first subnet while retaining deterministic evidence/replay.
    total = sum(net.num_addresses // 8 for net in spaces)
    start = int.from_bytes(hashlib.sha256(run_id.encode()).digest()[:8], "big") % total
    offset = 0
    for net in spaces:
        count = net.num_addresses // 8
        if start < offset + count:
            break
        offset += count
    else:  # pragma: no cover - arithmetic invariant
        raise EnvironmentGap("could not select deterministic private subnet search start")
    for step in range(total):
        global_index = (start + step) % total
        base_offset = 0
        for net in spaces:
            count = net.num_addresses // 8
            if global_index < base_offset + count:
                index = global_index - base_offset
                yield int(net.network_address) + index * 8, 8
                break
            base_offset += count


def select_network_plan(snapshot: dict[str, Any], run_id: str) -> dict[str, Any]:
    if not run_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for ch in run_id):
        raise EnvironmentGap("run identity is not safe for libvirt resource names")
    networks = snapshot.get("networks", [])
    domains = snapshot.get("domains", [])
    links = snapshot.get("links", [])
    digest = hashlib.sha256(run_id.encode()).hexdigest()
    network_name = f"o3k-ret-{digest[:10]}"
    bridge_name = f"o3kr{digest[:10]}"  # Linux IFNAMSIZ allows at most 15 characters.
    network_uuid = str(uuid.uuid5(UUID_NAMESPACE, run_id))
    if network_name in {item.get("name") for item in networks}:
        raise EnvironmentGap("run-owned management network name already exists")
    if network_uuid in {item.get("uuid") for item in networks}:
        raise EnvironmentGap("run-owned management network UUID already exists")
    if bridge_name in {item.get("ifname") for item in links}:
        raise EnvironmentGap("run-owned management bridge name already exists")
    for domain in domains:
        for interface in domain.get("interfaces", []):
            if interface.get("bridge") == bridge_name:
                raise EnvironmentGap("management bridge name is already referenced by a domain")

    intervals = _merged_intervals(_occupied_networks(snapshot))
    starts = [start for start, _ in intervals]
    subnet_value: int | None = None
    for candidate, _ in _candidate_bases(run_id):
        position = bisect.bisect_right(starts, candidate) - 1
        if position >= 0 and intervals[position][1] >= candidate:
            continue
        next_position = position + 1
        if next_position < len(intervals) and intervals[next_position][0] <= candidate + 7:
            continue
        subnet_value = candidate
        break
    if subnet_value is None:
        raise EnvironmentGap("no unused RFC1918 /29 remains in observed host/libvirt inventory")

    subnet = ipaddress.ip_network((subnet_value, 29))
    host_addresses = {host: str(subnet.network_address + index) for host, index in zip("abc", (2, 3, 4), strict=True)}
    occupied_macs = {
        str(interface.get("mac", "")).lower()
        for domain in domains
        for interface in domain.get("interfaces", [])
        if interface.get("mac")
    }
    occupied_macs.update(
        str(link.get("address", "")).lower()
        for link in links
        if link.get("address")
    )
    macs: dict[str, str] | None = None
    for nonce in range(65536):
        mac_digest = hashlib.sha256(f"{run_id}\0management-mac\0{nonce}".encode()).hexdigest()
        candidate_macs = {
            host: f"52:54:{mac_digest[i:i+2]}:{mac_digest[i+2:i+4]}:{mac_digest[i+4:i+6]}:{i+2:02x}"
            for i, host in enumerate("abc")
        }
        if len(set(candidate_macs.values())) == 3 and not (set(candidate_macs.values()) & occupied_macs):
            macs = candidate_macs
            break
    if macs is None:  # pragma: no cover - collision space exhaustion
        raise EnvironmentGap("could not select collision-free run-specific management MAC addresses")
    return {
        "schema": "o3k-fabric-v3-management-network-plan-v1",
        "owner": OWNERSHIP,
        "run_id": run_id,
        "network_name": network_name,
        "network_uuid": network_uuid,
        "bridge_name": bridge_name,
        "subnet": str(subnet),
        "prefixlen": subnet.prefixlen,
        "gateway": str(subnet.network_address + 1),
        "addresses": host_addresses,
        "macs": macs,
        "out_of_band_only": True,
        "dhcp": False,
    }


def network_xml(plan: dict[str, Any]) -> str:
    if plan.get("owner") != OWNERSHIP or plan.get("dhcp") is not False:
        raise EnvironmentGap("refusing to render an unowned or DHCP-enabled management network")
    if not plan.get("out_of_band_only"):
        raise EnvironmentGap("refusing to render management network as dataplane state")
    return (
        "<network>\n"
        f"  <name>{plan['network_name']}</name>\n"
        f"  <uuid>{plan['network_uuid']}</uuid>\n"
        f"  <description>{OWNERSHIP} run={plan['run_id']}</description>\n"
        "  <forward mode='nat'/>\n"
        f"  <bridge name='{plan['bridge_name']}' stp='on' delay='0'/>\n"
        f"  <ip address='{plan['gateway']}' prefix='{plan['prefixlen']}'/>\n"
        "</network>\n"
    )


def _write_json(path: pathlib.Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")


def _domain_names_attached_to(snapshot: dict[str, Any], network_name: str, bridge_name: str) -> list[str]:
    return sorted(
        domain["name"]
        for domain in snapshot.get("domains", [])
        if any(
            interface.get("network") == network_name or interface.get("bridge") == bridge_name
            for interface in domain.get("interfaces", [])
        )
    )


def _normalize_links(links: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stable_fields = ("ifname", "address", "master", "link_type", "linkinfo")
    result = []
    for link in links:
        record = {field: link[field] for field in stable_fields if field in link}
        result.append(record)
    return sorted(result, key=lambda item: item.get("ifname", ""))


def _normalize_routes(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    volatile = {"expires", "cacheinfo", "uid"}
    return sorted(
        ({key: value for key, value in route.items() if key not in volatile} for route in routes),
        key=lambda item: json.dumps(item, sort_keys=True),
    )


def _normalize_addresses(addresses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stable_info = {"family", "local", "prefixlen", "broadcast", "scope", "label", "protocol", "flags"}
    normalized = []
    for entry in addresses:
        info = [
            {key: value for key, value in address.items() if key in stable_info}
            for address in entry.get("addr_info", [])
        ]
        normalized.append({"ifname": entry.get("ifname"), "addr_info": sorted(info, key=lambda item: json.dumps(item, sort_keys=True))})
    return sorted(normalized, key=lambda item: item.get("ifname", ""))


def verify_foreign_unchanged(before: dict[str, Any], after: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    expected_networks = [item for item in before["networks"]]
    actual_networks = [item for item in after["networks"]]
    if expected_networks != actual_networks:
        raise EnvironmentGap("foreign libvirt network inventory changed")
    expected_domains = sorted(before["domains"], key=lambda item: item["name"])
    actual_domains = sorted(after["domains"], key=lambda item: item["name"])
    if expected_domains != actual_domains:
        raise EnvironmentGap("foreign libvirt domain inventory changed")
    if sorted(before["pools"], key=lambda item: item["name"]) != sorted(after["pools"], key=lambda item: item["name"]):
        raise EnvironmentGap("foreign libvirt storage pool inventory changed")
    expected_links = _normalize_links(before["links"])
    actual_links = _normalize_links(after["links"])
    # The exact run-owned bridge is expected to be absent after cleanup. Any
    # remaining bridge with that name means cleanup did not remove owned state.
    if any(item.get("ifname") == plan["bridge_name"] for item in actual_links):
        raise EnvironmentGap("run-owned management bridge remains after cleanup")
    if expected_links != actual_links:
        raise EnvironmentGap("foreign host link inventory changed")
    if _normalize_routes(before["routes"]) != _normalize_routes(after["routes"]):
        raise EnvironmentGap("host route inventory changed")
    if _normalize_addresses(before["addresses"]) != _normalize_addresses(after["addresses"]):
        raise EnvironmentGap("host address inventory changed")
    return {
        "foreign_networks_unchanged": True,
        "foreign_domains_unchanged": True,
        "foreign_pools_unchanged": True,
        "foreign_links_unchanged": True,
        "host_routes_unchanged": True,
        "host_addresses_unchanged": True,
    }


def verify_snapshots_unchanged(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    # Reused for checking that the accepted storage preflight left the host in
    # its original state before creating any campaign-owned network or guest.
    dummy_plan = {"bridge_name": "__no_campaign_bridge__"}
    return verify_foreign_unchanged(before, after, dummy_plan)


def verify_cleanup_snapshot(before: dict[str, Any], after: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    names = {item.get("name") for item in after.get("networks", [])}
    uuids = {item.get("uuid") for item in after.get("networks", [])}
    if plan["network_name"] in names or plan["network_uuid"] in uuids:
        raise EnvironmentGap("run-owned management network remains after cleanup")
    if any(item.get("ifname") == plan["bridge_name"] for item in after.get("links", [])):
        raise EnvironmentGap("run-owned management bridge remains after cleanup")
    return verify_foreign_unchanged(before, after, plan)


def _network_owned(xml: str, plan: dict[str, Any]) -> bool:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return False
    return (
        root.findtext("name") == plan["network_name"]
        and root.findtext("uuid") == plan["network_uuid"]
        and root.findtext("description") == f"{OWNERSHIP} run={plan['run_id']}"
        and (root.find("./bridge") is not None and root.find("./bridge").get("name") == plan["bridge_name"])
    )


def verify_created_network(snapshot: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    selected = [item for item in snapshot.get("networks", []) if item.get("name") == plan["network_name"]]
    if len(selected) != 1 or selected[0].get("uuid") != plan["network_uuid"] or not _network_owned(selected[0]["xml"], plan):
        raise EnvironmentGap("run-owned management network identity did not match immediately after start")
    if selected[0].get("active") != "yes":
        raise EnvironmentGap("run-owned management network is not active")
    subnet = ipaddress.ip_network(plan["subnet"])
    for other in snapshot.get("networks", []):
        if other.get("uuid") == plan["network_uuid"]:
            continue
        if any(network.overlaps(subnet) for network in _xml_networks({"networks": [other]})):
            raise EnvironmentGap("another libvirt network overlaps the selected management subnet")
    for route in snapshot.get("routes", []):
        destination = route.get("dst")
        if not destination or destination == "default":
            continue
        try:
            parsed = ipaddress.ip_network(destination, strict=False)
        except ValueError as exc:
            raise EnvironmentGap("invalid route destination during post-start revalidation") from exc
        if isinstance(parsed, ipaddress.IPv4Network) and parsed.overlaps(subnet) and route.get("dev") != plan["bridge_name"]:
            raise EnvironmentGap("non-run host route overlaps management subnet after network start")
    for entry in snapshot.get("addresses", []):
        if entry.get("ifname") == plan["bridge_name"]:
            continue
        for address in entry.get("addr_info", []):
            if address.get("family") != "inet":
                continue
            try:
                assigned = ipaddress.ip_interface(
                    f"{address['local']}/{address['prefixlen']}"
                ).network
            except (KeyError, ValueError) as exc:
                raise EnvironmentGap("invalid host address during post-start revalidation") from exc
            if assigned.overlaps(subnet):
                raise EnvironmentGap("non-run host address overlaps management subnet after network start")
    bridge_addresses = {
        (entry.get("ifname"), info.get("local"), info.get("prefixlen"))
        for entry in snapshot.get("addresses", [])
        for info in entry.get("addr_info", [])
        if info.get("family") == "inet"
    }
    if (plan["bridge_name"], plan["gateway"], plan["prefixlen"]) not in bridge_addresses:
        raise EnvironmentGap("run-owned bridge address does not match the selected gateway/prefix")
    return {"network_identity_verified": True, "active": True, "subnet": plan["subnet"]}


def remove_owned_network(plan: dict[str, Any], evidence_dir: pathlib.Path) -> dict[str, Any]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    network = plan["network_name"]
    xml = _command(VIRSH + ["net-dumpxml", network])
    if not _network_owned(xml, plan):
        raise EnvironmentGap("libvirt management network ownership proof failed; preserved network")
    snapshot = capture_snapshot()
    attached = _domain_names_attached_to(snapshot, network, plan["bridge_name"])
    if attached:
        _write_json(evidence_dir / "management-network-attached-domains.json", {"domains": attached})
        raise EnvironmentGap("run-owned management network still has attached domains; preserved network")
    _write_json(evidence_dir / "management-network-before-remove.json", {"xml": xml, "uuid": plan["network_uuid"]})
    info = _command(VIRSH + ["net-info", network])
    active = any(
        key.strip() == "Active" and value.strip() == "yes"
        for key, _, value in (line.partition(":") for line in info.splitlines())
    )
    if active:
        try:
            result = subprocess.run(VIRSH + ["net-destroy", network], check=False, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EnvironmentGap(f"run-owned management network destroy observer failed: {type(exc).__name__}") from exc
        _write_json(evidence_dir / "management-network-destroy-command.json", {"command_class": "exact_owned_libvirt_network_destroy", "exit_code": result.returncode, "stderr": result.stderr[-1000:]})
        if result.returncode:
            raise EnvironmentGap(f"run-owned management network destroy failed with exit {result.returncode}")
    try:
        result = subprocess.run(VIRSH + ["net-undefine", network], check=False, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EnvironmentGap(f"run-owned management network undefine observer failed: {type(exc).__name__}") from exc
    _write_json(evidence_dir / "management-network-undefine-command.json", {"command_class": "exact_owned_libvirt_network_undefine", "exit_code": result.returncode, "stderr": result.stderr[-1000:]})
    if result.returncode:
        raise EnvironmentGap(f"run-owned management network undefine failed with exit {result.returncode}")
    after = capture_snapshot()
    if any(item.get("name") == network or item.get("uuid") == plan["network_uuid"] for item in after["networks"]):
        raise EnvironmentGap("run-owned management network remains after destroy/undefine")
    if any(item.get("ifname") == plan["bridge_name"] for item in after["links"]):
        raise EnvironmentGap("run-owned management bridge remains after destroy/undefine")
    _write_json(evidence_dir / "management-network-after-remove.json", after)
    return {"network_removed": True, "network_name": network, "network_uuid": plan["network_uuid"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--output", required=True, type=pathlib.Path)
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--snapshot", required=True, type=pathlib.Path)
    plan_parser.add_argument("--run-id", required=True)
    plan_parser.add_argument("--output", required=True, type=pathlib.Path)
    xml_parser = subparsers.add_parser("xml")
    xml_parser.add_argument("--plan", required=True, type=pathlib.Path)
    xml_parser.add_argument("--output", required=True, type=pathlib.Path)
    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--plan", required=True, type=pathlib.Path)
    cleanup_parser.add_argument("--evidence-dir", required=True, type=pathlib.Path)
    verify_parser = subparsers.add_parser("verify-cleanup")
    verify_parser.add_argument("--before", required=True, type=pathlib.Path)
    verify_parser.add_argument("--after", required=True, type=pathlib.Path)
    verify_parser.add_argument("--plan", required=True, type=pathlib.Path)
    verify_parser.add_argument("--output", required=True, type=pathlib.Path)
    verify_start_parser = subparsers.add_parser("verify-created")
    verify_start_parser.add_argument("--snapshot", required=True, type=pathlib.Path)
    verify_start_parser.add_argument("--plan", required=True, type=pathlib.Path)
    verify_start_parser.add_argument("--output", required=True, type=pathlib.Path)
    verify_snapshot_parser = subparsers.add_parser("verify-snapshot")
    verify_snapshot_parser.add_argument("--before", required=True, type=pathlib.Path)
    verify_snapshot_parser.add_argument("--after", required=True, type=pathlib.Path)
    verify_snapshot_parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.action == "capture":
            _write_json(args.output, capture_snapshot())
        elif args.action == "plan":
            plan = select_network_plan(json.loads(args.snapshot.read_text()), args.run_id)
            _write_json(args.output, plan)
        elif args.action == "xml":
            args.output.write_text(network_xml(json.loads(args.plan.read_text())))
        elif args.action == "cleanup":
            result = remove_owned_network(json.loads(args.plan.read_text()), args.evidence_dir)
            _write_json(args.evidence_dir / "management-network-cleanup.json", result)
        elif args.action == "verify-created":
            result = verify_created_network(json.loads(args.snapshot.read_text()), json.loads(args.plan.read_text()))
            _write_json(args.output, result)
        elif args.action == "verify-snapshot":
            result = verify_snapshots_unchanged(json.loads(args.before.read_text()), json.loads(args.after.read_text()))
            _write_json(args.output, result)
        else:
            before = json.loads(args.before.read_text())
            after = json.loads(args.after.read_text())
            plan = json.loads(args.plan.read_text())
            _write_json(args.output, verify_cleanup_snapshot(before, after, plan))
        return 0
    except (EnvironmentGap, OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"ENVIRONMENT_GAP: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
