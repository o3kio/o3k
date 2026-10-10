#!/usr/bin/env python3
"""Prove a fresh campaign domain references only its two owned image files."""
from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET


def matches_owned_domain(xml: str, name: str, uuid: str, disk: str, seed: str) -> bool:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return False
    if root.tag != "domain":
        return False
    if root.findtext("name") != name or root.findtext("uuid") != uuid:
        return False

    devices = root.find("devices")
    if devices is None:
        return False
    disks = devices.findall("disk")
    if len(disks) != 2:
        return False

    sources: dict[str, str] = {}
    for device in disks:
        kind = device.get("device")
        source = device.find("source")
        if kind not in {"disk", "cdrom"} or source is None:
            return False
        if source.attrib.keys() != {"file"}:
            return False
        if kind in sources:
            return False
        sources[kind] = source.attrib["file"]
    return sources == {"disk": disk, "cdrom": seed}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    parser.add_argument("uuid")
    parser.add_argument("disk")
    parser.add_argument("seed")
    args = parser.parse_args()
    xml = sys.stdin.read()
    return 0 if matches_owned_domain(xml, args.name, args.uuid, args.disk, args.seed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
