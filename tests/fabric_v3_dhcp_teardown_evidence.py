#!/usr/bin/env python3
"""Validate supported Fabric DHCP teardown observations."""
from __future__ import annotations

import argparse
import json
from pathlib import PurePosixPath
import sys


class HarnessEvidenceError(ValueError):
    """The captured observation is incomplete or internally inconsistent."""


class CleanupResidueError(ValueError):
    """Run-owned DHCP provider state remains after supported teardown."""


def _parse_json_capture(text: str, label: str) -> dict[str, dict]:
    """Parse the path + JSON stream emitted by `find -print -exec cat`."""
    records: dict[str, dict] = {}
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        line_end = text.find("\n", offset)
        if line_end < 0:
            raise HarnessEvidenceError(f"{label}: missing JSON after path")
        path = text[offset:line_end]
        if not path.startswith("/"):
            raise HarnessEvidenceError(f"{label}: expected absolute path record")
        offset = line_end + 1
        while offset < len(text) and text[offset].isspace():
            offset += 1
        try:
            value, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError as error:
            raise HarnessEvidenceError(f"{label}: malformed JSON capture") from error
        if not isinstance(value, dict):
            raise HarnessEvidenceError(f"{label}: JSON record is not an object")
        if path in records:
            raise HarnessEvidenceError(f"{label}: duplicate path record")
        records[path] = value
    return records


def _parse_inventory(text: str) -> dict[str, tuple[str, int]]:
    """Parse GNU find's type, path, and byte-size inventory."""
    records: dict[str, tuple[str, int]] = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            raise HarnessEvidenceError("DHCP inventory record is malformed")
        kind, path, size_text = fields
        if len(kind) != 1 or not path.startswith("/"):
            raise HarnessEvidenceError("DHCP inventory has an invalid type or path")
        try:
            size = int(size_text)
        except ValueError as error:
            raise HarnessEvidenceError("DHCP inventory size is malformed") from error
        if size < 0 or path in records:
            raise HarnessEvidenceError("DHCP inventory has a negative size or duplicate path")
        records[path] = (kind, size)
    return records


def _validate_withdrawn_owner(owner: dict, realm_id: str, host: str) -> None:
    if owner.get("realm_id") != realm_id or owner.get("local_host") != f"host-{host}":
        raise CleanupResidueError("DHCP ownership tombstone has the wrong Realm or host")
    if (
        owner.get("dhcp_enabled") is not False
        or owner.get("gateway") is not None
        or owner.get("pending") is not False
        or owner.get("withdrawn") is not True
    ):
        raise CleanupResidueError("DHCP ownership tombstone is not fully withdrawn")
    if type(owner.get("schema_version")) is not int or owner["schema_version"] != 1:
        raise CleanupResidueError("DHCP ownership tombstone has an unsupported schema")
    authority = owner.get("authority_host")
    if not isinstance(authority, str) or authority not in {"host-a", "host-b", "host-c"}:
        raise CleanupResidueError("DHCP tombstone has an invalid authority host")
    generations = (
        "realm_generation",
        "directory_generation",
        "binding_generation",
        "local_fabric_generation",
    )
    for field in generations:
        value = owner.get(field)
        if type(value) is not int or value < 0:
            raise CleanupResidueError(f"DHCP tombstone has an invalid {field}")
    if owner["realm_generation"] != owner["directory_generation"]:
        raise CleanupResidueError("DHCP tombstone Realm generations disagree")
    mtu = owner.get("tenant_mtu")
    if type(mtu) is not int or not 1 <= mtu <= 65535:
        raise CleanupResidueError("DHCP tombstone has an invalid tenant MTU")


def _without_host_bindings(config_text: str) -> str:
    """Model the final generated config after all durable bindings are removed."""
    return "".join(
        line
        for line in config_text.splitlines(keepends=True)
        if not line.startswith("dhcp-host=")
    )


def validate_dhcp_teardown(
    run_id: str,
    realm_id: str,
    host: str,
    inventory_text: str,
    state_text: str,
    ownership_text: str,
    rendered_files_text: str,
    expected_config_text: str | None,
) -> dict:
    """Accept provider absence, including only known dormant rendered files."""
    if not run_id or not realm_id or host not in {"a", "b", "c"}:
        raise HarnessEvidenceError("invalid run, Realm, or host identity")

    base = PurePosixPath(f"/var/lib/o3k-fabric-v3/{run_id}/network/dhcp")
    fabric_root = base / "fabric"
    directory = fabric_root / realm_id
    expected_directories = {str(base), str(fabric_root), str(directory)}
    owner_path = str(directory / "fabric-dhcp-ownership.json")
    state_path = str(directory / "state.json")
    config_path = str(directory / "dnsmasq.conf")
    leases_path = str(directory / "dnsmasq.leases")
    expected_files = {owner_path, state_path, config_path, leases_path}

    inventory = _parse_inventory(inventory_text)
    unexpected = sorted(set(inventory) - expected_directories - expected_files)
    if unexpected:
        raise CleanupResidueError("unexpected run-owned DHCP path remains")
    for path, (kind, _size) in inventory.items():
        expected_kind = "d" if path in expected_directories else "f"
        if kind != expected_kind:
            raise CleanupResidueError("run-owned DHCP path is not a regular file or directory")
    for path in inventory:
        if path == str(fabric_root) and str(base) not in inventory:
            raise HarnessEvidenceError("DHCP fabric directory is missing its inventory root")
        if path == str(directory) and str(fabric_root) not in inventory:
            raise HarnessEvidenceError("DHCP Realm directory is missing its fabric parent")
        if path in expected_files and str(directory) not in inventory:
            raise HarnessEvidenceError("DHCP file is missing its Realm directory")

    states = _parse_json_capture(state_text, "state")
    owners = _parse_json_capture(ownership_text, "ownership")
    try:
        rendered_files = json.loads(rendered_files_text)
    except json.JSONDecodeError as error:
        raise HarnessEvidenceError("rendered DHCP file capture is malformed") from error
    if not isinstance(rendered_files, dict) or set(rendered_files) != {
        "dnsmasq.conf",
        "dnsmasq.leases",
    }:
        raise HarnessEvidenceError("rendered DHCP file capture has an unexpected shape")
    if any(value is not None and not isinstance(value, str) for value in rendered_files.values()):
        raise HarnessEvidenceError("rendered DHCP file capture has a non-text value")
    captured_paths = set(states) | set(owners)
    if captured_paths - set(inventory):
        raise HarnessEvidenceError("captured DHCP JSON does not match file inventory")

    files = set(inventory) & expected_files
    if not files:
        if states or owners or any(value is not None for value in rendered_files.values()):
            raise HarnessEvidenceError("DHCP JSON records exist without inventoried files")
        return {
            "artifact_type": "fabric-dhcp-teardown-observation",
            "host": f"host-{host}",
            "realm_id": realm_id,
            "run_id": run_id,
            "status": "passed",
            "tombstone": "absent",
            "rendered_config": "absent",
            "lease_file": "absent",
        }

    if owner_path not in files:
        raise CleanupResidueError("run-owned DHCP state lacks its ownership tombstone")
    if owner_path not in owners:
        raise HarnessEvidenceError("ownership tombstone is inventoried but was not captured")
    _validate_withdrawn_owner(owners[owner_path], realm_id, host)

    state = None
    if state_path in files:
        if state_path not in states:
            raise HarnessEvidenceError("state.json is inventoried but was not captured")
        state = states[state_path]
        if state.get("config") is not None or state.get("bindings") != {}:
            raise CleanupResidueError("DHCP config or bindings remain after teardown")
    elif states:
        raise HarnessEvidenceError("unlisted DHCP state record was captured")

    if config_path in files and state is None:
        raise CleanupResidueError("rendered dnsmasq config lacks empty canonical service state")
    config_text = rendered_files["dnsmasq.conf"]
    if (config_path in files) != (config_text is not None):
        raise HarnessEvidenceError("rendered config capture does not match file inventory")
    if config_path in files:
        expected_lease_path = str(directory / "dnsmasq.leases")
        lines = config_text.splitlines()
        if (
            not lines
            or lines[0] != "# Managed by o3k-dhcp; do not edit."
            or lines.count(f"dhcp-leasefile={expected_lease_path}") != 1
            or not config_text.endswith("\n")
        ):
            raise CleanupResidueError("dormant dnsmasq config is not the generated run-owned config")
        if expected_config_text is None:
            raise CleanupResidueError("dormant config has no captured run-owned authority baseline")
        expected_dormant_config = _without_host_bindings(expected_config_text)
        if config_text != expected_dormant_config:
            raise CleanupResidueError(
                "dormant dnsmasq config differs from the no-binding form of this run's authority config"
            )
        if any(line.startswith("dhcp-host=") for line in lines):
            raise CleanupResidueError("dormant dnsmasq config still contains DHCP host bindings")
    if leases_path in files and inventory[leases_path][1] != 0:
        raise CleanupResidueError("dnsmasq lease file is not empty after teardown")
    lease_text = rendered_files["dnsmasq.leases"]
    if (leases_path in files) != (lease_text is not None):
        raise HarnessEvidenceError("lease file capture does not match file inventory")
    if leases_path in files and lease_text != "":
        raise HarnessEvidenceError("empty lease file capture contains data")

    return {
        "artifact_type": "fabric-dhcp-teardown-observation",
        "host": f"host-{host}",
        "realm_id": realm_id,
        "run_id": run_id,
        "status": "passed",
        "tombstone": "withdrawn_nonpending",
        "state_json": "empty" if state is not None else "absent",
        "rendered_config": "dormant" if config_path in files else "absent",
        "lease_file": "empty" if leases_path in files else "absent",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    parser.add_argument("realm_id")
    parser.add_argument("host", choices=("a", "b", "c"))
    parser.add_argument("inventory")
    parser.add_argument("state")
    parser.add_argument("ownership")
    parser.add_argument("rendered_files")
    parser.add_argument("expected_config", help="captured authority config path, or '-' if no config is expected")
    args = parser.parse_args()
    try:
        result = validate_dhcp_teardown(
            args.run_id,
            args.realm_id,
            args.host,
            open(args.inventory, encoding="utf-8").read(),
            open(args.state, encoding="utf-8").read(),
            open(args.ownership, encoding="utf-8").read(),
            open(args.rendered_files, encoding="utf-8").read(),
            None if args.expected_config == "-" else open(args.expected_config, encoding="utf-8").read(),
        )
    except CleanupResidueError as error:
        print(f"CLEANUP_DEFECT: {error}", file=sys.stderr)
        return 1
    except (HarnessEvidenceError, OSError) as error:
        print(f"HARNESS_GAP: DHCP teardown evidence: {error}", file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, sort_keys=True, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
