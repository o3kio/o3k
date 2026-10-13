#!/usr/bin/env python3
"""Validate that run-owned DHCP state is inactive after supported teardown."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import uuid
from typing import Any


class EvidenceError(ValueError):
    """Captured DHCP state contradicts provider absence after teardown."""


ALLOWED_FILES = {
    "fabric-dhcp-ownership.json",
    "state.json",
    "dnsmasq.conf",
    "dnsmasq.leases",
}


def _json_documents(text: str, root: str) -> dict[str, dict[str, Any]]:
    pattern = re.compile(
        rf"(?m)^({re.escape(root)}/fabric/[^/]+/(?:state|fabric-dhcp-ownership)\.json)\n"
    )
    matches = list(pattern.finditer(text))
    documents: dict[str, dict[str, Any]] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        payload = text[match.end() : end].strip()
        try:
            value = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"malformed JSON observation: {pathlib.PurePosixPath(match[1]).name}") from exc
        if not isinstance(value, dict):
            raise EvidenceError(f"JSON observation is not an object: {pathlib.PurePosixPath(match[1]).name}")
        if match[1] in documents:
            raise EvidenceError("duplicate JSON observation path")
        documents[match[1]] = value
    return documents


def validate_host(
    host: str,
    run_id: str,
    file_listing: str,
    state_listing: str,
    ownership_listing: str,
    process_listing: str,
) -> dict[str, Any]:
    if host not in {"a", "b", "c"} or not run_id or "/" in run_id:
        raise EvidenceError("invalid campaign host or run identity")
    root = f"/var/lib/o3k-fabric-v3/{run_id}/network/dhcp"
    prefix = root + "/"
    entries = [line.strip().split(" ", 1) for line in file_listing.splitlines() if line.strip()]
    if any(len(entry) != 2 for entry in entries):
        raise EvidenceError(f"malformed DHCP filesystem inventory on host-{host}")
    if len([path for _, path in entries]) != len({path for _, path in entries}):
        raise EvidenceError(f"duplicate DHCP file inventory entry on host-{host}")

    by_realm: dict[str, set[str]] = {}
    paths = []
    for kind, raw_path in entries:
        if not raw_path.startswith(prefix):
            raise EvidenceError(f"DHCP inventory escaped the exact run-owned root on host-{host}")
        parts = pathlib.PurePosixPath(raw_path[len(prefix) :]).parts
        if not parts or parts[0] != "fabric" or len(parts) not in {1, 2, 3}:
            raise EvidenceError(f"unexpected DHCP inventory path on host-{host}")
        if kind == "d":
            if len(parts) not in {1, 2} or (len(parts) == 2 and parts[1] in {"", ".", ".."}):
                raise EvidenceError(f"unexpected DHCP directory on host-{host}")
            if len(parts) == 2:
                try:
                    uuid.UUID(parts[1])
                except ValueError as exc:
                    raise EvidenceError(f"invalid DHCP Realm directory on host-{host}") from exc
                by_realm.setdefault(parts[1], set())
            continue
        if kind != "f" or len(parts) != 3 or parts[1] in {"", ".", ".."}:
            raise EvidenceError(f"non-regular or misplaced DHCP entry on host-{host}")
        realm_id, filename = parts[1], parts[2]
        try:
            uuid.UUID(realm_id)
        except ValueError as exc:
            raise EvidenceError(f"invalid DHCP Realm path on host-{host}") from exc
        if filename not in ALLOWED_FILES:
            raise EvidenceError(f"unexpected run-owned DHCP file on host-{host}: {filename}")
        paths.append(raw_path)
        by_realm.setdefault(realm_id, set()).add(filename)

    states = _json_documents(state_listing, root)
    owners = _json_documents(ownership_listing, root)
    listed_json = {path for path in paths if path.endswith(".json")}
    if set(states) | set(owners) != listed_json:
        raise EvidenceError(f"DHCP JSON inventory and content observations disagree on host-{host}")

    for realm_id, files in by_realm.items():
        owner_path = f"{root}/fabric/{realm_id}/fabric-dhcp-ownership.json"
        state_path = f"{root}/fabric/{realm_id}/state.json"
        if owner_path not in owners:
            raise EvidenceError(f"withdrawn ownership tombstone is absent on host-{host}")
        owner = owners[owner_path]
        expected_owner = {
            "schema_version": 1,
            "realm_id": realm_id,
            "local_host": f"host-{host}",
            "dhcp_enabled": False,
            "gateway": None,
            "pending": False,
            "withdrawn": True,
        }
        for field, expected in expected_owner.items():
            if owner.get(field) != expected:
                raise EvidenceError(f"DHCP tombstone has unexpected {field} on host-{host}")
        if not isinstance(owner.get("authority_host"), str) or not owner["authority_host"]:
            raise EvidenceError(f"DHCP tombstone authority is absent on host-{host}")
        for field in ("realm_generation", "directory_generation", "binding_generation"):
            value = owner.get(field)
            if type(value) is not int or value < 0:
                raise EvidenceError(f"DHCP tombstone has invalid {field} on host-{host}")

        if state_path in states:
            state = states[state_path]
            if state.get("config") is not None or state.get("bindings") != {}:
                raise EvidenceError(f"active DHCP state remains on host-{host}")
        elif "dnsmasq.conf" in files or "dnsmasq.leases" in files:
            raise EvidenceError(f"DHCP runtime files have no inactive state record on host-{host}")

    if run_id in process_listing:
        raise EvidenceError(f"run-owned DHCP process remains on host-{host}")

    return {
        "host": f"host-{host}",
        "result": "PASS",
        "run_owned_realms": sorted(by_realm),
        "remaining_files": sorted(
            str(pathlib.PurePosixPath(path).relative_to(root)) for path in paths
        ),
        "active_dhcp_state_absent": True,
        "run_owned_process_absent": True,
    }


def validate_campaign(evidence_dir: pathlib.Path, run_id: str) -> dict[str, Any]:
    hosts = {}
    for host in ("a", "b", "c"):
        try:
            hosts[host] = validate_host(
                host,
                run_id,
                (evidence_dir / f"host-{host}-dhcp-files.txt").read_text(),
                (evidence_dir / f"host-{host}-dhcp-state.txt").read_text(),
                (evidence_dir / f"host-{host}-dhcp-ownership.txt").read_text(),
                (evidence_dir / f"host-{host}-dnsmasq-processes.txt").read_text(),
            )
        except OSError as exc:
            raise EvidenceError(f"required DHCP teardown observation is missing for host-{host}") from exc
    return {
        "artifact_type": "fabric-dhcp-teardown-absence",
        "result": "PASS",
        "run_id": run_id,
        "hosts": hosts,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True, type=pathlib.Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        result = validate_campaign(args.evidence_dir, args.run_id)
    except EvidenceError as exc:
        args.output.write_text(
            json.dumps(
                {
                    "artifact_type": "fabric-dhcp-teardown-absence",
                    "result": "FAIL",
                    "run_id": args.run_id,
                    "classification": "CLEANUP_DEFECT",
                    "failed_operation": "validate_dhcp_teardown_inventory",
                    "diagnostic": str(exc),
                },
                sort_keys=True,
                indent=2,
            )
            + "\n"
        )
        print(str(exc), file=sys.stderr)
        return 1
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
