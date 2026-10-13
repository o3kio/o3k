#!/usr/bin/env python3
"""Validate the durable DHCP withdrawal tombstone after a Fabric Remove."""
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any


class EvidenceError(ValueError):
    """The observed provider evidence contradicts successful withdrawal."""


def _read(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read {label}") from exc


def validate_withdrawal(
    tree: dict[str, Any],
    provider_ownership: dict[str, Any],
    tombstone: dict[str, Any],
    remove_row: dict[str, Any],
    agent_journal: dict[str, Any],
    endpoint_id: str,
) -> dict[str, Any]:
    if tree.get("root_exists") is not True or tree.get("status") != "present":
        raise EvidenceError("DHCP ownership root/tombstone is absent")
    if tree.get("files") != [
        {"path": "fabric-dhcp-ownership.json", "kind": "file"}
    ]:
        raise EvidenceError("DHCP tree contains active state, an unexpected entry, or a non-regular tombstone")

    if remove_row.get("action") != "Remove" or remove_row.get("state") != "succeeded":
        raise EvidenceError("durable C Remove is not successful")
    if remove_row.get("target_host_id") != "host-c" or remove_row.get("target_agent_id") != "network-agent-c":
        raise EvidenceError("durable Remove target is not network-agent-c")
    command_id = remove_row.get("command_id")
    matching = [
        item
        for item in agent_journal.get("plans", [])
        if item.get("command_id") == command_id and item.get("action") == "Remove"
    ]
    if len(matching) != 1:
        raise EvidenceError("network-agent-c journal does not contain exactly one matching Remove")

    plan = matching[0].get("plan") or {}
    fabric = plan.get("fabric") or {}
    directory = fabric.get("directory") or {}
    directory_generation = fabric.get("directory_generation")
    binding_generation = (fabric.get("encapsulation") or {}).get("binding_generation")
    realm_id = fabric.get("realm_id")
    local_host = fabric.get("local_host")
    participants = sorted(
        {
            entry.get("selected_host")
            for entry in directory.get("entries", [])
            if isinstance(entry, dict) and isinstance(entry.get("selected_host"), str)
        }
    )
    target = matching[0].get("target") or {}
    plan_fingerprint = plan.get("fingerprint_sha256")
    if (
        matching[0].get("status") != "Succeeded"
        or plan.get("operation_id") != remove_row.get("operation_id")
        or matching[0].get("operation_id") != remove_row.get("operation_id")
        or matching[0].get("idempotency_key") != remove_row.get("idempotency_key")
        or not plan_fingerprint
        or plan_fingerprint != remove_row.get("fingerprint_sha256")
        or target.get("agent_id") != remove_row.get("target_agent_id")
        or target.get("agent_epoch") != remove_row.get("target_agent_epoch")
        or remove_row.get("realm_id") != realm_id
        or remove_row.get("directory_generation") != directory_generation
        or remove_row.get("binding_generation") != binding_generation
        or remove_row.get("fabric_generation") != fabric.get("local_fabric_generation")
    ):
        raise EvidenceError("durable Remove row and dispatched agent journal identity/generation disagree")
    if (
        not realm_id
        or local_host != "host-c"
        or plan.get("node_id") != "host-c"
        or directory.get("realm_id") != realm_id
        or directory.get("directory_generation") != directory_generation
        or participants != ["host-a", "host-b"]
        or not isinstance(directory_generation, int)
        or not isinstance(binding_generation, int)
        or not isinstance(fabric.get("local_fabric_generation"), int)
    ):
        raise EvidenceError("matching Remove plan has invalid reduced Realm identity")

    realms = provider_ownership.get("realms")
    if not isinstance(realms, dict) or realm_id in realms:
        raise EvidenceError("C provider ownership still contains the removed Realm")
    for realm in realms.values():
        if not isinstance(realm, dict):
            raise EvidenceError("C provider ownership contains malformed Realm state")
        if any(
            endpoint_id in entries
            for entries in (
                realm.get("endpoint_taps", {}),
                realm.get("pending_endpoint_taps", {}),
            )
            if isinstance(entries, dict)
        ):
            raise EvidenceError("C provider ownership still contains the removed endpoint")

    expected_authority = participants[0]
    expected = {
        "schema_version": 1,
        "realm_id": realm_id,
        "local_host": "host-c",
        "authority_host": expected_authority,
        "realm_generation": directory_generation,
        "directory_generation": directory_generation,
        "binding_generation": binding_generation,
        "local_fabric_generation": fabric.get("local_fabric_generation"),
        "dhcp_enabled": False,
        "pending": False,
        "withdrawn": True,
    }
    for field, wanted in expected.items():
        if tombstone.get(field) != wanted:
            raise EvidenceError(f"DHCP withdrawal tombstone has unexpected {field}")

    return {
        "artifact_type": "fabric-dhcp-withdrawal-observation",
        "result": "PASS",
        "realm_id": realm_id,
        "local_host": "host-c",
        "authority_host": expected_authority,
        "realm_generation": directory_generation,
        "directory_generation": directory_generation,
        "binding_generation": binding_generation,
        "withdrawn": True,
        "pending": False,
        "active_dhcp_state_absent": True,
        "durable_tombstone_present": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", required=True, type=pathlib.Path)
    parser.add_argument("--ownership", required=True, type=pathlib.Path)
    parser.add_argument("--tombstone", required=True, type=pathlib.Path)
    parser.add_argument("--remove-row", required=True, type=pathlib.Path)
    parser.add_argument("--agent-journal", required=True, type=pathlib.Path)
    parser.add_argument("--endpoint-id", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        result = validate_withdrawal(
            _read(args.tree, "DHCP tree inventory"),
            _read(args.ownership, "provider ownership"),
            _read(args.tombstone, "DHCP withdrawal tombstone"),
            _read(args.remove_row, "durable Remove row"),
            _read(args.agent_journal, "network-agent journal"),
            args.endpoint_id,
        )
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    except EvidenceError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
