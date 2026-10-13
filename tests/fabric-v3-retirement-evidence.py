#!/usr/bin/env python3
"""Validate durable C retirement and observed A/B convergence evidence."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys
from typing import Any


class SurvivorReconciliationDefect(AssertionError):
    """Observed survivor state still contains a departing-host FDB entry."""


def _read(path: Path) -> Any:
    return json.loads(path.read_text())


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate(root: Path, realm: str, ports: list[str]) -> dict[str, Any]:
    if len(ports) != 3:
        raise ValueError("exactly three campaign ports are required")
    before = _read(root / "before-departure/plans/host-a.json")
    before_generation = int(before["directory_generation"])
    identities = _read(root / "environment/fabric-identities.json")
    transport = {entry["host_id"]: entry["fabric_transport_ip"] for entry in identities}
    assert set(transport) >= {"host-a", "host-b", "host-c"}, transport

    work = _read(root / "survivor-convergence/plans/durable-work.json")
    history = work["history"]
    latest: dict[str, dict[str, Any]] = {}
    for host in ("host-a", "host-b", "host-c"):
        rows = [row for row in history if row["target_host_id"] == host]
        assert rows, f"durable work history missing {host}"
        latest[host] = max(rows, key=lambda row: int(row["insertion_order"]))

    remove = _read(root / "c-delete/remove-command/c-remove-command.json")
    remove_matches = remove.get("matches", [])
    assert remove.get("found") is True and remove_matches, remove
    assert remove_matches[0]["command_id"] == remove["command_id"], remove_matches
    assert int(remove_matches[0]["insertion_order"]) == max(
        int(row["insertion_order"]) for row in remove_matches
    ), remove_matches
    c_latest = latest["host-c"]
    assert c_latest["action"] == "Remove", c_latest
    assert c_latest["state"] == "succeeded", c_latest
    assert c_latest["command_id"] == remove["command_id"], (c_latest, remove)
    assert c_latest["target_host_id"] == remove["local_host"] == "host-c", (c_latest, remove)
    assert remove_matches[0]["target_host_id"] == "host-c", remove_matches
    assert c_latest["target_agent_id"] == "network-agent-c", c_latest
    assert c_latest["target_agent_epoch"] == remove["target_agent_epoch"] and remove["target_agent_epoch"], (c_latest, remove)
    assert remove.get("outcome"), remove
    assert int(c_latest["insertion_order"]) > int(
        _read(root / "c-delete/retirement-obligation/c-prior-apply.json")["c_prior_apply"]["insertion_order"]
    ), c_latest
    assert not [
        row for row in history
        if row["target_host_id"] == "host-c"
        and row["state"].lower() in {"applying", "running", "unknown", "unknown_outcome", "retryable", "not_found"}
    ], history

    summary: dict[str, Any] = {}
    survivor_rows = []
    for host, peer, own_port, peer_port in (
        ("host-a", "host-b", ports[0], ports[1]),
        ("host-b", "host-a", ports[1], ports[0]),
    ):
        directory = root / "survivor-convergence"
        ownership = _read(directory / f"{host}/ownership.json")
        assert realm in ownership.get("realms", {}), (host, ownership)
        local = ownership["realms"][realm]
        plan = _read(directory / f"{host}/plan.json")
        assert plan.get("realm_id") == realm and plan.get("local_host") == host, (host, plan)
        entries = plan.get("directory", {}).get("entries", [])
        participants = {entry.get("selected_host") for entry in entries}
        assert participants == {"host-a", "host-b"}, (host, entries)
        endpoint_hosts = {entry.get("endpoint_id"): entry.get("selected_host") for entry in entries}
        assert endpoint_hosts == {ports[0]: "host-a", ports[1]: "host-b"}, (host, endpoint_hosts)
        her_peers = {entry.get("host_id") for entry in plan.get("peers", [])}
        assert her_peers == {peer}, (host, her_peers)
        assert int(plan["directory_generation"]) > before_generation, (host, plan, before_generation)
        assert int(plan["directory_generation"]) == int(local["directory_generation"]), (host, plan, local)
        assert int(plan["local_fabric_generation"]) == int(local["local_fabric_generation"]), (host, plan, local)

        expected_peer_ip = transport[peer]
        peers = local["vxlan"]["flood_peers"]
        assert peers == [expected_peer_ip], (host, peers, expected_peer_ip)
        fdb = (directory / f"{host}/fdb.txt").read_text().splitlines()
        destinations = {
            line.split("dst ", 1)[1].split()[0]
            for line in fdb
            if line.startswith("00:00:00:00:00:00 ") and " dst " in line
        }
        departing_ip = transport["host-c"]
        learned_departing = [
            line for line in fdb
            if " dst " in line
            and line.split(" dst ", 1)[1].split()[0] == departing_ip
            and line.split()[0].lower() != "00:00:00:00:00:00"
        ]
        if learned_departing:
            raise SurvivorReconciliationDefect(
                f"{host} survivor FDB retains learned departing host {departing_ip}: "
                f"{learned_departing}"
            )
        assert destinations == {expected_peer_ip}, (host, destinations, fdb)

        journal = _read(directory / f"{host}/command-journal.json")
        applied = [
            command for command in journal.get("plans", [])
            if command.get("action") == "Apply"
            and command.get("plan", {}).get("fabric", {}).get("realm_id") == realm
            and command.get("target", {}).get("agent_id") == f"network-agent-{host[-1]}"
        ]
        assert applied and applied[-1].get("status") == "Succeeded", (host, applied[-1] if applied else None)

        current = latest[host]
        assert current["action"] == "Apply" and current["state"] == "succeeded", current
        assert current["target_agent_id"] == f"network-agent-{host[-1]}", current
        assert current["participants"] == ["host-a", "host-b"], current
        assert current["her_peers"] == [peer], current
        assert int(current["insertion_order"]) > int(c_latest["insertion_order"]), (c_latest, current)
        assert _time(current["created_at"]) >= _time(c_latest["created_at"]), (c_latest, current)
        assert _time(current["updated_at"]) >= _time(c_latest["updated_at"]), (c_latest, current)
        survivor_rows.append(current)
        summary[host] = {
            "directory_generation": plan["directory_generation"],
            "local_fabric_generation": plan["local_fabric_generation"],
            "participants": sorted(participants),
            "HER_peers": sorted(her_peers),
            "flood_peers": peers,
            "FDB_destinations": sorted(destinations),
            "latest_apply_command_id": current["command_id"],
            "latest_apply_state": current["state"],
        }

    c_ownership = _read(root / "provider-absence/host-c/ownership/ownership.json")
    assert realm not in c_ownership.get("realms", {}), c_ownership.get("realms", {})
    assert not any(
        ports[2] in realm_state.get("endpoint_taps", {})
        or ports[2] in realm_state.get("pending_endpoint_taps", {})
        for realm_state in c_ownership.get("realms", {}).values()
    ), c_ownership

    return {
        "realm_id": realm,
        "prior_directory_generation": before_generation,
        "c_remove": remove,
        "c_remove_latest_history": c_latest,
        "survivors": summary,
        "removal_before_survivor_convergence": True,
        "stale_c_her": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--realm", required=True)
    parser.add_argument("--ports", nargs=3, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = validate(args.root, args.realm, args.ports)
    except SurvivorReconciliationDefect as error:
        print(f"SURVIVOR_RECONCILIATION_DEFECT: {error}", file=sys.stderr)
        return 3
    except AssertionError as error:
        # A well-formed snapshot that has not reached the retirement predicates
        # is retryable by the caller's bounded convergence poll.
        print(f"retirement evidence not converged: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        # Missing fields, malformed JSON, failed reads, and unexpected observer
        # errors are harness failures. Do not let the polling shell reinterpret
        # them as an O3K reconciliation defect.
        print(f"invalid retirement evidence: {type(error).__name__}", file=sys.stderr)
        return 2
    try:
        rendered = json.dumps(result, sort_keys=True, indent=2) + "\n"
        if args.output:
            args.output.write_text(rendered)
        else:
            print(rendered, end="")
    except Exception as error:
        print(f"retirement evidence output failure: {type(error).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
