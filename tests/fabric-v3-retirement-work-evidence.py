#!/usr/bin/env python3
"""Validate durable Fabric retirement evidence from the campaign SQLite store."""
from __future__ import annotations

import hashlib
import json
import pathlib
import sqlite3
import sys
from typing import Any


def work_rows(database: pathlib.Path) -> list[dict[str, Any]]:
    db = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=3)
    db.row_factory = sqlite3.Row
    try:
        rows = db.execute(
            "SELECT rowid AS insertion_order, command_id, operation_id, idempotency_key, "
            "target_host_id, target_agent_id, target_agent_epoch, controller_id, "
            "controller_epoch, fencing_token, fingerprint_sha256, snapshot, state, "
            "revision, created_at, updated_at FROM network_plan_work ORDER BY rowid"
        ).fetchall()
    finally:
        db.close()
    result = []
    for row in rows:
        item = dict(row)
        command = json.loads(bytes(item.pop("snapshot")))
        plan = command.get("plan", {})
        fabric = plan.get("fabric") or {}
        item.update(
            action=command.get("action"),
            command=command,
            plan=plan,
            fabric=fabric,
            realm_id=fabric.get("realm_id"),
            directory_generation=fabric.get("directory_generation"),
            binding_generation=(fabric.get("encapsulation") or {}).get("binding_generation"),
            local_fabric_generation=fabric.get("local_fabric_generation"),
            participants=sorted(
                {entry.get("selected_host") for entry in (fabric.get("directory") or {}).get("entries", [])}
            ),
            peers=sorted(peer.get("host_id") for peer in fabric.get("peers", [])),
        )
        result.append(item)
    return result


def realm_rows(database: pathlib.Path, realm_id: str) -> list[dict[str, Any]]:
    return [row for row in work_rows(database) if row["realm_id"] == realm_id]


def latest_by_host(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        latest[row["target_host_id"]] = row
    return latest


def command_evidence(row: dict[str, Any]) -> dict[str, Any]:
    return {
        key: row.get(key)
        for key in (
            "insertion_order",
            "command_id",
            "operation_id",
            "idempotency_key",
            "target_host_id",
            "target_agent_id",
            "target_agent_epoch",
            "controller_id",
            "controller_epoch",
            "fencing_token",
            "action",
            "state",
            "revision",
            "directory_generation",
            "binding_generation",
            "local_fabric_generation",
            "created_at",
            "updated_at",
        )
    }


def observe_remove_work_row(
    database: pathlib.Path,
    realm_id: str,
    timeout: float = 3.0,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "found": False,
        "observation_status": "error",
        "operation": "read_c_remove_work_row",
        "observer_type": "sqlite_read_only",
        "resource_class": "durable_network_plan_work",
        "command_class": "sqlite_read_only_work_observation",
    }
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"file:{database}?mode=ro", uri=True, timeout=timeout
        )
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT rowid AS insertion_order,command_id,operation_id,idempotency_key,"
            "target_host_id,target_agent_id,target_agent_epoch,controller_id,"
            "controller_epoch,fencing_token,fingerprint_sha256,snapshot,state,revision,"
            "outcome,created_at,updated_at FROM network_plan_work "
            "WHERE target_host_id='host-c' ORDER BY rowid DESC"
        ).fetchall()
        matches = []
        for row in rows:
            snapshot = bytes(row["snapshot"])
            command = json.loads(snapshot)
            plan = command.get("plan", {})
            fabric = plan.get("fabric", {}) if isinstance(plan, dict) else {}
            if command.get("action") == "Remove" and fabric.get("realm_id") == realm_id:
                item = {
                    key: row[key]
                    for key in (
                        "insertion_order",
                        "command_id",
                        "operation_id",
                        "idempotency_key",
                        "target_host_id",
                        "target_agent_id",
                        "target_agent_epoch",
                        "controller_id",
                        "controller_epoch",
                        "fencing_token",
                        "fingerprint_sha256",
                        "state",
                        "revision",
                        "created_at",
                        "updated_at",
                    )
                }
                outcome = row["outcome"]
                item.update(
                    action="Remove",
                    realm_id=realm_id,
                    directory_generation=fabric.get("directory_generation"),
                    binding_generation=(fabric.get("encapsulation") or {}).get(
                        "binding_generation"
                    ),
                    fabric_generation=fabric.get("local_fabric_generation"),
                    snapshot_sha256=hashlib.sha256(snapshot).hexdigest(),
                    outcome_sha256=(
                        hashlib.sha256(bytes(outcome)).hexdigest()
                        if outcome is not None
                        else None
                    ),
                )
                matches.append(item)
        result.update(
            found=bool(matches),
            observation_status="complete",
        )
        if matches:
            result.update(matches[0])
    except (sqlite3.Error, ValueError, TypeError, KeyError, IndexError) as exc:
        result["diagnostic"] = {
            "exception_type": type(exc).__name__,
            "sqlite_errorcode": getattr(exc, "sqlite_errorcode", None),
            "sqlite_errorname": getattr(exc, "sqlite_errorname", None),
            "message": str(exc)[:300],
        }
    finally:
        if connection is not None:
            connection.close()
    return result


def classify_observation_failure(result: dict[str, Any], phase_class: str) -> str:
    diagnostic = result.get("diagnostic") or {}
    if diagnostic.get("sqlite_errorname") in {
        "SQLITE_BUSY",
        "SQLITE_LOCKED",
        "SQLITE_CORRUPT",
        "SQLITE_IOERR",
        "SQLITE_ERROR",
        "SQLITE_SCHEMA",
        "SQLITE_NOTADB",
    }:
        return phase_class
    return "HARNESS_GAP"


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def verify_before(
    database: pathlib.Path,
    realm_id: str,
    plans_dir: pathlib.Path,
    ownership_dir: pathlib.Path,
    fdb_dir: pathlib.Path,
) -> dict[str, Any]:
    rows = realm_rows(database, realm_id)
    latest = latest_by_host(rows)
    hosts = {"host-a", "host-b", "host-c"}
    if set(latest) != hosts:
        raise ValueError(f"current durable Fabric hosts differ: {sorted(latest)}")
    generations = set()
    her: dict[str, dict[str, list[str]]] = {}
    for host in sorted(hosts):
        row = latest[host]
        expected_peers = hosts - {host}
        if row["action"] != "Apply" or row["state"] != "succeeded":
            raise ValueError(f"latest {host} work is not a successful Apply: {command_evidence(row)}")
        if row["target_agent_id"] != f"network-agent-{host[-1]}" or not row["target_agent_epoch"]:
            raise ValueError(f"latest {host} Apply target identity is incomplete: {command_evidence(row)}")
        if set(row["participants"]) != hosts or set(row["peers"]) != expected_peers:
            raise ValueError(f"latest {host} Apply has wrong participants/HER: {row}")
        generations.add(row["directory_generation"])

        plan = read_json(plans_dir / f"host-{host[-1]}-fabric-plan.json")
        if plan.get("realm_id") != realm_id or plan.get("local_host") != host:
            raise ValueError(f"provider plan identity mismatch for {host}: {plan}")
        if plan.get("directory_generation") != row["directory_generation"]:
            raise ValueError(f"provider plan generation differs from durable Apply for {host}")
        plan_hosts = {entry.get("selected_host") for entry in (plan.get("directory") or {}).get("entries", [])}
        plan_peers = {peer.get("host_id") for peer in plan.get("peers", [])}
        if plan_hosts != hosts or plan_peers != expected_peers:
            raise ValueError(f"provider plan participants/HER differ for {host}: {plan_hosts}/{plan_peers}")

        ownership = read_json(ownership_dir / f"host-{host[-1]}-ownership.json")
        realm = (ownership.get("realms") or {}).get(realm_id)
        if not realm:
            raise ValueError(f"provider ownership has no current Realm on {host}")
        flood = set((realm.get("vxlan") or {}).get("flood_peers", []))
        expected_ips = {peer.get("fabric_transport_ip") for peer in plan.get("peers", [])}
        if flood != expected_ips:
            raise ValueError(f"runtime HER differs for {host}: expected {expected_ips}, observed {flood}")
        fdb_text = (fdb_dir / f"host-{host[-1]}-her-fdb.txt").read_text()
        fdb_ips = {
            line.split(" dst ", 1)[1].split()[0]
            for line in fdb_text.splitlines()
            if line.startswith("00:00:00:00:00:00 ") and " dst " in line
        }
        if fdb_ips != expected_ips:
            raise ValueError(f"runtime FDB differs for {host}: expected {expected_ips}, observed {fdb_ips}")
        her[host] = {"participants": sorted(plan_hosts), "peers": sorted(plan_peers), "transport_ips": sorted(expected_ips)}
    if len(generations) != 1 or None in generations:
        raise ValueError(f"current Realm generation differs across hosts: {generations}")
    return {
        "realm_id": realm_id,
        "realm_generation": next(iter(generations)),
        "participants": sorted(hosts),
        "her": her,
        "latest_apply_by_host": {host: command_evidence(latest[host]) for host in sorted(hosts)},
        "latest_c_apply_insertion_order": latest["host-c"]["insertion_order"],
    }


def verify_order(database: pathlib.Path, realm_id: str, before_path: pathlib.Path) -> dict[str, Any]:
    before = read_json(before_path)
    if before.get("realm_id") != realm_id:
        raise ValueError("pre-delete evidence belongs to another Realm")
    rows = realm_rows(database, realm_id)
    prior_order = int(before["latest_c_apply_insertion_order"])
    prior_generation = int(before["realm_generation"])
    remove_rows = [
        row
        for row in rows
        if row["target_host_id"] == "host-c"
        and row["action"] == "Remove"
        and int(row["insertion_order"]) > prior_order
        and row["target_agent_id"] == "network-agent-c"
    ]
    successful_removes = [row for row in remove_rows if row["state"] == "succeeded"]
    if not successful_removes:
        raise ValueError(f"no successful durable C Remove after prior Apply: {remove_rows}")
    remove = successful_removes[0]
    survivor_apply: dict[str, dict[str, Any]] = {}
    for host in ("host-a", "host-b"):
        candidates = [
            row
            for row in rows
            if row["target_host_id"] == host
            and row["action"] == "Apply"
            and row["state"] == "succeeded"
            and row["participants"] == ["host-a", "host-b"]
            and row["directory_generation"] is not None
            and int(row["directory_generation"]) > prior_generation
        ]
        if not candidates:
            raise ValueError(f"no successful reduced-generation Apply for {host}")
        apply = candidates[0]
        if int(remove["insertion_order"]) >= int(apply["insertion_order"]):
            raise ValueError(
                f"survivor Apply was durably admitted before C Remove: {command_evidence(remove)} / {command_evidence(apply)}"
            )
        if apply["target_agent_id"] != f"network-agent-{host[-1]}" or not apply["target_agent_epoch"]:
            raise ValueError(f"survivor Apply target identity is incomplete: {command_evidence(apply)}")
        survivor_apply[host] = command_evidence(apply)

    later_c_apply = [
        row for row in rows
        if row["target_host_id"] == "host-c"
        and row["action"] == "Apply"
        and int(row["insertion_order"]) > int(remove["insertion_order"])
    ]
    if later_c_apply:
        raise ValueError(f"C Apply appears after retirement Remove: {later_c_apply}")
    return {
        "realm_id": realm_id,
        "prior_c_apply": before["latest_apply_by_host"]["host-c"],
        "c_remove": command_evidence(remove),
        "survivor_apply": survivor_apply,
        "ordering": "C Remove durable work precedes reduced-generation A/B Apply work",
    }


def verify_after_restart(
    database: pathlib.Path,
    realm_id: str,
    cutoff: int,
) -> dict[str, Any]:
    rows = realm_rows(database, realm_id)
    new_rows = [row for row in rows if int(row["insertion_order"]) > cutoff]
    new_c_apply = [row for row in new_rows if row["target_host_id"] == "host-c" and row["action"] == "Apply"]
    if new_c_apply:
        raise ValueError(f"controller restart recreated a C Apply: {new_c_apply}")
    latest_c = latest_by_host([row for row in rows if row["target_host_id"] == "host-c"]).get("host-c")
    if not latest_c or latest_c["action"] != "Remove" or latest_c["state"] != "succeeded":
        raise ValueError(f"C is not durably retired after controller restart: {latest_c}")
    return {
        "realm_id": realm_id,
        "post_restart_rows": [command_evidence(row) for row in new_rows],
        "c_apply_recreated": False,
        "latest_c_work": command_evidence(latest_c),
    }


def verify_survivors(
    realm_id: str,
    plans_dir: pathlib.Path,
    ownership_dir: pathlib.Path,
    fdb_dir: pathlib.Path,
    journals_dir: pathlib.Path,
    c_endpoint: str,
) -> dict[str, Any]:
    expected_hosts = {"host-a", "host-b"}
    generation: int | None = None
    result: dict[str, Any] = {}
    for host in sorted(expected_hosts):
        plan = read_json(plans_dir / f"host-{host[-1]}-fabric-plan.json")
        if plan.get("realm_id") != realm_id or plan.get("local_host") != host:
            raise ValueError(f"survivor plan identity mismatch for {host}")
        participants = {entry.get("selected_host") for entry in (plan.get("directory") or {}).get("entries", [])}
        peers = {peer.get("host_id") for peer in plan.get("peers", [])}
        expected_peers = expected_hosts - {host}
        if participants != expected_hosts or peers != expected_peers:
            raise ValueError(f"survivor plan contains stale participant/HER state for {host}: {participants}/{peers}")
        current_generation = int(plan["directory_generation"])
        before_path = plans_dir / f"host-{host[-1]}-plan-before.json"
        if before_path.exists():
            before = read_json(before_path)
            if int(before["directory_generation"]) >= current_generation:
                raise ValueError(
                    f"survivor generation did not advance after C departure for {host}"
                )
        if generation is None:
            generation = current_generation
        elif generation != current_generation:
            raise ValueError(f"survivor plan generations differ: {generation}/{current_generation}")

        ownership = read_json(ownership_dir / f"host-{host[-1]}-ownership.json")
        realm = (ownership.get("realms") or {}).get(realm_id)
        if not realm or c_endpoint in realm.get("endpoint_taps", {}) or c_endpoint in realm.get("pending_endpoint_taps", {}):
            raise ValueError(f"survivor ownership has stale C endpoint state on {host}")
        expected_ips = {peer.get("fabric_transport_ip") for peer in plan.get("peers", [])}
        flood = set((realm.get("vxlan") or {}).get("flood_peers", []))
        if flood != expected_ips:
            raise ValueError(f"survivor runtime HER differs on {host}: {flood}/{expected_ips}")
        fdb_text = (fdb_dir / f"host-{host[-1]}-her-fdb.txt").read_text()
        fdb_ips = {
            line.split(" dst ", 1)[1].split()[0]
            for line in fdb_text.splitlines()
            if line.startswith("00:00:00:00:00:00 ") and " dst " in line
        }
        if fdb_ips != expected_ips:
            raise ValueError(f"survivor runtime FDB differs on {host}: {fdb_ips}/{expected_ips}")

        journal = read_json(journals_dir / f"host-{host[-1]}-command-journal.json")
        applies = [
            command
            for command in journal.get("plans", [])
            if command.get("action") == "Apply"
            and command.get("target", {}).get("agent_id") == f"network-agent-{host[-1]}"
            and command.get("plan", {}).get("fabric", {}).get("realm_id") == realm_id
        ]
        if not applies or applies[-1].get("status") != "Succeeded":
            raise ValueError(f"survivor Apply is not observed successful for {host}")
        result[host] = {
            "participants": sorted(participants),
            "her": sorted(peers),
            "transport_ips": sorted(expected_ips),
            "directory_generation": current_generation,
            "latest_apply_command_id": applies[-1].get("command_id"),
        }

    c_ownership = read_json(ownership_dir / "host-c-ownership.json")
    if realm_id in c_ownership.get("realms", {}):
        raise ValueError("retired host C regained local Realm ownership")
    c_journal = read_json(journals_dir / "host-c-command-journal.json")
    c_commands = [
        command
        for command in c_journal.get("plans", [])
        if command.get("plan", {}).get("fabric", {}).get("realm_id") == realm_id
    ]
    if not c_commands or c_commands[-1].get("action") != "Remove" or c_commands[-1].get("status") != "Succeeded":
        raise ValueError("network-agent-c journal no longer ends in observed-successful Remove")
    return {
        "realm_id": realm_id,
        "directory_generation": generation,
        "participants": sorted(expected_hosts),
        "survivors": result,
        "retired_host_c_absent": True,
        "c_latest_agent_command": {
            key: c_commands[-1].get(key)
            for key in ("command_id", "operation_id", "idempotency_key", "action", "status")
        },
    }


def main(args: list[str]) -> None:
    mode = args[0]
    if mode == "observe-remove" and len(args) == 5:
        result = observe_remove_work_row(pathlib.Path(args[1]), args[2])
        output = pathlib.Path(args[3])
        history = pathlib.Path(args[4])
        output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        if result["observation_status"] != "complete":
            raise SystemExit(2)
        if result["found"]:
            line = json.dumps(
                {
                    key: result.get(key)
                    for key in ("command_id", "state", "revision", "updated_at")
                },
                sort_keys=True,
            )
            previous = history.read_text().splitlines() if history.exists() else []
            if not previous or previous[-1] != line:
                with history.open("a") as stream:
                    stream.write(line + "\n")
        print(result.get("state", ""))
    elif mode == "classify-observation" and len(args) == 3:
        result = read_json(pathlib.Path(args[1]))
        print(classify_observation_failure(result, args[2]))
    elif mode == "before" and len(args) == 7:
        result = verify_before(*(pathlib.Path(arg) for arg in (args[1],)), args[2], *(pathlib.Path(arg) for arg in args[3:6]))
        pathlib.Path(args[6]).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    elif mode == "order" and len(args) == 5:
        result = verify_order(pathlib.Path(args[1]), args[2], pathlib.Path(args[3]))
        pathlib.Path(args[4]).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    elif mode == "after-restart" and len(args) == 5:
        result = verify_after_restart(pathlib.Path(args[1]), args[2], int(args[3]))
        pathlib.Path(args[4]).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    elif mode == "survivors" and len(args) == 8:
        result = verify_survivors(args[1], *(pathlib.Path(arg) for arg in args[2:6]), args[6])
        pathlib.Path(args[7]).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    else:
        raise ValueError("usage: before DB REALM PLANS OWNERSHIP FDB OUT | order DB REALM BEFORE OUT | after-restart DB REALM ROWID OUT")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"retirement evidence invalid: {error}", file=sys.stderr)
        raise SystemExit(1)
