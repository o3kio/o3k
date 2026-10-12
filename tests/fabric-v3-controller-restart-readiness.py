#!/usr/bin/env python3
"""Build secret-free evidence that a restarted controller and its agents are current."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from datetime import datetime, timezone
from typing import Any


def _field(line: str, name: str) -> str | None:
    match = re.search(
        rf"(?:^|\s){re.escape(name)}=(?:\"([^\"]*)\"|'([^']*)'|([^\s,]+))",
        line,
    )
    if not match:
        return None
    return next((value for value in match.groups() if value is not None), None)


def _event_fields(line: str) -> tuple[str, dict[str, Any]]:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return line, {}
    if not isinstance(value, dict):
        return line, {}
    fields = value.get("fields")
    if not isinstance(fields, dict):
        fields = value
    message = fields.get("message")
    if not isinstance(message, str):
        message = line
    return message, fields


def parse_readiness(
    log_text: str,
    expected_controller_id: str,
    expected_controller_epoch: str,
    expected_agents: dict[str, str],
) -> dict[str, Any]:
    controller_seen: dict[str, Any] | None = None
    agents: dict[str, dict[str, Any]] = {}
    for line_number, line in enumerate(log_text.splitlines(), start=1):
        message, fields = _event_fields(line)
        if "controller session registered" in message:
            controller_id = fields.get("controller_id") or _field(line, "controller_id")
            controller_epoch = fields.get("controller_epoch") or _field(line, "controller_epoch")
            if isinstance(controller_id, str) and isinstance(controller_epoch, str):
                controller_seen = {
                    "identity": controller_id,
                    "epoch": controller_epoch,
                    "line": line_number,
                }
        if "compute agent registered" in message:
            agent_id = fields.get("agent_id") or _field(line, "agent_id")
            epoch = fields.get("epoch") or fields.get("agent_epoch") or _field(line, "epoch")
            if (
                isinstance(agent_id, str)
                and isinstance(epoch, str)
                and agent_id in expected_agents
                and controller_seen
                and controller_seen["identity"] == expected_controller_id
                and controller_seen["epoch"] == expected_controller_epoch
                and line_number > controller_seen["line"]
            ):
                agents[agent_id] = {"epoch": epoch, "line": line_number}

    missing = sorted(set(expected_agents) - agents.keys())
    mismatched = {
        agent_id: {"expected_epoch": expected_agents[agent_id], "observed_epoch": agents[agent_id]["epoch"]}
        for agent_id in sorted(set(expected_agents) & agents.keys())
        if agents[agent_id]["epoch"] != expected_agents[agent_id]
    }
    session_matches = bool(
        controller_seen
        and controller_seen["identity"] == expected_controller_id
        and controller_seen["epoch"] == expected_controller_epoch
    )
    all_agents_registered = not missing and not mismatched
    passed = session_matches and all_agents_registered
    return {
        "schema_version": 1,
        "artifact_type": "fabric-v3-controller-restart-readiness",
        "status": "passed" if passed else "pending",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "observer": "replacement_controller_log",
        "controller_session_matches": session_matches,
        "expected_controller_session": {
            "identity": expected_controller_id,
            "epoch": expected_controller_epoch,
        },
        "observed_controller_session": controller_seen,
        "expected_compute_agents": dict(sorted(expected_agents.items())),
        "registered_compute_agents": agents,
        "missing_compute_agent_ids": missing,
        "mismatched_compute_agent_epochs": mismatched,
        "all_expected_compute_agents_registered": all_agents_registered,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=pathlib.Path)
    parser.add_argument("--controller-id", required=True)
    parser.add_argument("--controller-epoch", required=True)
    parser.add_argument("--agent", action="append", required=True, metavar="ID=EPOCH")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if not args.controller_id.strip() or not args.controller_epoch.strip():
        parser.error("controller identity and epoch must be non-empty")
    expected_agents: dict[str, str] = {}
    for value in args.agent:
        agent_id, separator, epoch = value.partition("=")
        if not separator or not agent_id.strip() or not epoch.strip() or agent_id in expected_agents:
            parser.error("compute agents must have unique non-empty ID=EPOCH values")
        expected_agents[agent_id] = epoch

    try:
        log_text = args.log.read_text(encoding="utf-8")
    except FileNotFoundError:
        log_text = ""
    except OSError as error:
        print(f"cannot read replacement controller log: {type(error).__name__}", file=sys.stderr)
        return 2
    evidence = parse_readiness(log_text, args.controller_id, args.controller_epoch, expected_agents)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if evidence["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
