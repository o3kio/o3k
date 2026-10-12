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


def capture_agent_readiness(
    response_text: str, host: str, expected_agent_id: str
) -> tuple[dict[str, Any], int]:
    """Normalize one live agent /readyz response without retaining response details."""
    base: dict[str, Any] = {
        "schema_version": 1,
        "artifact_type": "fabric-v3-current-compute-agent-readiness",
        "host": host,
        "observer": "ssh_sudo_local_readyz",
    }
    if not host.strip() or not expected_agent_id.strip():
        return {**base, "status": "failed", "diagnostic": "missing_expected_identity"}, 2
    match = re.search(r"(?:\A|\n)__O3K_HTTP_STATUS=(\d{3})\s*\Z", response_text)
    if not match:
        return {**base, "status": "failed", "diagnostic": "missing_http_status"}, 2

    http_status = int(match.group(1))
    evidence = {**base, "http_status": http_status}
    if http_status == 503:
        return {**evidence, "status": "pending", "diagnostic": "agent_not_ready"}, 1
    if http_status != 200:
        return {**evidence, "status": "failed", "diagnostic": "unexpected_http_status"}, 4

    body = response_text[: match.start()].rstrip("\r\n")
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        return {**evidence, "status": "failed", "diagnostic": "malformed_ready_json"}, 4
    if not isinstance(value, dict):
        return {**evidence, "status": "failed", "diagnostic": "malformed_ready_json"}, 4
    if value.get("status") != "ready":
        return {**evidence, "status": "failed", "diagnostic": "invalid_ready_status"}, 4

    agent_id = value.get("agent_id")
    epoch = value.get("agent_epoch")
    if not isinstance(agent_id, str) or not agent_id.strip():
        return {**evidence, "status": "failed", "diagnostic": "missing_agent_id"}, 4
    if agent_id != expected_agent_id:
        return {
            **evidence,
            "status": "failed",
            "diagnostic": "agent_identity_changed",
            "expected_agent_id": expected_agent_id,
            "observed_agent_id": agent_id,
        }, 3
    if not isinstance(epoch, str) or not epoch.strip():
        return {**evidence, "status": "failed", "diagnostic": "missing_agent_epoch"}, 4
    return {
        **evidence,
        "status": "ready",
        "agent_id": agent_id,
        "agent_epoch": epoch,
    }, 0


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


def _write_evidence(path: pathlib.Path, evidence: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture-agent-ready")
    capture.add_argument("--response", required=True, type=pathlib.Path)
    capture.add_argument("--host", required=True)
    capture.add_argument("--expected-agent-id", required=True)
    capture.add_argument("--output", required=True, type=pathlib.Path)

    observe = commands.add_parser("observe-controller-restart")
    observe.add_argument("--log", required=True, type=pathlib.Path)
    observe.add_argument("--controller-id", required=True)
    observe.add_argument("--controller-epoch", required=True)
    observe.add_argument("--agent", action="append", required=True, metavar="ID=EPOCH")
    observe.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    if args.command == "capture-agent-ready":
        try:
            response_text = args.response.read_text(encoding="utf-8")
        except OSError as error:
            evidence = {
                "schema_version": 1,
                "artifact_type": "fabric-v3-current-compute-agent-readiness",
                "host": args.host,
                "observer": "ssh_sudo_local_readyz",
                "status": "failed",
                "diagnostic": f"response_read_{type(error).__name__}",
            }
            _write_evidence(args.output, evidence)
            print("cannot read current agent readiness response", file=sys.stderr)
            return 2
        evidence, status = capture_agent_readiness(
            response_text, args.host, args.expected_agent_id
        )
        _write_evidence(args.output, evidence)
        if status == 2:
            print("current agent readiness response is invalid", file=sys.stderr)
        elif status == 3:
            print("current compute agent identity changed after controller restart", file=sys.stderr)
        elif status == 4:
            print("current compute agent returned an invalid readiness response", file=sys.stderr)
        return status

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
    _write_evidence(args.output, evidence)
    return 0 if evidence["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
