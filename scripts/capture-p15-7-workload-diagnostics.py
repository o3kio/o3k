#!/usr/bin/env python3
"""Write a bounded allowlist-only snapshot for a failed P15.7 workload create."""

from __future__ import annotations

import json
import os
import pathlib
import re
import stat
import sys
import tempfile
import uuid


MAX_RAW_BYTES = 256 * 1024
MAX_EVENT_LINES = 64
MAX_DETAIL_CHARS = 2048
MAX_HOST_STATE_CHARS = 96 * 1024
SERVER_STATES = {"BUILDING", "ACTIVE", "ERROR", "DELETED", "UNKNOWN"}
OPERATION_STATES = {
    "pending", "running", "succeeded", "retryable", "unknown_outcome", "failed"
}
OPERATION_ERROR_CATEGORIES = {
    "invalid_request",
    "unauthenticated",
    "unauthorized",
    "conflict",
    "capacity",
    "not_found",
    "retryable",
    "unknown_outcome",
    "terminal",
    "retry_exhausted",
}
EVENT_MESSAGES = {
    "agent command received",
    "command accepted",
    "command acceptance rejected",
    "command execution completed",
    "command execution failed",
    "create failed definitively; reporting terminal failure",
    "libvirt create request",
    "libvirt create failed",
    "libvirt provider operation failed",
    "libvirt command failed",
}
EVENT_ERROR_KINDS = {
    "configuration",
    "identity_store",
    "transport",
    "tls",
    "network",
    "artifact",
    "libvirt",
    "libvirt_unavailable",
    "libvirt_connection_lost",
    "libvirt_not_found",
    "libvirt_invalid_request",
    "libvirt_operation_failed",
    "journal",
    "protocol",
}


def safe_child(root: pathlib.Path, name: str) -> pathlib.Path:
    path = root / name
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return path
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or path.parent != root:
        raise ValueError("unsafe diagnostic input")
    if metadata.st_size > MAX_RAW_BYTES:
        raise ValueError("diagnostic input exceeds size limit")
    return path


def read_json(root: pathlib.Path, name: str) -> object | None:
    path = safe_child(root, name)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def clean_http(value: str) -> str:
    return value if re.fullmatch(r"[0-9]{3}", value) else "unknown"


def clean_label(value: str) -> str:
    return value if re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", value) else "unknown"


def clean_detail(value: object, limit: int = MAX_DETAIL_CHARS) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.replace("\x00", "?")
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._-]+", "Bearer <redacted>", text)
    text = re.sub(r"(?i)(password|token|private[_ -]?key)=\S+", r"\1=<redacted>", text)
    text = re.sub(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", "<redacted-key>", text, flags=re.S)
    return text[:limit]


def resource_state(document: object) -> str:
    if not isinstance(document, dict):
        return "unavailable"
    status = document.get("status")
    state = status.get("state") if isinstance(status, dict) else None
    return state if isinstance(state, str) and state in SERVER_STATES else "unknown"


def operation_state(document: object) -> str:
    if not isinstance(document, dict):
        return "unavailable"
    state = document.get("state")
    return state if isinstance(state, str) and state in OPERATION_STATES else "unknown"


def operation_error_category(document: object) -> str:
    if not isinstance(document, dict):
        return "unavailable"
    error = document.get("error")
    if not isinstance(error, str):
        return "unknown"
    # The native operation contract exposes a bounded category in `error`.
    # Keep only that finite vocabulary; provider messages and payloads never
    # cross this diagnostic boundary.
    value = error.strip().lower()
    return value if value in OPERATION_ERROR_CATEGORIES else "unknown"


def agent_events(root: pathlib.Path, operation_id: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for agent in ("block-a", "block-b", "block-c", "compute-agent"):
        path = safe_child(root, f"agent-{agent}-events.raw.jsonl")
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-MAX_EVENT_LINES:]
        for line in lines:
            try:
                document = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(document, dict):
                continue
            fields = document.get("fields")
            if not isinstance(fields, dict):
                continue
            message = fields.get("message")
            if message not in EVENT_MESSAGES or fields.get("operation_id") != operation_id:
                continue
            event: dict[str, object] = {"agent": agent, "message": message}
            level = document.get("level")
            if isinstance(level, str) and level in {"TRACE", "DEBUG", "INFO", "WARN", "ERROR"}:
                event["level"] = level
            timestamp = document.get("timestamp")
            if isinstance(timestamp, str) and re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z?", timestamp
            ):
                event["timestamp"] = timestamp[:40]
            action = fields.get("action")
            if isinstance(action, str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", action):
                event["action"] = action
            state = fields.get("state")
            if isinstance(state, int) and not isinstance(state, bool) and 0 <= state <= 6:
                event["state"] = state
            console_bytes = fields.get("console_bytes")
            if isinstance(console_bytes, int) and not isinstance(console_bytes, bool) and 0 <= console_bytes <= 10_000_000:
                event["console_bytes"] = console_bytes
            error_kind = fields.get("error_kind")
            if isinstance(error_kind, str) and error_kind in EVENT_ERROR_KINDS:
                event["error_kind"] = error_kind
            for field in (
                "command_id",
                "resource_id",
                "domain",
                "libvirt_stage",
                "libvirt_operation",
                "libvirt_error_code",
                "libvirt_error_domain",
                "libvirt_error_message",
                "libvirt_detail",
                "error",
            ):
                value = clean_detail(fields.get(field))
                if value is not None:
                    event[field] = value
            events.append(event)
    return events[-MAX_EVENT_LINES:]


def agent_log_probes(root: pathlib.Path) -> list[dict[str, object]]:
    probes: list[dict[str, object]] = []
    for agent in ("block-a", "block-b", "block-c", "compute-agent"):
        path = safe_child(root, f"agent-{agent}-log-probe.raw")
        if not path.exists():
            continue
        value = path.read_text(encoding="ascii", errors="replace").strip()
        probe: dict[str, object] = {"agent": agent}
        if value == "missing":
            probe["status"] = "missing"
        elif value == "unreachable":
            probe["status"] = "unreachable"
        else:
            match = re.fullmatch(r"present ([0-9]+) alive ([01]) ready ([01])", value)
            if not match:
                match = re.fullmatch(r"present ([0-9]+)", value)
                if not match:
                    continue
            probe["status"] = "present"
            probe["bytes"] = int(match.group(1))
            if len(match.groups()) == 3:
                probe["process_alive"] = match.group(2) == "1"
                probe["ready"] = match.group(3) == "1"
        probes.append(probe)
    return probes


def agent_message_probes(root: pathlib.Path, operation_id: str) -> list[dict[str, object]]:
    probes: list[dict[str, object]] = []
    for agent in ("block-a", "block-b", "block-c", "compute-agent"):
        path = safe_child(root, f"agent-{agent}-message-probe.raw.jsonl")
        if not path.exists():
            continue
        counts = {message: 0 for message in EVENT_MESSAGES}
        matching = {message: 0 for message in EVENT_MESSAGES}
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-MAX_EVENT_LINES:]
        for line in lines:
            try:
                document = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(document, dict):
                continue
            fields = document.get("fields")
            if not isinstance(fields, dict):
                continue
            message = fields.get("message")
            if message not in EVENT_MESSAGES:
                continue
            counts[message] += 1
            if fields.get("operation_id") == operation_id:
                matching[message] += 1
        probes.append({
            "agent": agent,
            "message_counts": {key: value for key, value in counts.items() if value},
            "matching_operation_counts": {key: value for key, value in matching.items() if value},
        })
    return probes


def host_state(root: pathlib.Path) -> dict[str, str]:
    states: dict[str, str] = {}
    for label in ("block-a", "compute-agent"):
        path = safe_child(root, f"{label}-host-state.raw")
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        states[label] = clean_detail(text, MAX_HOST_STATE_CHARS) or ""
    return states


def write_atomic(destination: pathlib.Path, document: dict[str, object]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".p15-7-workload.", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    if len(sys.argv) not in (12, 13):
        print(
            "usage: capture-p15-7-workload-diagnostics.py OUTPUT WORK_ROOT SOURCE_SHA RUN_ID RESOURCE_ID OPERATION_ID HOST_A HOST_B DRAIN_ID SERVER_HTTP OPERATION_HTTP [workload-a|workload-b]",
            file=sys.stderr,
        )
        return 2
    (
        output_arg,
        work_root_arg,
        source_sha,
        run_id,
        resource_id,
        operation_id,
        host_a,
        host_b,
        drain_id,
        server_http,
        operation_http,
    ) = sys.argv[1:12]
    workload_label = sys.argv[12] if len(sys.argv) == 13 else "workload-b"
    if not re.fullmatch(r"workload-[ab]", workload_label):
        print("P15.7 workload diagnostics: invalid workload label", file=sys.stderr)
        return 2
    output = pathlib.Path(output_arg)
    work_root = pathlib.Path(work_root_arg)
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_sha):
        print("P15.7 workload diagnostics: invalid source SHA", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9._-]+", run_id):
        print("P15.7 workload diagnostics: invalid run ID", file=sys.stderr)
        return 2
    try:
        resource_id = str(uuid.UUID(resource_id))
        operation_id = str(uuid.UUID(operation_id))
        drain_id = None if workload_label == "workload-a" and drain_id == "none" else str(uuid.UUID(drain_id))
    except ValueError:
        print("P15.7 workload diagnostics: invalid resource identity", file=sys.stderr)
        return 2
    if work_root.is_symlink() or not work_root.is_dir():
        print("P15.7 workload diagnostics: unsafe work root", file=sys.stderr)
        return 2
    marker = safe_child(work_root, ".o3k-owned")
    try:
        marker_lines = marker.read_text(encoding="ascii").splitlines()
    except OSError:
        print("P15.7 workload diagnostics: run ownership is unproven", file=sys.stderr)
        return 2
    if marker_lines != ["o3k-p15-7-journey-owned-v1", f"run={run_id}"]:
        print("P15.7 workload diagnostics: run ownership is unproven", file=sys.stderr)
        return 2

    try:
        server = read_json(work_root, f"{workload_label}-state.raw.json")
        operation = read_json(work_root, f"{workload_label}-operation.raw.json")
        events = agent_events(work_root, operation_id)
        probes = agent_log_probes(work_root)
        message_probes = agent_message_probes(work_root, operation_id)
        host_states = host_state(work_root)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"P15.7 workload diagnostics: safe capture failed ({type(error).__name__})", file=sys.stderr)
        return 2

    write_atomic(
        output,
        {
            "artifact_type": "o3k-p15-7-workload-failure-diagnostics",
            "schema_version": 1,
            "status": "failed",
            "reason": f"{workload_label}_activation_failure",
            "tested_source_sha": source_sha.lower(),
            "run_id": run_id,
            "redacted": True,
            "resource_id": resource_id,
            "operation_id": operation_id,
            "placement_observation": {
                "workload_a_host": clean_label(host_a),
                "workload_b_host": clean_label(host_b),
                "drained_block_id": drain_id,
            },
            "observations": {
                "native_server_http_status": clean_http(server_http),
                "native_server_state": resource_state(server),
                "operation_http_status": clean_http(operation_http),
                "operation_state": operation_state(operation),
                "operation_error_category": operation_error_category(operation),
                "agent_events": events,
                "agent_log_probes": probes,
                "agent_message_probes": message_probes,
                "host_state_at_failure_boundary": host_states,
            },
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
