#!/usr/bin/env python3
"""Fail-closed, atomically persisted #1035 crash evidence state machine."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path


SCHEMA_VERSION = 3
PHASES = (
    "fault_armed",
    "terminal_state_observed",
    "endpoint_present_pre_crash",
    "process_identity_armed",
    "process_killed",
    "process_restarted",
    "repair_lock_acquired",
    "contending_create_waiting",
    "contending_create_started",
    "orphan_discovered",
    "repair_completed",
    "contending_create_accepted",
    "accounting_verified",
    "completed",
)
NEXT_PHASE = {phase: PHASES[index + 1] for index, phase in enumerate(PHASES[:-1])}
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def read_current(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"cannot read existing crash evidence: {error}") from error
    if not isinstance(current, dict):
        raise ValueError("existing crash evidence root is invalid")
    if current.get("artifact_type") != "o3k-p15-7-crash-injection-evidence":
        raise ValueError("existing crash evidence artifact type is invalid")
    if current.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("existing crash evidence schema version is stale")
    checkpoints = current.get("checkpoints")
    if not isinstance(checkpoints, list) or not all(isinstance(item, dict) for item in checkpoints):
        raise ValueError("existing checkpoints field is invalid")
    return current


def context_value(values: dict, current: dict, key: str) -> str | None:
    value = values.get(key, current.get(key))
    if value is None:
        return None
    return str(value)


def validate_context(values: dict, current: dict) -> dict:
    run_id = context_value(values, current, "run_id")
    source_sha = context_value(values, current, "source_sha")
    if not run_id:
        raise ValueError("crash evidence requires run_id")
    if not source_sha or not SHA_RE.fullmatch(source_sha):
        raise ValueError("crash evidence requires a full source_sha")
    context = {"run_id": run_id, "source_sha": source_sha}
    for key in ("server_id", "endpoint_id", "target_resource_id"):
        value = context_value(values, current, key)
        if value:
            context[key] = value
    for key in ("run_id", "source_sha", "server_id", "endpoint_id"):
        old = current.get(key)
        new = context.get(key)
        if old is not None and new is not None and str(old) != str(new):
            raise ValueError(f"crash evidence context changed for {key}")
    if "server_id" in context and "target_resource_id" in context:
        if context["server_id"] != context["target_resource_id"]:
            raise ValueError("crash evidence target resource does not match server")
    return context


def validate_transition(current: dict, phase: str, status: str, values: dict) -> None:
    if phase not in PHASES:
        raise ValueError("invalid crash evidence phase")
    if status not in {"running", "failed", "passed"}:
        raise ValueError("invalid crash evidence status")
    existing_status = current.get("status")
    if existing_status in {"failed", "passed"}:
        raise ValueError("terminal crash evidence cannot be advanced or overwritten")
    checkpoints = current.get("checkpoints", [])
    # Validate the entire persisted prefix before considering the next write.
    # This prevents a hand-edited/stale artifact with a missing middle phase
    # from being extended into an apparently valid run.
    for index, checkpoint in enumerate(checkpoints):
        if index >= len(PHASES) or checkpoint.get("phase") != PHASES[index]:
            raise ValueError("existing crash evidence checkpoint history is not a legal prefix")
        if checkpoint.get("status") not in {"running", "failed", "passed"}:
            raise ValueError("existing crash evidence checkpoint status is invalid")
        if checkpoint.get("status") == "passed" and checkpoint.get("phase") != "completed":
            raise ValueError("only completed crash evidence may be passed")
    if checkpoints:
        previous = checkpoints[-1].get("phase")
        if phase == previous and status == "failed" and checkpoints[-1].get("status") == "running":
            pass
        elif previous not in NEXT_PHASE or NEXT_PHASE[previous] != phase:
            raise ValueError(f"illegal crash evidence transition: {previous} -> {phase}")
    elif phase != PHASES[0]:
        raise ValueError("crash evidence must start at fault_armed")
    if status == "passed" and phase != "completed":
        raise ValueError("only completed crash evidence may be passed")
    if status == "failed":
        failure_phase = values.get("failure_phase", phase)
        if failure_phase != phase or failure_phase not in PHASES:
            raise ValueError("failure_phase must be the current legal phase")


def atomic_write(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    if len(sys.argv) < 4 or len(sys.argv[4:]) % 2:
        return fail("usage: p15-7-crash-evidence.py PATH PHASE STATUS [KEY VALUE ...]")
    path = Path(sys.argv[1])
    phase, status = sys.argv[2:4]
    values = dict(zip(sys.argv[4::2], sys.argv[5::2], strict=True))
    try:
        current = read_current(path)
        validate_transition(current, phase, status, values)
        context = validate_context(values, current)
    except ValueError as error:
        return fail(str(error))

    checkpoints = list(current.get("checkpoints", []))
    checkpoint = {"phase": phase, "status": status, **values, **context}
    checkpoints.append(checkpoint)
    document = {
        **current,
        "artifact_type": "o3k-p15-7-crash-injection-evidence",
        "schema_version": SCHEMA_VERSION,
        **context,
        "status": status,
        "phase": phase,
        "checkpoints": checkpoints,
    }
    if status == "failed":
        document["failure_phase"] = phase
    elif phase == "completed":
        document.pop("failure_phase", None)
    try:
        atomic_write(path, document)
    except OSError as error:
        return fail(f"cannot persist crash evidence atomically: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
