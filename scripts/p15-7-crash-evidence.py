#!/usr/bin/env python3
"""Atomically persist incremental #1035 crash-window evidence."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


PHASES = (
    "fault_armed",
    "terminal_state_observed",
    "endpoint_present_pre_crash",
    "process_killed",
    "process_restarted",
    "repair_lock_acquired",
    "contending_create_started",
    "contending_create_accepted",
    "orphan_discovered",
    "repair_completed",
    "accounting_verified",
    "completed",
)


def main() -> int:
    if len(sys.argv) < 4 or len(sys.argv[4:]) % 2:
        print("usage: p15-7-crash-evidence.py PATH PHASE STATUS [KEY VALUE ...]", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    phase, status = sys.argv[2:4]
    if phase not in PHASES or status not in {"running", "failed", "passed"}:
        print("invalid crash evidence phase or status", file=sys.stderr)
        return 2
    values = dict(zip(sys.argv[4::2], sys.argv[5::2], strict=True))
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        current = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, ValueError) as error:
        print(f"cannot read existing crash evidence: {error}", file=sys.stderr)
        return 1
    checkpoints = current.get("checkpoints", [])
    if not isinstance(checkpoints, list):
        print("existing checkpoints field is invalid", file=sys.stderr)
        return 1
    checkpoint = {"phase": phase, "status": status, **values}
    checkpoints.append(checkpoint)
    current.update(
        artifact_type="o3k-p15-7-crash-injection-evidence",
        schema_version=2,
        status=status,
        phase=phase,
        checkpoints=checkpoints,
    )
    if status == "failed":
        current["failure_phase"] = values.get("failure_phase", phase)
    elif phase == "completed" and status == "passed":
        current.pop("failure_phase", None)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(current, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
