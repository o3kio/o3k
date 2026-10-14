#!/usr/bin/env python3
"""Capture durable port-unbind evidence without conflating legacy status."""

import json
import os
from pathlib import Path
import sqlite3
import sys


class HarnessEvidenceError(Exception):
    """The read-only evidence source or output is unavailable."""


def inspect(database: Path, port_id: str) -> dict:
    if not database.is_file() or database.is_symlink():
        raise HarnessEvidenceError("controller evidence database is unavailable")

    try:
        connection = sqlite3.connect(
            f"{database.resolve().as_uri()}?mode=ro",
            uri=True,
            timeout=3,
        )
        connection.row_factory = sqlite3.Row
    except sqlite3.Error as error:
        raise HarnessEvidenceError("controller evidence database is unreadable") from error

    try:
        row = connection.execute(
            "SELECT id, status, binding_host, binding_state FROM network_ports WHERE id = ?",
            (port_id,),
        ).fetchone()
        value = dict(row) if row is not None else None
    except sqlite3.Error as error:
        raise HarnessEvidenceError("durable port binding query failed") from error
    finally:
        connection.close()

    if value is None:
        return {
            "port_id": port_id,
            "found": False,
            "status": None,
            "binding_host": None,
            "binding_state": None,
            "unbound_down_tombstone": False,
            "status_semantics": "legacy endpoint lifecycle field; public Neutron status is checked separately",
        }

    return {
        "port_id": port_id,
        "found": True,
        "status": value["status"],
        "binding_host": value["binding_host"],
        "binding_state": value["binding_state"],
        "unbound_down_tombstone": value["binding_host"] is None
        and value["binding_state"] == "down",
        "status_semantics": "legacy endpoint lifecycle field; public Neutron status is checked separately",
    }


def write_evidence(output: Path, evidence: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(evidence, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(arguments: list[str]) -> int:
    if len(arguments) != 3:
        print(
            "usage: fabric-v3-port-detach-evidence.py DB PORT_ID OUTPUT",
            file=sys.stderr,
        )
        return 2

    database, port_id, output = arguments
    try:
        evidence = inspect(Path(database), port_id)
        write_evidence(Path(output), evidence)
    except (HarnessEvidenceError, OSError) as error:
        print(f"HARNESS_GAP: {error}", file=sys.stderr)
        return 2

    if not evidence["unbound_down_tombstone"]:
        print("PORT_STATUS_DEFECT: durable port binding is not unbound/down", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
