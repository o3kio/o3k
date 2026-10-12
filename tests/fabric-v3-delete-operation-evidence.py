#!/usr/bin/env python3
"""Capture redacted durable evidence for a supported server DELETE."""

import json
import os
from pathlib import Path
import sqlite3
import sys


class LifecycleEvidenceError(Exception):
    """The accepted DELETE lacks one successful durable terminal record."""


class HarnessEvidenceError(Exception):
    """The harness cannot safely read or write the evidence source."""


def _connect_read_only(database: Path) -> sqlite3.Connection:
    if not database.is_file() or database.is_symlink():
        raise HarnessEvidenceError("controller evidence database is unavailable")
    try:
        connection = sqlite3.connect(
            f"{database.resolve().as_uri()}?mode=ro",
            uri=True,
            timeout=3,
        )
        connection.row_factory = sqlite3.Row
        return connection
    except sqlite3.Error as error:
        raise HarnessEvidenceError("controller evidence database is unreadable") from error


def capture(database: Path, server_id: str, started_at: str, http_status: str) -> dict:
    if http_status != "204":
        raise LifecycleEvidenceError("supported server DELETE did not return HTTP 204")

    connection = _connect_read_only(database)
    try:
        valid_start = connection.execute("SELECT julianday(?)", (started_at,)).fetchone()[0]
        if valid_start is None:
            raise HarnessEvidenceError("DELETE request start time is invalid")

        operations = connection.execute(
            """
            SELECT id, resource_id, kind, state, error_category, created_at
            FROM operations
            WHERE resource_id = ?
              AND kind = 'lifecycle:delete'
              AND julianday(created_at) >= julianday(?)
            ORDER BY created_at, id
            """,
            (server_id, started_at),
        ).fetchall()
        if len(operations) != 1 or operations[0]["state"] != "succeeded":
            raise LifecycleEvidenceError(
                "DELETE did not produce exactly one successful durable lifecycle operation"
            )

        audit_events = connection.execute(
            """
            SELECT event_id, timestamp, request_id, audit_id, service, action,
                   resource_type, resource_id, operation_id, outcome, reason_category
            FROM audit_events
            WHERE service = 'compute'
              AND action = 'compute:DeleteServer'
              AND resource_type = 'compute:server'
              AND resource_id = ?
              AND julianday(timestamp) >= julianday(?)
            ORDER BY timestamp, event_id
            """,
            (server_id, started_at),
        ).fetchall()
        if len(audit_events) != 1 or audit_events[0]["outcome"] != "succeeded":
            raise LifecycleEvidenceError(
                "DELETE did not produce exactly one successful durable audit event"
            )

        operation = operations[0]
        audit_event = audit_events[0]
        return {
            "server_id": server_id,
            "http_status": 204,
            "request_started_at_utc": started_at,
            "terminal_state": "succeeded",
            "operation": {
                "id": operation["id"],
                "kind": operation["kind"],
                "state": operation["state"],
                "created_at": operation["created_at"],
                "error_category": operation["error_category"],
            },
            "audit_event": {
                "event_id": audit_event["event_id"],
                "timestamp": audit_event["timestamp"],
                "request_id": audit_event["request_id"],
                "audit_id": audit_event["audit_id"],
                "service": audit_event["service"],
                "action": audit_event["action"],
                "resource_type": audit_event["resource_type"],
                "resource_id": audit_event["resource_id"],
                "operation_id": audit_event["operation_id"],
                "outcome": audit_event["outcome"],
                "reason_category": audit_event["reason_category"],
            },
        }
    except sqlite3.Error as error:
        raise HarnessEvidenceError("controller lifecycle evidence query failed") from error
    finally:
        connection.close()


def write_evidence(output: Path, evidence: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(evidence, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(arguments: list[str]) -> int:
    if len(arguments) != 5:
        print(
            "usage: fabric-v3-delete-operation-evidence.py DB SERVER_ID STARTED_AT HTTP_STATUS OUTPUT",
            file=sys.stderr,
        )
        return 2

    database, server_id, started_at, http_status, output = arguments
    try:
        evidence = capture(Path(database), server_id, started_at, http_status)
        write_evidence(Path(output), evidence)
        return 0
    except LifecycleEvidenceError as error:
        print(f"CLEANUP_DEFECT: {error}", file=sys.stderr)
        return 1
    except (HarnessEvidenceError, OSError) as error:
        print(f"HARNESS_GAP: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
