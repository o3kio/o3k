#!/usr/bin/env python3
"""Record caller-supplied endpoint state after server detach, before port DELETE."""

import json
import os
from pathlib import Path
import sqlite3
import sys


class HarnessEvidenceError(Exception):
    """The controller database or endpoint evidence could not be inspected."""


def inspect(database: Path, realm_id: str, endpoint_ids: list[str]) -> dict:
    if not database.is_file() or database.is_symlink():
        raise HarnessEvidenceError("controller evidence database is unavailable")
    if len(endpoint_ids) != 3 or len(set(endpoint_ids)) != len(endpoint_ids):
        raise HarnessEvidenceError("expected three unique campaign endpoint IDs")

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
        rows = [
            dict(row)
            for row in connection.execute(
                """
                SELECT id, realm_id, project_id, fixed_ip, mac, generation, state
                FROM canonical_endpoints
                WHERE realm_id = ?
                ORDER BY id
                """,
                (realm_id,),
            )
        ]
    except sqlite3.Error as error:
        raise HarnessEvidenceError("canonical endpoint query failed") from error
    finally:
        connection.close()

    by_id = {row["id"]: row for row in rows}
    expected_ids = set(endpoint_ids)
    actual_ids = set(by_id)
    all_expected_present_active = (
        actual_ids == expected_ids
        and all(by_id[endpoint_id]["state"] == "active" for endpoint_id in endpoint_ids)
    )
    return {
        "artifact_type": "fabric-v3-canonical-endpoint-retention",
        "phase": "after-c-server-delete-before-supported-port-delete",
        "realm_id": realm_id,
        "endpoint_ownership": "caller-supplied ports",
        "expected_endpoint_ids": endpoint_ids,
        "actual_endpoint_ids": sorted(actual_ids),
        "endpoints": rows,
        "all_expected_present_active": all_expected_present_active,
        "release_semantics": "caller-supplied endpoint remains until supported port DELETE",
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
    if len(arguments) != 6:
        print(
            "usage: fabric-v3-canonical-endpoint-retention-evidence.py DB REALM_ID ENDPOINT_A ENDPOINT_B ENDPOINT_C OUTPUT",
            file=sys.stderr,
        )
        return 2

    database, realm_id, *rest = arguments
    endpoint_ids, output = rest[:3], rest[3]
    try:
        evidence = inspect(Path(database), realm_id, endpoint_ids)
        write_evidence(Path(output), evidence)
    except (HarnessEvidenceError, OSError) as error:
        print(f"HARNESS_GAP: {error}", file=sys.stderr)
        return 2

    if not evidence["all_expected_present_active"]:
        print(
            "DURABLE_RETIREMENT_DEFECT: caller-supplied canonical endpoints were not retained active until port DELETE",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
