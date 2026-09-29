#!/usr/bin/env python3
"""Write a redacted, run-scoped PP.5 failure classification artifact."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


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
    if len(sys.argv) not in {14, 15}:
        return fail(
            "usage: write_p15_7-failure-artifact.py PATH SOURCE_SHA RUN_ID PHASE "
            "FAILURE_CLASS LAST_SUCCESSFUL_CHECKPOINT EXPECTED OBSERVED "
            "SERVER_ID ENDPOINT_ID CLEANUP_RESULT FOREIGN_STATE_RESULT MESSAGE "
            "[ATTEMPTED_PHASE]"
        )
    (
        path,
        source_sha,
        run_id,
        phase,
        failure_class,
        last_checkpoint,
        expected,
        observed,
        server_id,
        endpoint_id,
        cleanup_result,
        foreign_state_result,
        message,
        *optional,
    ) = sys.argv[1:]
    attempted_phase = optional[0] if optional else ""
    if len(source_sha) != 40 or any(char not in "0123456789abcdefABCDEF" for char in source_sha):
        return fail("failure artifact requires an exact source SHA")
    if not run_id or not failure_class or not phase:
        return fail("failure artifact requires run identity, phase and class")
    allowed = {
        "runner_preflight",
        "source_checkout",
        "postgres_prerequisite",
        "authority_preflight",
        "testlab_bootstrap",
        "storage_baseline",
        "generic_real_host_baseline",
        "scale_topology",
        "maintenance_lifecycle",
        "fault_injection",
        "crash_recovery",
        "orphan_repair",
        "evidence_validation",
        "cleanup",
        "product_correctness",
        "unknown",
    }
    if failure_class not in allowed:
        return fail("failure artifact class is not in the controlled taxonomy")
    if cleanup_result not in {"pending", "passed", "failed", "unknown"}:
        return fail("failure artifact cleanup result is invalid")
    if foreign_state_result not in {"unchanged", "changed", "unknown"}:
        return fail("failure artifact foreign-state result is invalid")
    document = {
        "artifact_type": "o3k-p15-7-failure-classification",
        "schema_version": 1,
        "status": "failed",
        "source_sha": source_sha.lower(),
        "run_id": run_id,
        "phase": phase,
        "attempted_phase": attempted_phase or None,
        "failure_class": failure_class,
        "last_successful_checkpoint": last_checkpoint or None,
        "expected": expected,
        "observed": observed,
        "target_resource_ids": {
            "server_id": server_id or None,
            "endpoint_id": endpoint_id or None,
        },
        "harness_version": os.environ.get("O3K_P15_7_HARNESS_VERSION", "unknown"),
        "evidence_schema_version": 3,
        "cleanup_result": cleanup_result,
        "foreign_state_result": foreign_state_result,
        "message": message,
        "recorded_unix_ms": int(time.time() * 1000),
    }
    digest_input = json.dumps(document, sort_keys=True).encode("utf-8")
    document["classification_digest"] = hashlib.sha256(digest_input).hexdigest()
    try:
        atomic_write(Path(path), document)
    except OSError as error:
        return fail(f"cannot persist failure classification atomically: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
