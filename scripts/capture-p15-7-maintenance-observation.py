#!/usr/bin/env python3
"""Append one bounded, sanitized poll from the maintenance reconnect wait."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import time
from pathlib import Path
from typing import Any

_DIAGNOSTICS_PATH = Path(__file__).with_name("capture-p15-7-maintenance-diagnostics.py")
_DIAGNOSTICS_SPEC = importlib.util.spec_from_file_location("p15_7_maintenance_diagnostics", _DIAGNOSTICS_PATH)
if _DIAGNOSTICS_SPEC is None or _DIAGNOSTICS_SPEC.loader is None:
    raise RuntimeError("maintenance diagnostics sanitizer is unavailable")
_DIAGNOSTICS = importlib.util.module_from_spec(_DIAGNOSTICS_SPEC)
_DIAGNOSTICS_SPEC.loader.exec_module(_DIAGNOSTICS)
request_ids = _DIAGNOSTICS.request_ids
sanitize = _DIAGNOSTICS.sanitize


MAX_OBSERVATIONS = 120
MAX_ARTIFACT_BYTES = 128 * 1024


def observation(body_path: Path, headers_path: Path, args: argparse.Namespace) -> dict[str, Any]:
    try:
        raw = body_path.read_bytes()
        if len(raw) > 64 * 1024:
            raise ValueError("response exceeds capture bound")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeError):
        value = None
    view = value if isinstance(value, dict) else {}
    block = view.get("block") if isinstance(view.get("block"), dict) else view
    try:
        headers = headers_path.read_bytes()[:16 * 1024].decode("utf-8", "replace")
    except OSError:
        headers = ""
    ids = [{"header": item["header"], "value": item["value"][:128]} for item in request_ids(headers)[:4]]
    return {
        "started_unix_ms": args.started_ms,
        "finished_unix_ms": args.finished_ms,
        "http_status": args.http_status,
        "exit_status": args.exit_status,
        "curl_exit_status": args.curl_exit_status,
        "run_id": args.run_id,
        "source_sha": args.source_sha,
        "request_ids": ids,
        "block_id": block.get("id") if isinstance(block.get("id"), str) else None,
        "execution_identity": block.get("execution_identity") if isinstance(block.get("execution_identity"), str) else None,
        "identity_matches": block.get("id") == args.block_id and block.get("execution_identity") == args.execution_identity,
        "state": block.get("state") if isinstance(block.get("state"), str) else None,
        "agent_available": view.get("agent_available") if isinstance(view.get("agent_available"), bool) else None,
        "generation": block.get("generation") if isinstance(block.get("generation"), int) else None,
        "resource_provider_ids": [item for item in block.get("resource_provider_ids", []) if isinstance(item, str)][:16]
        if isinstance(block.get("resource_provider_ids", []), list) else [],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--body", required=True, type=Path)
    parser.add_argument("--headers", required=True, type=Path)
    parser.add_argument("--started-ms", required=True, type=int)
    parser.add_argument("--finished-ms", required=True, type=int)
    parser.add_argument("--http-status", required=True)
    parser.add_argument("--exit-status", required=True, type=int)
    parser.add_argument("--curl-exit-status", required=True, type=int)
    parser.add_argument("--block-id", required=True)
    parser.add_argument("--execution-identity", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.run_id) or not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        raise SystemExit("invalid run provenance")
    if args.started_ms <= 0 or args.finished_ms < args.started_ms or args.finished_ms > int(time.time() * 1000):
        raise SystemExit("invalid observation timestamps")
    if not re.fullmatch(r"[0-9]{3}", args.http_status):
        raise SystemExit("invalid HTTP status")
    path = args.artifact
    if path.is_symlink():
        raise SystemExit("observation artifact must not be a symlink")
    existing = path.read_bytes() if path.exists() else b""
    if len(existing) >= MAX_ARTIFACT_BYTES or existing.count(b"\n") >= MAX_OBSERVATIONS:
        raise SystemExit("maintenance poll evidence exceeded its fixed bound")
    item = observation(args.body, args.headers, args)
    line = (json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode()
    line = sanitize(line.decode("utf-8")).encode("utf-8")
    if len(line) > 2048:
        raise SystemExit("maintenance poll observation exceeded its line bound")
    if len(existing) + len(line) > MAX_ARTIFACT_BYTES:
        raise SystemExit("maintenance poll evidence exceeded its fixed byte bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        with os.fdopen(fd, "ab") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        try:
            path.chmod(0o600)
        except OSError:
            pass
    print("true" if item["agent_available"] is True else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
