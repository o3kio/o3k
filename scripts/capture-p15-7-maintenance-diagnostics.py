#!/usr/bin/env python3
"""Publish bounded, redacted evidence for a failed maintenance reconnect."""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any


MAX_LOG_BYTES = 64 * 1024
MAX_LOG_LINES = 160
SECRET = re.compile(
    r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?|(?:access|refresh|id)?_?token\s*[:=]\s*|"
    r"password\s*[:=]\s*|client_secret\s*[:=]\s*|private[_ -]?key\s*[:=]\s*)"
    r"[^\s,;]+"
)
PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
CORRELATED = re.compile(
    r"(?i)(register|reconnect|agent|provider|building.?block|control.?plane|tls|heartbeat|"
    r"error|warn|failed|refused|timeout|unavailable|ready)"
)


def read_text(path: str, limit: int) -> str:
    try:
        return Path(path).read_bytes()[-limit:].decode("utf-8", "replace")
    except OSError:
        return ""


def sanitize(value: str) -> str:
    return SECRET.sub(r"\1[REDACTED]", PEM.sub("[REDACTED PRIVATE KEY]", value))


def request_ids(headers: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in headers.splitlines()[-80:]:
        match = re.match(r"(?i)^\s*(x-request-id|x-openstack-request-id|traceparent|x-correlation-id)\s*:\s*(.*?)\s*$", line)
        if match:
            found[match.group(1).lower()] = sanitize(match.group(2))[:256]
    return found


def selected_state(raw: str, block_id: str, execution_identity: str) -> dict[str, Any] | None:
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(value, dict):
        return None
    block = value.get("block") if isinstance(value.get("block"), dict) else value
    observed_id = block.get("id")
    identity = block.get("execution_identity")
    return {
        "identity_matches": observed_id == block_id and identity == execution_identity,
        "block_id": observed_id if isinstance(observed_id, str) else None,
        "execution_identity": identity if isinstance(identity, str) else None,
        "state": block.get("state") if isinstance(block.get("state"), str) else None,
        "agent_available": block.get("agent_available") if isinstance(block.get("agent_available"), bool) else None,
        "last_seen": block.get("last_seen") if isinstance(block.get("last_seen"), str) else None,
        "resource_provider_ids": [x for x in block.get("resource_provider_ids", []) if isinstance(x, str)][:16]
        if isinstance(block.get("resource_provider_ids", []), list) else [],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--api-body", required=True)
    parser.add_argument("--api-headers", required=True)
    parser.add_argument("--agent-log", required=True)
    parser.add_argument("--agent-ready", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--block-id", required=True)
    parser.add_argument("--execution-identity", required=True)
    parser.add_argument("--http-status", required=True)
    parser.add_argument("--started-ms", type=int, required=True)
    parser.add_argument("--finished-ms", type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha) or not re.fullmatch(r"[A-Za-z0-9_-]+", args.run_id):
        raise SystemExit("invalid run provenance")
    log = read_text(args.agent_log, MAX_LOG_BYTES)
    correlated = [sanitize(line)[:1000] for line in log.splitlines() if CORRELATED.search(line)]
    readiness = sanitize(read_text(args.agent_ready, 4096))[:2048]
    state = selected_state(read_text(args.api_body, 64 * 1024), args.block_id, args.execution_identity)
    doc = {
        "schema": "o3k.p15-7-maintenance-reconnect-diagnostics.v1",
        "captured_unix_ms": int(time.time() * 1000),
        "capture_window_unix_ms": {"start": args.started_ms, "finish": args.finished_ms},
        "source_sha": args.source_sha,
        "run_id": args.run_id,
        "building_block_id": args.block_id,
        "execution_identity": args.execution_identity,
        "control_plane": {
            "request": f"GET /operator/building-blocks/{args.block_id}",
            "http_status": args.http_status,
            "request_ids": request_ids(read_text(args.api_headers, 16 * 1024)),
            "observed": state,
        },
        "agent": {
            "readiness_probe": readiness,
            "correlated_log_lines": correlated[-MAX_LOG_LINES:],
            "source_bytes_captured": min(len(log.encode("utf-8", "replace")), MAX_LOG_BYTES),
            "truncated": len(log.encode("utf-8", "replace")) >= MAX_LOG_BYTES,
        },
        "capture_status": "captured",
    }
    destination = Path(args.artifact)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    destination.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
