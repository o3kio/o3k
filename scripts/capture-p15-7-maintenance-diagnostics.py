#!/usr/bin/env python3
"""Publish bounded, redacted and fail-closed maintenance diagnostics."""

from __future__ import annotations

import argparse
import json
import re
import signal
import time
from pathlib import Path
from typing import Any


MAX_LOG_BYTES = 64 * 1024
MAX_LOG_LINES = 160
MAX_LINE_CHARS = 1000
SECRET_VALUE = re.compile(
    r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?|(?:access|refresh|id)?_?token\s*[:=]\s*|"
    r"password\s*[:=]\s*|passwd\s*[:=]\s*|client[_-]?secret\s*[:=]\s*|"
    r"(?:api[_-]?key|credential|private[_ -]?key)\s*[:=]\s*)"
    r'("[^"\r\n]*"|\x27[^\x27\r\n]*\x27|[^\s,;]+)'
)
SECRET_JSON_FIELD = re.compile(r"(?i)(?:token|secret|password|passwd|credential|authorization|private.?key|api.?key)")
URL_USERINFO = re.compile(r"(?i)(https?://[^:/\s]+:)[^@/\s]+@")
URL_QUERY_SECRET = re.compile(r"(?i)([?&](?:token|access_token|password|secret|api_key)=)[^&#\s]+")
PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
CORRELATED = re.compile(
    r"(?i)(register|reconnect|agent|provider|building.?block|control.?plane|tls|heartbeat|"
    r"error|warn|failed|refused|timeout|unavailable|ready)"
)
REQUEST_ID = re.compile(r"(?i)^\s*(x-request-id|x-openstack-request-id|traceparent|x-correlation-id)\s*:\s*(.*?)\s*$")
REMAINING_SECRET = re.compile(
    r"(?i)\b(?:bearer\s+[a-z0-9._~+/=-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:password|passwd|token|secret|credential|authorization|api[_-]?key)\s*[:=]\s*(?!\[REDACTED\])[^\s,;]+)"
)


def read_bounded(path: str, limit: int) -> tuple[str, dict[str, Any]]:
    try:
        source = Path(path)
        size = source.stat().st_size
        with source.open("rb") as stream:
            stream.seek(max(0, size - limit))
            raw = stream.read(limit)
    except OSError as error:
        return "", {"available": False, "error": type(error).__name__, "source_bytes": 0, "truncated": False}
    return raw.decode("utf-8", "replace"), {
        "available": True,
        "source_bytes": size,
        "captured_bytes": len(raw),
        "truncated": size > limit,
        "truncation": "tail" if size > limit else "none",
    }


def sanitize(value: str) -> str:
    value = PEM.sub("[REDACTED PRIVATE KEY]", value)
    value = URL_USERINFO.sub(r"\1[REDACTED]@", value)
    value = URL_QUERY_SECRET.sub(r"\1[REDACTED]", value)
    return SECRET_VALUE.sub(r"\1[REDACTED]", value)


def redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SECRET_JSON_FIELD.search(str(key)) else redact_json(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_json(item) for item in value[:128]]
    if isinstance(value, str):
        return sanitize(value)[:MAX_LINE_CHARS]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return "[UNSUPPORTED VALUE]"


def request_ids(headers: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for index, line in enumerate(headers.splitlines()[-160:]):
        match = REQUEST_ID.match(line)
        if match:
            found.append({"header": match.group(1).lower(), "value": sanitize(match.group(2))[:256], "header_index": str(index)})
    return found[-32:]


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
        "maintenance_epoch": block.get("maintenance_epoch") if isinstance(block.get("maintenance_epoch"), (int, str)) else None,
    }


def signal_name(status: int) -> str | None:
    if 128 < status < 192:
        try:
            return signal.Signals(status - 128).name
        except ValueError:
            return f"SIG{status - 128}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("artifact", "api-body", "api-headers", "daemon-log", "agent-log", "agent-ready", "daemon-log-stderr", "agent-log-stderr", "agent-ready-stderr", "api-stderr", "probe-meta", "source-sha", "run-id", "block-id", "execution-identity", "http-status"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--started-ms", type=int, required=True)
    parser.add_argument("--finished-ms", type=int, required=True)
    parser.add_argument("--reboot-request-ms", type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha) or not re.fullmatch(r"[A-Za-z0-9_-]+", args.run_id):
        raise SystemExit("invalid run provenance")
    captured_ms = int(time.time() * 1000)
    issues: list[str] = []
    try:
        metadata = json.loads(Path(args.probe_meta).read_text(encoding="utf-8"))
        if not isinstance(metadata, dict):
            raise ValueError("probe metadata must be an object")
    except (OSError, ValueError):
        metadata = {}
        issues.append("probe_metadata_unavailable_or_malformed")
    if args.started_ms <= 0 or args.finished_ms < args.started_ms or captured_ms < args.finished_ms:
        issues.append("capture_window_invalid")
    if metadata.get("capture_start_ms") != args.started_ms or metadata.get("capture_finish_ms") != args.finished_ms:
        issues.append("capture_window_metadata_mismatch")
    if not args.execution_identity or args.execution_identity == "unknown":
        issues.append("expected_execution_identity_missing")
    if args.reboot_request_ms <= 0 or args.reboot_request_ms >= args.started_ms:
        issues.append("reboot_to_observation_timing_invalid")
    if not re.fullmatch(r"[0-9]{3}", args.http_status):
        issues.append("http_status_invalid")

    api_body, api_info = read_bounded(args.api_body, 64 * 1024)
    headers, headers_info = read_bounded(args.api_headers, 16 * 1024)
    daemon_log, daemon_log_info = read_bounded(args.daemon_log, MAX_LOG_BYTES)
    log, log_info = read_bounded(args.agent_log, MAX_LOG_BYTES)
    readiness, readiness_info = read_bounded(args.agent_ready, 4096)
    api_stderr, api_stderr_info = read_bounded(args.api_stderr, 4096)
    daemon_stderr, daemon_stderr_info = read_bounded(args.daemon_log_stderr, 4096)
    log_stderr, log_stderr_info = read_bounded(args.agent_log_stderr, 4096)
    ready_stderr, ready_stderr_info = read_bounded(args.agent_ready_stderr, 4096)
    for name, info in (("api_body", api_info), ("api_headers", headers_info), ("daemon_log", daemon_log_info), ("agent_log", log_info), ("agent_ready", readiness_info), ("probe_metadata", {"available": bool(metadata)})):
        if not info.get("available"):
            issues.append(f"{name}_unavailable")
    state = selected_state(api_body, args.block_id, args.execution_identity)
    if state is None:
        issues.append("api_state_unparseable")
    elif not state["identity_matches"]:
        issues.append("api_identity_mismatch")
    ids = request_ids(headers)
    probe_docs: dict[str, Any] = {}
    expected_probe_names = ("api_get", "daemon_log_local", "agent_log_ssh", "agent_ready_ssh")
    for name in expected_probe_names:
        item = metadata.get(name)
        if not isinstance(item, dict):
            issues.append(f"{name}_metadata_missing")
            continue
        start, finish, status = item.get("start_ms"), item.get("finish_ms"), item.get("exit_status")
        if not all(isinstance(x, int) for x in (start, finish, status)) or start < args.started_ms or finish < start or finish > args.finished_ms:
            issues.append(f"{name}_timing_or_status_invalid")
            continue
        if name == "api_get" and start <= args.reboot_request_ms:
            issues.append("api_observation_precedes_reboot")
        timeout = item.get("timed_out")
        if not isinstance(timeout, bool):
            issues.append(f"{name}_timeout_evidence_missing")
            timeout = status in (124, 137, 143)
        probe_docs[name] = {
            "started_unix_ms": start,
            "finished_unix_ms": finish,
            "exit_status": status,
            "signal": signal_name(status),
            "timed_out": timeout,
            "http_status": args.http_status if name == "api_get" else None,
        }

    correlated: list[str] = []
    for line in log.splitlines():
        if CORRELATED.search(line):
            correlated.append(sanitize(line)[:MAX_LINE_CHARS])
    if len(correlated) > MAX_LOG_LINES:
        correlated = correlated[: MAX_LOG_LINES // 2] + correlated[-(MAX_LOG_LINES // 2) :]
    redacted_probe_errors = {
        "api": sanitize(api_stderr)[:2048],
        "daemon_log_local": sanitize(daemon_stderr)[:2048],
        "agent_log_ssh": sanitize(log_stderr)[:2048],
        "agent_ready_ssh": sanitize(ready_stderr)[:2048],
    }
    api_excerpt = sanitize(api_body)[:2048] if state is None else None
    doc = {
        "schema": "o3k.p15-7-maintenance-reconnect-diagnostics.v2",
        "captured_unix_ms": captured_ms,
        "capture_window_unix_ms": {"start": args.started_ms, "finish": args.finished_ms},
        "maintenance_reboot_requested_unix_ms": args.reboot_request_ms,
        "expected_before_state": "ready",
        "source_sha": args.source_sha,
        "run_id": args.run_id,
        "building_block_id": args.block_id,
        "execution_identity": args.execution_identity,
        "probes": probe_docs,
        "control_plane": {
            "request": f"GET /operator/building-blocks/{args.block_id}",
            "http_status": args.http_status,
            "request_ids": ids,
            "response_excerpt": api_excerpt,
            "observed": state,
            "state_transition_observation": {
                "expected_before": "ready",
                "observed_after_reboot": state.get("state") if isinstance(state, dict) else None,
                "api_probe_started_after_reboot_request": bool(
                    isinstance(metadata.get("api_get"), dict)
                    and isinstance(metadata["api_get"].get("start_ms"), int)
                    and metadata["api_get"]["start_ms"] > args.reboot_request_ms
                ),
            },
            "correlated_daemon_log_lines": [sanitize(line)[:MAX_LINE_CHARS] for line in daemon_log.splitlines() if CORRELATED.search(line)][-MAX_LOG_LINES:],
            "daemon_log_capture": daemon_log_info,
        },
        "agent": {
            "readiness_probe": sanitize(readiness)[:2048],
            "correlated_log_lines": correlated,
            "log_capture": log_info,
            "readiness_capture": readiness_info,
        },
        "probe_stderr": redacted_probe_errors,
        "capture_inputs": {"api_body": api_info, "api_headers": headers_info, "daemon_log_stderr": daemon_stderr_info, "api_stderr": api_stderr_info, "agent_log_stderr": log_stderr_info, "agent_ready_stderr": ready_stderr_info},
        "capture_status": "captured" if not issues else "incomplete",
        "capture_issues": sorted(set(issues)),
    }
    serialized = json.dumps(redact_json(doc), indent=2, sort_keys=True) + "\n"
    if REMAINING_SECRET.search(serialized):
        raise SystemExit("sanitizer denylist rejected evidence")
    destination = Path(args.artifact)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(serialized, encoding="utf-8")
    destination.chmod(0o600)
    return 0 if not issues else 2


if __name__ == "__main__":
    raise SystemExit(main())
