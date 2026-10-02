#!/usr/bin/env python3
"""Persist bounded, redacted evidence for the #1035 contender wrapper."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import signal
import time


MAX_INPUT_BYTES = 256 * 1024
MAX_OUTPUT_CHARS = 32 * 1024
MAX_LOG_LINES = 96
MAX_LOG_CHARS = 24 * 1024
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
REQUEST_ID_RE = re.compile(
    r"(?i)(?:x[-_ ]?openstack[-_ ]?request[-_ ]?id|request[-_ ]?id|req[-_ ]?id)"
    r"\s*[:=]\s*[<\[\(]?([A-Za-z0-9._:-]{4,160})"
)


def safe_file(root: pathlib.Path, name: str) -> pathlib.Path | None:
    if not name:
        return None
    path = (root / name).resolve()
    if path.parent != root.resolve() or path.is_symlink() or not path.is_file():
        return None
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            return None
    except OSError:
        return None
    return path


def read_text(root: pathlib.Path, name: str) -> str:
    path = safe_file(root, name)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def sanitize(value: str, limit: int = MAX_OUTPUT_CHARS) -> tuple[str, bool]:
    value = value.replace("\x00", "?")
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer <redacted>", value)
    value = re.sub(r"(?i)(password|passwd|token|secret|private[_ -]?key)\s*[:=]\s*\S+", r"\1=<redacted>", value)
    value = re.sub(r"(?i)(postgres(?:ql)?://[^\s/@:]+):[^\s/@]+@", r"\1:<redacted>@", value)
    value = re.sub(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", "<redacted-key>", value, flags=re.S)
    truncated = len(value) > limit
    return value[:limit], truncated


def json_document(root: pathlib.Path, name: str) -> object | None:
    text = read_text(root, name)
    if not text:
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def clean_id(value: str) -> str | None:
    return value if UUID_RE.fullmatch(value or "") else None


def collect_request_ids(*texts: str, documents: object | None = None) -> list[str]:
    found: set[str] = set()
    for text in texts:
        for match in REQUEST_ID_RE.finditer(text):
            found.add(match.group(1)[:128])

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower().replace("-", "_") in {"request_id", "requestid", "x_openstack_request_id"}:
                    if isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9._:-]{4,160}", item):
                        found.add(item[:128])
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(documents)
    return sorted(found)[:32]


def state_from_server(document: object | None) -> str:
    if not isinstance(document, dict):
        return "unavailable"
    status = document.get("status")
    state = status.get("state") if isinstance(status, dict) else None
    return state if isinstance(state, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", state) else "unknown"


def operation_for(document: object | None, server_id: str) -> tuple[str | None, str]:
    if not isinstance(document, dict):
        return None, "unavailable"
    items = document.get("items")
    if not isinstance(items, list):
        return None, "unavailable"
    for item in items:
        if not isinstance(item, dict) or item.get("resource_id") != server_id:
            continue
        action = str(item.get("action", item.get("kind", ""))).lower()
        if "create" not in action:
            continue
        operation_id = item.get("id", item.get("operation_id"))
        return clean_id(str(operation_id or "")), str(item.get("state", "unknown"))[:32]
    return None, "unknown"


def correlated_lines(text: str) -> list[str]:
    lines: list[str] = []
    for line in text.splitlines():
        if re.search(r"(?i)(error|fail|timeout|timed out|provider|agent|request[-_ ]?id|operation)", line):
            cleaned, _ = sanitize(line, MAX_LOG_CHARS)
            if cleaned:
                lines.append(cleaned)
    return lines[-MAX_LOG_LINES:]


def signal_name(exit_status: int) -> str | None:
    if exit_status < 128 or exit_status > 192:
        return None
    number = exit_status - 128
    try:
        return signal.Signals(number).name
    except ValueError:
        return f"SIG{number}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--work-root", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--wrapper-exit-status", required=True, type=int)
    parser.add_argument("--pid", default="")
    parser.add_argument("--pgid", default="")
    parser.add_argument("--starttime", default="")
    parser.add_argument("--request-start-ms", required=True, type=int)
    parser.add_argument("--request-end-ms", required=True, type=int)
    parser.add_argument("--endpoint-id", default="")
    parser.add_argument("--server-id", default="")
    parser.add_argument("--operation-id", default="")
    parser.add_argument("--server-http-status", default="")
    parser.add_argument("--operation-http-status", default="")
    parser.add_argument("--server-state", default="")
    parser.add_argument("--operation-state", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = pathlib.Path(args.work_root).resolve()
    stdout_raw = read_text(root, "workload-d-create.txt")
    stderr_raw = read_text(root, "workload-d-create.err")
    stdout, stdout_truncated = sanitize(stdout_raw)
    stderr, stderr_truncated = sanitize(stderr_raw)
    reuse_stderr, reuse_truncated = sanitize(read_text(root, "reuse-port.err"))
    server_doc = json_document(root, "workload-d-show.json")
    operations_doc = json_document(root, "operations-d.json")
    server_id = clean_id(args.server_id) or next(iter(UUID_RE.findall(stdout_raw)), None)
    operation_id = clean_id(args.operation_id)
    inferred_operation, inferred_state = operation_for(operations_doc, server_id or "")
    operation_id = operation_id or inferred_operation
    operation_state = args.operation_state or inferred_state
    wrapper_status = args.wrapper_exit_status
    signal_value = signal_name(wrapper_status)
    elapsed = max(0, args.request_end_ms - args.request_start_ms)
    log_files = {
        "daemon": "contender-daemon.log",
        "agent": "contender-agent.log",
        "provider": "contender-provider.log",
    }
    logs: dict[str, list[str]] = {}
    for label, name in log_files.items():
        logs[label] = correlated_lines(read_text(root, name))
    request_ids = collect_request_ids(stdout_raw, stderr_raw, documents=[server_doc, operations_doc])
    artifact = {
        "artifact_type": "o3k-p15-7-contender-evidence",
        "schema_version": 1,
        "status": args.phase,
        "run_id": args.run_id,
        "source_sha": args.source_sha,
        "recorded_at_unix_ms": int(time.time() * 1000),
        "request": {
            "started_unix_ms": args.request_start_ms,
            "finished_unix_ms": args.request_end_ms,
            "elapsed_ms": elapsed,
            "endpoint_id": clean_id(args.endpoint_id),
            "server_id": server_id,
            "operation_id": operation_id,
            "request_ids": request_ids,
        },
        "wrapper": {
            "pid": args.pid or None,
            "pgid": args.pgid or None,
            "starttime": args.starttime or None,
            "exit_status": wrapper_status,
            "exited_normally": 0 <= wrapper_status < 128,
            "signal": signal_value,
            "timeout_detected": wrapper_status in {124, 137},
            "timeout_seconds": 67,
            "kill_after_seconds": 5,
            "timeout_signal": "SIGTERM",
            "timeout_kill_signal": "SIGKILL",
            "stdout": stdout,
            "stdout_truncated": stdout_truncated,
            "stderr": stderr,
            "stderr_truncated": stderr_truncated,
        },
        "server": {
            "id": server_id,
            "state": args.server_state or state_from_server(server_doc),
            "http_status": args.server_http_status or "unknown",
        },
        "operation": {
            "id": operation_id,
            "state": operation_state,
            "http_status": args.operation_http_status or "unknown",
        },
        "fixed_ip_reuse": {
            "stderr": reuse_stderr,
            "stderr_truncated": reuse_truncated,
        },
        "correlated_errors": logs,
    }
    output = pathlib.Path(args.artifact)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    output.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
