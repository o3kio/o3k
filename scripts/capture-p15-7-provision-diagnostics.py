#!/usr/bin/env python3
"""Write bounded, redacted diagnostics for a failed P15.7 journey."""

from __future__ import annotations

import json
import os
import pathlib
import re
import stat
import sys
import tempfile


MAX_LOG_BYTES = 256 * 1024
MAX_LINES = 160
MAX_LINE_LENGTH = 2000
LOG_NAMES = ("block-a-provision.log", "block-b-provision.log")
JWT = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])")
SENSITIVE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:authorization|bearer|"
    r"(?:access|refresh|id|operator|oidc)?[_-]?token|pass(?:word|wd)|secret|"
    r"credential|api[_-]?key|private[_ -]?key|client[_ -]?secret)(?![A-Za-z0-9])"
)
PEM_BEGIN = re.compile(r"-----BEGIN [^-]*(?:PRIVATE KEY|SECRET)-----")
PEM_END = re.compile(r"-----END [^-]*(?:PRIVATE KEY|SECRET)-----")


def clean_line(line: str, in_pem: bool) -> tuple[str | None, bool, int]:
    if in_pem:
        return None, not bool(PEM_END.search(line)), 1
    if PEM_BEGIN.search(line):
        return "<redacted sensitive diagnostic line>", not bool(PEM_END.search(line)), 1
    if SENSITIVE.search(line):
        return "<redacted sensitive diagnostic line>", False, 1
    redacted = JWT.sub("<redacted-token>", line)
    redacted = re.sub(
        r"(?i)(https?://)[^/@\s]+:[^/@\s]+@",
        r"\1<redacted>@",
        redacted,
    )
    redacted = "".join(ch if ch.isprintable() or ch == "\t" else "?" for ch in redacted)
    return redacted[:MAX_LINE_LENGTH], False, int(redacted != line)


def read_log(work_root: pathlib.Path, name: str) -> tuple[list[str], int, bool]:
    path = work_root / name
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return [], 0, False
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or path.parent != work_root:
        return ["<diagnostic log unavailable: unsafe file type>"], 0, True
    try:
        with path.open("rb") as stream:
            offset = max(0, metadata.st_size - MAX_LOG_BYTES)
            stream.seek(offset)
            data = stream.read(MAX_LOG_BYTES + 1)
    except OSError:
        return ["<diagnostic log unavailable: read failed>"], 0, True
    truncated = offset > 0 or len(data) > MAX_LOG_BYTES
    text = data[:MAX_LOG_BYTES].decode("utf-8", errors="replace")
    source_lines = text.splitlines()[-MAX_LINES:]
    output: list[str] = []
    redacted_count = 0
    in_pem = False
    for line in source_lines:
        value, in_pem, count = clean_line(line, in_pem)
        redacted_count += count
        if value is not None:
            output.append(value)
    if truncated:
        output.insert(0, "<older diagnostic output omitted>")
    return output, redacted_count, True


def write_atomic(destination: pathlib.Path, document: dict[str, object]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".p15-7-provision.", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    if len(sys.argv) not in (5, 6):
        print("usage: capture-p15-7-provision-diagnostics.py OUTPUT WORK_ROOT SOURCE_SHA RUN_ID [REASON]", file=sys.stderr)
        return 2
    output = pathlib.Path(sys.argv[1])
    work_root = pathlib.Path(sys.argv[2])
    source_sha, run_id = sys.argv[3:5]
    reason = sys.argv[5] if len(sys.argv) == 6 else "bounded_vm_provisioning_failed"
    if reason not in ("bounded_vm_provisioning_failed", "journey_failed"):
        print("P15.7 diagnostics: invalid failure reason", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_sha):
        print("P15.7 diagnostics: invalid source SHA", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9._-]+", run_id):
        print("P15.7 diagnostics: invalid run ID", file=sys.stderr)
        return 2
    if work_root.is_symlink() or not work_root.is_dir():
        print("P15.7 diagnostics: unsafe work root", file=sys.stderr)
        return 2
    marker = work_root / ".o3k-owned"
    try:
        marker_metadata = marker.lstat()
        marker_contents = marker.read_text(encoding="ascii").splitlines()
    except OSError:
        print("P15.7 diagnostics: run ownership is unproven", file=sys.stderr)
        return 2
    if (not stat.S_ISREG(marker_metadata.st_mode) or marker.is_symlink()
            or marker_contents != ["o3k-p15-7-journey-owned-v1", f"run={run_id}"]):
        print("P15.7 diagnostics: run ownership is unproven", file=sys.stderr)
        return 2

    records = []
    for name in LOG_NAMES:
        lines, redacted_count, available = read_log(work_root, name)
        status_path = work_root / f"{name.removesuffix('-provision.log')}-exit"
        try:
            status_metadata = status_path.lstat()
            if not stat.S_ISREG(status_metadata.st_mode) or status_path.is_symlink():
                raise OSError("unsafe status file")
            status = status_path.read_text(encoding="ascii").strip()
        except OSError:
            status = "unknown"
        if not re.fullmatch(r"[0-9]{1,3}", status):
            status = "unknown"
        records.append({
            "vm": name.removesuffix("-provision.log"),
            "exit_status": status,
            "log_available": available,
            "redacted_lines": redacted_count,
            "tail": lines,
        })
    write_atomic(output, {
        "artifact_type": "o3k-p15-7-provisioning-diagnostics",
        "schema_version": 1,
        "status": "failed",
        "reason": reason,
        "tested_source_sha": source_sha.lower(),
        "run_id": run_id,
        "redacted": True,
        "native_system_operator_token_acquired_before_provisioning": False,
        "signed_provider_token_refreshed_before_exchange": True,
        "vms": records,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
