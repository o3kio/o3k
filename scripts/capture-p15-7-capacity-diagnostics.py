#!/usr/bin/env python3
"""Capture bounded, redacted o3kd capacity diagnostics for a failed read."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path


def redact(value: str) -> str:
    value = re.sub(r"(?i)(bearer\s+)[^\s,;]+", r"\1<redacted>", value)
    value = re.sub(r"(?i)(postgres(?:ql)?://)[^\s/@]+:[^\s/@]+@", r"\1<redacted>@", value)
    value = re.sub(r"(?i)(password|token|secret)([=:])[^\s,;]+", r"\1\2<redacted>", value)
    return value[:2048]


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: capture-p15-7-capacity-diagnostics.py LOG OUTPUT", file=sys.stderr)
        return 2
    source, destination = map(Path, sys.argv[1:])
    lines: list[str] = []
    source_available = source.is_file() and not source.is_symlink()
    if source_available:
        with source.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if re.search(r"(?i)(capacity|diagnostic|placement|storeerror|operator)", line):
                    lines.append(redact(line.rstrip("\n")))
        lines = lines[-200:]
    document = {
        "artifact_type": "o3k-p15-7-capacity-diagnostics",
        "schema_version": 1,
        "status": "captured" if source_available else "unavailable",
        "source": "o3kd.log",
        "line_count": len(lines),
        "lines": lines,
        "recorded_at_unix_ms": int(time.time() * 1000),
    }
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, output)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
