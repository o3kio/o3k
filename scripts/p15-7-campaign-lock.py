#!/usr/bin/env python3
"""Atomically reserve the protected real-host campaign namespace."""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def lock_path() -> Path:
    raw = os.environ.get("O3K_P15_7_CAMPAIGN_LOCK_PATH", "/tmp/o3k-p15-7-campaign.lock")
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts or path.is_symlink():
        raise ValueError("campaign lock path must be an absolute non-symlink path")
    return path


def owner() -> dict[str, object]:
    run_id = os.environ.get("O3K_P15_7_RUN_ID") or os.environ.get("GITHUB_RUN_ID", "")
    source_sha = os.environ.get("O3K_P15_7_SOURCE_SHA") or os.environ.get("GITHUB_SHA", "")
    if not run_id or len(source_sha) != 40 or any(c not in "0123456789abcdefABCDEF" for c in source_sha):
        raise ValueError("campaign lock requires run identity and exact source SHA")
    return {
        "schema_version": 1,
        "run_id": run_id,
        "source_sha": source_sha.lower(),
        "pid": os.getpid(),
        "host": socket.gethostname(),
        "acquired_unix_ms": int(time.time() * 1000),
    }


def acquire() -> int:
    path = lock_path()
    record = owner()
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        try:
            prior = json.loads((path / "owner.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            prior = {"owner": "unreadable"}
        return fail(f"protected campaign lock is held: {json.dumps(prior, sort_keys=True)}")
    try:
        owner_path = path / "owner.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(owner_path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        try:
            (path / "owner.json").unlink()
        except FileNotFoundError:
            pass
        path.rmdir()
        raise
    print(json.dumps(record, sort_keys=True))
    return 0


def release() -> int:
    path = lock_path()
    if not path.exists():
        return 0
    try:
        expected = owner()
        actual = json.loads((path / "owner.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return fail(f"cannot validate protected campaign lock owner: {error}")
    for key in ("run_id", "source_sha"):
        if actual.get(key) != expected[key]:
            return fail("refusing to remove a campaign lock owned by another run")
    try:
        (path / "owner.json").unlink()
        path.rmdir()
    except OSError as error:
        return fail(f"cannot release protected campaign lock: {error}")
    return 0


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"acquire", "release"}:
        return fail("usage: p15-7-campaign-lock.py {acquire|release}")
    try:
        return acquire() if sys.argv[1] == "acquire" else release()
    except (OSError, ValueError) as error:
        return fail(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
