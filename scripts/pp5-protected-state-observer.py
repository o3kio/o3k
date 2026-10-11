#!/usr/bin/env python3
"""Narrow read-only observer for root-private PP.5 TestLab state."""

from __future__ import annotations

import argparse
import os
import re
import selectors
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


MAX_MARKER_BYTES = 512
MAX_ID_BYTES = 128


@dataclass
class ObservationError(Exception):
    operation: str
    observer_type: str
    resource_class: str
    diagnostic: str
    command_class: str | None = None
    exit_code: int | None = None


def expected_state_root(run_id: str) -> Path:
    if re.fullmatch(r"[0-9]+(-generic|-pp5)?", run_id):
        return Path("/var/lib/o3k-testlab") / run_id
    if re.fullmatch(r"local-[0-9]+(-generic|-pp5)?", run_id):
        temp = Path(os.environ.get("RUNNER_TEMP", os.environ.get("TMPDIR", "/tmp")))
        return temp.resolve(strict=True) / "o3k-testlab" / run_id
    raise ValueError("invalid TestLab run identity")


def _run(command: list[str], operation: str, resource_class: str) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired as error:
        raise ObservationError(operation, "sudo_read_only", resource_class,
                               type(error).__name__, "sudo", None) from error
    except OSError as error:
        raise ObservationError(operation, "sudo_read_only", resource_class,
                               type(error).__name__, "sudo", None) from error
    if result.returncode != 0:
        raise ObservationError(operation, "sudo_read_only", resource_class,
                               "PermissionError" if result.returncode in (1, 126, 127) else "SubprocessError",
                               "sudo", result.returncode)
    return result


def _bounded_cat(path: Path, operation: str, resource_class: str, limit: int) -> str:
    command = ["sudo", "-n", "cat", "--", str(path)]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as error:
        raise ObservationError(operation, "sudo_read_only", resource_class,
                               type(error).__name__, "sudo", None) from error
    if process.stdout is None:
        process.kill()
        process.wait(timeout=5)
        raise ObservationError(operation, "sudo_read_only", resource_class,
                               "SubprocessError", "sudo", process.returncode)
    content = bytearray()
    deadline = time.monotonic() + 5
    try:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        process.kill()
                        process.wait(timeout=5)
                        raise ObservationError(operation, "sudo_read_only", resource_class,
                                               "TimeoutExpired", "sudo", process.returncode)
                    chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(content)))
                    if not chunk:
                        break
                    content.extend(chunk)
                    if len(content) > limit:
                        process.kill()
                        process.wait(timeout=5)
                        raise ObservationError(operation, "sudo_read_only", resource_class,
                                               "ValueError", "sudo", process.returncode)
        finally:
            process.stdout.close()
        exit_code = process.wait(timeout=max(0, deadline - time.monotonic()))
    except ObservationError:
        raise
    except (OSError, subprocess.TimeoutExpired) as error:
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise ObservationError(operation, "sudo_read_only", resource_class,
                               type(error).__name__, "sudo", process.returncode) from error
    if exit_code != 0:
        raise ObservationError(operation, "sudo_read_only", resource_class,
                               "PermissionError" if exit_code in (1, 126, 127) else "SubprocessError",
                               "sudo", exit_code)
    if len(content) > limit:
        raise ObservationError(operation, "sudo_read_only", resource_class,
                               "ValueError", "sudo", exit_code)
    try:
        return bytes(content).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ObservationError(operation, "sudo_read_only", resource_class,
                               "UnicodeDecodeError", "sudo", exit_code) from error


def _validate_root(root: Path, run_id: str) -> Path:
    expected = expected_state_root(run_id)
    requested = Path(os.fspath(root))
    if requested != expected:
        raise ObservationError("validate_testlab_state_root", "runner_readable",
                               "testlab_state_root", "ValueError")
    _run(["sudo", "-n", "test", "-d", str(expected)],
         "inspect_testlab_state_root", "testlab_state_root")
    _run(["sudo", "-n", "test", "!", "-L", str(expected)],
         "reject_testlab_state_root_symlink", "testlab_state_root")
    resolved = _run(["sudo", "-n", "realpath", "-e", "--", str(expected)],
                    "resolve_testlab_state_root", "testlab_state_root").stdout.strip()
    if resolved != str(expected):
        raise ObservationError("resolve_testlab_state_root", "sudo_read_only",
                               "testlab_state_root", "ValueError", "sudo", 0)
    return expected


def verify_marker(state_root: Path, run_id: str, source_sha: str) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_sha):
        raise ObservationError("validate_candidate_sha", "runner_readable",
                               "testlab_ownership_marker", "ValueError")
    root = _validate_root(state_root, run_id)
    marker = root / ".o3k-run-owned"
    _run(["sudo", "-n", "test", "!", "-L", str(marker)],
         "reject_testlab_ownership_marker_symlink", "testlab_ownership_marker")
    _run(["sudo", "-n", "test", "-e", str(marker)],
         "verify_testlab_ownership_marker_exists", "testlab_ownership_marker")
    raw = _run(["sudo", "-n", "stat", "-c", "%u|%a|%F|%s", "--", str(marker)],
               "inspect_testlab_ownership_marker_metadata", "testlab_ownership_marker").stdout.strip()
    parts = raw.split("|")
    if len(parts) != 4:
        raise ObservationError("inspect_testlab_ownership_marker_metadata", "sudo_read_only",
                               "testlab_ownership_marker", "ValueError", "sudo", 0)
    uid, mode, file_type, size = parts
    if uid != "0" or mode != "600" or file_type != "regular file":
        raise ObservationError("validate_testlab_ownership_marker_metadata", "sudo_read_only",
                               "testlab_ownership_marker", "PermissionError")
    try:
        size_value = int(size)
    except ValueError as error:
        raise ObservationError("inspect_testlab_ownership_marker_metadata", "sudo_read_only",
                               "testlab_ownership_marker", "ValueError") from error
    if not 0 <= size_value <= MAX_MARKER_BYTES:
        raise ObservationError("validate_testlab_ownership_marker_size", "sudo_read_only",
                               "testlab_ownership_marker", "ValueError")
    contents = _bounded_cat(marker, "read_testlab_ownership_marker",
                            "testlab_ownership_marker", MAX_MARKER_BYTES)
    expected = [
        "o3k-disposable-testlab-v1",
        f"commit={source_sha.lower()}",
        f"run={run_id}",
    ]
    if contents.splitlines() != expected:
        raise ObservationError("validate_testlab_ownership_marker_contents", "sudo_read_only",
                               "testlab_ownership_marker", "ValueError")
    return {"owner_uid": 0, "mode": "0600", "regular_file": True,
            "privileged_observer": "sudo -n cat", "marker_verified": True}


def read_bootstrap_agent_id(state_root: Path, run_id: str, source_sha: str) -> str:
    verify_marker(state_root, run_id, source_sha)
    root = _validate_root(state_root, run_id)
    path = root / "tls" / "agent-id"
    _run(["sudo", "-n", "test", "-f", str(path)],
         "verify_bootstrap_compute_identity_exists", "bootstrap_compute_identity")
    _run(["sudo", "-n", "test", "!", "-L", str(path)],
         "reject_bootstrap_compute_identity_symlink", "bootstrap_compute_identity")
    raw = _run(["sudo", "-n", "stat", "-c", "%u|%F|%s", "--", str(path)],
               "inspect_bootstrap_compute_identity_metadata", "bootstrap_compute_identity").stdout.strip()
    parts = raw.split("|")
    if len(parts) != 3 or parts[0] != "0" or parts[1] != "regular file":
        raise ObservationError("inspect_bootstrap_compute_identity_metadata", "sudo_read_only",
                               "bootstrap_compute_identity", "PermissionError")
    try:
        size = int(parts[2])
    except ValueError as error:
        raise ObservationError("inspect_bootstrap_compute_identity_metadata", "sudo_read_only",
                               "bootstrap_compute_identity", "ValueError") from error
    if not 1 <= size <= MAX_ID_BYTES:
        raise ObservationError("validate_bootstrap_compute_identity_size", "sudo_read_only",
                               "bootstrap_compute_identity", "ValueError")
    value = _bounded_cat(path, "read_bootstrap_compute_identity",
                         "bootstrap_compute_identity", MAX_ID_BYTES).strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        raise ObservationError("validate_bootstrap_compute_identity", "sudo_read_only",
                               "bootstrap_compute_identity", "ValueError")
    return value


def read_marker_source_sha(state_root: Path, run_id: str) -> str:
    """Validate a stale run marker and return only its non-secret source SHA."""
    root = _validate_root(state_root, run_id)
    marker = root / ".o3k-run-owned"
    _run(["sudo", "-n", "test", "!", "-L", str(marker)],
         "reject_testlab_ownership_marker_symlink", "testlab_ownership_marker")
    _run(["sudo", "-n", "test", "-e", str(marker)],
         "verify_testlab_ownership_marker_exists", "testlab_ownership_marker")
    raw = _run(["sudo", "-n", "stat", "-c", "%u|%a|%F|%s", "--", str(marker)],
               "inspect_testlab_ownership_marker_metadata", "testlab_ownership_marker").stdout.strip()
    parts = raw.split("|")
    if len(parts) != 4 or parts[0] != "0" or parts[1] != "600" or parts[2] != "regular file":
        raise ObservationError("validate_testlab_ownership_marker_metadata", "sudo_read_only",
                               "testlab_ownership_marker", "PermissionError")
    try:
        size = int(parts[3])
    except ValueError as error:
        raise ObservationError("inspect_testlab_ownership_marker_metadata", "sudo_read_only",
                               "testlab_ownership_marker", "ValueError") from error
    if not 0 <= size <= MAX_MARKER_BYTES:
        raise ObservationError("validate_testlab_ownership_marker_size", "sudo_read_only",
                               "testlab_ownership_marker", "ValueError")
    contents = _bounded_cat(marker, "read_testlab_ownership_marker",
                            "testlab_ownership_marker", MAX_MARKER_BYTES).splitlines()
    if (len(contents) != 3 or contents[0] != "o3k-disposable-testlab-v1"
            or contents[2] != f"run={run_id}"):
        raise ObservationError("validate_testlab_ownership_marker_contents", "sudo_read_only",
                               "testlab_ownership_marker", "ValueError")
    source_sha = contents[1].removeprefix("commit=")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_sha):
        raise ObservationError("validate_testlab_ownership_marker_contents", "sudo_read_only",
                               "testlab_ownership_marker", "ValueError")
    return source_sha.lower()


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    marker = sub.add_parser("verify-marker")
    marker.add_argument("--state-root", type=Path, required=True)
    marker.add_argument("--run-id", required=True)
    marker.add_argument("--source-sha", required=True)
    identity = sub.add_parser("bootstrap-agent-id")
    identity.add_argument("--state-root", type=Path, required=True)
    identity.add_argument("--run-id", required=True)
    identity.add_argument("--source-sha", required=True)
    stale = sub.add_parser("read-marker-source-sha")
    stale.add_argument("--state-root", type=Path, required=True)
    stale.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        if args.command == "verify-marker":
            verify_marker(args.state_root, args.run_id, args.source_sha)
            return 0
        if args.command == "read-marker-source-sha":
            print(read_marker_source_sha(args.state_root, args.run_id))
            return 0
        print(read_bootstrap_agent_id(args.state_root, args.run_id, args.source_sha))
        return 0
    except ObservationError as error:
        print(f"PP.5 protected observer: {error.operation}: {error.diagnostic}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(f"PP.5 protected observer: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
