#!/usr/bin/env python3
"""Fail-closed PP.5 runner prerequisite check.

The protected runner may use either an explicitly configured loopback
PostgreSQL admin URL or the local ``postgres`` OS account.  The check keeps
the cheap qualification deterministic: it installs only the PostgreSQL
client when it is absent, bounds package-manager and probe operations, and
publishes a redacted artifact before returning failure.
"""

from __future__ import annotations

import json
import contextlib
import importlib.util
import io
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def artifact_path() -> Path:
    root = Path(env("O3K_PP5_ARTIFACT_DIR", "target/real-host-workflow-artifacts"))
    root.mkdir(parents=True, exist_ok=True)
    return root / "pp5-runner-prerequisite.json"


def write_artifact(path: Path, document: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def canonical_admin_url_is_valid() -> bool:
    """Reuse the canonical PostgreSQL URL policy; do not create a second authority."""
    source = Path(__file__).with_name("provision_pp5_postgres.py")
    spec = importlib.util.spec_from_file_location("pp5_postgres_authority", source)
    if spec is None or spec.loader is None:
        return False
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            spec.loader.exec_module(module)
            module.admin_url()
        except (SystemExit, OSError, ValueError):
            return False
    return True


def run_silent(command: list[str], timeout: int) -> bool:
    try:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def install_client() -> tuple[bool, str]:
    if shutil.which("psql"):
        return True, "already_present"
    if not shutil.which("sudo") or not shutil.which("apt-get") or not shutil.which("flock"):
        return False, "package_tools_unavailable"
    lock = "/run/lock/o3k-testlab-apt.lock"
    if not run_silent(["sudo", "-n", "test", "-d", "/run/lock"], 10):
        return False, "package_lock_directory_unavailable"
    command = [
        "sudo", "-n", "flock", "-x", lock, "bash", "-c",
        "set -euo pipefail; "
        "timeout --signal=TERM --kill-after=30s 300s "
        "env DEBIAN_FRONTEND=noninteractive apt-get update -qq; "
        "timeout --signal=TERM --kill-after=30s 300s "
        "env DEBIAN_FRONTEND=noninteractive apt-get install -y "
        "--no-install-recommends postgresql-client",
    ]
    if not run_silent(command, 660):
        return False, "postgresql_client_install_failed"
    return (shutil.which("psql") is not None), "installed" if shutil.which("psql") else "install_incomplete"


def main() -> int:
    started = int(time.time())
    output = artifact_path()
    fd, attempt_name = tempfile.mkstemp(
        prefix="pp5-runner-prerequisite-", suffix=".json", dir=output.parent, text=True
    )
    os.close(fd)
    attempt = Path(attempt_name)
    document = {
        "artifact_type": "pp5-runner-prerequisite",
        "schema_version": 1,
        "status": "running",
        "current_phase": "client_tools",
        "failure_phase": None,
        "failure_reason": None,
        "attempt_artifact": attempt.name,
        "run_id": env("O3K_PP5_RUN_ID") or env("GITHUB_RUN_ID"),
        "source_sha": env("O3K_PP5_SOURCE_SHA") or env("GITHUB_SHA"),
        "redacted": True,
        "started_at": started,
    }

    def checkpoint() -> None:
        write_artifact(attempt, document)
        write_artifact(output, document)

    # Publish before package installation or any probe so interruption leaves
    # a precise running artifact rather than silently losing the attempt.
    checkpoint()
    admin_configured = bool(env("O3K_PP5_POSTGRES_ADMIN_URL"))
    admin_valid = not admin_configured or canonical_admin_url_is_valid()
    client_before = shutil.which("psql") is not None
    if admin_configured and not admin_valid:
        client_ok, client_action = False, "not_attempted_invalid_admin_url"
    else:
        client_ok, client_action = install_client()
    local_account = False
    try:
        local_account = pwd.getpwnam("postgres").pw_uid != 0
    except KeyError:
        pass
    local_probe = None
    failure_phase = None
    failure_reason = None

    if not admin_valid:
        failure_phase = "configuration"
        failure_reason = "invalid_admin_url"
    elif not client_ok:
        failure_phase = "client_tools"
        failure_reason = client_action
    elif not admin_configured:
        document["current_phase"] = "postgres_admin"
        checkpoint()
        local_probe = run_silent(
            [
                "sudo", "-n", "-u", "postgres", "psql", "-X", "-w",
                "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-Atqc", "SELECT 1",
            ],
            30,
        )
        if not local_account or not local_probe:
            failure_phase = "postgres_admin"
            failure_reason = "configure_admin_url_or_local_postgres_access"

    status = "failed" if failure_phase else "passed"
    document.update(
        status=status,
        current_phase=failure_phase or "completed",
        failure_phase=failure_phase,
        failure_reason=failure_reason,
        client_present_before=client_before,
        client_present_after=shutil.which("psql") is not None,
        client_action=client_action,
        admin_url_present=admin_configured,
        admin_url_valid=admin_valid,
        local_postgres_account=local_account,
        local_postgres_probe=local_probe,
        finished_at=int(time.time()),
    )
    checkpoint()
    if failure_phase:
        print(f"PP5 runner prerequisite failed: {failure_phase} ({failure_reason})", file=sys.stderr)
        return 2
    print("PP5 runner prerequisite PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
