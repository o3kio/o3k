#!/usr/bin/env python3
"""Fail-closed PP.5 runner prerequisite check.

The protected runner may use either an explicitly configured loopback
PostgreSQL admin URL or a run-owned local PostgreSQL installation.  The check
keeps the cheap qualification deterministic: package/service operations are
bounded, local service state is recorded for restoration, and redacted
artifacts are published before returning failure.
"""

from __future__ import annotations

import json
import contextlib
import importlib.util
import io
import os
import pwd
import re
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


def service_state_path() -> Path:
    root = Path(env("O3K_PP5_ARTIFACT_DIR", "target/real-host-workflow-artifacts"))
    root.mkdir(parents=True, exist_ok=True)
    return root / "pp5-runner-postgres-service-state.json"


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


def install_packages(packages: list[str]) -> tuple[bool, str]:
    if not shutil.which("sudo") or not shutil.which("apt-get") or not shutil.which("flock"):
        return False, "package_tools_unavailable"
    if not packages or any(not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", package) for package in packages):
        return False, "unsafe_package_name"
    lock = "/run/lock/o3k-testlab-apt.lock"
    if not run_silent(["sudo", "-n", "test", "-d", "/run/lock"], 10):
        return False, "package_lock_directory_unavailable"
    package_list = " ".join(packages)
    command = [
        "sudo", "-n", "flock", "-x", lock, "bash", "-c",
        "set -euo pipefail; "
        "timeout --signal=TERM --kill-after=30s 300s "
        "env DEBIAN_FRONTEND=noninteractive apt-get update -qq; "
        "timeout --signal=TERM --kill-after=30s 300s "
        "env DEBIAN_FRONTEND=noninteractive apt-get install -y "
        f"--no-install-recommends {package_list}",
    ]
    if not run_silent(command, 660):
        return False, "postgresql_package_install_failed"
    return True, "installed"


def install_client() -> tuple[bool, str]:
    if shutil.which("psql"):
        return True, "already_present"
    ok, reason = install_packages(["postgresql-client"])
    return ok and shutil.which("psql") is not None, reason


def local_service_active() -> bool:
    for command in (
        ["sudo", "-n", "systemctl", "is-active", "--quiet", "postgresql"],
        ["sudo", "-n", "service", "postgresql", "status"],
    ):
        if run_silent(command, 15):
            return True
    return False


def start_local_service() -> bool:
    for command in (
        ["sudo", "-n", "systemctl", "start", "postgresql"],
        ["sudo", "-n", "service", "postgresql", "start"],
    ):
        if run_silent(command, 60) and local_service_active():
            return True
    return False


def stop_local_service() -> bool:
    for command in (
        ["sudo", "-n", "systemctl", "stop", "postgresql"],
        ["sudo", "-n", "service", "postgresql", "stop"],
    ):
        if run_silent(command, 60):
            return not local_service_active()
    return False


def local_server_binary_present() -> bool:
    if shutil.which("postgres") or shutil.which("pg_ctlcluster"):
        return True
    versioned_root = Path("/usr/lib/postgresql")
    return any(versioned_root.glob("*/bin/postgres"))


def write_service_state(was_active: bool, started: bool, server_installed: bool) -> None:
    write_artifact(service_state_path(), {
        "artifact_type": "pp5-runner-postgres-service-state",
        "schema_version": 1,
        "run_id": env("O3K_PP5_RUN_ID") or env("GITHUB_RUN_ID"),
        "source_sha": env("O3K_PP5_SOURCE_SHA") or env("GITHUB_SHA"),
        "redacted": True,
        "local_service_was_active": was_active,
        "local_service_started": started,
        "server_package_installed": server_installed,
    })


def restore_service() -> int:
    path = service_state_path()
    if not path.is_file():
        return 0
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print("PP5 PostgreSQL service state is unreadable", file=sys.stderr)
        return 2
    expected_run = env("O3K_PP5_RUN_ID") or env("GITHUB_RUN_ID")
    expected_sha = env("O3K_PP5_SOURCE_SHA") or env("GITHUB_SHA")
    if not expected_run:
        print("PP5 PostgreSQL service state run mismatch", file=sys.stderr)
        return 2
    # A prior workflow may leave its redacted state artifact on a shared
    # runner. Never mutate a service based on another run's ledger; leave that
    # artifact untouched and let the current run's own state be restored by a
    # later invocation. This is safe because ownership is exact run-scoped.
    if state.get("run_id") != expected_run:
        return 0
    if not expected_sha or state.get("source_sha") != expected_sha:
        print("PP5 PostgreSQL service state source mismatch", file=sys.stderr)
        return 2
    if state.get("local_service_started") and not state.get("local_service_was_active"):
        if not stop_local_service():
            print("PP5 PostgreSQL service restore failed", file=sys.stderr)
            return 2
    return 0


def ensure_local_server() -> tuple[bool, str, bool, bool]:
    """Install/start local PostgreSQL when no external authority is configured."""
    was_active = local_service_active()
    try:
        account_present = pwd.getpwnam("postgres").pw_uid != 0
    except KeyError:
        account_present = False
    client_present = shutil.which("psql") is not None
    server_present = account_present and local_server_binary_present()
    server_installed = False
    if not server_present or not client_present:
        packages = []
        if not server_present:
            packages.append("postgresql")
        if not client_present:
            packages.append("postgresql-client")
        ok, reason = install_packages(packages)
        if not ok:
            write_service_state(was_active, not was_active and local_service_active(), False)
            return False, reason, was_active, False
        server_installed = True
        if not shutil.which("psql"):
            write_service_state(was_active, not was_active and local_service_active(), server_installed)
            return False, "postgresql_client_unavailable_after_install", was_active, server_installed
    if not was_active and not start_local_service():
        write_service_state(was_active, not was_active and local_service_active(), server_installed)
        return False, "postgresql_service_start_failed", was_active, server_installed
    write_service_state(was_active, not was_active, server_installed)
    return True, "already_active" if was_active else "started", was_active, server_installed


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
    local_account = False
    try:
        local_account = pwd.getpwnam("postgres").pw_uid != 0
    except KeyError:
        pass
    if admin_configured and not admin_valid:
        client_ok, client_action = False, "not_attempted_invalid_admin_url"
        server_action = "not_attempted_invalid_admin_url"
        service_was_active = None
        server_installed = False
    elif admin_configured:
        client_ok, client_action = install_client()
        server_action = "external_admin_url"
        service_was_active = None
        server_installed = False
        # Mark this run as external-authority-only so a stale service-state
        # artifact from an earlier run cannot cause final cleanup to stop a
        # service it did not start.
        write_service_state(False, False, False)
    else:
        document["current_phase"] = "postgres_server"
        checkpoint()
        client_ok, server_action, service_was_active, server_installed = ensure_local_server()
        client_action = server_action
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
        failure_phase = "postgres_server" if not admin_configured else "client_tools"
        failure_reason = server_action if not admin_configured else client_action
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
            failure_reason = "local_postgres_peer_access_failed"

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
        local_service_was_active=service_was_active,
        local_server_installed=server_installed,
        server_action=server_action,
        finished_at=int(time.time()),
    )
    checkpoint()
    if failure_phase:
        print(f"PP5 runner prerequisite failed: {failure_phase} ({failure_reason})", file=sys.stderr)
        return 2
    print("PP5 runner prerequisite PASS")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "restore":
        raise SystemExit(restore_service())
    raise SystemExit(main())
