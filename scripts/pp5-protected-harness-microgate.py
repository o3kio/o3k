#!/usr/bin/env python3
"""Read-only PP.5 runner boundary proof, stopped before S1 workload creation."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
OBSERVER_PATH = ROOT / "scripts" / "pp5-protected-state-observer.py"
SPEC = importlib.util.spec_from_file_location("pp5_protected_state_observer", OBSERVER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("protected state observer module unavailable")
OBSERVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = OBSERVER
SPEC.loader.exec_module(OBSERVER)
sys.path.insert(0, str(ROOT / "scripts"))
import provision_pp5_postgres as POSTGRES  # noqa: E402


class GateFailure(Exception):
    def __init__(self, operation: str, observer_type: str, resource_class: str,
                 diagnostic: str, command_class: str | None = None,
                 exit_code: int | None = None) -> None:
        super().__init__(diagnostic)
        self.operation = operation
        self.observer_type = observer_type
        self.resource_class = resource_class
        self.diagnostic = diagnostic
        self.command_class = command_class
        self.exit_code = exit_code


class Context:
    def __init__(self) -> None:
        self.current_operation = "initialize_microgate"
        self.observer_type = "runner_readable"
        self.resource_class = "campaign_state"

    def at(self, operation: str, observer: str, resource: str) -> None:
        self.current_operation = operation
        self.observer_type = observer
        self.resource_class = resource

    def run(self, operation: str, observer: str, resource: str,
            command: list[str], *, timeout: int = 20) -> subprocess.CompletedProcess[str]:
        self.at(operation, observer, resource)
        try:
            result = subprocess.run(command, check=False, capture_output=True,
                                    text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise GateFailure(operation, observer, resource, type(error).__name__,
                              pathlib.Path(command[0]).name, None) from error
        except OSError as error:
            raise GateFailure(operation, observer, resource, type(error).__name__,
                              pathlib.Path(command[0]).name, None) from error
        if result.returncode != 0:
            raise GateFailure(operation, observer, resource, "SubprocessError",
                              pathlib.Path(command[0]).name, result.returncode)
        return result

    def json_command(self, operation: str, command: list[str], observer: str,
                     resource: str) -> Any:
        result = self.run(operation, observer, resource, command)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise GateFailure(operation, observer, resource, "JSONDecodeError",
                              pathlib.Path(command[0]).name, result.returncode) from error


def read_json(path: pathlib.Path, operation: str, context: Context) -> dict[str, Any]:
    context.at(operation, "runner_readable", "workflow_evidence")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GateFailure(operation, context.observer_type, context.resource_class,
                          type(error).__name__) from error
    if not isinstance(value, dict):
        raise GateFailure(operation, context.observer_type, context.resource_class,
                          "ValueError")
    return value


def parse_pid_record(contents: str, binary: str) -> tuple[int, str, str]:
    fields = contents.strip().split("|")
    expected_owner = {"o3kd": "o3k", "o3k-compute": "o3k-compute"}.get(binary)
    if (expected_owner is None or len(fields) != 4 or not fields[0].isdigit()
            or not fields[1].isdigit() or fields[2] != expected_owner or fields[3] != binary):
        raise ValueError("TestLab PID record identity mismatch")
    return int(fields[0]), fields[1], fields[2]


def verify_workflow_prerequisites(args: argparse.Namespace, context: Context) -> dict[str, Any]:
    generic = read_json(args.generic_cleanup, "verify_generic_epoch_absence", context)
    if (generic.get("status") != "passed"
            or generic.get("workflow_run_id") != args.run_id
            or str(generic.get("tested_source_sha", "")).lower() != args.source_sha.lower()
            or generic.get("workload_absence_status") != 0
            or generic.get("cleanup_command_status") != 0
            or generic.get("post_cleanup_inventory_status") != 0
            or generic.get("pre_teardown_workload_absence") != "passed"
            or generic.get("cleanup_command") != "passed"
            or generic.get("post_teardown_host_absence") != "passed"
            or any(generic.get(field) != 0 for field in (
                "run_owned_servers", "run_owned_ports", "run_owned_domains", "run_owned_processes"))
            or generic.get("generic_roots_absent") is not True
            or generic.get("foreign_state_unchanged") is not True):
        raise GateFailure("verify_generic_epoch_absence", "runner_readable",
                          "generic_testlab_epoch", "ValueError")
    binding = read_json(args.campaign_binding, "verify_campaign_database_binding", context)
    if (binding.get("status") != "passed"
            or binding.get("run_id") != args.run_id
            or str(binding.get("source_sha", "")).lower() != args.source_sha.lower()
            or binding.get("manifest_validation") != "passed"
            or binding.get("campaign_sentinel") != "passed"
            or binding.get("campaign_url_restored") is not True
            or binding.get("destructive_urls_absent") is not True
            or os.environ.get("O3K_DATABASE_BACKEND") != "postgres"
            or os.environ.get("O3K_P15_7_POSTGRES_MODE") != "external"
            or not os.environ.get("O3K_PP5_CAMPAIGN_DATABASE_URL")):
        raise GateFailure("verify_campaign_database_binding", "runner_readable",
                          "campaign_database_binding", "ValueError")
    manifest = read_json(args.postgres_manifest, "verify_campaign_postgres_manifest", context)
    context.at("validate_campaign_postgres_manifest", "runner_readable", "campaign_database_manifest")
    try:
        POSTGRES.check_manifest_identity(manifest, args.run_id, args.source_sha)
        if manifest.get("provisioning", {}).get("status") != "completed":
            raise ValueError("campaign database provisioning is incomplete")
        if manifest.get("cleanup"):
            raise ValueError("campaign database map is already in cleanup")
        campaign_url = os.environ["O3K_PP5_CAMPAIGN_DATABASE_URL"]
        POSTGRES.validate_url(manifest, "campaign", campaign_url)
    except (ValueError, KeyError, SystemExit) as error:
        raise GateFailure("validate_campaign_postgres_manifest", "runner_readable",
                          "campaign_database_manifest", type(error).__name__) from error
    context.at("verify_campaign_postgres_sentinel", "api_observation", "campaign_database_sentinel")
    try:
        sentinel_matches = POSTGRES.verify_purpose_sentinel(campaign_url, manifest, "campaign")
    except SystemExit as error:
        raise GateFailure("verify_campaign_postgres_sentinel", "api_observation",
                          "campaign_database_sentinel", "SubprocessError", "psql",
                          error.code if isinstance(error.code, int) else None) from error
    if not sentinel_matches:
        raise GateFailure("verify_campaign_postgres_sentinel", "api_observation",
                          "campaign_database_sentinel", "ValueError")
    if any(os.environ.get(name) for name in (
            "O3K_PP5_WORKSPACE_DATABASE_URL", "O3K_PP5_ENDPOINT_DATABASE_URL",
            "O3K_PP5_P13_DATABASE_URL")):
        raise GateFailure("verify_destructive_database_urls_absent", "runner_readable",
                          "campaign_database_binding", "ValueError")
    return manifest


def verify_runner_roots(args: argparse.Namespace, context: Context) -> None:
    context.at("resolve_runner_temp", "runner_readable", "runner_temp")
    try:
        runner_temp = pathlib.Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        expected_pid = runner_temp / "o3k-testlab-pids" / f"{args.run_id}-pp5"
        expected_inventory = runner_temp / "o3k-testlab-inventory" / f"{args.run_id}-pp5"
        pid_root = pathlib.Path(args.pid_root)
        inventory_root = pathlib.Path(args.inventory_root)
        if pid_root != expected_pid or inventory_root != expected_inventory:
            raise ValueError("runner roots do not match the exact PP.5 run identity")
        for operation, path, required_mode in (
                ("inspect_testlab_pid_root", pid_root, 0o700),
                ("inspect_testlab_inventory_root", inventory_root, 0o755)):
            context.at(operation, "runner_readable", "testlab_runner_root")
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise PermissionError("runner root owner/type mismatch")
            if stat.S_IMODE(info.st_mode) != required_mode:
                raise PermissionError("runner root mode mismatch")
            if path.resolve(strict=True) != path:
                raise PermissionError("runner root resolves outside its exact identity")
        context.at("verify_testlab_pid_records", "runner_readable", "testlab_pid_root")
        for binary in ("o3kd", "o3k-compute"):
            record = pid_root / f"{binary}.pid"
            info = record.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise PermissionError("TestLab PID record metadata mismatch")
            pid, recorded_start, recorded_owner = parse_pid_record(
                record.read_text(encoding="ascii"), binary)
            proc_stat = context.run(
                "verify_testlab_process_identity", "sudo_read_only", "testlab_process",
                ["sudo", "-n", "cat", "--", f"/proc/{pid}/stat"], timeout=5).stdout
            close = proc_stat.rfind(")")
            stat_fields = proc_stat[close + 2:].split() if close >= 0 else []
            if len(stat_fields) <= 19 or stat_fields[19] != recorded_start:
                raise PermissionError("TestLab PID start time does not match its run-owned record")
            executable = context.run(
                "verify_testlab_process_executable", "sudo_read_only", "testlab_process",
                ["sudo", "-n", "readlink", f"/proc/{pid}/exe"], timeout=5).stdout.strip()
            expected_executable = str(pathlib.Path(args.state_root) / "bin" / binary)
            if executable != expected_executable:
                raise PermissionError("TestLab process executable does not match its run-owned binary")
            process_uid = context.run(
                "verify_testlab_process_owner", "sudo_read_only", "testlab_process",
                ["sudo", "-n", "stat", "-c", "%U", "--", f"/proc/{pid}"], timeout=5).stdout.strip()
            if process_uid != recorded_owner:
                raise PermissionError("TestLab process UID does not match its run-owned record")
        context.at("verify_testlab_inventory_marker", "runner_readable", "testlab_inventory_root")
        marker = inventory_root / ".o3k-inventory-owned"
        info = marker.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o644):
            raise PermissionError("TestLab inventory marker metadata mismatch")
        expected_marker = {
            "o3k-disposable-inventory-v1",
            f"commit={args.source_sha.lower()}",
            f"run={args.run_id}-pp5",
        }
        if set(marker.read_text(encoding="utf-8").splitlines()) != expected_marker:
            raise ValueError("TestLab inventory marker identity mismatch")
        context.at("resolve_openstack_cli_venv", "runner_executable", "openstack_cli_venv")
        venv = pathlib.Path(args.openstack_venv)
        if (venv.parent != runner_temp or not venv.name.startswith("o3k-openstack-venv.")
                or venv.is_symlink() or not venv.is_dir()):
            raise ValueError("OpenStack virtualenv is not the exact run-owned runner directory")
        venv_info = venv.stat()
        if venv_info.st_uid != os.getuid():
            raise PermissionError("OpenStack virtualenv owner mismatch")
        venv_marker = venv / ".o3k-venv-owned"
        marker_info = venv_marker.lstat()
        if (not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != os.getuid()
                or stat.S_IMODE(marker_info.st_mode) != 0o600):
            raise PermissionError("OpenStack virtualenv marker metadata mismatch")
        if set(venv_marker.read_text(encoding="utf-8").splitlines()) != {
                "o3k-disposable-venv-v1", f"commit={args.source_sha.lower()}",
                f"run={args.run_id}-pp5"}:
            raise ValueError("OpenStack virtualenv marker identity mismatch")
        cli = venv / "bin" / "openstack"
        cli_info = cli.lstat()
        if not stat.S_ISREG(cli_info.st_mode) or not os.access(cli, os.X_OK):
            raise PermissionError("OpenStack CLI is not runner-executable")
        path_cli = shutil.which("openstack")
        if path_cli is None or pathlib.Path(path_cli).resolve() != cli.resolve():
            raise FileNotFoundError("OpenStack CLI PATH does not select the run-owned virtualenv")
    except OSError as error:
        raise GateFailure(context.current_operation, context.observer_type,
                          context.resource_class, type(error).__name__) from error
    except ValueError as error:
        raise GateFailure(context.current_operation, context.observer_type,
                          context.resource_class, type(error).__name__) from error


def generated_operator_token_path(args: argparse.Namespace, context: Context) -> pathlib.Path | None:
    if os.environ.get("O3K_P15_7_AUTHORITY_MODE", "testlab-keycloak") != "testlab-keycloak":
        return None
    context.at("prepare_operator_token_output", "runner_readable", "operator_token")
    try:
        runner_temp = pathlib.Path(os.environ.get("RUNNER_TEMP", "/tmp")).resolve(strict=True)
        path = runner_temp / f"o3k-pp5-microgate-token-{args.run_id}"
        if path.exists() or path.is_symlink():
            raise FileExistsError("run-scoped token output already exists")
        return path
    except OSError as error:
        raise GateFailure("prepare_operator_token_output", "runner_readable",
                          "operator_token", type(error).__name__) from error


def remove_generated_operator_token(path: pathlib.Path, args: argparse.Namespace) -> None:
    runner_temp = pathlib.Path(os.environ.get("RUNNER_TEMP", "/tmp")).resolve(strict=True)
    expected = runner_temp / f"o3k-pp5-microgate-token-{args.run_id}"
    if path != expected:
        raise ValueError("operator token path is outside its exact run identity")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise PermissionError("generated operator token metadata changed")
    path.unlink()
    if path.exists() or path.is_symlink():
        raise OSError("generated operator token remains after cleanup")


def obtain_operator_token(args: argparse.Namespace, context: Context,
                          generated_path: pathlib.Path | None) -> str:
    mode = os.environ.get("O3K_P15_7_AUTHORITY_MODE", "testlab-keycloak")
    if mode == "testlab-keycloak":
        path = generated_path
        if path is None:
            raise GateFailure("prepare_operator_token_output", "runner_readable",
                              "operator_token", "ValueError")
        env = dict(os.environ)
        env.update({
            "O3K_P15_7_AUTHORITY_MODE": "testlab-keycloak",
            "O3K_P15_7_KEYCLOAK_STATE_ROOT": os.environ.get(
                "O3K_P15_7_KEYCLOAK_STATE_ROOT",
                str(path.parent / f"o3k-p15-7-keycloak-{args.run_id}")),
            "O3K_P15_7_NATIVE_API_URL": f"http://127.0.0.1:{args.api_port}/o3k/v1",
            "O3K_P15_7_AUTHORITY_OUTPUT_FILE": str(path),
            "GITHUB_RUN_ID": args.run_id,
            "O3K_P15_7_SOURCE_SHA": args.source_sha,
        })
        context.at("exchange_system_operator_authority", "api_observation", "operator_authority")
        try:
            result = subprocess.run(["bash", str(ROOT / "scripts" / "p15-7-keycloak-authority.sh"),
                                     "exchange"], check=False, capture_output=True,
                                    text=True, timeout=30, env=env)
        except (OSError, subprocess.SubprocessError) as error:
            raise GateFailure("exchange_system_operator_authority", "api_observation",
                              "operator_authority", type(error).__name__, "bash", None) from error
        if result.returncode != 0:
            raise GateFailure("exchange_system_operator_authority", "api_observation",
                              "operator_authority", "SubprocessError", "bash", result.returncode)
        token_path = path
    elif mode == "external-oidc":
        token_value = os.environ.get("O3K_P15_7_OPERATOR_TOKEN_FILE", "")
        token_path = pathlib.Path(token_value) if token_value else pathlib.Path()
        if not token_value:
            raise GateFailure("read_operator_token", "runner_readable", "operator_token", "FileNotFoundError")
    else:
        raise GateFailure("select_operator_authority", "runner_readable",
                          "operator_authority", "ValueError")

    context.at("read_operator_token", "runner_readable", "operator_token")
    try:
        if token_path.is_symlink() or not token_path.is_file():
            raise OSError("token file unavailable")
        metadata = token_path.stat()
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o777 != 0o600:
            raise PermissionError("token file owner/mode invalid")
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise GateFailure("read_operator_token", "runner_readable", "operator_token",
                          type(error).__name__) from error
    if not token or "\n" in token:
        raise GateFailure("validate_operator_token", "runner_readable", "operator_token", "ValueError")
    return token


def api_json(context: Context, base: str, token: str, path: str,
             resource_class: str) -> Any:
    context.at("GET " + path.split("?", 1)[0], "api_observation", resource_class)
    request = urllib.request.Request(base + path, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise GateFailure(context.current_operation, "api_observation",
                                  resource_class, "HTTPError", "urllib", response.status)
            payload = response.read(2 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        raise GateFailure(context.current_operation, "api_observation", resource_class,
                          "HTTPError", "urllib", error.code) from error
    except (OSError, TimeoutError) as error:
        raise GateFailure(context.current_operation, "api_observation", resource_class,
                          type(error).__name__, "urllib", None) from error
    if len(payload) > 2 * 1024 * 1024:
        raise GateFailure(context.current_operation, "api_observation", resource_class, "ValueError")
    try:
        return json.loads(payload)
    except json.JSONDecodeError as error:
        raise GateFailure(context.current_operation, "api_observation", resource_class,
                          "JSONDecodeError") from error


def foreign_fingerprint(args: argparse.Namespace, context: Context) -> tuple[dict[str, Any], dict[str, Any]]:
    before = read_json(args.generic_baseline, "read_pre_generic_foreign_fingerprint", context)
    before_foreign = before.get("foreign_state")
    if before.get("status") != "available" or not isinstance(before_foreign, dict):
        raise GateFailure("read_pre_generic_foreign_fingerprint", "runner_readable",
                          "foreign_state", "ValueError")
    before_domains = before.get("domains")
    if not isinstance(before_domains, list) or any(not isinstance(name, str) for name in before_domains):
        raise GateFailure("read_pre_generic_libvirt_inventory", "runner_readable",
                          "libvirt_domains", "ValueError")
    with tempfile.TemporaryDirectory(prefix="o3k-pp5-microgate-") as temporary:
        path = pathlib.Path(temporary) / "inventory.json"
        env = {"PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
               "O3K_REAL_HOST_OPENSTACK_INVENTORY": "false",
               "O3K_REAL_HOST_PROTECTED_PATHS": ""}
        libvirt_image_root = os.environ.get("O3K_P15_7_LIBVIRT_IMAGE_ROOT")
        if libvirt_image_root:
            env["O3K_P15_7_LIBVIRT_IMAGE_ROOT"] = libvirt_image_root
        context.at("collect_fresh_pp5_foreign_fingerprint", "libvirt_observation", "foreign_host_state")
        try:
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / "real-host-owned-inventory.py"),
                                     str(path)], check=False, capture_output=True, text=True,
                                    timeout=45, env=env)
        except (OSError, subprocess.SubprocessError) as error:
            raise GateFailure("collect_fresh_pp5_foreign_fingerprint", "libvirt_observation",
                              "foreign_host_state", type(error).__name__, "python3", None) from error
        if result.returncode != 0:
            raise GateFailure("collect_fresh_pp5_foreign_fingerprint", "libvirt_observation",
                              "foreign_host_state", "SubprocessError", "python3", result.returncode)
        after = read_json(path, "read_fresh_pp5_foreign_fingerprint", context)
    after_foreign = after.get("foreign_state")
    fields = ("domains_sha256", "network_links_sha256", "pools_count", "pools_sha256")
    if after.get("status") != "available" or not isinstance(after_foreign, dict):
        raise GateFailure("read_fresh_pp5_foreign_fingerprint", "runner_readable",
                          "foreign_state", "ValueError")
    after_domains = after.get("domains")
    if not isinstance(after_domains, list) or any(not isinstance(name, str) for name in after_domains):
        raise GateFailure("read_fresh_pp5_libvirt_inventory", "runner_readable",
                          "libvirt_domains", "ValueError")
    new_managed_domains = sorted(set(after_domains) - set(before_domains))
    removed_managed_domains = sorted(set(before_domains) - set(after_domains))
    unchanged = (not new_managed_domains and not removed_managed_domains
                 and all(before_foreign.get(field) == after_foreign.get(field) for field in fields))
    return ({field: before_foreign.get(field) for field in fields},
            {"unchanged": unchanged, "compared_fields": list(fields),
             "new_managed_domain_count": len(new_managed_domains),
             "removed_managed_domain_count": len(removed_managed_domains)})


def run_gate(args: argparse.Namespace) -> dict[str, Any]:
    context = Context()
    document: dict[str, Any] = {
        "artifact_type": "pp5-lane-initial-state",
        "schema_version": 1,
        "phase": "s1-boundary",
        "workflow_run_id": args.run_id,
        "tested_source_sha": args.source_sha,
        "status": "failed",
        "classification": "HARNESS_GAP",
        "redacted": True,
    }
    generated_token: pathlib.Path | None = None
    try:
        if not re.fullmatch(r"[0-9]+", args.run_id) or not re.fullmatch(r"[0-9a-fA-F]{40}", args.source_sha):
            raise GateFailure("validate_campaign_identity", "runner_readable", "campaign_identity", "ValueError")
        manifest = verify_workflow_prerequisites(args, context)

        bootstrap = read_json(args.bootstrap_artifact, "verify_fresh_pp5_bootstrap_artifact", context)
        if (bootstrap.get("status") != "passed"
                or str(bootstrap.get("source_commit", "")).lower() != args.source_sha.lower()
                or bootstrap.get("state_directory") != str(args.state_root)
                or bootstrap.get("provider") != "agent"
                or bootstrap.get("readiness") != {"o3kd": True, "compute": True}):
            raise GateFailure("verify_fresh_pp5_bootstrap_artifact", "runner_readable",
                              "fresh_pp5_testlab", "ValueError")

        context.at("read_testlab_ownership_marker", "sudo_read_only", "testlab_ownership_marker")
        try:
            marker = OBSERVER.verify_marker(pathlib.Path(args.state_root), f"{args.run_id}-pp5", args.source_sha)
        except OBSERVER.ObservationError as error:
            raise GateFailure(error.operation, error.observer_type, error.resource_class,
                              error.diagnostic, error.command_class, error.exit_code) from error
        document["ownership_marker"] = marker

        verify_runner_roots(args, context)
        openstack = str(pathlib.Path(args.openstack_venv) / "bin" / "openstack")
        configured_project_id = os.environ.get("OS_PROJECT_ID", "").strip()
        project_identity = configured_project_id or os.environ.get("OS_PROJECT_NAME", "admin").strip() or "admin"
        project = context.json_command("lookup_openstack_project_identity",
                                       [openstack, "project", "show", project_identity, "-f", "json"],
                                       "api_observation", "openstack_project_identity")
        if (not isinstance(project, dict) or not isinstance(project.get("id"), str)
                or not project["id"] or (configured_project_id and project["id"] != configured_project_id)):
            raise GateFailure("lookup_openstack_project_identity", "api_observation",
                              "openstack_project_identity", "ValueError", "openstack", 0)
        project_id = project["id"]
        if not isinstance(bootstrap.get("project_id"), str) or project_id != bootstrap["project_id"]:
            raise GateFailure("verify_openstack_project_identity", "api_observation",
                              "openstack_project_identity", "ValueError", "openstack", 0)
        servers = context.json_command("list_project_scoped_servers",
                                       [openstack, "server", "list", "--project", project_id, "-f", "json"],
                                       "api_observation", "openstack_servers")
        ports = context.json_command("list_project_scoped_ports",
                                     [openstack, "port", "list", "--project", project_id, "-f", "json"],
                                     "api_observation", "openstack_ports")
        if not isinstance(servers, list) or not isinstance(ports, list):
            raise GateFailure("validate_project_scoped_inventory", "api_observation",
                              "openstack_inventory", "ValueError")

        domain_output = context.run("list_libvirt_domains", "libvirt_observation", "libvirt_domains",
                                    ["virsh", "-c", "qemu:///system", "list", "--all", "--name"]).stdout
        owned_domain_prefix = f"o3k-p15-7-{args.run_id}-"
        domains = [line.strip() for line in domain_output.splitlines()
                   if line.strip().startswith(owned_domain_prefix)]
        counts = {"servers": len(servers), "ports": len(ports), "domains": len(domains)}
        if any(counts.values()):
            raise GateFailure("verify_zero_existing_workloads", "api_observation",
                              "run_owned_workloads", "ValueError")

        context.at("read_bootstrap_compute_identity", "sudo_read_only", "bootstrap_compute_identity")
        try:
            bootstrap_id = OBSERVER.read_bootstrap_agent_id(
                pathlib.Path(args.state_root), f"{args.run_id}-pp5", args.source_sha)
        except OBSERVER.ObservationError as error:
            raise GateFailure(error.operation, error.observer_type, error.resource_class,
                              error.diagnostic, error.command_class, error.exit_code) from error

        generated_token = generated_operator_token_path(args, context)
        token = obtain_operator_token(args, context, generated_token)
        api_port = args.api_port
        base = f"http://127.0.0.1:{api_port}/o3k/v1"
        blocks = api_json(context, base, token, "/operator/building-blocks", "canonical_topology")
        providers = api_json(context, base, token, "/operator/diagnostics/providers?limit=200",
                             "provider_diagnostics")
        capacity = api_json(context, base, token, "/operator/diagnostics/capacity", "capacity_diagnostics")
        if (not isinstance(blocks, list) or not isinstance(providers, dict)
                or not isinstance(providers.get("items"), list) or providers.get("has_more") is True
                or not isinstance(capacity, dict) or not isinstance(capacity.get("dimensions"), list)):
            raise GateFailure("validate_canonical_diagnostics", "api_observation",
                              "canonical_diagnostics", "ValueError")

        context.at("assess_s1_topology", "api_observation", "canonical_topology")
        provider_state = {item.get("provider_id"): item.get("state") for item in providers["items"]
                          if isinstance(item, dict) and isinstance(item.get("provider_id"), str)}
        identities: list[str] = []
        eligible = 0
        for view in blocks:
            if not isinstance(view, dict) or not isinstance(view.get("block"), dict):
                raise GateFailure("assess_s1_topology", "api_observation", "canonical_topology", "ValueError")
            block = view["block"]
            identity = block.get("execution_identity")
            if not isinstance(identity, str) or not identity:
                raise GateFailure("assess_s1_topology", "api_observation", "canonical_topology", "ValueError")
            identities.append(identity)
            provider_ids = block.get("resource_provider_ids") or []
            if not isinstance(provider_ids, list):
                raise GateFailure("assess_s1_topology", "api_observation", "canonical_topology", "ValueError")
            states = [provider_state.get(provider_id) for provider_id in provider_ids]
            live = any(state is not None for state in states)
            is_eligible = (block.get("state") == "ready" and live
                           and any(state == "Enabled" for state in states)
                           and not (block.get("drain_blockers") or []))
            eligible += int(is_eligible)
        if identities != [bootstrap_id] or eligible != 1:
            raise GateFailure("assess_s1_topology", "api_observation", "canonical_topology", "ValueError")

        context.at("verify_provider_allocations_zero", "api_observation", "provider_allocations")
        provider_allocations: list[int] = []
        for provider in providers["items"]:
            capacities = provider.get("capacity") if isinstance(provider, dict) else None
            if not isinstance(capacities, list) or not capacities:
                raise GateFailure("verify_provider_allocations_zero", "api_observation",
                                  "provider_allocations", "ValueError")
            for item in capacities:
                allocated = item.get("allocated") if isinstance(item, dict) else None
                if not isinstance(allocated, int) or allocated != 0:
                    raise GateFailure("verify_provider_allocations_zero", "api_observation",
                                      "provider_allocations", "ValueError")
                provider_allocations.append(allocated)
        dimensions = capacity["dimensions"]
        if not dimensions or any(not isinstance(item, dict) or item.get("allocated") != 0 for item in dimensions):
            raise GateFailure("verify_capacity_diagnostics_zero", "api_observation",
                              "capacity_diagnostics", "ValueError")

        _, foreign = foreign_fingerprint(args, context)
        if foreign.get("new_managed_domain_count", 0):
            raise GateFailure("verify_zero_existing_workloads", "libvirt_observation",
                              "run_owned_workloads", "ValueError")
        if foreign["unchanged"] is not True:
            raise GateFailure("compare_foreign_state", "libvirt_observation", "foreign_host_state", "ValueError")

        generic = read_json(args.generic_cleanup, "verify_generic_epoch_absence", context)
        binding = read_json(args.campaign_binding, "verify_campaign_database_binding", context)
        generic_residue = sum(generic.get(field, 1) for field in (
            "run_owned_servers", "run_owned_ports", "run_owned_domains", "run_owned_processes"))
        document.update({
            "status": "passed",
            "classification": None,
            "generic_epoch_absent": True,
            "campaign_database_bound": True,
            "fresh_pp5_testlab": True,
            "existing_workloads": counts,
            "eligible_compute_hosts": eligible,
            "child_compute_hosts": len(blocks) - 1,
            "provider_allocations_zero": True,
            "foreign_state_unchanged": True,
            "generic_teardown": generic.get("cleanup_command"),
            "generic_pre_teardown_absence": generic.get("pre_teardown_workload_absence"),
            "generic_post_teardown_host_absence": generic.get("post_teardown_host_absence"),
            "generic_pre_teardown_workload_absence": generic.get("pre_teardown_workload_absence"),
            "generic_owned_residue": generic_residue,
            "campaign_manifest_validation": binding.get("manifest_validation"),
            "campaign_sentinel": binding.get("campaign_sentinel"),
            "campaign_manifest_status": manifest.get("provisioning", {}).get("status"),
            "campaign_database": manifest.get("databases", {}).get("campaign", {}).get("name"),
            "campaign_role": manifest.get("role"),
            "campaign_host": manifest.get("server", {}).get("host"),
            "campaign_port": manifest.get("server", {}).get("port"),
            "project_scoped_server_count": len(servers),
            "project_scoped_port_count": len(ports),
            "run_owned_libvirt_domain_count": len(domains),
            "new_managed_domain_count": foreign.get("new_managed_domain_count", 0),
            "topology_total_hosts": len(blocks),
            "capacity_dimensions_checked": len(dimensions),
            "provider_allocation_dimensions_checked": len(provider_allocations),
            "pre_s1_workload_created": False,
        })
    except GateFailure as error:
        document.update({"failed_operation": error.operation,
                         "observer_type": error.observer_type,
                         "resource_class": error.resource_class,
                         "diagnostic": error.diagnostic})
        if error.command_class is not None:
            document["command_class"] = error.command_class
        if error.exit_code is not None:
            document["exit_code"] = error.exit_code
    except OBSERVER.ObservationError as error:
        document.update({"failed_operation": error.operation,
                         "observer_type": error.observer_type,
                         "resource_class": error.resource_class,
                         "diagnostic": error.diagnostic})
        if error.command_class is not None:
            document["command_class"] = error.command_class
        if error.exit_code is not None:
            document["exit_code"] = error.exit_code
    except Exception as error:  # keep evidence redacted and operation-specific
        document.update({"failed_operation": context.current_operation,
                         "observer_type": context.observer_type,
                         "resource_class": context.resource_class,
                         "diagnostic": type(error).__name__})
    finally:
        if generated_token is not None:
            try:
                remove_generated_operator_token(generated_token, args)
            except (OSError, ValueError) as error:
                cleanup_failure = {
                    "failed_operation": "remove_microgate_operator_token",
                    "observer_type": "runner_readable",
                    "resource_class": "operator_token",
                    "diagnostic": type(error).__name__,
                }
                if document.get("status") == "passed":
                    document.update(cleanup_failure)
                    document.update(status="failed", classification="HARNESS_GAP")
                else:
                    document["cleanup_failure"] = cleanup_failure
    return document


def validate_initial_state(args: argparse.Namespace) -> int:
    try:
        value = json.loads(args.artifact.read_text(encoding="utf-8"))
        microgate = json.loads(args.microgate_artifact.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 1
    counts = value.get("existing_workloads") if isinstance(value, dict) else None
    valid = (
        isinstance(value, dict)
        and value.get("artifact_type") == "pp5-lane-initial-state"
        and value.get("phase") == "s1-boundary"
        and value.get("status") == "passed"
        and value.get("workflow_run_id") == args.run_id
        and str(value.get("tested_source_sha", "")).lower() == args.source_sha.lower()
        and value.get("generic_epoch_absent") is True
        and value.get("campaign_database_bound") is True
        and value.get("fresh_pp5_testlab") is True
        and isinstance(counts, dict)
        and counts == {"servers": 0, "ports": 0, "domains": 0}
        and value.get("eligible_compute_hosts") == 1
        and value.get("child_compute_hosts") == 0
        and value.get("provider_allocations_zero") is True
        and value.get("foreign_state_unchanged") is True
        and value.get("generic_pre_teardown_workload_absence") == "passed"
        and value.get("generic_teardown") == "passed"
        and value.get("generic_post_teardown_host_absence") == "passed"
        and value.get("generic_owned_residue") == 0
        and value.get("campaign_manifest_validation") == "passed"
        and value.get("campaign_sentinel") == "passed"
        and value.get("pre_s1_workload_created") is False
        and isinstance(microgate, dict)
        and microgate.get("artifact_type") == "pp5-protected-harness-microgate"
        and microgate.get("status") == "passed"
        and microgate.get("phase") == "s1-boundary-preconditions"
        and microgate.get("workflow_run_id") == args.run_id
        and str(microgate.get("tested_source_sha", "")).lower() == args.source_sha.lower()
        and microgate.get("pre_s1_workload_created") is False
    )
    if not valid:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    gate = sub.add_parser("run")
    gate.add_argument("--run-id", required=True)
    gate.add_argument("--source-sha", required=True)
    gate.add_argument("--state-root", type=pathlib.Path, required=True)
    gate.add_argument("--generic-cleanup", type=pathlib.Path, required=True)
    gate.add_argument("--campaign-binding", type=pathlib.Path, required=True)
    gate.add_argument("--postgres-manifest", type=pathlib.Path, required=True)
    gate.add_argument("--bootstrap-artifact", type=pathlib.Path, required=True)
    gate.add_argument("--generic-baseline", type=pathlib.Path, required=True)
    gate.add_argument("--pid-root", type=pathlib.Path, required=True)
    gate.add_argument("--inventory-root", type=pathlib.Path, required=True)
    gate.add_argument("--openstack-venv", type=pathlib.Path, required=True)
    gate.add_argument("--api-port", type=int, required=True)
    gate.add_argument("--artifact", type=pathlib.Path, required=True)
    gate.add_argument("--microgate-artifact", type=pathlib.Path, required=True)
    verify = sub.add_parser("validate-artifact")
    verify.add_argument("--run-id", required=True)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--artifact", type=pathlib.Path, required=True)
    verify.add_argument("--microgate-artifact", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.command == "validate-artifact":
        return validate_initial_state(args)
    for target in (args.artifact, args.microgate_artifact):
        target.parent.mkdir(parents=True, exist_ok=True)
    pending = {
        "artifact_type": "pp5-lane-initial-state",
        "schema_version": 1,
        "phase": "s1-boundary",
        "workflow_run_id": args.run_id,
        "tested_source_sha": args.source_sha,
        "status": "failed",
        "classification": "HARNESS_GAP",
        "redacted": True,
    }
    microgate_pending = {
        "artifact_type": "pp5-protected-harness-microgate",
        "schema_version": 1,
        "phase": "s1-boundary-preconditions",
        "workflow_run_id": args.run_id,
        "tested_source_sha": args.source_sha,
        "status": "failed",
        "classification": "HARNESS_GAP",
        "redacted": True,
    }
    args.artifact.write_text(json.dumps(pending, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.microgate_artifact.write_text(json.dumps(microgate_pending, indent=2, sort_keys=True) + "\n",
                                       encoding="utf-8")
    result = run_gate(args)
    args.artifact.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    gate_result = dict(result)
    gate_result["artifact_type"] = "pp5-protected-harness-microgate"
    gate_result["phase"] = "s1-boundary-preconditions"
    args.microgate_artifact.write_text(json.dumps(gate_result, indent=2, sort_keys=True) + "\n",
                                       encoding="utf-8")
    if result.get("status") != "passed":
        print("PP.5 protected harness microgate failed: " + str(result.get("failed_operation")), file=sys.stderr)
        return 1
    print("PP.5 PROTECTED HARNESS MICROGATE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
