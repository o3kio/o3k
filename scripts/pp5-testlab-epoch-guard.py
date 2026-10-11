#!/usr/bin/env python3
"""Fail-closed PP.5 TestLab phase isolation checks.

The generic epoch proof has three independent phases: exact run-owned API
absence before teardown, teardown command success, and host-only absence after
teardown. This guard never deletes cloud or host resources.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any


OBSERVER_PATH = pathlib.Path(__file__).with_name("pp5-protected-state-observer.py")
OBSERVER_SPEC = importlib.util.spec_from_file_location("pp5_protected_state_observer", OBSERVER_PATH)
if OBSERVER_SPEC is None or OBSERVER_SPEC.loader is None:
    raise RuntimeError("PP.5 protected state observer is unavailable")
PROTECTED_OBSERVER = importlib.util.module_from_spec(OBSERVER_SPEC)
sys.modules[OBSERVER_SPEC.name] = PROTECTED_OBSERVER
OBSERVER_SPEC.loader.exec_module(PROTECTED_OBSERVER)


FOREIGN_FIELDS = (
    "domains_sha256",
    "network_links_sha256",
    "pools_count",
    "pools_sha256",
)
LIFECYCLE_RESOURCES = {
    "server": "server_id",
    "port": "port_id",
    "image": "image_id",
    "keypair": "keypair_id",
    "network": "network_id",
    "subnet": "subnet_id",
    "flavor": "flavor_id",
}
NOT_FOUND = re.compile(
    r"not[ -]?found|could not find|no .*found|no (server|port|image|keypair|network|subnet|flavor)\b|404",
    re.IGNORECASE,
)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} is not a JSON object")
    return value


def write_evidence(path: pathlib.Path, phase: str, run_id: str, **fields: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "artifact_type": "pp5-testlab-epoch-guard",
        "schema_version": 2,
        "redacted": True,
        "phase": phase,
        "workflow_run_id": run_id,
        "status": "passed",
        "finished_at": int(time.time()),
        **fields,
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def fail(path: pathlib.Path, phase: str, run_id: str, reason: str, **fields: Any) -> int:
    write_evidence(
        path,
        phase,
        run_id,
        status="failed",
        classification="HARNESS_GAP",
        reason=reason,
        **fields,
    )
    print(f"PP.5 TestLab epoch guard: HARNESS_GAP: {reason}", file=sys.stderr)
    return 1


class OperationFailure(Exception):
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

    def evidence(self) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "failed_operation": self.operation,
            "observer_type": self.observer_type,
            "resource_class": self.resource_class,
            "diagnostic": self.diagnostic,
        }
        if self.command_class is not None:
            fields["command_class"] = self.command_class
        if self.exit_code is not None:
            fields["exit_code"] = self.exit_code
        return fields


def run_owned_api_absence(args: argparse.Namespace) -> int:
    """Verify only exact resource IDs captured by the successful lifecycle."""
    checked = {"servers": 0, "ports": 0, "other_resources": 0}
    remaining: dict[str, int | None] = {"servers": None, "ports": None, "domains": None}
    context: dict[str, Any] = {
        "current_operation": "read_generic_lifecycle_evidence",
        "observer_type": "runner_readable",
        "resource_class": "generic_lifecycle_evidence",
    }

    def at(operation: str, observer_type: str, resource_class: str) -> None:
        context.clear()
        context.update(current_operation=operation, observer_type=observer_type,
                       resource_class=resource_class)

    def current_failure(error: Exception) -> dict[str, Any]:
        fields = {
            "failed_operation": context["current_operation"],
            "observer_type": context["observer_type"],
            "resource_class": context["resource_class"],
            "diagnostic": str(error) if isinstance(error, RuntimeError) else type(error).__name__,
        }
        fields.update({key: context[key] for key in ("command_class", "exit_code") if key in context})
        return fields

    try:
        lifecycle = load_json(args.lifecycle)
        if lifecycle.get("workflow_run_id") != args.run_id:
            raise ValueError("lifecycle evidence belongs to a different workflow run")
        if lifecycle.get("testlab_phase_id") != f"{args.run_id}-generic":
            raise ValueError("lifecycle evidence is not bound to the generic TestLab phase")
        cleanup_evidence = lifecycle.get("cleanup")
        if (
            lifecycle.get("status") != "passed"
            or not isinstance(cleanup_evidence, dict)
            or cleanup_evidence.get("status") != "passed"
        ):
            raise ValueError("public lifecycle or its cleanup did not pass")
        resources = lifecycle.get("resources")
        cleanup = cleanup_evidence.get("resources")
        if not isinstance(resources, dict) or not isinstance(cleanup, dict):
            raise ValueError("lifecycle resource ownership evidence is missing")
        if set(resources) != set(LIFECYCLE_RESOURCES.values()) or set(cleanup) != set(LIFECYCLE_RESOURCES):
            raise ValueError("lifecycle resource ownership evidence is incomplete")

        server_id = resources["server_id"]
        for resource, id_key in LIFECYCLE_RESOURCES.items():
            at(f"show_run_owned_{resource}", "api_observation", f"openstack_{resource}")
            resource_id = resources[id_key]
            if not isinstance(resource_id, str) or not resource_id or len(resource_id) > 128:
                raise ValueError("lifecycle resource identity is invalid")
            if cleanup[resource] != "verified_absent":
                raise ValueError("lifecycle cleanup did not verify every run-owned resource absent")
            try:
                result = subprocess.run(
                    ["openstack", resource, "show", resource_id, "-f", "json"],
                    check=False,
                    text=True,
                    capture_output=True,
                    timeout=20,
                )
            except (OSError, subprocess.SubprocessError) as error:
                context["command_class"] = "openstack"
                raise RuntimeError(type(error).__name__) from error
            context.update(command_class="openstack", exit_code=result.returncode)
            if result.returncode == 0:
                if resource == "server":
                    remaining["servers"] = 1
                elif resource == "port":
                    remaining["ports"] = 1
                raise ValueError("a run-owned lifecycle resource remains in the API")
            if not NOT_FOUND.search(result.stderr):
                raise ValueError("API could not prove a run-owned resource absent")
            if resource == "server":
                remaining["servers"] = 0
                checked["servers"] += 1
            elif resource == "port":
                remaining["ports"] = 0
                checked["ports"] += 1
            else:
                checked["other_resources"] += 1

        at("list_run_owned_libvirt_domain", "libvirt_observation", "libvirt_domains")
        try:
            domain_result = subprocess.run(
                ["virsh", "-c", "qemu:///system", "list", "--all", "--name"],
                check=False,
                text=True,
                capture_output=True,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError) as error:
            context["command_class"] = "virsh"
            raise RuntimeError(type(error).__name__) from error
        context.update(command_class="virsh", exit_code=domain_result.returncode)
        if domain_result.returncode != 0:
            raise RuntimeError("SubprocessError")
        domain_output = domain_result.stdout
        expected_domain = f"o3k-{server_id}"
        if expected_domain in {line.strip() for line in domain_output.splitlines()}:
            remaining["domains"] = 1
            raise ValueError("run-owned libvirt domain remains before TestLab teardown")
        remaining["domains"] = 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        return fail(
            args.artifact,
            "pre-teardown-api-absence",
            args.run_id,
            "run-owned lifecycle API or domain absence could not be proven before teardown",
            run_owned_servers=remaining["servers"],
            run_owned_ports=remaining["ports"],
            run_owned_domains=remaining["domains"],
            servers_checked=checked["servers"],
            ports_checked=checked["ports"],
            other_resources_absent=checked["other_resources"],
            **current_failure(error),
        )

    write_evidence(
        args.artifact,
        "pre-teardown-api-absence",
        args.run_id,
        run_owned_servers=0,
        run_owned_ports=0,
        run_owned_domains=0,
        servers_checked=checked["servers"],
        ports_checked=checked["ports"],
        other_resources_absent=checked["other_resources"],
        exact_run_owned_ids_checked=True,
        api_absence_proven_before_teardown=True,
    )
    return 0


def process_matches_state_root(state_root: pathlib.Path) -> list[str]:
    """Return redacted PIDs for live executables still rooted in this epoch."""
    matches: list[str] = []
    proc_root = pathlib.Path("/proc")
    try:
        subprocess.run(["sudo", "-n", "true"], check=True, capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as error:
        raise OperationFailure("verify_sudo_read_only_process_observer", "sudo_read_only",
                               "run_owned_processes", type(error).__name__, "sudo") from error
    try:
        entries = list(proc_root.iterdir())
    except OSError as error:
        raise OperationFailure("enumerate_host_processes", "runner_readable",
                               "host_process_inventory", type(error).__name__) from error
    expected_prefix = str(state_root) + "/bin/"
    for entry in entries:
        if not entry.name.isdigit():
            continue
        operation = "inspect_host_process_cmdline"
        try:
            if not (entry / "cmdline").read_bytes():
                continue
        except OSError:
            if not entry.exists():
                continue
            # If a process cannot be read, the privileged exe check below is
            # still required; cmdline contents are never retained.
        operation = "inspect_host_process_executable"
        try:
            result = subprocess.run(
                ["sudo", "-n", "readlink", str(entry / "exe")],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise OperationFailure(operation, "sudo_read_only", "run_owned_processes",
                                   type(error).__name__, "sudo") from error
        if result.returncode != 0:
            if not entry.exists():
                continue
            raise OperationFailure(operation, "sudo_read_only", "run_owned_processes",
                                   "SubprocessError", "sudo", result.returncode)
        executable = result.stdout.rstrip("\n")
        if not executable:
            raise OperationFailure(operation, "sudo_read_only", "run_owned_processes", "ValueError", "sudo", 0)
        if executable.startswith(expected_prefix):
            matches.append(entry.name)
    return matches


def post_teardown_host_absence(args: argparse.Namespace) -> int:
    roots = {
        "state": pathlib.Path(args.state_root),
        "pid": pathlib.Path(args.pid_root),
        "inventory": pathlib.Path(args.inventory_root),
    }
    if args.openstack_venv:
        roots["openstack_venv"] = pathlib.Path(args.openstack_venv)
    if args.image_path:
        roots["image"] = pathlib.Path(args.image_path)
        roots["image_marker"] = pathlib.Path(args.image_path + ".o3k-owned")

    operation = "inspect_generic_testlab_roots"
    remaining_roots: list[str] = []
    live_processes: list[str] = []
    try:
        remaining_roots = []
        for name, path in roots.items():
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            remaining_roots.append(name)
        if remaining_roots:
            raise OperationFailure("verify_generic_testlab_roots_absent", "runner_readable",
                                   "generic_testlab_roots", "ValueError")
        live_processes = process_matches_state_root(pathlib.Path(args.state_root))
        if live_processes:
            raise OperationFailure("verify_run_owned_processes_absent", "sudo_read_only",
                                   "run_owned_processes", "ValueError")
        operation = "read_pre_teardown_host_inventory"
        before = load_json(args.baseline)
        operation = "read_post_teardown_host_inventory"
        after = load_json(args.after)
        if before.get("status") != "available" or after.get("status") != "available":
            raise OperationFailure(operation, "runner_readable", "host_owned_inventory", "ValueError")
        if after.get("openstack", {}).get("status") != "not_checked":
            raise OperationFailure("verify_post_teardown_inventory_is_host_only", "runner_readable",
                                   "host_owned_inventory", "ValueError")
        for field in ("domains", "network_links", "pools"):
            if before.get(field) != after.get(field):
                raise OperationFailure("compare_run_owned_host_inventory", "libvirt_observation",
                                       field, "ValueError")
        before_foreign = before.get("foreign_state")
        after_foreign = after.get("foreign_state")
        if not isinstance(before_foreign, dict) or not isinstance(after_foreign, dict):
            raise OperationFailure("validate_foreign_state_fingerprints", "runner_readable",
                                   "foreign_state", "ValueError")
        differences = {
            key: {"before": before_foreign.get(key), "after": after_foreign.get(key)}
            for key in FOREIGN_FIELDS
            if before_foreign.get(key) != after_foreign.get(key)
        }
        if remaining_roots or live_processes or differences:
            failed_operation = (
                "verify_generic_testlab_roots_absent" if remaining_roots else
                "verify_run_owned_processes_absent" if live_processes else
                "compare_foreign_state_fingerprint"
            )
            resource_class = (
                "generic_testlab_roots" if remaining_roots else
                "run_owned_processes" if live_processes else
                "foreign_state"
            )
            return fail(
                args.artifact,
                "post-teardown-host-absence",
                args.run_id,
                "generic TestLab host state remains or foreign state changed",
                generic_roots_absent=not remaining_roots,
                run_owned_processes=0 if not live_processes else len(live_processes),
                foreign_state_unchanged=not differences,
                foreign_state_differences=differences,
                failed_operation=failed_operation,
                observer_type="libvirt_observation" if differences else "runner_readable",
                resource_class=resource_class,
                diagnostic="ValueError",
            )
    except OperationFailure as error:
        return fail(
            args.artifact,
            "post-teardown-host-absence",
            args.run_id,
            "post-teardown host-only absence could not be proven",
            generic_roots_absent=not remaining_roots,
            run_owned_processes=len(live_processes),
            foreign_state_unchanged=None,
            **error.evidence(),
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return fail(
            args.artifact,
            "post-teardown-host-absence",
            args.run_id,
            "post-teardown host-only absence could not be proven",
            generic_roots_absent=not remaining_roots,
            run_owned_processes=len(live_processes),
            foreign_state_unchanged=None,
            failed_operation=operation,
            observer_type="runner_readable",
            resource_class="host_owned_inventory",
            diagnostic=type(error).__name__,
        )

    write_evidence(
        args.artifact,
        "post-teardown-host-absence",
        args.run_id,
        generic_roots_absent=True,
        run_owned_processes=0,
        run_owned_host_state_matches_baseline=True,
        foreign_state_unchanged=True,
        compared_foreign_fields=list(FOREIGN_FIELDS),
        openstack_api_consulted=False,
    )
    return 0


def generic_cleanup(args: argparse.Namespace) -> int:
    source_sha = getattr(args, "source_sha", "")
    statuses = {
        "workload_absence_status": int(args.workload_status),
        "cleanup_command_status": int(args.cleanup_status),
        "post_cleanup_inventory_status": int(args.inventory_status),
    }
    phase_paths = {
        "pre_teardown_workload_absence": args.workloads,
        "post_teardown_host_absence": args.host_absence,
    }
    failures: list[str] = []
    evidence: dict[str, dict[str, Any]] = {}
    for label, path in phase_paths.items():
        try:
            document = load_json(path)
            evidence[label] = document
            expected_phase = (
                "pre-teardown-api-absence"
                if label == "pre_teardown_workload_absence"
                else "post-teardown-host-absence"
            )
            if (
                document.get("status") != "passed"
                or document.get("workflow_run_id") != args.run_id
                or document.get("phase") != expected_phase
            ):
                failures.append(label)
        except (OSError, ValueError, json.JSONDecodeError):
            failures.append(label)
    failures.extend(name for name, status in statuses.items() if status != 0)
    api = evidence.get("pre_teardown_workload_absence", {})
    host = evidence.get("post_teardown_host_absence", {})
    if api.get("exact_run_owned_ids_checked") is not True or any(
        api.get(field) != 0
        for field in ("run_owned_servers", "run_owned_ports", "run_owned_domains")
    ):
        failures.append("pre_teardown_workload_absence")
    if (
        host.get("generic_roots_absent") is not True
        or host.get("run_owned_processes") != 0
        or host.get("foreign_state_unchanged") is not True
        or host.get("openstack_api_consulted") is not False
    ):
        failures.append("post_teardown_host_absence")
    if failures:
        if statuses["workload_absence_status"] != 0:
            failure = {
                "failed_operation": api.get("failed_operation", "verify_pre_teardown_api_absence"),
                "observer_type": api.get("observer_type", "api_observation"),
                "resource_class": api.get("resource_class", "run_owned_openstack_resources"),
                "exit_code": statuses["workload_absence_status"],
            }
            for key in ("command_class", "diagnostic"):
                if api.get(key) is not None:
                    failure[key] = api[key]
        elif statuses["cleanup_command_status"] != 0:
            failure = {
                "failed_operation": "teardown_generic_testlab",
                "observer_type": "runner_executable",
                "resource_class": "generic_testlab_epoch",
                "command_class": "cleanup-disposable-testlab.sh",
                "exit_code": statuses["cleanup_command_status"],
            }
        elif statuses["post_cleanup_inventory_status"] != 0:
            failure = {
                "failed_operation": host.get("failed_operation", "collect_post_teardown_host_inventory"),
                "observer_type": host.get("observer_type", "libvirt_observation"),
                "resource_class": host.get("resource_class", "host_owned_inventory"),
                "exit_code": statuses["post_cleanup_inventory_status"],
            }
            for key in ("command_class", "diagnostic"):
                if host.get(key) is not None:
                    failure[key] = host[key]
        elif "pre_teardown_workload_absence" in failures:
            failure = {
                "failed_operation": "validate_pre_teardown_workload_absence",
                "observer_type": "runner_readable",
                "resource_class": "generic_lifecycle_evidence",
            }
        else:
            failure = {
                "failed_operation": "validate_post_teardown_host_absence",
                "observer_type": "runner_readable",
                "resource_class": "generic_testlab_host_state",
            }
        return fail(
            args.artifact,
            "generic-cleanup",
            args.run_id,
            "one or more generic TestLab cleanup proof phases failed",
            **failure,
            tested_source_sha=source_sha.lower() if source_sha else None,
            **statuses,
            failed_phases=sorted(set(failures)),
            run_owned_servers=api.get("run_owned_servers"),
            run_owned_ports=api.get("run_owned_ports"),
            run_owned_domains=api.get("run_owned_domains"),
            servers_checked=api.get("servers_checked"),
            ports_checked=api.get("ports_checked"),
            generic_roots_absent=host.get("generic_roots_absent"),
            run_owned_processes=host.get("run_owned_processes"),
            foreign_state_unchanged=host.get("foreign_state_unchanged"),
        )
    write_evidence(
        args.artifact,
        "generic-cleanup",
        args.run_id,
        tested_source_sha=source_sha.lower() if source_sha else None,
        **statuses,
        pre_teardown_workload_absence="passed",
        cleanup_command="passed",
        post_teardown_host_absence="passed",
        run_owned_servers=api.get("run_owned_servers"),
        run_owned_ports=api.get("run_owned_ports"),
        run_owned_domains=api.get("run_owned_domains"),
        servers_checked=api.get("servers_checked"),
        ports_checked=api.get("ports_checked"),
        generic_roots_absent=host.get("generic_roots_absent"),
        run_owned_processes=host.get("run_owned_processes"),
        foreign_state_unchanged=host.get("foreign_state_unchanged"),
    )
    return 0


def command_json(command: list[str], operation: str, observer_type: str,
                 resource_class: str, context: dict[str, str | int | None]) -> Any:
    context.clear()
    context.update(current_operation=operation, observer_type=observer_type,
                   resource_class=resource_class)
    try:
        result = subprocess.run(command, check=False, text=True, capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as error:
        context["command_class"] = pathlib.Path(command[0]).name
        context["exit_code"] = None
        raise RuntimeError(type(error).__name__) from error
    if result.returncode != 0:
        context["command_class"] = pathlib.Path(command[0]).name
        context["exit_code"] = result.returncode
        raise RuntimeError("SubprocessError")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        context["command_class"] = pathlib.Path(command[0]).name
        context["exit_code"] = result.returncode
        raise RuntimeError("JSONDecodeError") from error


def lane_project_id(context: dict[str, str | int | None]) -> str:
    configured = os.environ.get("OS_PROJECT_ID", "").strip()
    if configured:
        return configured
    project_name = os.environ.get("OS_PROJECT_NAME", "admin").strip() or "admin"
    project = command_json(["openstack", "project", "show", project_name, "-f", "json"],
                           "lookup_project_identity", "api_observation", "openstack_project_identity", context)
    if not isinstance(project, dict) or not isinstance(project.get("id"), str) or not project["id"]:
        raise ValueError("current TestLab project identity is unavailable")
    return project["id"]


def lane_preconditions(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"[0-9]+-pp5", args.testlab_run_id):
        return fail(args.artifact, "lane-preconditions", args.run_id,
                    "selected lane is not bound to the PP.5 phase identity",
                    failed_operation="validate_pp5_phase_identity",
                    observer_type="runner_readable",
                    resource_class="testlab_run_identity",
                    diagnostic="ValueError")
    context: dict[str, str | int | None] = {
        "current_operation": "read_testlab_ownership_marker",
        "observer_type": "sudo_read_only",
        "resource_class": "testlab_ownership_marker",
    }

    def at(operation: str, observer_type: str, resource_class: str) -> None:
        context.clear()
        context.update(current_operation=operation, observer_type=observer_type,
                       resource_class=resource_class)

    def fail_context(error: Exception) -> dict[str, str | int | None]:
        fields: dict[str, str | int | None] = {
            "failed_operation": context.get("current_operation"),
            "observer_type": context.get("observer_type"),
            "resource_class": context.get("resource_class"),
            "diagnostic": str(error) if isinstance(error, RuntimeError) else type(error).__name__,
        }
        fields.update({key: context[key] for key in ("command_class", "exit_code") if key in context})
        return fields

    try:
        PROTECTED_OBSERVER.verify_marker(pathlib.Path(args.state_root), args.testlab_run_id, args.source_sha)
        project_id = lane_project_id(context)
        servers = command_json(["openstack", "server", "list", "--project", project_id, "-f", "json"],
                               "list_project_scoped_servers", "api_observation", "openstack_servers", context)
        ports = command_json(["openstack", "port", "list", "--project", project_id, "-f", "json"],
                             "list_project_scoped_ports", "api_observation", "openstack_ports", context)
        if not isinstance(servers, list) or not isinstance(ports, list):
            at("validate_project_scoped_inventory", "api_observation", "openstack_inventory")
            raise ValueError("project-scoped OpenStack server/port inventory is malformed")
        at("list_libvirt_domains", "libvirt_observation", "libvirt_domains")
        try:
            domain_output = subprocess.run(
                ["virsh", "-c", "qemu:///system", "list", "--all", "--name"],
                check=False, text=True, capture_output=True, timeout=20,
            )
        except (OSError, subprocess.SubprocessError) as error:
            context["command_class"] = "virsh"
            context["exit_code"] = None
            raise RuntimeError(type(error).__name__) from error
        if domain_output.returncode != 0:
            context["command_class"] = "virsh"
            context["exit_code"] = domain_output.returncode
            raise RuntimeError("SubprocessError")
        context["command_class"] = "virsh"
        context["exit_code"] = 0
        run_domain_prefix = f"o3k-p15-7-{args.run_id}-"
        run_domains = sorted(line.strip() for line in domain_output.stdout.splitlines()
                             if line.strip().startswith(run_domain_prefix))
        counts = {"run_owned_servers": len(servers), "run_owned_ports": len(ports),
                  "run_owned_domains": len(run_domains)}
        if any(counts.values()):
            at("verify_zero_existing_workloads", "api_observation", "run_owned_workloads")
            return fail(args.artifact, "lane-preconditions", args.run_id,
                        "fresh PP.5 TestLab has pre-existing run-owned workloads",
                        **counts, **fail_context(ValueError()))
    except PROTECTED_OBSERVER.ObservationError as error:
        context.update(current_operation=error.operation, observer_type=error.observer_type,
                       resource_class=error.resource_class, diagnostic=error.diagnostic)
        if error.command_class is not None:
            context["command_class"] = error.command_class
        if error.exit_code is not None:
            context["exit_code"] = error.exit_code
        return fail(args.artifact, "lane-preconditions", args.run_id,
                    "fresh PP.5 ownership marker could not be verified",
                    failed_operation=error.operation,
                    observer_type=error.observer_type,
                    resource_class=error.resource_class,
                    diagnostic=error.diagnostic,
                    **({"command_class": error.command_class} if error.command_class else {}),
                    **({"exit_code": error.exit_code} if error.exit_code is not None else {}))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        return fail(args.artifact, "lane-preconditions", args.run_id,
                    "fresh PP.5 workload inventory could not be proven empty",
                    **fail_context(error))
    write_evidence(args.artifact, "lane-preconditions", args.run_id,
                   testlab_phase_id=args.testlab_run_id, **counts,
                   ownership_marker_verified=True,
                   provider_allocations="awaiting-native-diagnostics-before-workload-mutation",
                   topology="awaiting-canonical-topology-check-before-workload-mutation")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    api = subparsers.add_parser("pre-teardown-api-absence")
    api.add_argument("--run-id", required=True)
    api.add_argument("--lifecycle", type=pathlib.Path, required=True)
    api.add_argument("--artifact", type=pathlib.Path, required=True)

    host = subparsers.add_parser("post-teardown-host-absence")
    host.add_argument("--run-id", required=True)
    host.add_argument("--state-root", required=True)
    host.add_argument("--pid-root", required=True)
    host.add_argument("--inventory-root", required=True)
    host.add_argument("--openstack-venv", default="")
    host.add_argument("--image-path", default="")
    host.add_argument("--baseline", type=pathlib.Path, required=True)
    host.add_argument("--after", type=pathlib.Path, required=True)
    host.add_argument("--artifact", type=pathlib.Path, required=True)

    cleanup = subparsers.add_parser("generic-cleanup")
    cleanup.add_argument("--run-id", required=True)
    cleanup.add_argument("--source-sha", default="")
    cleanup.add_argument("--workload-status", type=int, required=True)
    cleanup.add_argument("--cleanup-status", type=int, required=True)
    cleanup.add_argument("--inventory-status", type=int, required=True)
    cleanup.add_argument("--workloads", type=pathlib.Path, required=True)
    cleanup.add_argument("--host-absence", type=pathlib.Path, required=True)
    cleanup.add_argument("--artifact", type=pathlib.Path, required=True)

    lane = subparsers.add_parser("lane-preconditions")
    lane.add_argument("--run-id", required=True)
    lane.add_argument("--testlab-run-id", required=True)
    lane.add_argument("--state-root", required=True)
    lane.add_argument("--source-sha", required=True)
    lane.add_argument("--artifact", type=pathlib.Path, required=True)

    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+", args.run_id):
        parser.error("workflow run ID must be numeric")
    if args.command == "pre-teardown-api-absence":
        return run_owned_api_absence(args)
    if args.command == "post-teardown-host-absence":
        return post_teardown_host_absence(args)
    if args.command == "generic-cleanup":
        return generic_cleanup(args)
    return lane_preconditions(args)


if __name__ == "__main__":
    raise SystemExit(main())
