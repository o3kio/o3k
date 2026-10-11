#!/usr/bin/env python3
"""Fail-closed PP.5 TestLab phase isolation checks.

This guard owns no cloud resources. It observes the run-scoped filesystem,
OpenStack projection, and libvirt names, then writes redacted phase evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any


FOREIGN_FIELDS = ("domains_sha256", "network_links_sha256", "pools_count")


def load_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} is not a JSON object")
    return value


def write_evidence(path: pathlib.Path, phase: str, run_id: str, **fields: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "artifact_type": "pp5-testlab-epoch-guard",
        "schema_version": 1,
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


def generic_cleanup(args: argparse.Namespace) -> int:
    state_root = pathlib.Path(args.state_root)
    pid_root = pathlib.Path(args.runner_temp) / "o3k-testlab-pids" / f"{args.run_id}-generic"
    inventory_root = pathlib.Path(args.runner_temp) / "o3k-testlab-inventory" / f"{args.run_id}-generic"
    present = [str(path) for path in (state_root, pid_root, inventory_root) if path.exists()]
    cleanup_status = int(getattr(args, "cleanup_status", 0))
    if cleanup_status != 0:
        return fail(args.artifact, "generic-cleanup", args.run_id,
                    "generic TestLab cleanup command failed", cleanup_exit_code=cleanup_status,
                    remaining_roots=present)
    if present:
        return fail(args.artifact, "generic-cleanup", args.run_id,
                    "generic TestLab ownership roots remain after cleanup", remaining_roots=present)
    try:
        workloads = load_json(args.workloads)
        if workloads.get("status") != "passed" or any(
            workloads.get(field) != 0
            for field in ("run_owned_servers", "run_owned_ports", "run_owned_domains")
        ):
            return fail(args.artifact, "generic-cleanup", args.run_id,
                        "generic TestLab workload absence was not proven before teardown",
                        workload_check_status=workloads.get("status"),
                        run_owned_servers=workloads.get("run_owned_servers"),
                        run_owned_ports=workloads.get("run_owned_ports"),
                        run_owned_domains=workloads.get("run_owned_domains"))
        before = load_json(args.baseline)
        after = load_json(args.after)
        if before.get("status") != "available" or after.get("status") != "available":
            raise ValueError("host inventory snapshot is unavailable")
        before_foreign = before.get("foreign_state")
        after_foreign = after.get("foreign_state")
        if not isinstance(before_foreign, dict) or not isinstance(after_foreign, dict):
            raise ValueError("foreign state evidence is missing")
        differences = {
            key: {"before": before_foreign.get(key), "after": after_foreign.get(key)}
            for key in FOREIGN_FIELDS
            if before_foreign.get(key) != after_foreign.get(key)
        }
        if differences:
            return fail(args.artifact, "generic-cleanup", args.run_id,
                        "foreign host state changed across generic TestLab cleanup",
                        foreign_state_differences=differences)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return fail(args.artifact, "generic-cleanup", args.run_id,
                    "generic cleanup or foreign-state evidence is unavailable",
                    diagnostic=str(error))
    write_evidence(args.artifact, "generic-cleanup", args.run_id,
                   generic_owned_roots_absent=True, foreign_state_unchanged=True,
                   generic_workload_absence_proven=True,
                   compared_foreign_fields=list(FOREIGN_FIELDS))
    return 0


def command_json(command: list[str]) -> Any:
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    return json.loads(result.stdout)


def generic_workloads(args: argparse.Namespace) -> int:
    try:
        servers = command_json(["openstack", "server", "list", "--all-projects", "-f", "json"])
        ports = command_json(["openstack", "port", "list", "--all-projects", "-f", "json"])
        domain_output = subprocess.run(
            ["virsh", "-c", "qemu:///system", "list", "--all", "--name"],
            check=True, text=True, capture_output=True,
        ).stdout
        if not isinstance(servers, list) or not isinstance(ports, list):
            raise ValueError("OpenStack server/port inventory is malformed")
        domains = sorted(line.strip() for line in domain_output.splitlines()
                         if line.strip().startswith("o3k-"))
        counts = {"run_owned_servers": len(servers), "run_owned_ports": len(ports),
                  "run_owned_domains": len(domains)}
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        return fail(args.artifact, "generic-workloads", args.run_id,
                    "generic TestLab workload absence could not be inspected before teardown",
                    diagnostic=str(error))
    if any(counts.values()):
        return fail(args.artifact, "generic-workloads", args.run_id,
                    "generic TestLab has workloads remaining after public lifecycle validation",
                    **counts)
    write_evidence(args.artifact, "generic-workloads", args.run_id, **counts,
                   absence_proven_before_teardown=True)
    return 0


def lane_preconditions(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"[0-9]+-pp5", args.testlab_run_id):
        return fail(args.artifact, "lane-preconditions", args.run_id,
                    "selected lane is not bound to the PP.5 phase identity")
    marker = pathlib.Path(args.state_root) / ".o3k-run-owned"
    try:
        marker_lines = marker.read_text(encoding="utf-8").splitlines()
        if "o3k-disposable-testlab-v1" not in marker_lines or f"run={args.testlab_run_id}" not in marker_lines:
            raise ValueError("PP.5 TestLab ownership marker does not match phase identity")
        servers = command_json(["openstack", "server", "list", "--all-projects", "-f", "json"])
        ports = command_json(["openstack", "port", "list", "--all-projects", "-f", "json"])
        if not isinstance(servers, list) or not isinstance(ports, list):
            raise ValueError("OpenStack server/port inventory is malformed")
        domain_output = subprocess.run(
            ["virsh", "-c", "qemu:///system", "list", "--all", "--name"],
            check=True, text=True, capture_output=True,
        ).stdout
        # The libvirt provider names guest domains `o3k-<resource-id>` rather
        # than run-scoping the name. At the lane boundary the protected
        # preflight has already established an ownership-clean host; treat any
        # remaining O3K domain as an ambiguity and fail closed without deleting it.
        run_domains = sorted(line.strip() for line in domain_output.splitlines()
                             if line.strip().startswith("o3k-"))
        domain_digest = hashlib.sha256("\n".join(run_domains).encode("utf-8")).hexdigest()
        counts = {"run_owned_servers": len(servers), "run_owned_ports": len(ports),
                  "run_owned_domains": len(run_domains)}
        if any(counts.values()):
            return fail(args.artifact, "lane-preconditions", args.run_id,
                        "fresh PP.5 TestLab has pre-existing run-owned workloads or an ambiguous O3K domain",
                        **counts, o3k_domain_candidates_sha256=domain_digest)
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        return fail(args.artifact, "lane-preconditions", args.run_id,
                    "fresh PP.5 workload inventory could not be proven empty",
                    diagnostic=str(error))
    write_evidence(args.artifact, "lane-preconditions", args.run_id,
                   testlab_phase_id=args.testlab_run_id, **counts,
                   o3k_domain_candidates_sha256=domain_digest,
                   provider_allocations="awaiting-native-diagnostics-before-workload-mutation",
                   topology="awaiting-canonical-topology-check-before-workload-mutation")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    cleanup = subparsers.add_parser("generic-cleanup")
    cleanup.add_argument("--run-id", required=True)
    cleanup.add_argument("--runner-temp", required=True)
    cleanup.add_argument("--state-root", required=True)
    cleanup.add_argument("--cleanup-status", type=int, default=0)
    cleanup.add_argument("--workloads", type=pathlib.Path, required=True)
    cleanup.add_argument("--baseline", type=pathlib.Path, required=True)
    cleanup.add_argument("--after", type=pathlib.Path, required=True)
    cleanup.add_argument("--artifact", type=pathlib.Path, required=True)
    lane = subparsers.add_parser("lane-preconditions")
    lane.add_argument("--run-id", required=True)
    lane.add_argument("--testlab-run-id", required=True)
    lane.add_argument("--state-root", required=True)
    lane.add_argument("--artifact", type=pathlib.Path, required=True)
    workloads = subparsers.add_parser("generic-workloads")
    workloads.add_argument("--run-id", required=True)
    workloads.add_argument("--artifact", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+", args.run_id):
        parser.error("workflow run ID must be numeric")
    if args.command == "generic-cleanup":
        return generic_cleanup(args)
    if args.command == "generic-workloads":
        return generic_workloads(args)
    return lane_preconditions(args)


if __name__ == "__main__":
    raise SystemExit(main())
