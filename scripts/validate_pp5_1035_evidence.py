#!/usr/bin/env python3
"""Fail-closed validator for one focused PP.5 #1035 restart artifact.

This validator is intentionally separate from the full P15.7/S5 validator.  A
focused artifact proves only the real-process restart contract and never
certifies the full campaign.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "o3k.pp5-1035-restart.v1"
ARTIFACT_TYPE = "focused #1035 acceptance artifact"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ValidationError(ValueError):
    pass


def _get(obj: dict[str, Any], *path: str) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            raise ValidationError("missing " + ".".join(path))
        cur = cur[key]
    return cur


def _nonempty(obj: dict[str, Any], *path: str) -> Any:
    value = _get(obj, *path)
    if value in (None, "", [], {}):
        raise ValidationError("empty " + ".".join(path))
    return value


def _bool(obj: dict[str, Any], *path: str) -> bool:
    value = _get(obj, *path)
    if value is not True:
        raise ValidationError("expected true: " + ".".join(path))
    return True


def validate_artifact(artifact: dict[str, Any], expected_sha: str | None = None) -> None:
    if _get(artifact, "artifact_type") != ARTIFACT_TYPE:
        raise ValidationError("wrong artifact_type")
    if _get(artifact, "schema") != SCHEMA:
        raise ValidationError("wrong schema")
    if _get(artifact, "profile") != "PP.5":
        raise ValidationError("wrong profile")
    if _get(artifact, "status") != "completed":
        raise ValidationError("status is not completed")
    if _get(artifact, "current_phase") != "completed":
        raise ValidationError("current_phase is not completed")
    if _get(artifact, "failure_phase") is not None:
        raise ValidationError("completed artifact has failure_phase")
    run_id = _nonempty(artifact, "run_id")
    if not isinstance(run_id, str):
        raise ValidationError("run_id is not a string")
    source_sha = _nonempty(artifact, "source_sha")
    if not isinstance(source_sha, str) or not SHA_RE.fullmatch(source_sha):
        raise ValidationError("invalid source_sha")
    if expected_sha is not None and source_sha != expected_sha:
        raise ValidationError("source_sha does not match expected SHA")
    harness = _nonempty(artifact, "harness_digest")
    if not isinstance(harness, str) or not HEX64_RE.fullmatch(harness):
        raise ValidationError("invalid harness_digest")
    for field in ("started_at", "completed_at"):
        _nonempty(artifact, "timestamps", field)

    for section in ("old", "new"):
        pid = _nonempty(artifact, section, "pid")
        start = _nonempty(artifact, section, "proc_starttime")
        if not isinstance(pid, int) or pid <= 0:
            raise ValidationError(f"invalid {section}.pid")
        if not isinstance(start, int) or start <= 0:
            raise ValidationError(f"invalid {section}.proc_starttime")
        exe = _nonempty(artifact, section, "executable_path")
        digest = _nonempty(artifact, section, "executable_sha256")
        if not isinstance(exe, str) or not exe.startswith("/"):
            raise ValidationError(f"invalid {section}.executable_path")
        if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
            raise ValidationError(f"invalid {section}.executable_sha256")
        _nonempty(artifact, section, "cmdline_digest")
        _nonempty(artifact, section, "state_root")
        for listener in ("http", "control"):
            _nonempty(artifact, section, "listeners", listener, "socket")
            owner = _get(artifact, section, "listeners", listener, "owner")
            if owner != {"pid": pid, "proc_starttime": start}:
                raise ValidationError(f"{section}.{listener} owner does not bind identity")
            _bool(artifact, section, "listeners", listener, "owned")
    if (artifact["old"]["pid"], artifact["old"]["proc_starttime"]) == (
        artifact["new"]["pid"],
        artifact["new"]["proc_starttime"],
    ):
        raise ValidationError("old/new process identities are equal")

    _nonempty(artifact, "terminal_state", "server_id")
    _nonempty(artifact, "terminal_state", "delete_operation_id")
    _nonempty(artifact, "terminal_state", "project_id")
    _nonempty(artifact, "terminal_state", "endpoint_id")
    if _get(artifact, "terminal_state", "operation_state") != "Succeeded":
        raise ValidationError("delete operation is not Succeeded")
    if _get(artifact, "terminal_state", "resource_state") != "DELETED":
        raise ValidationError("resource is not DELETED")
    _bool(artifact, "terminal_state", "owned_endpoint_present")
    for field in ("ownership", "project", "binding", "ip"):
        _nonempty(artifact, "terminal_state", "endpoint", field)
    _nonempty(artifact, "kill", "signal")
    if _get(artifact, "kill", "signal") != "SIGKILL":
        raise ValidationError("wrong kill signal")
    _nonempty(artifact, "kill", "timestamp")
    _bool(artifact, "kill", "old_process_gone")
    _bool(artifact, "kill", "old_http_listener_gone")
    _bool(artifact, "kill", "old_control_listener_gone")

    env = _get(artifact, "environment")
    if not isinstance(env, dict):
        raise ValidationError("environment is not an object")
    for key in ("intended", "effective", "secret_presence"):
        if not isinstance(_get(env, key), dict):
            raise ValidationError(f"environment.{key} is not an object")
    if _get(env, "match") is not True:
        raise ValidationError("environment_match is false")
    for key, value in env["effective"].items():
        if any(secret in key.upper() for secret in ("PASSWORD", "TOKEN", "PRIVATE_KEY", "SECRET")):
            raise ValidationError("secret value stored in effective environment")
        if not isinstance(value, (str, int, float, bool)):
            raise ValidationError("invalid effective environment value")
    for key, value in env["secret_presence"].items():
        if not isinstance(value, bool):
            raise ValidationError("secret presence must be boolean")

    _nonempty(artifact, "readiness", "status")
    if _get(artifact, "readiness", "status") != 200:
        raise ValidationError("replacement readiness did not return 200")
    _nonempty(artifact, "readiness", "body_sha256")
    _bool(artifact, "readiness", "served_by_new")
    for field in ("old", "new"):
        _nonempty(artifact, "controller", field, "id")
        _nonempty(artifact, "controller", field, "epoch")
    _bool(artifact, "controller", "transition_recorded")
    for field in ("first_periodic_tick", "repair_lease_attempt", "repair_lease_result", "repair_function_entered", "lock_waiting", "lock_acquired", "repair_hold_engaged", "orphan_discovered"):
        _nonempty(artifact, "reconciler", field)
    lease = _get(artifact, "lease")
    for field in ("work_key", "work_kind", "previous_owner", "previous_epoch", "lease_expiry", "new_owner", "new_epoch", "acquire_result", "acquired_at", "recovery_latency_ms"):
        _nonempty(lease, field)
    if lease["work_key"] != "server-endpoint-orphan-repair" or lease["work_kind"] != "repair":
        raise ValidationError("wrong repair lease identity")
    orphan = _get(artifact, "orphan")
    for field in ("operation_succeeded", "resource_deleted", "endpoint_present", "ownership_valid", "project_matches", "no_live_references", "orphan_eligible"):
        _bool(orphan, field)
    response = _get(artifact, "responsiveness")
    _nonempty(response, "request_start")
    _nonempty(response, "request_end")
    if _get(response, "status") != 200 or not isinstance(_get(response, "latency_ms"), (int, float)):
        raise ValidationError("invalid responsiveness proof")
    _bool(response, "bounded_success")
    contention = _get(artifact, "contention")
    for field in ("create_request_start", "waiter_marker_at", "repair_release_at", "repair_released_at", "repair_completed_at", "create_accepted_at", "create_resource_id", "create_operation_id"):
        _nonempty(contention, field)
    _bool(contention, "waiter_observed")
    if not isinstance(contention["acceptance_latency_ms"], (int, float)) or contention["acceptance_latency_ms"] > 65000:
        raise ValidationError("create acceptance exceeded 65 seconds")
    if not isinstance(contention["create_to_active_latency_ms"], (int, float)) or contention["create_to_active_latency_ms"] < 0:
        raise ValidationError("invalid create-to-active latency")
    repair = _get(artifact, "repair")
    for field in ("unbind_attempted", "unbind_result", "release_attempted", "release_result", "pass_number", "completed_at"):
        _nonempty(repair, field)
    _bool(repair, "endpoint_absent")
    accounting = _get(artifact, "accounting")
    _nonempty(accounting, "fixed_ip")
    for field in ("quota_baseline", "quota_before", "quota_during", "quota_after"):
        if not isinstance(_get(accounting, field), int):
            raise ValidationError(f"accounting.{field} must be numeric")
    if accounting["quota_after"] != accounting["quota_baseline"]:
        raise ValidationError("quota was not restored to baseline")
    if accounting.get("quota_restored") is not True:
        raise ValidationError("quota restoration was not explicitly proven")
    _bool(accounting, "fixed_ip_reusable")
    _bool(accounting, "no_duplicate_endpoint")
    _bool(accounting, "no_duplicate_allocation")
    caller = _get(artifact, "caller")
    for field in ("endpoint_id", "project", "ownership_before", "ownership_after"):
        _nonempty(caller, field)
    _bool(caller, "exists_before")
    _bool(caller, "exists_after")
    _bool(caller, "ownership_unchanged")
    foreign = _get(artifact, "foreign")
    for field in ("project", "port_id", "network_id", "subnet_id", "attachment_id", "before", "after"):
        _nonempty(foreign, field)
    _bool(foreign, "changed") if foreign.get("changed") is True else None
    if foreign.get("changed") is not False:
        raise ValidationError("foreign state changed or was not checked")
    teardown = _get(artifact, "teardown")
    for field in ("owned_servers", "owned_endpoints", "owned_allocations", "run_processes", "run_listeners", "sync_files"):
        if _get(teardown, field) != 0:
            raise ValidationError(f"teardown.{field} is not zero")
    _bool(teardown, "foreign_unchanged")
    fairness = _get(artifact, "fairness")
    if not isinstance(fairness.get("sweep_opportunities"), int) or fairness["sweep_opportunities"] < 2:
        raise ValidationError("insufficient repeated sweep opportunities")
    if fairness.get("eventual_acquisition") is not True or fairness.get("starvation") is not False:
        raise ValidationError("fairness/starvation proof failed")
    observability = _get(artifact, "observability")
    _nonempty(observability, "log")
    if not isinstance(observability.get("log_sha256"), str) or not HEX64_RE.fullmatch(observability["log_sha256"]):
        raise ValidationError("invalid observability log digest")
    if not observability.get("repair_lines"):
        raise ValidationError("missing repair log transitions")
    secret_scan = _get(artifact, "secret_scan")
    _bool(secret_scan, "passed")
    if secret_scan.get("checked_secret_values") is not True:
        raise ValidationError("secret scan did not check known secret values")
    _nonempty(secret_scan, "log")


def validate_file(path: Path, expected_sha: str | None = None) -> dict[str, Any]:
    artifact = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(artifact, dict):
        raise ValidationError("artifact root is not an object")
    validate_artifact(artifact, expected_sha)
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--source-sha")
    args = parser.parse_args()
    try:
        validate_file(args.artifact, args.source_sha)
    except (OSError, json.JSONDecodeError, ValidationError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: {args.artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
