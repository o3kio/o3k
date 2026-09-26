#!/usr/bin/env python3
"""Mutation tests for the focused PP.5 #1035 evidence validator."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from validate_pp5_1035_evidence import ValidationError, validate_artifact


def valid_artifact() -> dict:
    owner = {"pid": 101, "proc_starttime": 202}
    listener = lambda: {"socket": "127.0.0.1:1", "owner": owner.copy(), "owned": True}
    return {
        "artifact_type": "focused #1035 acceptance artifact", "schema": "o3k.pp5-1035-restart.v1", "profile": "PP.5",
        "status": "completed", "current_phase": "completed", "failure_phase": None, "run_id": "run",
        "source_sha": "a" * 40, "harness_digest": "b" * 64,
        "timestamps": {"started_at": "t", "completed_at": "t"},
        "old": {"pid": 101, "proc_starttime": 202, "executable_path": "/bin/o3kd", "executable_sha256": "c" * 64, "cmdline_digest": "d" * 64, "state_root": "/tmp/run", "listeners": {"http": listener(), "control": listener()}},
        "new": {"pid": 103, "proc_starttime": 204, "executable_path": "/bin/o3kd", "executable_sha256": "c" * 64, "cmdline_digest": "d" * 64, "state_root": "/tmp/run", "listeners": {"http": {"socket": "127.0.0.1:1", "owner": {"pid": 103, "proc_starttime": 204}, "owned": True}, "control": {"socket": "127.0.0.1:1", "owner": {"pid": 103, "proc_starttime": 204}, "owned": True}}},
        "terminal_state": {"server_id": "s", "delete_operation_id": "op", "project_id": "p", "endpoint_id": "e", "operation_state": "Succeeded", "resource_state": "DELETED", "owned_endpoint_present": True, "endpoint": {"ownership": "p", "project": "p", "binding": {"status": "ACTIVE"}, "ip": "192.0.2.3"}},
        "kill": {"signal": "SIGKILL", "timestamp": "t", "old_process_gone": True, "old_http_listener_gone": True, "old_control_listener_gone": True},
        "environment": {"intended": {"RUN": "run"}, "effective": {"RUN": "run"}, "secret_presence": {"PASSWORD": True}, "match": True},
        "readiness": {"status": 200, "body_sha256": "e" * 64, "served_by_new": True},
        "controller": {"old": {"id": "old", "epoch": "1"}, "new": {"id": "new", "epoch": "2"}, "transition_recorded": True},
        "reconciler": {k: "t" for k in ("first_periodic_tick", "repair_lease_attempt", "repair_lease_result", "repair_function_entered", "lock_waiting", "lock_acquired", "repair_hold_engaged", "orphan_discovered")},
        "lease": {"work_key": "server-endpoint-orphan-repair", "work_kind": "repair", "previous_owner": "none", "previous_epoch": "none", "lease_expiry": "t", "new_owner": "new", "new_epoch": "2", "acquire_result": "Acquired", "acquired_at": "t", "recovery_latency_ms": 0},
        "orphan": {k: True for k in ("operation_succeeded", "resource_deleted", "endpoint_present", "ownership_valid", "project_matches", "no_live_references", "orphan_eligible")},
        "responsiveness": {"request_start": "t", "request_end": "t", "status": 200, "latency_ms": 1, "bounded_success": True},
        "contention": {"create_request_start": "t", "waiter_marker_at": "t", "repair_release_at": "t", "repair_released_at": "t", "repair_completed_at": "t", "create_accepted_at": "t", "create_resource_id": "s2", "create_operation_id": "op2", "waiter_observed": True, "acceptance_latency_ms": 1, "create_to_active_latency_ms": 1},
        "repair": {"unbind_attempted": True, "unbind_result": "Succeeded", "release_attempted": True, "release_result": "Succeeded", "pass_number": 1, "completed_at": "t", "endpoint_absent": True},
        "accounting": {"fixed_ip": "192.0.2.3", "quota_baseline": 1, "quota_before": 2, "quota_during": 2, "quota_after": 1, "quota_restored": True, "fixed_ip_reusable": True, "no_duplicate_endpoint": True, "no_duplicate_allocation": True},
        "caller": {"endpoint_id": "caller", "project": "p", "ownership_before": "p", "ownership_after": "p", "exists_before": True, "exists_after": True, "ownership_unchanged": True},
        "foreign": {"project": "foreign", "port_id": "fp", "network_id": "fn", "subnet_id": "fs", "attachment_id": "not-applicable", "before": {"id": "fp"}, "after": {"id": "fp"}, "changed": False},
        "teardown": {"owned_servers": 0, "owned_endpoints": 0, "owned_allocations": 0, "run_processes": 0, "run_listeners": 0, "sync_files": 0, "foreign_unchanged": True},
        "fairness": {"sweep_opportunities": 2, "contending_requests": 1, "eventual_acquisition": True, "starvation": False},
        "observability": {"log": "/tmp/run/o3kd.log", "log_sha256": "f" * 64, "repair_lines": ["orphan repair sweep"]},
        "secret_scan": {"passed": True, "log": "/tmp/run/o3kd.log", "checked_secret_values": True},
    }


class ValidatorMutationTests(unittest.TestCase):
    def assert_rejected(self, path: tuple[str, ...]) -> None:
        artifact = valid_artifact()
        cursor = artifact
        for key in path[:-1]:
            cursor = cursor[key]
        cursor.pop(path[-1], None)
        with self.assertRaises(ValidationError):
            validate_artifact(artifact)

    def test_required_evidence_mutations_rejected(self) -> None:
        for path in (
            ("old", "pid"), ("old", "proc_starttime"), ("old", "executable_sha256"),
            ("old", "listeners", "http", "owned"), ("environment", "match"),
            ("controller", "new", "id"), ("reconciler", "first_periodic_tick"),
            ("lease", "work_key"), ("orphan", "orphan_eligible"),
            ("contention", "waiter_observed"), ("accounting", "quota_after"),
            ("caller", "endpoint_id"), ("foreign", "port_id"), ("teardown", "sync_files"),
        ):
            self.assert_rejected(path)

    def test_wrong_sha_and_status_rejected(self) -> None:
        artifact = valid_artifact()
        with self.assertRaises(ValidationError):
            validate_artifact(artifact, "f" * 40)
        artifact = valid_artifact(); artifact["status"] = "failed"
        with self.assertRaises(ValidationError):
            validate_artifact(artifact)

    def test_secret_value_rejected(self) -> None:
        artifact = valid_artifact(); artifact["environment"]["effective"]["O3K_PASSWORD"] = "secret"
        with self.assertRaises(ValidationError):
            validate_artifact(artifact)


if __name__ == "__main__":
    unittest.main()
