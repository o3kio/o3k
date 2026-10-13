#!/usr/bin/env python3
"""Regression tests for post-controller-restart agent readiness evidence."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent
DRIVER = (ROOT / "fabric-v3-o3k-three-host-campaign.sh").read_text()
SPEC = importlib.util.spec_from_file_location(
    "agent_readiness", ROOT / "fabric-v3-agent-readiness.py"
)
assert SPEC and SPEC.loader
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)

NOW_MS = 1_800_000_000_000
CONTROLLER_START_MS = NOW_MS - 10_000


def valid_inputs():
    manifest = {
        "compute_agents": {
            "host-a": {"agent_id": "compute-agent-a", "agent_epoch": "epoch-a"},
            "host-b": {"agent_id": "compute-agent-b", "agent_epoch": "epoch-b"},
        }
    }
    ready = {
        "host-a": {"status": "ready", "agent_id": "compute-agent-a", "agent_epoch": "epoch-a"},
        "host-b": {"status": "ready", "agent_id": "compute-agent-b", "agent_epoch": "epoch-b"},
    }
    return manifest, ready


def controller_log_for(ready, *, timestamp_ms=CONTROLLER_START_MS + 1_000):
    timestamp = datetime.fromtimestamp(timestamp_ms / 1000, timezone.utc).isoformat().replace("+00:00", "Z")
    return "\n".join(
        json.dumps({
            "timestamp": timestamp,
            "fields": {
                "message": "compute agent registered",
                "agent_id": ready[host]["agent_id"],
                "epoch": ready[host]["agent_epoch"],
            },
        })
        for host in ready
    )


def evaluate(
    manifest,
    ready,
    *,
    consecutive_observations=1,
    controller_log=None,
    required_hosts=("host-a", "host-b"),
    phase="post-controller-restart-before-supported-teardown",
):
    return helper.evaluate(
        manifest,
        ready,
        controller_log=controller_log if controller_log is not None else controller_log_for(ready),
        controller_start_ms=CONTROLLER_START_MS,
        consecutive_observations=consecutive_observations,
        required_hosts=required_hosts,
        phase=phase,
    )


def valid_three_host_inputs():
    manifest, ready = valid_inputs()
    manifest["compute_agents"]["host-c"] = {
        "agent_id": "compute-agent-c",
        "agent_epoch": "epoch-c",
    }
    ready["host-c"] = {
        "status": "ready",
        "agent_id": "compute-agent-c",
        "agent_epoch": "epoch-c",
    }
    return manifest, ready


class AgentReadinessRegression(unittest.TestCase):
    def test_fresh_current_agents_pass_only_after_two_observations(self):
        manifest, ready = valid_inputs()
        first = evaluate(manifest, ready, consecutive_observations=1)
        second = evaluate(manifest, ready, consecutive_observations=2)
        self.assertTrue(first["observation_valid"])
        self.assertEqual(first["status"], "pending")
        self.assertEqual(second["status"], "passed")
        self.assertEqual([item["agent_epoch"] for item in second["agents"]], ["epoch-a", "epoch-b"])
        self.assertEqual([item["bootstrap_agent_epoch"] for item in second["agents"]], ["epoch-a", "epoch-b"])

    def test_new_post_restart_epochs_are_accepted_and_recorded(self):
        manifest, ready = valid_inputs()
        ready["host-a"]["agent_epoch"] = "epoch-a-after-restart"
        ready["host-b"]["agent_epoch"] = "epoch-b-after-restart"
        result = evaluate(manifest, ready, consecutive_observations=2)
        self.assertTrue(result["observation_valid"])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(
            [(item["bootstrap_agent_epoch"], item["agent_epoch"], item["epoch_changed_from_bootstrap"]) for item in result["agents"]],
            [("epoch-a", "epoch-a-after-restart", True), ("epoch-b", "epoch-b-after-restart", True)],
        )

    def test_three_host_barrier_requires_current_a_b_c_identities_and_epochs(self):
        manifest, ready = valid_three_host_inputs()
        result = evaluate(
            manifest,
            ready,
            consecutive_observations=2,
            required_hosts=("host-a", "host-b", "host-c"),
            phase="post-controller-restart-before-retirement",
        )
        self.assertTrue(result["observation_valid"])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["phase"], "post-controller-restart-before-retirement")
        self.assertEqual(result["required_hosts"], ["host-a", "host-b", "host-c"])
        self.assertEqual([item["host"] for item in result["agents"]], ["host-a", "host-b", "host-c"])
        self.assertEqual(result["agents"][2]["agent_epoch"], "epoch-c")

    def test_three_host_barrier_fails_if_c_is_not_ready_or_not_registered(self):
        manifest, ready = valid_three_host_inputs()
        ready["host-c"]["status"] = "starting"
        result = evaluate(
            manifest,
            ready,
            required_hosts=("host-a", "host-b", "host-c"),
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["classification"], "HARNESS_GAP")
        self.assertEqual(result["failed_operation"], "read_compute_agent_readyz")
        self.assertIn("host-c", result["diagnostic"])

        manifest, ready = valid_three_host_inputs()
        log = controller_log_for(ready)
        ready["host-c"]["agent_epoch"] = "unregistered-c-epoch"
        result = evaluate(
            manifest,
            ready,
            controller_log=log,
            required_hosts=("host-a", "host-b", "host-c"),
        )
        self.assertEqual(result["classification"], "HARNESS_GAP")
        self.assertEqual(result["failed_operation"], "observe_compute_agent_registration_after_restart")

    def test_invalid_required_host_set_fails_closed(self):
        manifest, ready = valid_three_host_inputs()
        for hosts in ((), ("host-a", "host-a"), ("host-d",)):
            with self.subTest(hosts=hosts):
                result = evaluate(manifest, ready, required_hosts=hosts)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["classification"], "HARNESS_GAP")
                self.assertEqual(result["failed_operation"], "validate_required_compute_agent_set")

    def test_three_host_cli_requires_c_readiness_input(self):
        manifest, ready = valid_three_host_inputs()
        start_time = datetime.fromtimestamp(CONTROLLER_START_MS / 1000, timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            paths = {
                "manifest": directory / "manifest.json",
                "ready_a": directory / "ready-a.json",
                "ready_b": directory / "ready-b.json",
                "ready_c": directory / "ready-c.json",
                "controller_start": directory / "controller-start.json",
                "controller_log": directory / "controller.log",
                "output": directory / "result.json",
            }
            paths["manifest"].write_text(json.dumps(manifest))
            for host in ("a", "b", "c"):
                paths[f"ready_{host}"].write_text(json.dumps(ready[f"host-{host}"]))
            paths["controller_start"].write_text(json.dumps({
                "start_requested_at_utc": start_time.isoformat().replace("+00:00", "Z")
            }))
            paths["controller_log"].write_text(controller_log_for(ready))
            command = [
                sys.executable,
                str(ROOT / "fabric-v3-agent-readiness.py"),
                "validate",
                "--manifest", str(paths["manifest"]),
                "--ready-a", str(paths["ready_a"]),
                "--ready-b", str(paths["ready_b"]),
                "--ready-c", str(paths["ready_c"]),
                "--required-hosts", "host-a,host-b,host-c",
                "--phase", "post-controller-restart-before-retirement",
                "--controller-log", str(paths["controller_log"]),
                "--controller-start", str(paths["controller_start"]),
                "--consecutive-observations", "2",
                "--output", str(paths["output"]),
            ]
            passed = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            result = json.loads(paths["output"].read_text())
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["required_hosts"], ["host-a", "host-b", "host-c"])

            command.remove("--ready-c")
            command.remove(str(paths["ready_c"]))
            rejected = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 1)
            result = json.loads(paths["output"].read_text())
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertEqual(result["failed_operation"], "read_compute_agent_readiness_inputs")

    def test_current_epoch_must_have_post_restart_controller_registration(self):
        manifest, ready = valid_inputs()
        result = evaluate(
            manifest,
            ready,
            controller_log=controller_log_for(ready, timestamp_ms=CONTROLLER_START_MS - 1),
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["classification"], "HARNESS_GAP")
        self.assertEqual(result["failed_operation"], "observe_compute_agent_registration_after_restart")

    def test_cli_reads_restart_metadata_and_accepts_registered_new_epoch(self):
        manifest, ready = valid_inputs()
        ready["host-a"]["agent_epoch"] = "epoch-a-after-restart"
        ready["host-b"]["agent_epoch"] = "epoch-b-after-restart"
        start_time = datetime.fromtimestamp(CONTROLLER_START_MS / 1000, timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            paths = {
                "manifest": directory / "manifest.json",
                "ready_a": directory / "ready-a.json",
                "ready_b": directory / "ready-b.json",
                "controller_start": directory / "controller-start.json",
                "controller_log": directory / "controller.log",
                "output": directory / "result.json",
            }
            for key, value in (
                ("manifest", manifest),
                ("ready_a", ready["host-a"]),
                ("ready_b", ready["host-b"]),
                ("controller_start", {"start_requested_at_utc": start_time.isoformat().replace("+00:00", "Z")}),
            ):
                paths[key].write_text(json.dumps(value))
            paths["controller_log"].write_text(controller_log_for(ready))
            command = [
                sys.executable,
                str(ROOT / "fabric-v3-agent-readiness.py"),
                "validate",
                "--manifest", str(paths["manifest"]),
                "--ready-a", str(paths["ready_a"]),
                "--ready-b", str(paths["ready_b"]),
                "--controller-log", str(paths["controller_log"]),
                "--controller-start", str(paths["controller_start"]),
                "--consecutive-observations", "2",
                "--output", str(paths["output"]),
            ]
            passed = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            result = json.loads(paths["output"].read_text())
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["agents"][0]["agent_epoch"], "epoch-a-after-restart")
            self.assertTrue(result["agents"][0]["epoch_changed_from_bootstrap"])

            paths["controller_log"].write_text(
                controller_log_for(ready, timestamp_ms=CONTROLLER_START_MS - 1)
            )
            rejected = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 1)
            result = json.loads(paths["output"].read_text())
            self.assertEqual(result["failed_operation"], "observe_compute_agent_registration_after_restart")

    def test_wrong_agent_identity_or_missing_epoch_fails_closed(self):
        for field, value in (("agent_id", "other-agent"), ("agent_epoch", "")):
            with self.subTest(field=field):
                manifest, ready = valid_inputs()
                ready["host-a"][field] = value
                result = evaluate(manifest, ready, consecutive_observations=2)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["classification"], "HARNESS_GAP")
                self.assertEqual(result["failed_operation"], "read_compute_agent_readyz")

    def test_unregistered_current_epoch_fails_closed(self):
        manifest, ready = valid_inputs()
        current_controller_log = controller_log_for(ready)
        ready["host-a"]["agent_epoch"] = "unexpected-epoch"
        result = evaluate(manifest, ready, controller_log=current_controller_log)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_operation"], "observe_compute_agent_registration_after_restart")

    def test_guest_not_ready_fails_closed(self):
        manifest, ready = valid_inputs()
        ready["host-b"]["status"] = "starting"
        result = evaluate(manifest, ready, consecutive_observations=2)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_operation"], "read_compute_agent_readyz")

    def test_readiness_evidence_does_not_require_operator_api_scope(self):
        manifest, ready = valid_inputs()
        result = evaluate(manifest, ready, consecutive_observations=2)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["observer_type"], "runner_executable_guest_readyz+controller_log")
        self.assertNotIn("api_observation", repr(result))

    def test_restart_readiness_gate_precedes_traffic_and_c_delete(self):
        start_timestamp = DRIVER.index('controller_start_requested_at="$(date -u +%FT%T.%NZ)"')
        restart_launch = DRIVER.index('"$PRODUCT_SOURCE_DIR/target/release/o3kd"', start_timestamp)
        start_record = DRIVER.index('"$EVIDENCE/restart/startup-recovery/controller-start.json"', restart_launch)
        self.assertLess(start_timestamp, restart_launch)
        self.assertLess(restart_launch, start_record)
        ready = DRIVER.index('curl -fsS "$BASE/readyz" >"$EVIDENCE/restart/ready.json"', restart_launch)
        gate = DRIVER.index('wait_for_current_compute_agents \\\n  "pre-retirement-compute-agent-readiness"', ready)
        restart_traffic = DRIVER.index('for pair in a:b b:a a:c c:a b:c c:b; do', gate)
        c_delete = DRIVER.index('delete_started_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"', restart_traffic)
        self.assertLess(restart_launch, ready)
        self.assertLess(ready, gate)
        self.assertLess(gate, restart_traffic)
        self.assertLess(restart_traffic, c_delete)
        start = DRIVER.index('wait_for_current_compute_agents() {')
        end = DRIVER.index('\n}\n', start)
        readiness_function = DRIVER[start:end]
        self.assertNotIn('diagnostics/providers', readiness_function)
        self.assertNotIn('x-auth-token', readiness_function)
        self.assertNotIn('--providers', readiness_function)
        self.assertIn('host-$host-ready.command.json', readiness_function)
        self.assertIn('runner_executable_guest_readyz+controller_log', readiness_function)
        self.assertIn('fabric-v3-agent-readiness.py', readiness_function)
        self.assertIn('--controller-log "$controller_log"', readiness_function)
        self.assertIn('--controller-start "$controller_start"', readiness_function)
        self.assertIn('HARNESS_GAP', DRIVER[gate:restart_traffic])
        self.assertNotRegex(readiness_function, r'\b(POST|PUT|DELETE)\b')

    def test_three_host_barrier_precedes_post_restart_traffic_and_c_delete(self):
        ready = DRIVER.index('curl -fsS "$BASE/readyz" >"$EVIDENCE/restart/ready.json"')
        gate = DRIVER.index('wait_for_current_compute_agents \\\n  "pre-retirement-compute-agent-readiness"', ready)
        traffic = DRIVER.index('for pair in a:b b:a a:c c:a b:c c:b; do', gate)
        c_delete = DRIVER.index('delete_started_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"', traffic)
        self.assertLess(ready, gate)
        self.assertLess(gate, traffic)
        self.assertLess(traffic, c_delete)
        invocation = DRIVER[gate:traffic]
        self.assertIn('"post-controller-restart-before-retirement"', invocation)
        self.assertIn('  a b c \\\n', invocation)
        self.assertIn('"HARNESS_GAP"', invocation)
        deletion = DRIVER[c_delete:]
        self.assertIn('c-delete/operation/response-headers.txt', deletion)
        self.assertIn('c-delete/operation/response-body.txt', deletion)
        self.assertIn('c-delete/operation/http-status.txt', deletion)


if __name__ == "__main__":
    unittest.main()
