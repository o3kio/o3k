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
    providers = {
        "items": [
            {
                "provider_id": "compute-agent-a",
                "status": "healthy",
                "availability": "available",
                "observed_at_unix_ms": NOW_MS - 1_000,
            },
            {
                "provider_id": "compute-agent-b",
                "status": "healthy",
                "availability": "available",
                "observed_at_unix_ms": NOW_MS - 1_000,
            },
        ]
    }
    ready = {
        "host-a": {"status": "ready", "agent_id": "compute-agent-a", "agent_epoch": "epoch-a"},
        "host-b": {"status": "ready", "agent_id": "compute-agent-b", "agent_epoch": "epoch-b"},
    }
    return manifest, providers, ready


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
        for host in ("host-a", "host-b")
    )


def evaluate(manifest, providers, ready, *, consecutive_observations=1, controller_log=None):
    return helper.evaluate(
        manifest,
        providers,
        ready,
        NOW_MS,
        controller_log=controller_log if controller_log is not None else controller_log_for(ready),
        controller_start_ms=CONTROLLER_START_MS,
        consecutive_observations=consecutive_observations,
    )


class AgentReadinessRegression(unittest.TestCase):
    def test_fresh_current_agents_pass_only_after_two_observations(self):
        manifest, providers, ready = valid_inputs()
        first = evaluate(manifest, providers, ready, consecutive_observations=1)
        second = evaluate(manifest, providers, ready, consecutive_observations=2)
        self.assertTrue(first["observation_valid"])
        self.assertEqual(first["status"], "pending")
        self.assertEqual(second["status"], "passed")
        self.assertEqual([item["agent_epoch"] for item in second["agents"]], ["epoch-a", "epoch-b"])
        self.assertEqual([item["bootstrap_agent_epoch"] for item in second["agents"]], ["epoch-a", "epoch-b"])

    def test_new_post_restart_epochs_are_accepted_and_recorded(self):
        manifest, providers, ready = valid_inputs()
        ready["host-a"]["agent_epoch"] = "epoch-a-after-restart"
        ready["host-b"]["agent_epoch"] = "epoch-b-after-restart"
        result = evaluate(manifest, providers, ready, consecutive_observations=2)
        self.assertTrue(result["observation_valid"])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(
            [(item["bootstrap_agent_epoch"], item["agent_epoch"], item["epoch_changed_from_bootstrap"]) for item in result["agents"]],
            [("epoch-a", "epoch-a-after-restart", True), ("epoch-b", "epoch-b-after-restart", True)],
        )

    def test_current_epoch_must_have_post_restart_controller_registration(self):
        manifest, providers, ready = valid_inputs()
        result = evaluate(
            manifest,
            providers,
            ready,
            controller_log=controller_log_for(ready, timestamp_ms=CONTROLLER_START_MS - 1),
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["classification"], "HARNESS_GAP")
        self.assertEqual(result["failed_operation"], "observe_compute_agent_registration_after_restart")

    def test_cli_reads_restart_metadata_and_accepts_registered_new_epoch(self):
        manifest, providers, ready = valid_inputs()
        ready["host-a"]["agent_epoch"] = "epoch-a-after-restart"
        ready["host-b"]["agent_epoch"] = "epoch-b-after-restart"
        start_time = datetime.fromtimestamp(CONTROLLER_START_MS / 1000, timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            paths = {
                "manifest": directory / "manifest.json",
                "providers": directory / "providers.json",
                "ready_a": directory / "ready-a.json",
                "ready_b": directory / "ready-b.json",
                "controller_start": directory / "controller-start.json",
                "controller_log": directory / "controller.log",
                "output": directory / "result.json",
            }
            for key, value in (
                ("manifest", manifest),
                ("providers", providers),
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
                "--providers", str(paths["providers"]),
                "--ready-a", str(paths["ready_a"]),
                "--ready-b", str(paths["ready_b"]),
                "--controller-log", str(paths["controller_log"]),
                "--controller-start", str(paths["controller_start"]),
                "--now-ms", str(NOW_MS),
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

    def test_missing_provider_is_a_harness_gap(self):
        manifest, providers, ready = valid_inputs()
        providers["items"] = providers["items"][:1]
        result = evaluate(manifest, providers, ready, consecutive_observations=2)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["classification"], "HARNESS_GAP")
        self.assertEqual(result["failed_operation"], "read_compute_agent_registry")

    def test_wrong_agent_identity_or_missing_epoch_fails_closed(self):
        for field, value in (("agent_id", "other-agent"), ("agent_epoch", "")):
            with self.subTest(field=field):
                manifest, providers, ready = valid_inputs()
                ready["host-a"][field] = value
                result = evaluate(manifest, providers, ready, consecutive_observations=2)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["classification"], "HARNESS_GAP")
                self.assertEqual(result["failed_operation"], "read_compute_agent_readyz")

    def test_unregistered_current_epoch_fails_closed(self):
        manifest, providers, ready = valid_inputs()
        current_controller_log = controller_log_for(ready)
        ready["host-a"]["agent_epoch"] = "unexpected-epoch"
        result = evaluate(manifest, providers, ready, controller_log=current_controller_log)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_operation"], "observe_compute_agent_registration_after_restart")

    def test_unhealthy_unavailable_stale_or_future_registry_observation_fails(self):
        for field, value in (
            ("status", "unavailable"),
            ("availability", "unavailable"),
            ("observed_at_unix_ms", NOW_MS - 15_001),
            ("observed_at_unix_ms", NOW_MS + 1),
            ("observed_at_unix_ms", CONTROLLER_START_MS - 1),
        ):
            with self.subTest(field=field, value=value):
                manifest, providers, ready = valid_inputs()
                providers["items"][0][field] = value
                result = evaluate(manifest, providers, ready, consecutive_observations=2)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["classification"], "HARNESS_GAP")
                self.assertEqual(result["failed_operation"], "read_compute_agent_registry")

    def test_guest_not_ready_fails_closed(self):
        manifest, providers, ready = valid_inputs()
        ready["host-b"]["status"] = "starting"
        result = evaluate(manifest, providers, ready, consecutive_observations=2)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_operation"], "read_compute_agent_readyz")

    def test_duplicate_provider_identity_fails_closed_without_copying_extra_fields(self):
        manifest, providers, ready = valid_inputs()
        providers["items"].append({
            "provider_id": "compute-agent-a",
            "status": "healthy",
            "availability": "available",
            "observed_at_unix_ms": NOW_MS - 1_000,
            "credential_fixture": "do-not-copy-this-value",
        })
        result = evaluate(manifest, providers, ready, consecutive_observations=2)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["classification"], "HARNESS_GAP")
        self.assertNotIn("do-not-copy-this-value", repr(result))

    def test_restart_readiness_gate_precedes_teardown_and_is_read_only(self):
        start_timestamp = DRIVER.index('controller_start_requested_at="$(date -u +%FT%T.%NZ)"')
        restart_launch = DRIVER.index('"$PRODUCT_SOURCE_DIR/target/release/o3kd"', start_timestamp)
        start_record = DRIVER.index('"$EVIDENCE/restart/startup-recovery/controller-start.json"', restart_launch)
        self.assertLess(start_timestamp, restart_launch)
        self.assertLess(restart_launch, start_record)
        restart_traffic = DRIVER.index('A/B canonical ARP MAC changed after controller restart')
        gate = DRIVER.index('wait_for_survivor_compute_agents \\\n', restart_traffic)
        teardown_comment = DRIVER.index('# Supported API teardown; provider state is never manually repaired/deleted.')
        delete = DRIVER.index('curl --fail --silent --show-error --max-time 60 -X DELETE "$BASE/v2.1/$PROJECT_ID/servers/$id"')
        self.assertLess(restart_traffic, gate)
        self.assertLess(gate, teardown_comment)
        self.assertLess(gate, delete)
        start = DRIVER.index('wait_for_survivor_compute_agents() {')
        end = DRIVER.index('\n}\n', start)
        readiness_function = DRIVER[start:end]
        self.assertIn('$BASE/o3k/v1/operator/diagnostics/providers?limit=200', readiness_function)
        self.assertNotIn('$BASE/operator/diagnostics/providers?limit=200', readiness_function)
        self.assertIn('provider diagnostics returned an HTTP client error', readiness_function)
        self.assertIn('fabric-v3-agent-readiness.py', readiness_function)
        self.assertIn('--controller-log "$EVIDENCE/restart/startup-recovery/o3kd.log"', readiness_function)
        self.assertIn('--controller-start "$EVIDENCE/restart/startup-recovery/controller-start.json"', readiness_function)
        self.assertIn('HARNESS_GAP', DRIVER[gate:teardown_comment])
        self.assertNotRegex(readiness_function, r'\b(POST|PUT|DELETE)\b')


if __name__ == "__main__":
    unittest.main()
