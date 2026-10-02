import importlib.util
import contextlib
import io
import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/capture-p15-7-maintenance-diagnostics.py"
SPEC = importlib.util.spec_from_file_location("maintenance_diagnostics", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)
OBSERVATION_SCRIPT = ROOT / "scripts/capture-p15-7-maintenance-observation.py"
OBSERVATION_SPEC = importlib.util.spec_from_file_location("maintenance_observation", OBSERVATION_SCRIPT)
OBSERVATION_MODULE = importlib.util.module_from_spec(OBSERVATION_SPEC)
assert OBSERVATION_SPEC and OBSERVATION_SPEC.loader
OBSERVATION_SPEC.loader.exec_module(OBSERVATION_MODULE)


class MaintenanceDiagnosticsTests(unittest.TestCase):
    def make_inputs(self, root: Path, *, identity="agent-e", start=100, finish=200, api_status=0):
        (root / "body").write_text(json.dumps({
            "id": "block-123", "execution_identity": identity,
            "state": "ready", "agent_available": False,
            "resource_provider_ids": ["rp-e"], "token": "must-not-leak",
        }))
        (root / "headers").write_text(
            "HTTP/1.1 503 Service Unavailable\r\nX-Request-ID: req-456\r\n"
            "X-OpenStack-Request-ID: req-789\r\n"
        )
        (root / "provider-body").write_text(json.dumps({"items": [
            {"provider_id": "rp-e", "state": "Enabled", "availability": "available",
             "status": "healthy", "observed_at_unix_ms": 190},
        ]}))
        (root / "daemon").write_text("control plane reconnect warning\npassword=daemon-secret\n")
        (root / "agent").write_text(
            "noise\nagent reconnect failed password=agent-secret\n" + "x" * 100_000
        )
        (root / "ready").write_text("curl error token=readiness-secret\n")
        (root / "api-stderr").write_text("curl timeout password=stderr-secret\n")
        (root / "daemon-stderr").write_text("")
        (root / "agent-stderr").write_text("")
        (root / "ready-stderr").write_text("")
        probes = {
            "capture_start_ms": start, "capture_finish_ms": finish,
            "api_get": {"start_ms": start + 1, "finish_ms": start + 2, "exit_status": api_status, "timed_out": api_status == 28},
            "daemon_log_local": {"start_ms": start + 3, "finish_ms": start + 4, "exit_status": 0, "timed_out": False},
            "agent_log_ssh": {"start_ms": start + 5, "finish_ms": start + 6, "exit_status": 0, "timed_out": False},
            "agent_ready_ssh": {"start_ms": start + 7, "finish_ms": start + 8, "exit_status": 124, "timed_out": True},
        }
        (root / "probes").write_text(json.dumps(probes))

    def invoke(self, root: Path, *, identity="agent-e", start=100, finish=200, status="503", reboot=90):
        return subprocess.run([
            "python3", str(SCRIPT), "--artifact", str(root / "out.json"),
            "--api-body", str(root / "body"), "--api-headers", str(root / "headers"),
            "--provider-body", str(root / "provider-body"), "--provider-http-status", "200",
            "--provider-exit-status", "0",
            "--daemon-log", str(root / "daemon"), "--agent-log", str(root / "agent"),
            "--agent-ready", str(root / "ready"), "--api-stderr", str(root / "api-stderr"),
            "--daemon-log-stderr", str(root / "daemon-stderr"), "--agent-log-stderr", str(root / "agent-stderr"),
            "--agent-ready-stderr", str(root / "ready-stderr"), "--probe-meta", str(root / "probes"),
            "--source-sha", "a" * 40, "--run-id", "123", "--block-id", "block-123",
            "--execution-identity", identity, "--http-status", status,
            "--started-ms", str(start), "--finished-ms", str(finish), "--reboot-request-ms", str(reboot),
        ], check=False, capture_output=True, text=True)

    def test_redacts_url_and_structured_secret_fields(self):
        value = MODULE.sanitize(
            "Authorization: Bearer abc123 password=pwd-value client_secret=client-value "
            "https://user:pass@example.invalid/path?access_token=querysecret "
            'password="multi word secret" export TOKEN=\'quoted token value\''
        )
        for secret in ("abc123", "pwd-value", "client-value", "user:pass", "querysecret", "multi word secret", "quoted token value"):
            self.assertNotIn(secret, value)
        redacted = MODULE.redact_json({"access_token": "json-secret", "provider": {"api_key": "key-secret"}})
        self.assertEqual(redacted["access_token"], "[REDACTED]")
        self.assertEqual(redacted["provider"]["api_key"], "[REDACTED]")

    def test_publishes_correlated_identity_and_timeout_evidence_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_inputs(root)
            result = self.invoke(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            raw = (root / "out.json").read_text()
            for secret in ("must-not-leak", "daemon-secret", "agent-secret", "readiness-secret", "stderr-secret"):
                self.assertNotIn(secret, raw)
            doc = json.loads(raw)
            self.assertEqual(doc["capture_status"], "captured")
            self.assertTrue(doc["control_plane"]["observed"]["identity_matches"])
            self.assertFalse(doc["control_plane"]["observed"]["agent_available"])
            self.assertEqual(len(doc["control_plane"]["request_ids"]), 2)
            self.assertEqual(doc["control_plane"]["provider_diagnostics"]["providers"][0]["provider_id"], "rp-e")
            self.assertEqual(doc["probes"]["agent_ready_ssh"]["exit_status"], 124)
            self.assertTrue(doc["probes"]["agent_ready_ssh"]["timed_out"])
            self.assertLessEqual(len(doc["agent"]["correlated_log_lines"]), 160)
            self.assertTrue(doc["agent"]["log_capture"]["truncated"])
            self.assertEqual((root / "out.json").stat().st_mode & 0o777, 0o600)

    def test_observation_projects_view_level_availability_and_request_ids(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "body").write_text(json.dumps({
                "block": {"id": "block-123", "execution_identity": "agent-e", "state": "draining",
                          "generation": 4, "resource_provider_ids": ["rp-e"]},
                "agent_available": True, "access_token": "must-not-leak",
            }))
            (root / "headers").write_text("HTTP/1.1 200 OK\r\nX-Request-ID: req-456\r\n")
            args = type("Args", (), {
                "body": root / "body", "headers": root / "headers", "started_ms": 100,
                "finished_ms": 101, "http_status": "200", "exit_status": 0, "curl_exit_status": 0,
                "run_id": "123", "source_sha": "a" * 40, "block_id": "block-123",
                "execution_identity": "agent-e",
            })()
            item = OBSERVATION_MODULE.observation(args.body, args.headers, args)
            self.assertTrue(item["identity_matches"])
            self.assertTrue(item["agent_available"])
            self.assertEqual(item["state"], "draining")
            self.assertEqual(item["request_ids"][0]["value"], "req-456")
            self.assertNotIn("access_token", json.dumps(item))

    def test_diagnostic_reads_agent_availability_from_building_block_view(self):
        view = json.dumps({
            "block": {"id": "block-123", "execution_identity": "agent-e", "state": "draining"},
            "agent_available": True,
        })
        item = MODULE.selected_state(view, "block-123", "agent-e")
        self.assertIsNotNone(item)
        self.assertTrue(item["agent_available"])

    def test_observation_writer_bounds_count_and_sanitizes_each_line(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "body").write_text(json.dumps({
                "block": {"id": "block-123", "execution_identity": "agent-e", "state": "draining"},
                "agent_available": False,
            }))
            (root / "headers").write_text("X-Request-ID: request-1\r\n")
            artifact = root / "observations.jsonl"
            now = int(time.time() * 1000)
            argv = ["capture", "--artifact", str(artifact), "--body", str(root / "body"),
                    "--headers", str(root / "headers"), "--started-ms", str(now), "--finished-ms", str(now),
                    "--http-status", "200", "--exit-status", "0", "--curl-exit-status", "0",
                    "--block-id", "block-123", "--execution-identity", "agent-e", "--run-id", "123",
                    "--source-sha", "a" * 40]
            for _ in range(OBSERVATION_MODULE.MAX_OBSERVATIONS):
                with patch("sys.argv", argv):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(OBSERVATION_MODULE.main(), 0)
            with patch("sys.argv", argv), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                OBSERVATION_MODULE.main()
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
            lines = artifact.read_text().splitlines()
            self.assertEqual(len(lines), OBSERVATION_MODULE.MAX_OBSERVATIONS)
            self.assertTrue(all(json.loads(line)["agent_available"] is False for line in lines))

    def test_missing_input_wrong_identity_and_bad_time_are_not_captured(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_inputs(root, identity="different-agent")
            result = self.invoke(root)
            self.assertEqual(result.returncode, 2)
            doc = json.loads((root / "out.json").read_text())
            self.assertEqual(doc["capture_status"], "incomplete")
            self.assertIn("api_identity_mismatch", doc["capture_issues"])
            self.make_inputs(root, start=300, finish=200)
            result = self.invoke(root, start=300, finish=200)
            self.assertEqual(result.returncode, 2)
            self.assertIn("capture_window_invalid", json.loads((root / "out.json").read_text())["capture_issues"])
            self.make_inputs(root)
            result = self.invoke(root, reboot=102)
            self.assertEqual(result.returncode, 2)
            self.assertIn("api_observation_precedes_reboot", json.loads((root / "out.json").read_text())["capture_issues"])
            (root / "daemon").unlink()
            result = self.invoke(root)
            self.assertEqual(result.returncode, 2)
            self.assertIn("daemon_log_unavailable", json.loads((root / "out.json").read_text())["capture_issues"])

    def test_capture_occurs_before_destructive_cleanup_and_raw_probe_removal(self):
        source = (ROOT / "scripts/p15-7-real-host-journey.sh").read_text()
        cleanup = source[source.index("cleanup() {"):source.index("trap cleanup EXIT")]
        self.assertLess(cleanup.index('capture_failure_diagnostics "$exit_status"'), cleanup.index("secure_remove_credentials"))
        self.assertLess(cleanup.index('capture_failure_diagnostics "$exit_status"'), cleanup.index('for i in "${!DOMAINS[@]}"'))
        self.assertIn('secure_remove_credentials "$WORK_ROOT/maintenance-api.body.raw"', source)


if __name__ == "__main__":
    unittest.main()
