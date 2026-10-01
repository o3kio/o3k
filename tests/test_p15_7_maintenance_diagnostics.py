import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/capture-p15-7-maintenance-diagnostics.py"
SPEC = importlib.util.spec_from_file_location("maintenance_diagnostics", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


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
            "https://user:pass@example.invalid/path?access_token=querysecret"
        )
        for secret in ("abc123", "pwd-value", "client-value", "user:pass", "querysecret"):
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
            self.assertEqual(doc["probes"]["agent_ready_ssh"]["exit_status"], 124)
            self.assertTrue(doc["probes"]["agent_ready_ssh"]["timed_out"])
            self.assertLessEqual(len(doc["agent"]["correlated_log_lines"]), 160)
            self.assertTrue(doc["agent"]["log_capture"]["truncated"])
            self.assertEqual((root / "out.json").stat().st_mode & 0o777, 0o600)

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
