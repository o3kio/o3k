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
    def test_redacts_secrets_and_preserves_request_identity(self):
        value = MODULE.sanitize(
            "Authorization: Bearer abc123 password=pwd-value "
            "client_secret=client-value private_key=key-value"
        )
        for secret in ("abc123", "pwd-value", "client-value", "key-value"):
            self.assertNotIn(secret, value)
        self.assertEqual(
            MODULE.request_ids("HTTP/1.1 503 Service Unavailable\r\nX-Request-ID: req-123\r\n"),
            {"x-request-id": "req-123"},
        )

    def test_published_artifact_has_exact_block_state_and_bounded_logs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "body").write_text(json.dumps({
                "id": "block-123", "execution_identity": "agent-e",
                "state": "ready", "agent_available": False,
                "resource_provider_ids": ["rp-e"], "token": "must-not-leak",
            }))
            (root / "headers").write_text("X-Request-ID: req-456\n")
            (root / "agent").write_text(
                "noise\nagent reconnect failed password=bad\n" + "x" * 100_000
            )
            (root / "ready").write_text("curl error token=secret\n")
            result = subprocess.run([
                "python3", str(SCRIPT), "--artifact", str(root / "out.json"),
                "--api-body", str(root / "body"), "--api-headers", str(root / "headers"),
                "--agent-log", str(root / "agent"), "--agent-ready", str(root / "ready"),
                "--source-sha", "a" * 40, "--run-id", "123", "--block-id", "block-123",
                "--execution-identity", "agent-e", "--http-status", "503",
                "--started-ms", "100", "--finished-ms", "200",
            ], check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            raw = (root / "out.json").read_text()
            self.assertNotIn("must-not-leak", raw)
            self.assertNotIn("secret", raw)
            doc = json.loads(raw)
            self.assertTrue(doc["control_plane"]["observed"]["identity_matches"])
            self.assertFalse(doc["control_plane"]["observed"]["agent_available"])
            self.assertEqual(doc["control_plane"]["request_ids"]["x-request-id"], "req-456")
            self.assertLessEqual(len(doc["agent"]["correlated_log_lines"]), 160)
            self.assertTrue(doc["agent"]["truncated"])


if __name__ == "__main__":
    unittest.main()
