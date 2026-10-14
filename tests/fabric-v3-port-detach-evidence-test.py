#!/usr/bin/env python3
import json
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).with_name("fabric-v3-port-detach-evidence.py")
PORT_ID = "00000000-0000-4000-8000-000000000103"


class PortDetachEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = self.root / "controller.sqlite"
        self.output = self.root / "port-evidence.json"
        with sqlite3.connect(self.database) as db:
            db.execute(
                """
                CREATE TABLE network_ports (
                    id TEXT PRIMARY KEY, status TEXT, binding_host TEXT,
                    binding_state TEXT
                )
                """
            )

    def tearDown(self):
        self.temp.cleanup()

    def _insert(self, *, status="ACTIVE", binding_host=None, binding_state="down"):
        with sqlite3.connect(self.database) as db:
            db.execute(
                "INSERT INTO network_ports VALUES (?, ?, ?, ?)",
                (PORT_ID, status, binding_host, binding_state),
            )

    def _run(self):
        return subprocess.run(
            [sys.executable, str(HELPER), str(self.database), PORT_ID, str(self.output)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_legacy_active_status_does_not_override_down_binding_tombstone(self):
        self._insert(status="ACTIVE")

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["status"], "ACTIVE")
        self.assertIsNone(evidence["binding_host"])
        self.assertEqual(evidence["binding_state"], "down")
        self.assertTrue(evidence["unbound_down_tombstone"])
        self.assertIn("public Neutron status is checked separately", evidence["status_semantics"])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_bound_host_fails_and_observation_is_preserved(self):
        self._insert(binding_host="host-c")

        result = self._run()

        self.assertEqual(result.returncode, 1, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["binding_host"], "host-c")
        self.assertFalse(evidence["unbound_down_tombstone"])

    def test_non_down_binding_state_fails_and_observation_is_preserved(self):
        self._insert(binding_state="bound")

        result = self._run()

        self.assertEqual(result.returncode, 1, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["binding_state"], "bound")
        self.assertFalse(evidence["unbound_down_tombstone"])

    def test_missing_port_fails_and_records_absence(self):
        result = self._run()

        self.assertEqual(result.returncode, 1, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertFalse(evidence["found"])
        self.assertFalse(evidence["unbound_down_tombstone"])

    def test_output_symlink_is_not_followed(self):
        self._insert()
        target = self.root / "target.txt"
        target.write_text("preserve this file")
        self.output.symlink_to(target)

        result = self._run()

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(target.read_text(), "preserve this file")


if __name__ == "__main__":
    unittest.main()
