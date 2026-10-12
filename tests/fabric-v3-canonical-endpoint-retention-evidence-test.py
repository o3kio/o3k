#!/usr/bin/env python3
import json
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).with_name("fabric-v3-canonical-endpoint-retention-evidence.py")
REALM_ID = "00000000-0000-4000-8000-000000000120"
PROJECT_ID = "00000000-0000-4000-8000-000000000121"
ENDPOINT_IDS = [
    "00000000-0000-4000-8000-000000000131",
    "00000000-0000-4000-8000-000000000132",
    "00000000-0000-4000-8000-000000000133",
]


class CanonicalEndpointRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = self.root / "controller.sqlite"
        self.output = self.root / "canonical-endpoint-state.json"
        with sqlite3.connect(self.database) as db:
            db.execute(
                """
                CREATE TABLE canonical_endpoints (
                    id TEXT PRIMARY KEY, realm_id TEXT, project_id TEXT,
                    fixed_ip TEXT, mac TEXT, generation INTEGER, state TEXT
                )
                """
            )
            for index, endpoint_id in enumerate(ENDPOINT_IDS):
                db.execute(
                    "INSERT INTO canonical_endpoints VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        endpoint_id,
                        REALM_ID,
                        PROJECT_ID,
                        f"10.77.0.{index + 2}",
                        f"02:00:00:00:00:{index + 2:02x}",
                        1,
                        "active",
                    ),
                )

    def tearDown(self):
        self.temp.cleanup()

    def _run(self):
        return subprocess.run(
            [
                sys.executable,
                str(HELPER),
                str(self.database),
                REALM_ID,
                *ENDPOINT_IDS,
                str(self.output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_caller_supplied_endpoints_remain_active_until_port_delete(self):
        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["phase"], "after-c-server-delete-before-supported-port-delete")
        self.assertEqual(evidence["endpoint_ownership"], "caller-supplied ports")
        self.assertEqual(evidence["actual_endpoint_ids"], sorted(ENDPOINT_IDS))
        self.assertTrue(evidence["all_expected_present_active"])
        self.assertEqual(
            evidence["release_semantics"],
            "caller-supplied endpoint remains until supported port DELETE",
        )
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_missing_departing_endpoint_fails_as_durable_lifecycle_defect(self):
        with sqlite3.connect(self.database) as db:
            db.execute("DELETE FROM canonical_endpoints WHERE id = ?", (ENDPOINT_IDS[2],))

        result = self._run()

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("DURABLE_RETIREMENT_DEFECT", result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertFalse(evidence["all_expected_present_active"])

    def test_inactive_departing_endpoint_fails_as_durable_lifecycle_defect(self):
        with sqlite3.connect(self.database) as db:
            db.execute(
                "UPDATE canonical_endpoints SET state='released' WHERE id = ?",
                (ENDPOINT_IDS[2],),
            )

        result = self._run()

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("DURABLE_RETIREMENT_DEFECT", result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertFalse(evidence["all_expected_present_active"])

    def test_unexpected_endpoint_in_campaign_realm_fails_closed(self):
        with sqlite3.connect(self.database) as db:
            db.execute(
                "INSERT INTO canonical_endpoints VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "00000000-0000-4000-8000-000000000199",
                    REALM_ID,
                    PROJECT_ID,
                    "10.77.0.99",
                    "02:00:00:00:00:99",
                    1,
                    "active",
                ),
            )

        result = self._run()

        self.assertEqual(result.returncode, 1, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertFalse(evidence["all_expected_present_active"])

    def test_missing_table_is_harness_gap(self):
        with sqlite3.connect(self.database) as db:
            db.execute("DROP TABLE canonical_endpoints")

        result = self._run()

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("HARNESS_GAP", result.stderr)
        self.assertFalse(self.output.exists())

    def test_output_symlink_is_not_followed(self):
        target = self.root / "target.txt"
        target.write_text("preserve this file")
        self.output.symlink_to(target)

        result = self._run()

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(target.read_text(), "preserve this file")


if __name__ == "__main__":
    unittest.main()
