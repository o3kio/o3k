#!/usr/bin/env python3
import json
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).with_name("fabric-v3-delete-operation-evidence.py")
SERVER_ID = "00000000-0000-4000-8000-000000000103"
DELETE_OPERATION_ID = "00000000-0000-4000-8000-000000000203"
STARTED_AT = "2026-10-12T11:35:35Z"


class DeleteOperationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = self.root / "controller.sqlite"
        self.output = self.root / "delete-evidence.json"
        self._create_database()

    def tearDown(self):
        self.temp.cleanup()

    def _create_database(self):
        with sqlite3.connect(self.database) as db:
            db.executescript(
                """
                CREATE TABLE operations (
                    id TEXT, resource_id TEXT, kind TEXT, state TEXT,
                    error_category TEXT, created_at TEXT, private_payload TEXT
                );
                CREATE TABLE audit_events (
                    event_id TEXT, timestamp TEXT, request_id TEXT, audit_id TEXT,
                    service TEXT, action TEXT, resource_type TEXT, resource_id TEXT,
                    operation_id TEXT, outcome TEXT, reason_category TEXT,
                    private_payload TEXT
                );
                """
            )

    def _insert_delete(self, *, operation_state="succeeded", audit_outcome="succeeded"):
        with sqlite3.connect(self.database) as db:
            db.execute(
                "INSERT INTO operations VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    DELETE_OPERATION_ID,
                    SERVER_ID,
                    "lifecycle:delete",
                    operation_state,
                    None,
                    "2026-10-12 11:35:35",
                    "private-delete-payload-must-not-leak",
                ),
            )
            db.execute(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "00000000-0000-4000-8000-000000000303",
                    "2026-10-12T11:35:35.250000Z",
                    "generated-request-id-not-the-client-label",
                    "00000000-0000-4000-8000-000000000403",
                    "compute",
                    "compute:DeleteServer",
                    "compute:server",
                    SERVER_ID,
                    None,
                    audit_outcome,
                    None,
                    "private-audit-payload-must-not-leak",
                ),
            )

    def _run(self, http_status="204"):
        return subprocess.run(
            [
                sys.executable,
                str(HELPER),
                str(self.database),
                SERVER_ID,
                STARTED_AT,
                http_status,
                str(self.output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_fractional_audit_time_and_generated_request_id_are_accepted(self):
        self._insert_delete()

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["operation"]["id"], DELETE_OPERATION_ID)
        self.assertEqual(evidence["operation"]["state"], "succeeded")
        self.assertEqual(evidence["audit_event"]["request_id"], "generated-request-id-not-the-client-label")
        self.assertEqual(evidence["audit_event"]["outcome"], "succeeded")
        self.assertEqual(evidence["http_status"], 204)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        serialized = self.output.read_text()
        self.assertNotIn("private-delete-payload-must-not-leak", serialized)
        self.assertNotIn("private-audit-payload-must-not-leak", serialized)

    def test_nonterminal_delete_operation_is_rejected(self):
        self._insert_delete(operation_state="applying")

        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_failed_delete_audit_event_is_rejected(self):
        self._insert_delete(audit_outcome="failed")

        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_non_204_response_is_rejected(self):
        self._insert_delete()

        result = self._run(http_status="500")

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_ambiguous_matching_delete_operations_are_rejected(self):
        self._insert_delete()
        with sqlite3.connect(self.database) as db:
            db.execute(
                "INSERT INTO operations VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "00000000-0000-4000-8000-000000000204",
                    SERVER_ID,
                    "lifecycle:delete",
                    "succeeded",
                    None,
                    "2026-10-12 11:35:36",
                    "private-duplicate-operation-payload",
                ),
            )

        result = self._run()

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(self.output.exists())

    def test_ambiguous_matching_delete_audit_events_are_rejected(self):
        self._insert_delete()
        with sqlite3.connect(self.database) as db:
            db.execute(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "00000000-0000-4000-8000-000000000304",
                    "2026-10-12T11:35:36.250000Z",
                    "second-generated-request-id",
                    "00000000-0000-4000-8000-000000000404",
                    "compute",
                    "compute:DeleteServer",
                    "compute:server",
                    SERVER_ID,
                    None,
                    "succeeded",
                    None,
                    "private-duplicate-audit-payload",
                ),
            )

        result = self._run()

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(self.output.exists())

    def test_output_symlink_is_not_followed(self):
        self._insert_delete()
        target = self.root / "target.txt"
        target.write_text("preserve this file")
        self.output.symlink_to(target)

        result = self._run()

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(target.read_text(), "preserve this file")


if __name__ == "__main__":
    unittest.main()
