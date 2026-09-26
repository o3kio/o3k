#!/usr/bin/env python3
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "pp5_runner_prerequisite", Path(__file__).with_name("pp5-runner-prerequisite.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class RunnerPrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {
            "O3K_PP5_ARTIFACT_DIR": self.temp.name,
            "O3K_PP5_RUN_ID": "unit-run",
            "O3K_PP5_SOURCE_SHA": "a" * 40,
        }

    def tearDown(self):
        self.temp.cleanup()

    def artifact(self):
        return json.loads(Path(self.temp.name, "pp5-runner-prerequisite.json").read_text())

    def test_local_peer_prerequisite_passes_without_recording_credentials(self):
        with patch.dict(os.environ, self.env, clear=False), \
                patch.object(MODULE.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(MODULE.pwd, "getpwnam"), \
                patch.object(MODULE, "run_silent", return_value=True):
            self.assertEqual(MODULE.main(), 0)
        artifact = self.artifact()
        self.assertEqual(artifact["status"], "passed")
        self.assertTrue(artifact["local_postgres_probe"])
        self.assertNotIn("DATABASE_URL", json.dumps(artifact))

    def test_missing_client_fails_before_database_probe(self):
        with patch.dict(os.environ, self.env, clear=False), \
                patch.object(MODULE.shutil, "which", return_value=None), \
                patch.object(MODULE, "run_silent", return_value=False):
            self.assertEqual(MODULE.main(), 2)
        artifact = self.artifact()
        self.assertEqual(artifact["failure_phase"], "client_tools")
        self.assertFalse(artifact["client_present_after"])

    def test_missing_admin_path_fails_closed(self):
        with patch.dict(os.environ, self.env, clear=False), \
                patch.object(MODULE.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(MODULE.pwd, "getpwnam", side_effect=KeyError("postgres")), \
                patch.object(MODULE, "run_silent", return_value=False):
            self.assertEqual(MODULE.main(), 2)
        self.assertEqual(self.artifact()["failure_phase"], "postgres_admin")

    def test_invalid_configured_admin_url_fails_before_probe(self):
        environment = dict(self.env, O3K_PP5_POSTGRES_ADMIN_URL="postgres://user@remote.invalid/postgres")
        with patch.dict(os.environ, environment, clear=False), \
                patch.object(MODULE.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(MODULE, "run_silent", return_value=True):
            self.assertEqual(MODULE.main(), 2)
        artifact = self.artifact()
        self.assertEqual(artifact["failure_phase"], "configuration")
        self.assertFalse(artifact["admin_url_valid"])

    def test_attempt_artifact_is_preserved_across_runs(self):
        with patch.dict(os.environ, self.env, clear=False), \
                patch.object(MODULE.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(MODULE.pwd, "getpwnam"), \
                patch.object(MODULE, "run_silent", return_value=True):
            self.assertEqual(MODULE.main(), 0)
            first = sorted(Path(self.temp.name).glob("pp5-runner-prerequisite-*.json"))[0]
            first_content = first.read_text()
            self.assertEqual(MODULE.main(), 0)
        attempts = sorted(Path(self.temp.name).glob("pp5-runner-prerequisite-*.json"))
        self.assertGreaterEqual(len(attempts), 2)
        self.assertEqual(first.read_text(), first_content)

    def test_failed_attempt_is_preserved_when_next_attempt_succeeds(self):
        environment = dict(self.env, O3K_PP5_POSTGRES_ADMIN_URL="postgres://user@remote.invalid/postgres")
        with patch.dict(os.environ, environment, clear=False), \
                patch.object(MODULE.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(MODULE, "run_silent", return_value=True):
            self.assertEqual(MODULE.main(), 2)
            failed = sorted(Path(self.temp.name).glob("pp5-runner-prerequisite-*.json"))[0]
            failed_content = failed.read_text()
            os.environ.pop("O3K_PP5_POSTGRES_ADMIN_URL", None)
            self.assertEqual(MODULE.main(), 0)
        self.assertEqual(json.loads(failed.read_text())["status"], "failed")
        self.assertEqual(failed.read_text(), failed_content)


if __name__ == "__main__":
    unittest.main()
