#!/usr/bin/env python3
import importlib.util
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
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
        self.assertEqual(artifact["failure_phase"], "postgres_server")
        self.assertFalse(artifact["client_present_after"])

    def test_missing_admin_path_fails_closed(self):
        with patch.dict(os.environ, self.env, clear=False), \
                patch.object(MODULE.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(MODULE.pwd, "getpwnam", side_effect=KeyError("postgres")), \
                patch.object(MODULE, "run_silent", return_value=False):
            self.assertEqual(MODULE.main(), 2)
        self.assertEqual(self.artifact()["failure_phase"], "postgres_server")

    def test_invalid_configured_admin_url_fails_before_probe(self):
        environment = dict(self.env, O3K_PP5_POSTGRES_ADMIN_URL="postgres://user@remote.invalid/postgres")
        with patch.dict(os.environ, environment, clear=False), \
                patch.object(MODULE.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(MODULE, "run_silent", return_value=True):
            self.assertEqual(MODULE.main(), 2)
        artifact = self.artifact()
        self.assertEqual(artifact["failure_phase"], "configuration")
        self.assertFalse(artifact["admin_url_valid"])

    def test_external_authority_marks_service_state_as_not_owned(self):
        environment = dict(self.env, O3K_PP5_POSTGRES_ADMIN_URL="postgres://user@127.0.0.1/postgres")
        with patch.dict(os.environ, environment, clear=False), \
                patch.object(MODULE, "canonical_admin_url_is_valid", return_value=True), \
                patch.object(MODULE, "install_client", return_value=(True, "already_present")), \
                patch.object(MODULE.shutil, "which", return_value="/usr/bin/psql"):
            self.assertEqual(MODULE.main(), 0)
        state = json.loads(Path(self.temp.name, "pp5-runner-postgres-service-state.json").read_text())
        self.assertEqual(state["run_id"], "unit-run")
        self.assertFalse(state["local_service_started"])

    def test_stale_service_state_is_ignored_without_mutation(self):
        state = {
            "run_id": "prior-run",
            "source_sha": "b" * 40,
            "local_service_started": True,
            "local_service_was_active": False,
        }
        Path(self.temp.name, "pp5-runner-postgres-service-state.json").write_text(json.dumps(state))
        with patch.dict(os.environ, self.env, clear=False), \
                patch.object(MODULE, "stop_local_service") as stop:
            self.assertEqual(MODULE.restore_service(), 0)
        stop.assert_not_called()

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

    def test_missing_server_is_installed_and_started(self):
        with patch.dict(os.environ, self.env, clear=False), \
                patch.object(MODULE, "local_service_active", return_value=False), \
                patch.object(MODULE.pwd, "getpwnam", side_effect=KeyError("postgres")), \
                patch.object(MODULE.shutil, "which", side_effect=lambda name: "/usr/bin/psql" if name == "psql" else None), \
                patch.object(MODULE, "install_packages", return_value=(True, "installed")) as install, \
                patch.object(MODULE, "start_local_service", return_value=True), \
                patch.object(MODULE, "run_silent", return_value=True):
            ok, reason, was_active, installed = MODULE.ensure_local_server()
        self.assertTrue(ok)
        self.assertEqual(reason, "started")
        self.assertFalse(was_active)
        self.assertTrue(installed)
        install.assert_called_once_with(["postgresql"])
        state = json.loads(Path(self.temp.name, "pp5-runner-postgres-service-state.json").read_text())
        self.assertTrue(state["local_service_started"])
        self.assertTrue(state["server_package_installed"])

    def test_server_start_failure_is_bounded_and_recorded(self):
        with patch.dict(os.environ, self.env, clear=False), \
                patch.object(MODULE, "local_service_active", return_value=False), \
                patch.object(MODULE.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=100)), \
                patch.object(MODULE.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(MODULE, "start_local_service", return_value=False):
            ok, reason, _, _ = MODULE.ensure_local_server()
        self.assertFalse(ok)
        self.assertEqual(reason, "postgresql_service_start_failed")
        self.assertTrue(Path(self.temp.name, "pp5-runner-postgres-service-state.json").is_file())

    def test_service_start_and_probe_are_bounded(self):
        calls = []

        def capture(command, timeout):
            calls.append((command, timeout))
            return True

        with patch.object(MODULE, "run_silent", side_effect=capture), \
                patch.object(MODULE, "local_service_active", return_value=True):
            self.assertTrue(MODULE.start_local_service())
        self.assertEqual(calls[0][1], 60)

    def test_peer_probe_binds_to_postgres_os_account(self):
        calls = []

        def capture(command, timeout):
            calls.append((command, timeout))
            return True

        with patch.dict(os.environ, self.env, clear=False), \
                patch.object(MODULE, "ensure_local_server", return_value=(True, "started", False, True)), \
                patch.object(MODULE.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=100)), \
                patch.object(MODULE.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(MODULE, "run_silent", side_effect=capture):
            self.assertEqual(MODULE.main(), 0)
        self.assertEqual(calls, [([
            "sudo", "-n", "-u", "postgres", "psql", "-X", "-w", "-d", "postgres",
            "-v", "ON_ERROR_STOP=1", "-Atqc", "SELECT 1",
        ], 30)])

    def test_restore_requires_exact_run_and_source(self):
        state = {
            "run_id": "unit-run",
            "source_sha": "a" * 40,
            "local_service_started": True,
            "local_service_was_active": False,
        }
        Path(self.temp.name, "pp5-runner-postgres-service-state.json").write_text(json.dumps(state))
        with patch.dict(os.environ, self.env, clear=False), \
                patch.object(MODULE, "stop_local_service", return_value=True) as stop:
            self.assertEqual(MODULE.restore_service(), 0)
        stop.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
