#!/usr/bin/env python3
"""Portable prerequisite regressions; no PostgreSQL mutation or host setup."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "pp5_postgres", Path(__file__).with_name("provision_pp5_postgres.py")
)
pg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pg)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env = patch.dict(os.environ, {
            "O3K_PP5_RUN_ID": "preflight_unit",
            "O3K_PP5_SOURCE_SHA": "a" * 40,
            "O3K_PP5_ARTIFACT_DIR": self.temp.name,
            "O3K_PP5_POSTGRES_ADMIN_URL":
                "postgresql://admin:DO_NOT_LOG@127.0.0.1:5432/postgres",
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def invoke(self, response="160015|t|t|t", error=None):
        queries = []

        def query(sql, url=""):
            queries.append(sql)
            if error:
                pg.die(error)
            return response if "pg_roles" in sql and "current_user" in sql else ""

        with patch.object(pg.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(pg, "psql", side_effect=query), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                pg.preflight()
                passed = True
            except SystemExit:
                passed = False
        artifact = json.loads(Path(self.temp.name, "pp5-postgres-preflight.json").read_text())
        self.assertEqual(artifact["status"], "passed" if passed else "failed")
        self.assertEqual(artifact["source_sha"], "a" * 40)
        self.assertNotIn("DO_NOT_LOG", json.dumps(artifact))
        self.assertTrue(all(sql.lstrip().startswith("SELECT ") for sql in queries))
        return passed, artifact

    def test_success_read_only(self):
        passed, artifact = self.invoke()
        self.assertTrue(passed)
        self.assertEqual(len(set(artifact["databases"].values())), 4)

    def test_recheck_preserves_failed_attempt(self):
        passed, failed = self.invoke(error="connection failed")
        self.assertFalse(passed)
        passed, successful = self.invoke()
        self.assertTrue(passed)
        self.assertNotEqual(failed["attempt_artifact"], successful["attempt_artifact"])
        preserved = json.loads(Path(self.temp.name, failed["attempt_artifact"]).read_text())
        self.assertEqual(preserved["status"], "failed")
        self.assertEqual(preserved["failure_phase"], "admin_connection")

    def test_insufficient_privileges(self):
        passed, artifact = self.invoke("160015|f|t|f")
        self.assertFalse(passed)
        self.assertEqual(artifact["failure_phase"], "admin_privileges")

    def test_non_superuser_admin_privileges(self):
        passed, _ = self.invoke("160015|f|t|t")
        self.assertTrue(passed)

    def test_malformed_privilege_response(self):
        for response in ("unexpected", "160015|t|unknown|t"):
            with self.subTest(response=response):
                passed, artifact = self.invoke(response)
                self.assertFalse(passed)
                self.assertEqual(artifact["failure_phase"], "admin_privileges")

    def test_failed_preflight_blocks_provisioning(self):
        with patch.object(pg, "preflight", side_effect=SystemExit(2)), \
                patch.object(pg, "psql") as query, self.assertRaises(SystemExit):
            pg.provision()
        query.assert_not_called()

    def test_connection_failure(self):
        passed, artifact = self.invoke(error="PostgreSQL command failed (exit=2); diagnostics withheld")
        self.assertFalse(passed)
        self.assertEqual(artifact["failure_phase"], "admin_connection")

    def test_bad_urls_rejected_before_query(self):
        for url in ("https://127.0.0.1", "postgres://admin@remote.invalid/postgres",
                    "postgres://admin@127.0.0.1:bad/postgres",
                    "postgres://admin@127.0.0.1/postgres?host=remote.invalid"):
            with self.subTest(url=url), patch.dict(os.environ, {"O3K_PP5_POSTGRES_ADMIN_URL": url}):
                passed, artifact = self.invoke()
                self.assertFalse(passed)
                self.assertEqual(artifact["failure_phase"], "configuration")

    def test_identifiers_cannot_truncate_or_inject(self):
        for run in ("x" * 60, "bad;sql", "ü", ""):
            with self.subTest(run=run), patch.dict(os.environ, {"O3K_PP5_RUN_ID": run}):
                with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                    pg.expected_names(pg.run_id())

    def test_role_length_cannot_be_truncated(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.expected_role("x" * 56)

    def test_missing_client(self):
        with patch.object(pg.shutil, "which", return_value=None), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.preflight()
        artifact = json.loads(Path(self.temp.name, "pp5-postgres-preflight.json").read_text())
        self.assertEqual(artifact["failure_phase"], "client_tools")

    def test_local_admin_requires_postgres_account(self):
        with patch.dict(os.environ, {"O3K_PP5_POSTGRES_ADMIN_URL": ""}), \
                patch.object(pg.pwd, "getpwnam", side_effect=KeyError("postgres")):
            passed, artifact = self.invoke()
        self.assertFalse(passed)
        self.assertEqual(artifact["failure_phase"], "client_tools")

    def test_local_admin_requires_noninteractive_sudo(self):
        with patch.dict(os.environ, {"O3K_PP5_POSTGRES_ADMIN_URL": ""}), \
                patch.object(pg.shutil, "which", side_effect=lambda name: "psql" if name == "psql" else None), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.preflight()
        artifact = json.loads(Path(self.temp.name, "pp5-postgres-preflight.json").read_text())
        self.assertEqual(artifact["failure_phase"], "client_tools")

    def test_existing_role_refused(self):
        def query(sql, url=""):
            if "current_user" in sql:
                return "160015|t|t|t"
            return "1" if "pg_roles" in sql else ""
        with patch.object(pg.shutil, "which", return_value="psql"), \
                patch.object(pg, "psql", side_effect=query), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.preflight()
        artifact = json.loads(Path(self.temp.name, "pp5-postgres-preflight.json").read_text())
        self.assertEqual(artifact["failure_phase"], "name_availability")

    def test_existing_database_refused(self):
        def query(sql, url=""):
            return "160015|t|t|t" if "current_user" in sql else "1"
        with patch.object(pg.shutil, "which", return_value="psql"), \
                patch.object(pg, "psql", side_effect=query), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.preflight()
        artifact = json.loads(Path(self.temp.name, "pp5-postgres-preflight.json").read_text())
        self.assertEqual(artifact["failure_phase"], "name_availability")

    def test_psql_never_exposes_sql_or_url_in_argv(self):
        url = os.environ["O3K_PP5_POSTGRES_ADMIN_URL"]
        sql = "SELECT 'DO_NOT_LOG'"
        observed = {}

        def capture(command, **kwargs):
            observed["passfile"] = Path(kwargs["env"]["PGPASSFILE"]).read_text()
            observed["mode"] = Path(kwargs["env"]["PGPASSFILE"]).stat().st_mode & 0o777
            return subprocess.CompletedProcess(command, 0, "ok", "")

        with patch.object(pg.subprocess, "run", side_effect=capture) as run:
            self.assertEqual(pg.psql(sql, url), "ok")
        args, kwargs = run.call_args
        self.assertNotIn("O3K_PP5_POSTGRES_ADMIN_URL", kwargs["env"])
        self.assertNotIn(url, args[0])
        self.assertNotIn(sql, args[0])
        self.assertEqual(kwargs["input"], sql)
        self.assertEqual(kwargs["env"]["PGDATABASE"], "postgres")
        self.assertEqual(kwargs["env"]["PGHOST"], "127.0.0.1")
        self.assertEqual(kwargs["env"]["PGPORT"], "5432")
        self.assertEqual(kwargs["env"]["PGUSER"], "admin")
        self.assertNotIn("PGPASSWORD", kwargs["env"])
        self.assertIn("PGPASSFILE", kwargs["env"])
        self.assertEqual(observed["passfile"], "127.0.0.1:5432:postgres:admin:DO_NOT_LOG\n")
        self.assertEqual(observed["mode"], 0o600)
        self.assertFalse(Path(kwargs["env"]["PGPASSFILE"]).exists())
        self.assertEqual(kwargs["timeout"], 30)
        self.assertIn("statement_timeout=20000", kwargs["env"]["PGOPTIONS"])
        self.assertIn("lock_timeout=10000", kwargs["env"]["PGOPTIONS"])

    def test_psql_decodes_credentials_and_preserves_tls(self):
        url = "postgresql://a%40b:p%25word@[::1]:5544/run_db?sslmode=verify-full&sslrootcert=%2Ftmp%2Fca.pem"
        with patch.dict(os.environ, {"PGSERVICE": "foreign", "PGPASSWORD": "stale"}), \
                patch.object(pg.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "1", "")) as run:
            pg.psql("SELECT 1", url)
        effective = run.call_args.kwargs["env"]
        self.assertEqual(effective["PGUSER"], "a@b")
        self.assertNotIn("PGPASSWORD", effective)
        self.assertNotIn("PGSERVICE", effective)
        self.assertEqual(effective["PGHOST"], "::1")
        self.assertEqual(effective["PGPORT"], "5544")
        self.assertEqual(effective["PGSSLMODE"], "verify-full")
        self.assertEqual(effective["PGSSLROOTCERT"], "/tmp/ca.pem")
        self.assertIn("lock_timeout=10000", effective["PGOPTIONS"])
        self.assertFalse(Path(effective["PGPASSFILE"]).exists())

    def test_manifest_role_is_exact_run_owned_role(self):
        manifest = {
            "schema": pg.SCHEMA,
            "schema_version": 1,
            "run_id": "preflight_unit",
            "source_sha": "a" * 40,
            "role": "attacker",
            "server": {"host": "127.0.0.1", "port": 5432},
            "databases": {
                purpose: {"name": name}
                for purpose, name in pg.expected_names("preflight_unit").items()
            },
            "all_distinct": True,
        }
        Path(self.temp.name, "pp5-postgres-purpose-map.json").write_text(json.dumps(manifest))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.load_manifest()

    def test_database_owner_must_match_manifest_role(self):
        manifest = {
            "role": pg.expected_role("preflight_unit"),
            "databases": {
                purpose: {"name": name}
                for purpose, name in pg.expected_names("preflight_unit").items()
            },
        }
        with patch.object(pg, "psql", return_value="foreign_role"), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.verify_database_ownership(manifest, os.environ["O3K_PP5_POSTGRES_ADMIN_URL"])

    def test_psql_redacts_failures_and_timeout(self):
        for error in (subprocess.CalledProcessError(2, ["psql"], stderr="DO_NOT_LOG"),
                      subprocess.TimeoutExpired(["psql"], 30, stderr="DO_NOT_LOG"),
                      FileNotFoundError("DO_NOT_LOG")):
            stream = io.StringIO()
            with patch.object(pg.subprocess, "run", side_effect=error), \
                    contextlib.redirect_stderr(stream), self.assertRaises(SystemExit):
                pg.psql("SELECT 1", os.environ["O3K_PP5_POSTGRES_ADMIN_URL"])
            self.assertNotIn("DO_NOT_LOG", stream.getvalue())

    def test_rejected_connection_override_does_not_leave_passfile(self):
        url = "postgresql://admin:DO_NOT_LOG@127.0.0.1:5432/postgres?host=evil.invalid"
        before = set(Path(tempfile.gettempdir()).glob("pp5-pgpass-*"))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.psql("SELECT 1", url)
        self.assertEqual(before, set(Path(tempfile.gettempdir()).glob("pp5-pgpass-*")))


if __name__ == "__main__":
    unittest.main()
