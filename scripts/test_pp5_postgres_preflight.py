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

    def test_psql_escapes_passfile_delimiters_and_filters_sensitive_environment(self):
        url = "postgresql://admin:p%3Ass%5Cword@127.0.0.1:5432/postgres"
        with patch.dict(os.environ, {
            "app_DATABASE_URL": "postgresql://should-not-be-inherited",
            "service_token": "should-not-be-inherited",
            "lower_pgpassword": "should-not-be-inherited",
            "o3k_pp5_postgres_admin_url": "postgresql://should-not-be-inherited",
        }, clear=False), patch.object(
            pg.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0, "ok", ""),
        ) as run:
            pg.psql("SELECT 1", url)
        effective = run.call_args.kwargs["env"]
        self.assertNotIn("app_DATABASE_URL", effective)
        self.assertNotIn("service_token", effective)
        self.assertNotIn("lower_pgpassword", effective)
        self.assertNotIn("o3k_pp5_postgres_admin_url", effective)

    def test_psql_passfile_escaping_is_written_before_subprocess(self):
        url = "postgresql://admin:p%3Ass%5Cword@127.0.0.1:5432/postgres"
        observed = {}

        def capture(command, **kwargs):
            observed["passfile"] = Path(kwargs["env"]["PGPASSFILE"]).read_text()
            return subprocess.CompletedProcess(command, 0, "ok", "")

        with patch.object(pg.subprocess, "run", side_effect=capture):
            pg.psql("SELECT 1", url)
        self.assertEqual(observed["passfile"], "127.0.0.1:5432:postgres:admin:p\\:ss\\\\word\n")

    def test_psql_rejects_newline_in_password(self):
        url = "postgresql://admin:p%0Asecret@127.0.0.1:5432/postgres"
        before = set(Path(tempfile.gettempdir()).glob("pp5-pgpass-*"))
        with patch.object(pg.subprocess, "run") as run, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.psql("SELECT 1", url)
        run.assert_not_called()
        self.assertEqual(before, set(Path(tempfile.gettempdir()).glob("pp5-pgpass-*")))

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

    def test_cleanup_owner_check_allows_missing_partial_database(self):
        manifest = {
            "role": pg.expected_role("preflight_unit"),
            "databases": {
                purpose: {"name": name}
                for purpose, name in pg.expected_names("preflight_unit").items()
            },
        }
        responses = iter(("", manifest["role"], manifest["role"], manifest["role"]))
        with patch.object(pg, "psql", side_effect=lambda *args: next(responses)):
            pg.verify_database_ownership(
                manifest, os.environ["O3K_PP5_POSTGRES_ADMIN_URL"], allow_missing=True
            )

    def test_missing_database_is_still_rejected_during_strict_verify(self):
        manifest = {
            "role": pg.expected_role("preflight_unit"),
            "databases": {
                purpose: {"name": name}
                for purpose, name in pg.expected_names("preflight_unit").items()
            },
        }
        with patch.object(pg, "psql", return_value=""), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.verify_database_ownership(
                manifest, os.environ["O3K_PP5_POSTGRES_ADMIN_URL"]
            )

    def test_verify_after_p13_checks_actual_database_name(self):
        manifest = {
            "run_id": "preflight_unit",
            "source_sha": "a" * 40,
            "provisioning": {"status": "completed"},
            "databases": {
                purpose: {"name": name}
                for purpose, name in pg.expected_names("preflight_unit").items()
            },
        }
        urls = {purpose: f"postgresql://role@127.0.0.1:5432/{name}"
                for purpose, name in pg.expected_names("preflight_unit").items()}
        with patch.object(pg, "load_manifest", return_value=manifest), \
                patch.object(pg, "verify_database_ownership"), \
                patch.object(pg, "urls_from_env", return_value=urls), \
                patch.object(pg, "db_psql", return_value="wrong_database"), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.verify_after_p13()

    def test_unexpected_preflight_exception_is_recorded_and_redacted(self):
        with patch.object(pg.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(pg, "psql", side_effect=RuntimeError("DO_NOT_LOG")), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                pg.preflight()
        artifact = json.loads(Path(self.temp.name, "pp5-postgres-preflight.json").read_text())
        self.assertEqual(artifact["status"], "failed")
        self.assertEqual(artifact["failure_phase"], "admin_connection")
        self.assertNotIn("DO_NOT_LOG", json.dumps(artifact))

    def test_psql_redacts_failures_and_timeout(self):
        for error in (subprocess.CalledProcessError(2, ["psql"], stderr="DO_NOT_LOG"),
                      subprocess.TimeoutExpired(["psql"], 30, stderr="DO_NOT_LOG"),
                      FileNotFoundError("DO_NOT_LOG"),
                      ValueError("DO_NOT_LOG")):
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



class CampaignBindingTests(unittest.TestCase):
    """Exercise the actual generic workflow shell and campaign binding wrapper."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = Path(__file__).resolve().parents[1]
        self.run = "123456"
        self.sha = "a" * 40
        self.role = pg.expected_role(self.run)
        self.urls = {purpose: pg.build_url("", self.role, "DO_NOT_LOG", name)
                     for purpose, name in pg.expected_names(self.run).items()}
        self.canonical = self.root / "canonical.env"
        self.values = {
            "O3K_PP5_RUN_ID": self.run, "O3K_PP5_SOURCE_SHA": self.sha,
            "O3K_PP5_POSTGRES_TARGET": "127.0.0.1:5432",
            "O3K_PP5_POSTGRES_ROLE": self.role,
            **{pg.ENV_NAMES[p]: url for p, url in self.urls.items()},
        }
        self.write_env()
        self.manifest = {
            "schema": pg.SCHEMA, "schema_version": 1,
            "run_id": self.run, "source_sha": self.sha, "role": self.role,
            "server": {"host": "127.0.0.1", "port": 5432},
            "databases": {p: {"name": name} for p, name in pg.expected_names(self.run).items()},
            "all_distinct": True, "provisioning": {"status": "completed"},
        }
        self.write_manifest()
        self.github_env = self.root / "github.env"
        self.environment = {**os.environ, **self.values,
                            "GITHUB_RUN_ID": self.run, "TARGET_SHA": self.sha,
                            "GITHUB_ENV": str(self.github_env),
                            "O3K_PP5_ENV_FILE": str(self.canonical),
                            "O3K_PP5_ARTIFACT_DIR": str(self.root),
                            "O3K_PP5_POSTGRES_ADMIN_URL": "",
                            "PATH": str(self.root) + os.pathsep + os.environ["PATH"]}
        # Only the PostgreSQL transport is substituted. The real wrapper,
        # canonical-file validation, URL checks and sentinel comparison run.
        client = self.root / "psql"
        client.write_text("#!/usr/bin/env python3\nimport os,sys\n"
                          "assert os.environ['PGDATABASE'] == 'o3k_pp5_s5_123456'\n"
                          "assert os.environ['PGUSER'] == 'o3k_pp5_123456'\n"
                          "assert not os.environ.get('O3K_PP5_WORKSPACE_DATABASE_URL')\n"
                          "sql = sys.stdin.read()\n"
                          "assert sql.startswith('SELECT purpose,run_id,source_sha')\n"
                          "print(os.environ.get('TEST_SENTINEL', 'campaign|123456|' + 'a'*40))\n")
        client.chmod(0o700)

    def write_env(self):
        self.canonical.write_text("".join(f"{k}={v}\n" for k, v in self.values.items()))
        self.canonical.chmod(0o600)

    def write_manifest(self):
        (self.root / "pp5-postgres-purpose-map.json").write_text(json.dumps(self.manifest))

    def bind(self, success=True):
        result = subprocess.run(["bash", "-x", "scripts/pp5-bind-campaign-postgres.sh"],
                                cwd=self.repo, env=self.environment, text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        # Mask commands are the runner's secret-registration protocol, not log
        # evidence. Nothing else may disclose credentials, even under bash -x.
        log = "\n".join(line for line in result.stdout.splitlines()
                        if not line.startswith("::add-mask::")) + result.stderr
        self.assertNotIn("DO_NOT_LOG", log)
        self.assertNotIn("postgresql://", log)
        artifact = json.loads((self.root / "pp5-campaign-binding.json").read_text())
        self.assertNotIn("DO_NOT_LOG", json.dumps(artifact))
        self.assertNotIn("postgresql://", json.dumps(artifact))
        self.assertEqual(artifact["status"], "passed" if success else "failed")
        if not success:
            self.assertEqual(artifact["classification"], "HARNESS_GAP")
            self.assertFalse(self.github_env.exists())
        return result, artifact

    def test_binding_consumes_actual_provisioner_output(self):
        with patch.dict(os.environ, {**self.environment, "O3K_PP5_PERSIST_ENV": "0"}, clear=True), \
                patch.object(pg, "preflight"), patch.object(pg, "psql", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()):
            pg.provision()
        self.environment[pg.ENV_NAMES["campaign"]] = ""
        before = self.canonical.read_bytes()
        self.bind()
        self.assertEqual(self.canonical.read_bytes(), before)
        canonical = dict(line.split("=", 1) for line in before.decode().splitlines())
        bound = dict(line.split("=", 1) for line in self.github_env.read_text().splitlines())
        self.assertEqual(bound["O3K_DATABASE_URL"], canonical[pg.ENV_NAMES["campaign"]])

    def test_generic_blanking_then_canonical_restore(self):
        workflow = (self.repo / ".github/workflows/real-host-validation.yml").read_text()
        block = workflow.split("- name: Bind generic phase to workspace PostgreSQL", 1)[1].split("\n      - name:", 1)[0]
        body = block.split("        run: |\n", 1)[1]
        shell = "\n".join(line[10:] for line in body.splitlines())
        original = self.canonical.read_bytes()
        subprocess.run(["bash", "-c", shell], cwd=self.repo, env=self.environment, check=True)
        generic = dict(line.split("=", 1) for line in self.github_env.read_text().splitlines())
        self.assertEqual(generic["O3K_PP5_CAMPAIGN_DATABASE_URL"], "")
        self.assertEqual(self.canonical.read_bytes(), original)
        self.environment.update(generic)
        self.github_env.unlink()
        result, artifact = self.bind()
        bound = dict(line.split("=", 1) for line in self.github_env.read_text().splitlines())
        self.assertEqual(bound, {
            "O3K_DATABASE_BACKEND": "postgres", "O3K_DATABASE_URL": self.urls["campaign"],
            "O3K_PP5_CAMPAIGN_DATABASE_URL": self.urls["campaign"],
            "O3K_P15_7_POSTGRES_MODE": "external", "O3K_P15_7_EXTERNAL_PG_TARGET": "127.0.0.1:5432",
            **{pg.ENV_NAMES[p]: "" for p in ("workspace", "endpoint", "p13")},
        })
        self.assertEqual(result.stdout.splitlines()[0], "::add-mask::" + self.urls["campaign"])
        self.assertEqual(self.canonical.read_bytes(), original)
        self.assertEqual(artifact["campaign_sentinel"], "passed")

    def test_restored_binding_survives_daemon_environment_serialization(self):
        self.bind()
        bound = dict(line.split("=", 1) for line in self.github_env.read_text().splitlines())
        # Execute the existing bootstrap writer and its daemon shell consumption,
        # without requiring privileged TestLab/VM setup in ordinary CI.
        bootstrap = (self.repo / "scripts/bootstrap-disposable-testlab.sh").read_text()
        start = bootstrap.index('if [[ -n "${O3K_DATABASE_BACKEND:-}" ]]')
        end = bootstrap.index("\nfi", bootstrap.index('if [[ -n "${O3K_DATABASE_URL:-}" ]]', start)) + 3
        daemon_env = self.root / "o3kd.env"
        command = bootstrap[start:end] + '\nset -a; source "$o3kd_env_tmp"; set +a\n'
        command += "python3 -c 'import os; assert os.environ[\"O3K_DATABASE_BACKEND\"] == \"postgres\"; assert os.environ[\"O3K_DATABASE_URL\"] == os.environ[\"O3K_PP5_CAMPAIGN_DATABASE_URL\"]'"
        result = subprocess.run(["bash", "-euo", "pipefail", "-c", command],
                                env={**self.environment, **bound, "o3kd_env_tmp": str(daemon_env)},
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("DO_NOT_LOG", result.stdout + result.stderr)

    def test_removed_generic_virtualenv_is_not_required(self):
        missing = str(self.root / "removed-generic-venv")
        self.environment.update(O3K_OPENSTACK_VENV=missing,
                                PATH=missing + "/bin:" + self.environment["PATH"],
                                OS_CLIENT_CONFIG_FILE=str(self.root / "removed-clouds.yaml"))
        self.bind()

    def test_completed_cleanup_is_rejected(self):
        self.manifest["cleanup"] = {"status": "completed"}
        self.write_manifest()
        self.bind(False)

    def test_manifest_failures(self):
        cases = [("run_id", "other"), ("source_sha", "b" * 40),
                 ("provisioning", {"status": "started"}), ("role", "foreign"),
                 ("server", {"host": "127.0.0.1", "port": 5544}),
                 ("databases", {p: {"name": "wrong"} for p in pg.PURPOSES})]
        for key, value in cases:
            with self.subTest(key=key):
                old = self.manifest[key]
                self.manifest[key] = value
                self.write_manifest()
                self.bind(False)
                self.manifest[key] = old
        (self.root / "pp5-postgres-purpose-map.json").unlink()
        self.bind(False)

    def test_canonical_identity_and_url_failures(self):
        cases = [("O3K_PP5_RUN_ID", "other"), ("O3K_PP5_SOURCE_SHA", "b" * 40),
                 ("O3K_PP5_POSTGRES_TARGET", "127.0.0.1:9999"),
                 ("O3K_PP5_POSTGRES_ROLE", "foreign"),
                 (pg.ENV_NAMES["campaign"], self.urls["workspace"]),
                 (pg.ENV_NAMES["campaign"], self.urls["campaign"].replace(":5432", ":5544")),
                 (pg.ENV_NAMES["campaign"], self.urls["campaign"].replace(":5432", ":0")),
                 (pg.ENV_NAMES["campaign"], self.urls["campaign"].replace(self.role + ":", "foreign:")),
                 (pg.ENV_NAMES["campaign"], self.urls["campaign"] + "?host=foreign"),
                 (pg.ENV_NAMES["campaign"], "postgresql://[DO_NOT_LOG"),
                 (pg.ENV_NAMES["campaign"], "")]
        for key, value in cases:
            with self.subTest(key=key, case=cases.index((key, value))):
                old = self.values[key]
                self.values[key] = value
                self.write_env()
                self.bind(False)
                self.values[key] = old

    def test_workflow_identity_cannot_be_overridden(self):
        for key in ("GITHUB_RUN_ID", "TARGET_SHA"):
            with self.subTest(key=key):
                old = self.environment[key]
                self.environment[key] = "b" * 40
                self.bind(False)
                self.environment[key] = old

    def test_postgres_client_failure_is_redacted(self):
        (self.root / "psql").write_text("#!/bin/sh\nprintf 'DO_NOT_LOG postgresql://secret' >&2\nexit 2\n")
        self.bind(False)

    def test_sentinel_mismatch(self):
        for value in ("workspace|123456|" + self.sha, "campaign|wrong|" + self.sha,
                      "campaign|123456|" + "b" * 40, ""):
            self.environment["TEST_SENTINEL"] = value
            self.bind(False)

    def test_file_missing_symlink_mode_and_malformed(self):
        self.canonical.unlink()
        self.bind(False)
        self.write_env()
        other = self.root / "other.env"
        self.canonical.rename(other)
        self.canonical.symlink_to(other)
        self.bind(False)
        self.canonical.unlink()
        other.rename(self.canonical)
        self.canonical.chmod(0o644)
        self.bind(False)
        self.canonical.chmod(0o600)
        for malformed in ("broken DO_NOT_LOG\n", "O3K_PP5_RUN_ID=123456\n" * 2,
                          "EVIL=$(touch should-not-exist)\n", "\x00DO_NOT_LOG"):
            self.write_env()
            with self.canonical.open("a") as handle:
                handle.write(malformed)
            self.bind(False)

    def test_shell_metacharacters_are_literal_and_masked(self):
        # A valid percent-encoded password and multiple TLS options must survive
        # sourcing as literal data, without shell command/query interpretation.
        self.values[pg.ENV_NAMES["campaign"]] = pg.build_url(
            "postgresql://127.0.0.1:5432/postgres?sslmode=require&sslrootcert=%2Ftmp%2Fca.pem",
            self.role, "DO_NOT_LOG%$(false)", pg.expected_names(self.run)["campaign"])
        self.write_env()
        result, _ = self.bind()
        url = self.values[pg.ENV_NAMES["campaign"]]
        self.assertEqual(result.stdout.splitlines()[0], "::add-mask::" + url.replace("%", "%25"))
        bound = dict(line.split("=", 1) for line in self.github_env.read_text().splitlines())
        self.assertEqual(bound["O3K_DATABASE_URL"], url)

    def test_non_regular_file(self):
        self.canonical.unlink()
        os.mkfifo(self.canonical, 0o600)
        self.bind(False)

    def test_invalid_manifest_is_redacted(self):
        (self.root / "pp5-postgres-purpose-map.json").write_text("DO_NOT_LOG")
        self.bind(False)

    def test_wrong_owner(self):
        with patch.dict(os.environ, self.environment, clear=True), \
                patch.object(pg.os, "getuid", return_value=os.getuid() + 1), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            pg.campaign_env()


if __name__ == "__main__":
    unittest.main()
