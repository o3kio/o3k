#!/usr/bin/env python3
"""Regression tests for scripts/okf-memory.py using temporary Git repositories."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "okf-memory.py"


def run(command: list[str], cwd: Path, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


class OkfMemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = Path(tempfile.mkdtemp(prefix="o3k-okf-memory-test-"))
        run(["git", "init", "-q"], self.tempdir)
        run(["git", "config", "user.name", "OKF Test"], self.tempdir)
        run(["git", "config", "user.email", "okf-test@example.invalid"], self.tempdir)
        (self.tempdir / "app.txt").write_text("alpha\n", encoding="utf-8")
        run(["git", "add", "app.txt"], self.tempdir)
        run(["git", "commit", "-qm", "initial"], self.tempdir)
        run(
            ["git", "remote", "add", "origin", "https://github.com/kubedoio/o3k-rust.git"],
            self.tempdir,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tempdir)

    def helper(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return run([sys.executable, str(SCRIPT), *args], self.tempdir, check=check)

    def commit_okf(self, message: str) -> None:
        run(["git", "add", ".okf"], self.tempdir)
        run(["git", "commit", "-qm", message], self.tempdir)

    def test_capture_checkpoint_projection_and_command_redaction(self) -> None:
        self.helper("init")
        self.commit_okf("initialize okf")
        self.helper("start", "--workstream", "issue-42")

        with (self.tempdir / "app.txt").open("a", encoding="utf-8") as handle:
            handle.write("beta\n")
        run(["git", "add", "app.txt"], self.tempdir)
        run(["git", "commit", "-qm", "feat: beta"], self.tempdir)
        self.helper(
            "exec",
            "--",
            sys.executable,
            "-c",
            "import sys; sys.exit(0)",
            "API_TOKEN=supersecret",
        )
        self.helper("checkpoint")

        with (self.tempdir / "app.txt").open("a", encoding="utf-8") as handle:
            handle.write("gamma\n")
        self.helper("exec", "--", sys.executable, "-c", "import sys; sys.exit(0)")
        self.helper("end")
        self.helper("check")

        runs = sorted(
            (self.tempdir / ".okf" / "workstreams" / "issue-42" / "runs").glob("**/*.md")
        )
        self.assertEqual(len(runs), 2)
        combined = "\n".join(path.read_text(encoding="utf-8") for path in runs)
        self.assertNotIn("supersecret", combined)
        self.assertIn("API_TOKEN=***REDACTED***", combined)
        self.assertIn("**PASS**", combined)

        projection = self.tempdir / ".okf" / "current" / "workstreams" / "issue-42.md"
        before = hashlib.sha256(projection.read_bytes()).hexdigest()
        self.helper("refresh")
        after = hashlib.sha256(projection.read_bytes()).hexdigest()
        self.assertEqual(before, after, "refresh must be deterministic")

    def test_append_only_guard_rejects_run_mutation(self) -> None:
        self.helper("init")
        self.commit_okf("initialize okf")
        self.helper("start", "--workstream", "issue-7")
        with (self.tempdir / "app.txt").open("a", encoding="utf-8") as handle:
            handle.write("delta\n")
        self.helper("end")
        self.commit_okf("record run")
        base = run(["git", "rev-parse", "HEAD"], self.tempdir).stdout.strip()
        self.helper("check", "--base", base)

        run_record = next(
            (self.tempdir / ".okf" / "workstreams" / "issue-7" / "runs").glob("**/*.md")
        )
        with run_record.open("a", encoding="utf-8") as handle:
            handle.write("tamper\n")
        result = self.helper("check", "--base", base, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("append-only run record modified", result.stderr)

    def test_default_branch_requires_explicit_workstream_when_no_pr_is_detectable(self) -> None:
        self.helper("init")
        result = self.helper("start", check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("pass --workstream issue-<number>", result.stderr)


if __name__ == "__main__":
    unittest.main()
