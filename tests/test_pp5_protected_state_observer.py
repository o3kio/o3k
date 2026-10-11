from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pp5_protected_state_observer_test", ROOT / "scripts" / "pp5-protected-state-observer.py")
assert SPEC is not None and SPEC.loader is not None
OBSERVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = OBSERVER
SPEC.loader.exec_module(OBSERVER)


class ProtectedStateObserverTests(unittest.TestCase):
    run_id = "12345-pp5"
    sha = "a" * 40
    root = pathlib.Path("/var/lib/o3k-testlab/12345-pp5")

    def setUp(self) -> None:
        self.run_calls: list[list[str]] = []

    def successful_run(self, command: list[str], *_args, **_kwargs):
        self.run_calls.append(command)
        if "stat" in command:
            return subprocess.CompletedProcess(command, 0, "0|600|regular file|80\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    def test_root_owned_0600_marker_uses_bounded_privileged_cat_only(self) -> None:
        marker = self.root / ".o3k-run-owned"
        with patch.object(OBSERVER, "_validate_root", return_value=self.root), \
                patch.object(OBSERVER, "_run", side_effect=self.successful_run), \
                patch.object(OBSERVER, "_bounded_cat", return_value=(
                    f"o3k-disposable-testlab-v1\ncommit={self.sha}\nrun={self.run_id}\n")) as cat, \
                patch.object(pathlib.Path, "read_text", side_effect=AssertionError("direct read used")):
            result = OBSERVER.verify_marker(self.root, self.run_id, self.sha)

        self.assertEqual(result["owner_uid"], 0)
        self.assertEqual(result["mode"], "0600")
        cat.assert_called_once_with(marker, "read_testlab_ownership_marker",
                                    "testlab_ownership_marker", OBSERVER.MAX_MARKER_BYTES)
        self.assertEqual(self.run_calls[0][2:4], ["test", "!"])

    def test_marker_symlink_is_rejected_before_read(self) -> None:
        with patch.object(OBSERVER, "_validate_root", return_value=self.root), \
                patch.object(OBSERVER, "_run", side_effect=OBSERVER.ObservationError(
                    "reject_testlab_ownership_marker_symlink", "sudo_read_only",
                    "testlab_ownership_marker", "SubprocessError", "sudo", 1)), \
                patch.object(OBSERVER, "_bounded_cat") as cat:
            with self.assertRaises(OBSERVER.ObservationError) as raised:
                OBSERVER.verify_marker(self.root, self.run_id, self.sha)
        self.assertEqual(raised.exception.operation, "reject_testlab_ownership_marker_symlink")
        cat.assert_not_called()

    def test_wrong_owner_and_mode_are_rejected(self) -> None:
        for metadata in ("1000|600|regular file|80", "0|644|regular file|80"):
            with self.subTest(metadata=metadata), \
                    patch.object(OBSERVER, "_validate_root", return_value=self.root), \
                    patch.object(OBSERVER, "_run", side_effect=[
                        subprocess.CompletedProcess([], 0, "", ""),
                        subprocess.CompletedProcess([], 0, "", ""),
                        subprocess.CompletedProcess([], 0, metadata, ""),
                    ]), patch.object(OBSERVER, "_bounded_cat") as cat:
                with self.assertRaises(OBSERVER.ObservationError) as raised:
                    OBSERVER.verify_marker(self.root, self.run_id, self.sha)
                self.assertEqual(raised.exception.operation, "validate_testlab_ownership_marker_metadata")
                cat.assert_not_called()

    def test_wrong_run_id_and_source_sha_fail_closed(self) -> None:
        for run_id, sha in (("54321-pp5", self.sha), (self.run_id, "b" * 40)):
            with self.subTest(run_id=run_id, sha=sha), \
                    patch.object(OBSERVER, "_validate_root", return_value=self.root), \
                    patch.object(OBSERVER, "_run", side_effect=self.successful_run), \
                    patch.object(OBSERVER, "_bounded_cat", return_value=(
                        f"o3k-disposable-testlab-v1\ncommit={self.sha}\nrun={self.run_id}\n")):
                with self.assertRaises(OBSERVER.ObservationError) as raised:
                    OBSERVER.verify_marker(self.root, run_id, sha)
                self.assertEqual(raised.exception.operation,
                                 "validate_testlab_ownership_marker_contents")

    def test_sudo_unavailable_reports_exact_privileged_operation(self) -> None:
        with patch.object(OBSERVER, "_validate_root", return_value=self.root), \
                patch.object(OBSERVER, "_run", side_effect=OBSERVER.ObservationError(
                    "reject_testlab_ownership_marker_symlink", "sudo_read_only",
                    "testlab_ownership_marker", "FileNotFoundError", "sudo", None)):
            with self.assertRaises(OBSERVER.ObservationError) as raised:
                OBSERVER.verify_marker(self.root, self.run_id, self.sha)
        self.assertEqual(raised.exception.operation, "reject_testlab_ownership_marker_symlink")
        self.assertEqual(raised.exception.observer_type, "sudo_read_only")
        self.assertEqual(raised.exception.command_class, "sudo")

    def test_wrong_expected_root_fails_before_sudo(self) -> None:
        with patch.object(OBSERVER, "_run") as run:
            with self.assertRaises(OBSERVER.ObservationError) as raised:
                OBSERVER._validate_root(pathlib.Path("/tmp/not-the-run-root"), self.run_id)
        self.assertEqual(raised.exception.operation, "validate_testlab_state_root")
        run.assert_not_called()

    def test_noncanonical_path_to_expected_root_fails_before_sudo(self) -> None:
        alternate = pathlib.Path("/var/lib/o3k-testlab/other/../12345-pp5")
        with patch.object(OBSERVER, "_run") as run:
            with self.assertRaises(OBSERVER.ObservationError) as raised:
                OBSERVER._validate_root(alternate, self.run_id)
        self.assertEqual(raised.exception.operation, "validate_testlab_state_root")
        run.assert_not_called()

    def test_state_root_symlink_is_rejected_by_privileged_observer(self) -> None:
        calls: list[list[str]] = []

        def reject_symlink(command: list[str], operation: str, *_args, **_kwargs):
            calls.append(command)
            if operation == "reject_testlab_state_root_symlink":
                raise OBSERVER.ObservationError(operation, "sudo_read_only", "testlab_state_root",
                                                "SubprocessError", "sudo", 1)
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(OBSERVER, "_run", side_effect=reject_symlink):
            with self.assertRaises(OBSERVER.ObservationError) as raised:
                OBSERVER._validate_root(self.root, self.run_id)
        self.assertEqual(raised.exception.operation, "reject_testlab_state_root_symlink")
        self.assertEqual(calls, [
            ["sudo", "-n", "test", "-d", str(self.root)],
            ["sudo", "-n", "test", "!", "-L", str(self.root)],
        ])

    def test_bounded_cat_uses_exact_sudo_command_and_enforces_limit(self) -> None:
        command = ["sudo", "-n", "cat", "--", str(self.root / ".o3k-run-owned")]

        class FakeProcess:
            def __init__(self, argv, **_kwargs):
                self.argv = argv
                read_fd, write_fd = os.pipe()
                os.write(write_fd, b"safe")
                os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb")
                self.returncode = 0
                self.killed = False

            def wait(self, timeout=None):
                return self.returncode

            def kill(self):
                self.killed = True
                self.returncode = -9

        with patch.object(OBSERVER.subprocess, "Popen", side_effect=FakeProcess) as popen:
            value = OBSERVER._bounded_cat(self.root / ".o3k-run-owned", "read_testlab_ownership_marker",
                                          "testlab_ownership_marker", 8)
        self.assertEqual(value, "safe")
        self.assertEqual(popen.call_args.args[0], command)

    def test_bounded_cat_rejects_oversized_output(self) -> None:
        class FakeProcess:
            def __init__(self, _argv, **_kwargs):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, b"too long")
                os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb")
                self.returncode = 0
                self.killed = False

            def wait(self, timeout=None):
                return self.returncode

            def kill(self):
                self.killed = True
                self.returncode = -9

        with patch.object(OBSERVER.subprocess, "Popen", side_effect=FakeProcess):
            with self.assertRaises(OBSERVER.ObservationError) as raised:
                OBSERVER._bounded_cat(self.root / ".o3k-run-owned", "read_testlab_ownership_marker",
                                      "testlab_ownership_marker", 4)
        self.assertEqual(raised.exception.diagnostic, "ValueError")
        self.assertEqual(raised.exception.command_class, "sudo")

    def test_stale_marker_source_sha_uses_same_privileged_observer(self) -> None:
        marker = self.root / ".o3k-run-owned"
        with patch.object(OBSERVER, "_validate_root", return_value=self.root), \
                patch.object(OBSERVER, "_run", side_effect=self.successful_run), \
                patch.object(OBSERVER, "_bounded_cat", return_value=(
                    f"o3k-disposable-testlab-v1\ncommit={self.sha}\nrun={self.run_id}\n")), \
                patch.object(pathlib.Path, "read_text", side_effect=AssertionError("direct read used")):
            value = OBSERVER.read_marker_source_sha(self.root, self.run_id)
        self.assertEqual(value, self.sha)

    def test_stale_marker_wrong_run_id_fails_closed(self) -> None:
        with patch.object(OBSERVER, "_validate_root", return_value=self.root), \
                patch.object(OBSERVER, "_run", side_effect=self.successful_run), \
                patch.object(OBSERVER, "_bounded_cat", return_value=(
                    f"o3k-disposable-testlab-v1\ncommit={self.sha}\nrun=wrong\n")):
            with self.assertRaises(OBSERVER.ObservationError) as raised:
                OBSERVER.read_marker_source_sha(self.root, self.run_id)
        self.assertEqual(raised.exception.operation, "validate_testlab_ownership_marker_contents")


if __name__ == "__main__":
    unittest.main()
