#!/usr/bin/env python3
"""Behavioral regressions for PP.5 TestLab epoch ownership gates."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pp5_epoch_guard", ROOT / "scripts" / "pp5-testlab-epoch-guard.py"
)
assert SPEC is not None and SPEC.loader is not None
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class TestLabEpochGuardTests(unittest.TestCase):
    def test_generic_active_server_can_be_cleaned_before_lane_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            baseline = root / "generic-before.json"
            after = root / "generic-after.json"
            artifact = root / "cleanup.json"
            runner_temp = root / "runner"
            runner_temp.mkdir()
            state_root = root / "state-generic"
            baseline.write_text(json.dumps({
                "status": "available",
                "domains": ["o3k-server-generic"],
                "openstack": {"resources": {"servers": [{"status": "ACTIVE"}]}},
                "foreign_state": {"domains_sha256": "a", "network_links_sha256": "b", "pools_count": 2},
            }), encoding="utf-8")
            after.write_text(json.dumps({
                "status": "available", "domains": [], "openstack": {"resources": {"servers": []}},
                "foreign_state": {"domains_sha256": "a", "network_links_sha256": "b", "pools_count": 2},
            }), encoding="utf-8")
            workloads = root / "generic-workloads.json"
            workloads.write_text(json.dumps({
                "status": "passed", "run_owned_servers": 0,
                "run_owned_ports": 0, "run_owned_domains": 0,
            }), encoding="utf-8")
            args = Namespace(run_id="42", runner_temp=str(runner_temp), state_root=str(state_root),
                             baseline=baseline, after=after, workloads=workloads, artifact=artifact)

            self.assertEqual(GUARD.generic_cleanup(args), 0)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["generic_owned_roots_absent"])
            self.assertTrue(result["generic_workload_absence_proven"])
            self.assertTrue(result["foreign_state_unchanged"])

    def test_generic_active_server_must_be_absent_before_teardown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            artifact = root / "workloads.json"
            completed = [
                SimpleNamespace(stdout='[{"ID":"active-server","Status":"ACTIVE"}]'),
                SimpleNamespace(stdout="[]"),
                SimpleNamespace(stdout="o3k-active-server\n"),
            ]
            args = Namespace(run_id="42", artifact=artifact)
            with patch.object(GUARD.subprocess, "run", side_effect=completed):
                self.assertEqual(GUARD.generic_workloads(args), 1)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertEqual(result["run_owned_servers"], 1)
            self.assertNotIn("active-server", artifact.read_text(encoding="utf-8"))

    def test_generic_cleanup_rejects_foreign_state_change_as_harness_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            baseline = root / "before.json"
            after = root / "after.json"
            artifact = root / "failure.json"
            workloads = root / "workloads.json"
            runner_temp = root / "runner"
            runner_temp.mkdir()
            workloads.write_text(json.dumps({
                "status": "passed", "run_owned_servers": 0,
                "run_owned_ports": 0, "run_owned_domains": 0,
            }), encoding="utf-8")
            for path, digest in ((baseline, "before"), (after, "after")):
                path.write_text(json.dumps({
                    "status": "available",
                    "foreign_state": {"domains_sha256": digest, "network_links_sha256": "b", "pools_count": 0},
                }), encoding="utf-8")
            args = Namespace(run_id="42", runner_temp=str(runner_temp), state_root=str(root / "absent"),
                             baseline=baseline, after=after, workloads=workloads, artifact=artifact)

            self.assertEqual(GUARD.generic_cleanup(args), 1)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")

    def test_lane_cannot_start_with_existing_server(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state_root = root / "state"
            state_root.mkdir()
            (state_root / ".o3k-run-owned").write_text(
                "o3k-disposable-testlab-v1\nrun=42-pp5\n", encoding="utf-8"
            )
            artifact = root / "preconditions.json"
            args = Namespace(run_id="42", testlab_run_id="42-pp5", state_root=str(state_root), artifact=artifact)
            completed = [
                SimpleNamespace(stdout='[{"ID":"owned-server"}]'),
                SimpleNamespace(stdout="[]"),
                SimpleNamespace(stdout=""),
            ]
            with patch.object(GUARD.subprocess, "run", side_effect=completed):
                self.assertEqual(GUARD.lane_preconditions(args), 1)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertEqual(result["run_owned_servers"], 1)
            self.assertNotIn("o3k_domain_candidates", result)

    def test_lane_precondition_failure_names_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state_root = root / "state"
            state_root.mkdir()
            (state_root / ".o3k-run-owned").write_text(
                "o3k-disposable-testlab-v1\nrun=42-pp5\n", encoding="utf-8"
            )
            artifact = root / "preconditions.json"
            completed = [
                SimpleNamespace(stdout="[]"),
                SimpleNamespace(stdout="[]"),
                SimpleNamespace(stdout="o3k-foreign-sensitive-id\n"),
            ]
            args = Namespace(run_id="42", testlab_run_id="42-pp5", state_root=str(state_root), artifact=artifact)
            with patch.object(GUARD.subprocess, "run", side_effect=completed):
                self.assertEqual(GUARD.lane_preconditions(args), 1)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertEqual(result["run_owned_domains"], 1)
            self.assertNotIn("o3k-foreign-sensitive-id", artifact.read_text(encoding="utf-8"))

    def test_empty_lane_workload_inventory_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state_root = root / "state"
            state_root.mkdir()
            (state_root / ".o3k-run-owned").write_text(
                "o3k-disposable-testlab-v1\nrun=42-pp5\n", encoding="utf-8"
            )
            artifact = root / "preconditions.json"
            args = Namespace(run_id="42", testlab_run_id="42-pp5", state_root=str(state_root), artifact=artifact)
            completed = [
                SimpleNamespace(stdout="[]"),
                SimpleNamespace(stdout="[]"),
                SimpleNamespace(stdout=""),
            ]
            with patch.object(GUARD.subprocess, "run", side_effect=completed):
                self.assertEqual(GUARD.lane_preconditions(args), 0)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["run_owned_servers"], 0)
            self.assertEqual(result["run_owned_ports"], 0)
            self.assertEqual(result["run_owned_domains"], 0)


if __name__ == "__main__":
    unittest.main()
