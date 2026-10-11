#!/usr/bin/env python3
"""Behavioral regressions for PP.5 TestLab cleanup phase proofs."""

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


def lifecycle_evidence() -> dict[str, object]:
    resources = {
        "image_id": "image-owned",
        "keypair_id": "keypair-owned",
        "network_id": "network-owned",
        "subnet_id": "subnet-owned",
        "port_id": "port-owned",
        "flavor_id": "flavor-owned",
        "server_id": "server-owned",
    }
    return {
        "status": "passed",
        "workflow_run_id": "42",
        "testlab_phase_id": "42-generic",
        "cleanup": {
            "status": "passed",
            "resources": {name: "verified_absent" for name in GUARD.LIFECYCLE_RESOURCES},
        },
        "resources": resources,
    }


def host_snapshot(*, foreign_domains: str = "d", foreign_links: str = "l", foreign_pools: str = "p", pools: int = 2):
    return {
        "status": "available",
        "domains": [],
        "network_links": [],
        "pools": [],
        "openstack": {"status": "not_checked", "resources": {}},
        "foreign_state": {
            "domains_sha256": foreign_domains,
            "network_links_sha256": foreign_links,
            "protected_paths_sha256": "paths",
            "pools_count": pools,
            "pools_sha256": foreign_pools,
        },
    }


class TestLabEpochGuardTests(unittest.TestCase):
    def write_lifecycle(self, root: pathlib.Path) -> pathlib.Path:
        lifecycle = root / "openstack-cli-result.json"
        lifecycle.write_text(json.dumps(lifecycle_evidence()), encoding="utf-8")
        return lifecycle

    def api_args(self, root: pathlib.Path) -> Namespace:
        return Namespace(
            run_id="42",
            lifecycle=self.write_lifecycle(root),
            artifact=root / "pre-teardown.json",
        )

    def absent_api_responses(self):
        return [
            SimpleNamespace(returncode=1, stderr="ResourceNotFound: not found", stdout="")
            for _ in GUARD.LIFECYCLE_RESOURCES
        ] + [SimpleNamespace(stdout="", stderr="", returncode=0)]

    def test_run_owned_ids_are_checked_without_all_projects_queries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = self.api_args(root)
            calls = []

            def run(command, **_kwargs):
                calls.append(command)
                if command[0] == "openstack":
                    return SimpleNamespace(returncode=1, stderr="ResourceNotFound: not found", stdout="")
                return SimpleNamespace(returncode=0, stderr="", stdout="o3k-foreign-server\n")

            with patch.object(GUARD.subprocess, "run", side_effect=run):
                self.assertEqual(GUARD.run_owned_api_absence(args), 0)
            self.assertTrue(all("--all-projects" not in command for command in calls))
            port_calls = [command for command in calls if command[:2] == ["openstack", "port"]]
            self.assertEqual(port_calls, [["openstack", "port", "show", "port-owned", "-f", "json"]])
            self.assertNotIn("foreign-project-port", str(calls))
            result = json.loads(args.artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["run_owned_servers"], 0)
            self.assertEqual(result["run_owned_ports"], 0)
            self.assertEqual(result["run_owned_domains"], 0)
            self.assertEqual(result["servers_checked"], 1)
            self.assertEqual(result["ports_checked"], 1)
            self.assertTrue(result["exact_run_owned_ids_checked"])

    def test_run_owned_server_remaining_is_harness_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = self.api_args(root)
            responses = self.absent_api_responses()
            responses[0] = SimpleNamespace(returncode=0, stderr="", stdout="{}")
            with patch.object(GUARD.subprocess, "run", side_effect=responses):
                self.assertEqual(GUARD.run_owned_api_absence(args), 1)
            result = json.loads(args.artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertEqual(result["failed_operation"], "show_run_owned_server")
            self.assertEqual(result["observer_type"], "api_observation")
            self.assertEqual(result["resource_class"], "openstack_server")
            self.assertEqual(result["command_class"], "openstack")
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["run_owned_servers"], 1)
            self.assertNotIn("server-owned", args.artifact.read_text(encoding="utf-8"))

    def test_run_owned_port_remaining_is_harness_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = self.api_args(root)
            responses = self.absent_api_responses()
            responses[1] = SimpleNamespace(returncode=0, stderr="", stdout="{}")
            with patch.object(GUARD.subprocess, "run", side_effect=responses):
                self.assertEqual(GUARD.run_owned_api_absence(args), 1)
            result = json.loads(args.artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertEqual(result["failed_operation"], "show_run_owned_port")
            self.assertEqual(result["observer_type"], "api_observation")
            self.assertEqual(result["resource_class"], "openstack_port")
            self.assertEqual(result["run_owned_servers"], 0)
            self.assertEqual(result["run_owned_ports"], 1)

    def test_api_unavailable_is_not_treated_as_absence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = self.api_args(root)
            responses = self.absent_api_responses()
            responses[1] = SimpleNamespace(returncode=2, stderr="unsupported option", stdout="")
            with patch.object(GUARD.subprocess, "run", side_effect=responses):
                self.assertEqual(GUARD.run_owned_api_absence(args), 1)
            result = json.loads(args.artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertEqual(result["failed_operation"], "show_run_owned_port")
            self.assertEqual(result["command_class"], "openstack")
            self.assertEqual(result["exit_code"], 2)

    def test_supported_openstack_no_resource_response_proves_absence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = self.api_args(root)
            responses = [
                SimpleNamespace(returncode=1, stderr=f"No {resource} with a name or ID exists", stdout="")
                for resource in GUARD.LIFECYCLE_RESOURCES
            ] + [SimpleNamespace(stdout="", stderr="", returncode=0)]
            with patch.object(GUARD.subprocess, "run", side_effect=responses):
                self.assertEqual(GUARD.run_owned_api_absence(args), 0)

    def test_lifecycle_from_another_workflow_run_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = self.api_args(root)
            lifecycle = json.loads(args.lifecycle.read_text(encoding="utf-8"))
            lifecycle["workflow_run_id"] = "41"
            args.lifecycle.write_text(json.dumps(lifecycle), encoding="utf-8")
            with patch.object(GUARD.subprocess, "run", side_effect=self.absent_api_responses()) as mocked:
                self.assertEqual(GUARD.run_owned_api_absence(args), 1)
            mocked.assert_not_called()
            result = json.loads(args.artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertEqual(result["failed_operation"], "read_generic_lifecycle_evidence")

    def test_lifecycle_from_another_testlab_phase_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = self.api_args(root)
            lifecycle = json.loads(args.lifecycle.read_text(encoding="utf-8"))
            lifecycle["testlab_phase_id"] = "42-pp5"
            args.lifecycle.write_text(json.dumps(lifecycle), encoding="utf-8")
            with patch.object(GUARD.subprocess, "run", side_effect=self.absent_api_responses()) as mocked:
                self.assertEqual(GUARD.run_owned_api_absence(args), 1)
            mocked.assert_not_called()
            result = json.loads(args.artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertEqual(result["failed_operation"], "read_generic_lifecycle_evidence")

    def test_all_three_cleanup_phases_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            workload = root / "workload.json"
            host = root / "host.json"
            artifact = root / "cleanup.json"
            workload.write_text(json.dumps({"status": "passed", "run_owned_servers": 1}), encoding="utf-8")
            host.write_text(json.dumps({"status": "passed"}), encoding="utf-8")
            args = Namespace(run_id="42", workload_status=0, cleanup_status=0, inventory_status=0,
                             workloads=workload, host_absence=host, artifact=artifact)
            self.assertEqual(GUARD.generic_cleanup(args), 1)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertIn("pre_teardown_workload_absence", result["failed_phases"])

    def test_cleanup_command_failure_is_a_distinct_harness_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            workload = root / "workload.json"
            host = root / "host.json"
            artifact = root / "cleanup.json"
            workload.write_text(json.dumps({"status": "passed"}), encoding="utf-8")
            host.write_text(json.dumps({"status": "passed"}), encoding="utf-8")
            args = Namespace(run_id="42", workload_status=0, cleanup_status=9, inventory_status=0,
                             workloads=workload, host_absence=host, artifact=artifact)
            self.assertEqual(GUARD.generic_cleanup(args), 1)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["cleanup_command_status"], 9)
            self.assertEqual(result["workload_absence_status"], 0)
            self.assertEqual(result["post_cleanup_inventory_status"], 0)

    def test_host_absence_passes_without_openstack_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            before = root / "before.json"
            after = root / "after.json"
            before.write_text(json.dumps(host_snapshot()), encoding="utf-8")
            after.write_text(json.dumps(host_snapshot()), encoding="utf-8")
            artifact = root / "host-absence.json"
            args = Namespace(
                run_id="42", state_root=str(root / "state"), pid_root=str(root / "pid"),
                inventory_root=str(root / "inventory"), openstack_venv="", image_path="",
                baseline=before, after=after, artifact=artifact,
            )
            with patch.object(GUARD, "process_matches_state_root", return_value=[]):
                self.assertEqual(GUARD.post_teardown_host_absence(args), 0)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertTrue(result["openstack_api_consulted"] is False)
            self.assertTrue(result["generic_roots_absent"])

    def test_testlab_state_root_remaining_is_harness_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state = root / "state"
            state.mkdir()
            before = root / "before.json"
            after = root / "after.json"
            before.write_text(json.dumps(host_snapshot()), encoding="utf-8")
            after.write_text(json.dumps(host_snapshot()), encoding="utf-8")
            artifact = root / "host-absence.json"
            args = Namespace(run_id="42", state_root=str(state), pid_root=str(root / "pid"),
                             inventory_root=str(root / "inventory"), openstack_venv="", image_path="",
                             baseline=before, after=after, artifact=artifact)
            with patch.object(GUARD, "process_matches_state_root", return_value=[]):
                self.assertEqual(GUARD.post_teardown_host_absence(args), 1)
            self.assertEqual(json.loads(artifact.read_text(encoding="utf-8"))["classification"], "HARNESS_GAP")

    def test_foreign_state_change_is_harness_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            before = root / "before.json"
            after = root / "after.json"
            before.write_text(json.dumps(host_snapshot()), encoding="utf-8")
            after.write_text(json.dumps(host_snapshot(foreign_links="changed")), encoding="utf-8")
            artifact = root / "host-absence.json"
            args = Namespace(run_id="42", state_root=str(root / "state"), pid_root=str(root / "pid"),
                             inventory_root=str(root / "inventory"), openstack_venv="", image_path="",
                             baseline=before, after=after, artifact=artifact)
            with patch.object(GUARD, "process_matches_state_root", return_value=[]):
                self.assertEqual(GUARD.post_teardown_host_absence(args), 1)
            self.assertEqual(json.loads(artifact.read_text(encoding="utf-8"))["classification"], "HARNESS_GAP")

    def test_foreign_pool_identity_change_with_same_count_is_harness_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            before = root / "before.json"
            after = root / "after.json"
            before.write_text(json.dumps(host_snapshot(foreign_pools="first-pool")), encoding="utf-8")
            after.write_text(json.dumps(host_snapshot(foreign_pools="different-pool")), encoding="utf-8")
            artifact = root / "host-absence.json"
            args = Namespace(run_id="42", state_root=str(root / "state"), pid_root=str(root / "pid"),
                             inventory_root=str(root / "inventory"), openstack_venv="", image_path="",
                             baseline=before, after=after, artifact=artifact)
            with patch.object(GUARD, "process_matches_state_root", return_value=[]):
                self.assertEqual(GUARD.post_teardown_host_absence(args), 1)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertFalse(result["foreign_state_unchanged"])

    def test_run_owned_process_remaining_is_harness_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            before = root / "before.json"
            after = root / "after.json"
            before.write_text(json.dumps(host_snapshot()), encoding="utf-8")
            after.write_text(json.dumps(host_snapshot()), encoding="utf-8")
            artifact = root / "host-absence.json"
            args = Namespace(run_id="42", state_root=str(root / "state"), pid_root=str(root / "pid"),
                             inventory_root=str(root / "inventory"), openstack_venv="", image_path="",
                             baseline=before, after=after, artifact=artifact)
            with patch.object(GUARD, "process_matches_state_root", return_value=["123"]):
                self.assertEqual(GUARD.post_teardown_host_absence(args), 1)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertEqual(result["run_owned_processes"], 1)

    def test_three_passing_phases_allow_cleanup_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            workload = root / "workload.json"
            host = root / "host.json"
            artifact = root / "cleanup.json"
            workload.write_text(json.dumps({
                "status": "passed", "phase": "pre-teardown-api-absence", "workflow_run_id": "42",
                "run_owned_servers": 0, "run_owned_ports": 0,
                "run_owned_domains": 0, "exact_run_owned_ids_checked": True,
                "servers_checked": 1, "ports_checked": 1, "other_resources_absent": 5,
            }), encoding="utf-8")
            host.write_text(json.dumps({
                "status": "passed", "phase": "post-teardown-host-absence", "workflow_run_id": "42",
                "generic_roots_absent": True,
                "foreign_state_unchanged": True, "run_owned_processes": 0,
                "openstack_api_consulted": False,
            }), encoding="utf-8")
            args = Namespace(run_id="42", workload_status=0, cleanup_status=0, inventory_status=0,
                             workloads=workload, host_absence=host, artifact=artifact)
            self.assertEqual(GUARD.generic_cleanup(args), 0)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["pre_teardown_workload_absence"], "passed")
            self.assertEqual(result["cleanup_command"], "passed")
            self.assertEqual(result["post_teardown_host_absence"], "passed")

    def test_cleanup_gate_rejects_proof_from_another_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            workload = root / "workload.json"
            host = root / "host.json"
            artifact = root / "cleanup.json"
            workload.write_text(json.dumps({
                "status": "passed", "phase": "pre-teardown-api-absence", "workflow_run_id": "41",
                "run_owned_servers": 0, "run_owned_ports": 0, "run_owned_domains": 0,
                "exact_run_owned_ids_checked": True,
            }), encoding="utf-8")
            host.write_text(json.dumps({
                "status": "passed", "phase": "post-teardown-host-absence", "workflow_run_id": "42",
                "generic_roots_absent": True, "foreign_state_unchanged": True,
                "run_owned_processes": 0, "openstack_api_consulted": False,
            }), encoding="utf-8")
            args = Namespace(run_id="42", workload_status=0, cleanup_status=0, inventory_status=0,
                             workloads=workload, host_absence=host, artifact=artifact)
            self.assertEqual(GUARD.generic_cleanup(args), 1)
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertIn("pre_teardown_workload_absence", result["failed_phases"])

    def test_lane_cannot_start_with_existing_server(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state_root = root / "state"
            state_root.mkdir()
            (state_root / ".o3k-run-owned").write_text(
                "o3k-disposable-testlab-v1\nrun=42-pp5\n", encoding="utf-8"
            )
            artifact = root / "preconditions.json"
            args = Namespace(run_id="42", testlab_run_id="42-pp5", source_sha="a" * 40,
                             state_root=str(state_root), artifact=artifact)
            completed = [
                SimpleNamespace(returncode=0, stdout='[{"ID":"active-server"}]'),
                SimpleNamespace(returncode=0, stdout="[]"),
                SimpleNamespace(returncode=0, stdout="o3k-p15-7-42-server\n"),
            ]
            with patch.object(GUARD.PROTECTED_OBSERVER, "verify_marker", return_value={
                "owner_uid": 0, "mode": "0600", "regular_file": True,
                "privileged_observer": "sudo -n cat", "marker_verified": True,
            }) as marker, patch.dict(GUARD.os.environ, {"OS_PROJECT_ID": "testlab-project"}), \
                    patch.object(GUARD.subprocess, "run", side_effect=completed) as mocked:
                self.assertEqual(GUARD.lane_preconditions(args), 1)
            marker.assert_called_once_with(state_root, "42-pp5", "a" * 40)
            self.assertTrue(all("--all-projects" not in call.args[0] for call in mocked.call_args_list))
            self.assertEqual(
                mocked.call_args_list[0].args[0],
                ["openstack", "server", "list", "--project", "testlab-project", "-f", "json"],
            )
            self.assertEqual(
                mocked.call_args_list[1].args[0],
                ["openstack", "port", "list", "--project", "testlab-project", "-f", "json"],
            )
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["classification"], "HARNESS_GAP")
            self.assertEqual(result["run_owned_servers"], 1)

    def test_lane_clean_start_ignores_foreign_project_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state_root = root / "state"
            state_root.mkdir()
            (state_root / ".o3k-run-owned").write_text(
                "o3k-disposable-testlab-v1\nrun=42-pp5\n", encoding="utf-8"
            )
            artifact = root / "preconditions.json"
            args = Namespace(run_id="42", testlab_run_id="42-pp5", source_sha="a" * 40,
                             state_root=str(state_root), artifact=artifact)
            completed = [
                SimpleNamespace(returncode=0, stdout="[]"),
                SimpleNamespace(returncode=0, stdout="[]"),
                SimpleNamespace(returncode=0, stdout=""),
            ]
            with patch.object(GUARD.PROTECTED_OBSERVER, "verify_marker", return_value={
                "owner_uid": 0, "mode": "0600", "regular_file": True,
                "privileged_observer": "sudo -n cat", "marker_verified": True,
            }) as marker, patch.dict(GUARD.os.environ, {"OS_PROJECT_ID": "testlab-project"}), \
                    patch.object(GUARD.subprocess, "run", side_effect=completed):
                self.assertEqual(GUARD.lane_preconditions(args), 0)
            marker.assert_called_once_with(state_root, "42-pp5", "a" * 40)
            self.assertNotIn("--all-projects", str(completed))
            result = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(result["run_owned_servers"], 0)
            self.assertEqual(result["run_owned_ports"], 0)


if __name__ == "__main__":
    unittest.main()
