from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pp5_protected_harness_microgate_test", ROOT / "scripts" / "pp5-protected-harness-microgate.py")
assert SPEC is not None and SPEC.loader is not None
MICROGATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MICROGATE
SPEC.loader.exec_module(MICROGATE)


class ProtectedHarnessMicrogateTests(unittest.TestCase):
    run_id = "12345"
    source_sha = "a" * 40
    state_root = pathlib.Path("/var/lib/o3k-testlab/12345-pp5")
    campaign_url = "postgresql://o3k_pp5_12345:secret@127.0.0.1:5544/o3k_pp5_s5_12345"

    def test_pid_record_uses_the_bootstrap_service_identity(self) -> None:
        self.assertEqual(MICROGATE.parse_pid_record("123|456|o3k|o3kd\n", "o3kd"),
                         (123, "456", "o3k"))
        self.assertEqual(MICROGATE.parse_pid_record("124|457|o3k-compute|o3k-compute\n", "o3k-compute"),
                         (124, "457", "o3k-compute"))
        with self.assertRaises(ValueError):
            MICROGATE.parse_pid_record("123|456|1001|o3kd\n", "o3kd")

    def args(self, root: pathlib.Path) -> Namespace:
        return Namespace(
            run_id=self.run_id,
            source_sha=self.source_sha,
            state_root=self.state_root,
            generic_cleanup=root / "generic.json",
            campaign_binding=root / "binding.json",
            postgres_manifest=root / "manifest.json",
            bootstrap_artifact=root / "bootstrap.json",
            generic_baseline=root / "baseline.json",
            pid_root=root / "pids" / "12345-pp5",
            inventory_root=root / "inventory" / "12345-pp5",
            openstack_venv=root / "venv",
            api_port=28080,
            artifact=root / "initial.json",
            microgate_artifact=root / "microgate.json",
        )

    def read_evidence(self, path: pathlib.Path, operation: str, _context):
        if operation == "verify_fresh_pp5_bootstrap_artifact":
            return {
                "status": "passed", "source_commit": self.source_sha,
                "state_directory": str(self.state_root), "provider": "agent",
                "project_id": "project-123", "readiness": {"o3kd": True, "compute": True},
            }
        if operation == "verify_generic_epoch_absence":
            return {
                "status": "passed", "pre_teardown_workload_absence": "passed",
                "cleanup_command": "passed", "post_teardown_host_absence": "passed",
                "workflow_run_id": self.run_id, "tested_source_sha": self.source_sha,
                "workload_absence_status": 0, "cleanup_command_status": 0,
                "post_cleanup_inventory_status": 0,
                "run_owned_servers": 0, "run_owned_ports": 0,
                "run_owned_domains": 0, "run_owned_processes": 0,
                "generic_roots_absent": True, "foreign_state_unchanged": True,
            }
        if operation == "verify_campaign_database_binding":
            return {"manifest_validation": "passed", "campaign_sentinel": "passed"}
        raise AssertionError(operation)

    def setup_run_gate(self, root: pathlib.Path, *, blocks=None, providers=None,
                       capacity=None, run_side_effect=None, api_side_effect=None,
                       marker_side_effect=None, foreign_result=None, token_side_effect=None):
        args = self.args(root)
        calls: list[tuple[str, list[str]]] = []
        default_blocks = [{"block": {
            "execution_identity": "bootstrap-agent", "state": "ready",
            "resource_provider_ids": ["provider-1"], "drain_blockers": [],
        }}]
        default_providers = {"items": [{"provider_id": "provider-1", "state": "Enabled",
                                        "capacity": [{"allocated": 0}]}], "has_more": False}
        default_capacity = {"dimensions": [{"allocated": 0}]}

        def json_command(_self, operation, command, _observer, _resource):
            calls.append((operation, command))
            if operation == "lookup_openstack_project_identity":
                return {"id": "project-123"}
            if operation in {"list_project_scoped_servers", "list_project_scoped_ports"}:
                return []
            raise AssertionError(operation)

        def run(_self, operation, observer, resource, command, **_kwargs):
            calls.append((operation, command))
            if run_side_effect:
                return run_side_effect(operation, observer, resource, command)
            return subprocess.CompletedProcess(command, 0, "", "")

        def api_json(_context, _base, _token, path, _resource):
            calls.append(("GET " + path.split("?", 1)[0], []))
            if api_side_effect:
                return api_side_effect(path)
            if path == "/operator/building-blocks":
                return blocks if blocks is not None else default_blocks
            if path.startswith("/operator/diagnostics/providers"):
                return providers if providers is not None else default_providers
            if path == "/operator/diagnostics/capacity":
                return capacity if capacity is not None else default_capacity
            raise AssertionError(path)

        def obtain_token(_args, _context, _generated_path):
            return "opaque-token"

        generic = {"status": "passed", "pre_teardown_workload_absence": "passed",
                   "cleanup_command": "passed", "post_teardown_host_absence": "passed",
                   "workflow_run_id": self.run_id, "tested_source_sha": self.source_sha,
                   "workload_absence_status": 0, "cleanup_command_status": 0,
                   "post_cleanup_inventory_status": 0,
                   "run_owned_servers": 0, "run_owned_ports": 0,
                   "run_owned_domains": 0, "run_owned_processes": 0,
                   "generic_roots_absent": True, "foreign_state_unchanged": True}
        binding = {"manifest_validation": "passed", "campaign_sentinel": "passed"}
        marker_patch = ({"side_effect": marker_side_effect} if marker_side_effect else {
            "return_value": {
                "owner_uid": 0, "mode": "0600", "regular_file": True,
                "privileged_observer": "sudo -n cat", "marker_verified": True,
            }
        })
        with patch.dict(os.environ, {
            "RUNNER_TEMP": str(root),
            "O3K_DATABASE_BACKEND": "postgres",
            "O3K_P15_7_POSTGRES_MODE": "external",
            "O3K_PP5_CAMPAIGN_DATABASE_URL": self.campaign_url,
            "O3K_PP5_WORKSPACE_DATABASE_URL": "",
            "O3K_PP5_ENDPOINT_DATABASE_URL": "",
            "O3K_PP5_P13_DATABASE_URL": "",
        }, clear=True), \
                patch.object(MICROGATE, "verify_workflow_prerequisites", return_value={}), \
                patch.object(MICROGATE, "verify_runner_roots"), \
                patch.object(MICROGATE, "read_json", side_effect=lambda path, operation, context:
                             self.read_evidence(path, operation, context)), \
                patch.object(MICROGATE.OBSERVER, "verify_marker", **marker_patch), \
                patch.object(MICROGATE.OBSERVER, "read_bootstrap_agent_id", return_value="bootstrap-agent"), \
                patch.object(MICROGATE, "obtain_operator_token",
                             side_effect=token_side_effect or obtain_token), \
                patch.object(MICROGATE.Context, "json_command", new=json_command), \
                patch.object(MICROGATE.Context, "run", new=run), \
                patch.object(MICROGATE, "api_json", side_effect=api_json), \
                patch.object(MICROGATE, "foreign_fingerprint", return_value=(
                    {"domains_sha256": "x"}, foreign_result if foreign_result is not None else {
                        "unchanged": True, "new_managed_domain_count": 0,
                        "removed_managed_domain_count": 0,
                        "compared_fields": ["domains_sha256"]})), \
                patch.object(MICROGATE.POSTGRES, "verify_purpose_sentinel", return_value=True):
            document = MICROGATE.run_gate(args)
        return args, document, calls

    def test_read_only_microgate_proves_project_scoped_initial_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args, document, calls = self.setup_run_gate(pathlib.Path(temporary))
        self.assertEqual(document["status"], "passed")
        self.assertEqual(document["existing_workloads"], {"servers": 0, "ports": 0, "domains": 0})
        self.assertEqual(document["eligible_compute_hosts"], 1)
        self.assertEqual(document["child_compute_hosts"], 0)
        self.assertTrue(document["provider_allocations_zero"])
        self.assertTrue(document["foreign_state_unchanged"])
        self.assertFalse(document["pre_s1_workload_created"])
        scoped = {operation: command for operation, command in calls
                  if operation in {"list_project_scoped_servers", "list_project_scoped_ports"}}
        self.assertEqual(scoped["list_project_scoped_servers"][3:6], ["--project", "project-123", "-f"])
        self.assertEqual(scoped["list_project_scoped_ports"][3:6], ["--project", "project-123", "-f"])
        forbidden = {"create", "delete", "set", "unset", "add", "remove"}
        self.assertFalse(any(command and command[1] in forbidden for _op, command in calls))
        serialized = json.dumps(document)
        self.assertNotIn("secret", serialized)
        self.assertNotIn(self.campaign_url, serialized)
        self.assertEqual(args.artifact.name, "initial.json")

    def test_generated_token_is_removed_after_success_without_evidence_leak(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)

            def create_token(_args, _context, path):
                assert path is not None
                path.write_text("short-lived-secret-token", encoding="utf-8")
                path.chmod(0o600)
                return "short-lived-secret-token"

            _args, document, _calls = self.setup_run_gate(root, token_side_effect=create_token)
            token_path = root / f"o3k-pp5-microgate-token-{self.run_id}"
            self.assertFalse(token_path.exists())
        self.assertEqual(document["status"], "passed")
        self.assertNotIn("short-lived-secret-token", json.dumps(document))

    def test_generated_token_is_removed_when_exchange_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)

            def fail_after_token_write(_args, _context, path):
                assert path is not None
                path.write_text("short-lived-secret-token", encoding="utf-8")
                path.chmod(0o600)
                raise MICROGATE.GateFailure("exchange_system_operator_authority", "api_observation",
                                            "operator_authority", "SubprocessError", "bash", 1)

            _args, document, _calls = self.setup_run_gate(root, token_side_effect=fail_after_token_write)
            self.assertFalse((root / f"o3k-pp5-microgate-token-{self.run_id}").exists())
        self.assertEqual(document["status"], "failed")
        self.assertEqual(document["failed_operation"], "exchange_system_operator_authority")
        self.assertNotIn("short-lived-secret-token", json.dumps(document))

    def test_token_cleanup_failure_fails_the_microgate_with_redacted_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)

            def change_token_mode(_args, _context, path):
                assert path is not None
                path.write_text("short-lived-secret-token", encoding="utf-8")
                path.chmod(0o640)
                return "short-lived-secret-token"

            _args, document, _calls = self.setup_run_gate(root, token_side_effect=change_token_mode)
            token_path = root / f"o3k-pp5-microgate-token-{self.run_id}"
            self.assertTrue(token_path.exists())
            token_path.unlink()
        self.assertEqual(document["status"], "failed")
        self.assertEqual(document["failed_operation"], "remove_microgate_operator_token")
        self.assertEqual(document["diagnostic"], "PermissionError")
        self.assertNotIn("short-lived-secret-token", json.dumps(document))

    def test_libvirt_inventory_failure_reports_exact_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def fail_libvirt(operation, _observer, _resource, command):
                if operation == "list_libvirt_domains":
                    raise MICROGATE.GateFailure(operation, "libvirt_observation", "libvirt_domains",
                                                "SubprocessError", "virsh", 2)
                return subprocess.CompletedProcess(command, 0, "", "")
            _args, document, _calls = self.setup_run_gate(pathlib.Path(temporary),
                                                           run_side_effect=fail_libvirt)
        self.assertEqual(document["status"], "failed")
        self.assertEqual(document["failed_operation"], "list_libvirt_domains")
        self.assertEqual(document["observer_type"], "libvirt_observation")
        self.assertEqual(document["command_class"], "virsh")
        self.assertEqual(document["exit_code"], 2)

    def test_sudo_marker_observation_failure_reports_exact_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            error = MICROGATE.OBSERVER.ObservationError(
                "read_testlab_ownership_marker", "sudo_read_only", "testlab_ownership_marker",
                "PermissionError", "sudo", 1)
            _args, document, _calls = self.setup_run_gate(
                pathlib.Path(temporary), marker_side_effect=error)
        self.assertEqual(document["status"], "failed")
        self.assertEqual(document["classification"], "HARNESS_GAP")
        self.assertEqual(document["failed_operation"], "read_testlab_ownership_marker")
        self.assertEqual(document["observer_type"], "sudo_read_only")
        self.assertEqual(document["resource_class"], "testlab_ownership_marker")
        self.assertEqual(document["command_class"], "sudo")
        self.assertEqual(document["exit_code"], 1)

    def test_topology_api_failure_reports_exact_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def fail_topology(path):
                if path == "/operator/building-blocks":
                    raise MICROGATE.GateFailure("GET /operator/building-blocks", "api_observation",
                                                "canonical_topology", "HTTPError", "urllib", 500)
                raise AssertionError(path)
            _args, document, _calls = self.setup_run_gate(pathlib.Path(temporary),
                                                           api_side_effect=fail_topology)
        self.assertEqual(document["failed_operation"], "GET /operator/building-blocks")
        self.assertEqual(document["resource_class"], "canonical_topology")

    def test_nonzero_provider_allocation_blocks_s1(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            providers = {"items": [{"provider_id": "provider-1", "state": "Enabled",
                                    "capacity": [{"allocated": 1}]}], "has_more": False}
            _args, document, _calls = self.setup_run_gate(pathlib.Path(temporary), providers=providers)
        self.assertEqual(document["failed_operation"], "verify_provider_allocations_zero")
        self.assertEqual(document["classification"], "HARNESS_GAP")

    def test_child_compute_host_blocks_s1(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            blocks = [
                {"block": {"execution_identity": "bootstrap-agent", "state": "ready",
                           "resource_provider_ids": ["provider-1"], "drain_blockers": []}},
                {"block": {"execution_identity": "child-agent", "state": "ready",
                           "resource_provider_ids": ["provider-2"], "drain_blockers": []}},
            ]
            _args, document, _calls = self.setup_run_gate(pathlib.Path(temporary), blocks=blocks)
        self.assertEqual(document["failed_operation"], "assess_s1_topology")
        self.assertEqual(document["classification"], "HARNESS_GAP")

    def test_new_managed_libvirt_domain_blocks_s1(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _args, document, _calls = self.setup_run_gate(
                pathlib.Path(temporary), foreign_result={
                    "unchanged": False, "new_managed_domain_count": 1,
                    "removed_managed_domain_count": 0, "compared_fields": ["domains_sha256"]})
        self.assertEqual(document["failed_operation"], "verify_zero_existing_workloads")
        self.assertEqual(document["observer_type"], "libvirt_observation")
        self.assertEqual(document["resource_class"], "run_owned_workloads")
        self.assertEqual(document["classification"], "HARNESS_GAP")

    def test_initial_state_validator_requires_both_passed_artifacts_and_exact_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            artifact = root / "initial.json"
            microgate = root / "microgate.json"
            valid = {
                "artifact_type": "pp5-lane-initial-state", "phase": "s1-boundary", "status": "passed",
                "workflow_run_id": self.run_id, "tested_source_sha": self.source_sha,
                "generic_epoch_absent": True, "campaign_database_bound": True,
                "fresh_pp5_testlab": True, "existing_workloads": {"servers": 0, "ports": 0, "domains": 0},
                "eligible_compute_hosts": 1, "child_compute_hosts": 0, "provider_allocations_zero": True,
                "foreign_state_unchanged": True, "generic_pre_teardown_workload_absence": "passed",
                "generic_teardown": "passed", "generic_post_teardown_host_absence": "passed",
                "generic_owned_residue": 0, "campaign_manifest_validation": "passed",
                "campaign_sentinel": "passed", "pre_s1_workload_created": False,
            }
            artifact.write_text(json.dumps(valid), encoding="utf-8")
            microgate.write_text(json.dumps({"artifact_type": "pp5-protected-harness-microgate",
                                             "status": "passed", "workflow_run_id": self.run_id,
                                             "phase": "s1-boundary-preconditions",
                                             "tested_source_sha": self.source_sha,
                                             "pre_s1_workload_created": False}), encoding="utf-8")
            self.assertEqual(MICROGATE.validate_initial_state(Namespace(
                run_id=self.run_id, source_sha=self.source_sha, artifact=artifact,
                microgate_artifact=microgate)), 0)
            valid["existing_workloads"]["servers"] = 1
            artifact.write_text(json.dumps(valid), encoding="utf-8")
            self.assertEqual(MICROGATE.validate_initial_state(Namespace(
                run_id=self.run_id, source_sha=self.source_sha, artifact=artifact,
                microgate_artifact=microgate)), 1)


if __name__ == "__main__":
    unittest.main()
