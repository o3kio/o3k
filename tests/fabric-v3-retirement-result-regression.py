#!/usr/bin/env python3
"""Regression tests for the secret-free retirement campaign result artifact."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "fabric_v3_retirement_result", ROOT / "fabric-v3-retirement-result.py"
)
assert SPEC and SPEC.loader
result_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(result_module)


class RetirementResultRegression(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)

        def write(path: str, value: object) -> None:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(value))

        write("manifest.json", {
            "run_id": "run-1", "product_sha": "product-sha", "product_tree": "product-tree",
            "harness_sha": "harness-sha", "harness_tree": "harness-tree",
        })
        write("before-departure/durable-work/pre-delete-work-history.json", {
            "realm_id": "realm-1", "realm_generation": 8,
            "participants": ["host-a", "host-b", "host-c"],
            "her": {"host-a": {"peers": ["host-b", "host-c"]}},
            "latest_apply_by_host": {"host-c": {"command_id": "c-apply-8"}},
        })
        write("c-delete/retirement-obligation/durable-order.json", {
            "prior_c_apply": {"command_id": "c-apply-8"},
            "c_remove": {"action": "Remove", "state": "succeeded", "target_host_id": "host-c",
                         "target_agent_id": "network-agent-c", "target_agent_epoch": "network-epoch-c-1",
                         "idempotency_key": "idem-c-remove", "command_id": "c-remove-9"},
            "ordering": "C Remove durable work precedes reduced-generation A/B Apply work",
        })
        write("c-delete/provider-absence/result.json", {
            "endpoint_tap_absent": True, "realm_links_absent": True,
            "realm_namespace_absent": True, "vxlan_absent": True,
            "fabric_plan_absent": True, "anti_spoof_absent": True,
            "local_dhcp_state_absent": True,
        })
        write("endpoint-removal/survivor-state.json", {
            "participants": ["host-a", "host-b"], "directory_generation": 9,
            "retired_host_c_absent": True,
            "survivors": {"host-a": {"her": ["host-b"]}, "host-b": {"her": ["host-a"]}},
        })
        write("restart/startup-recovery/result.json", {
            "controller_restarted": True, "c_apply_recreated": False,
            "c_provider_state_absent": True, "desired_participants": ["host-a", "host-b"],
        })
        write("restart/startup-recovery/controller-stop.json", {"old_controller_pid": "101"})
        write("restart/startup-recovery/controller-stop-observed.json", {"old_process_gone": True})
        write("restart/startup-recovery/controller-start.json", {"new_controller_pid": "202"})
        (self.root / "restart/durable-work/pre-restart-rowid.txt").parent.mkdir(parents=True, exist_ok=True)
        (self.root / "restart/durable-work/pre-restart-rowid.txt").write_text("14\n")
        write("restart/durable-work/retirement-after-restart.json", {
            "c_apply_recreated": False,
            "latest_c_work": {"action": "Remove", "state": "succeeded"},
        })
        write("restart/provider-absence/result.json", {
            "endpoint_tap_absent": True, "realm_links_absent": True,
            "realm_namespace_absent": True, "vxlan_absent": True,
            "fabric_plan_absent": True, "anti_spoof_absent": True,
            "local_dhcp_state_absent": True,
        })
        write("c-delete/retirement-obligation/ordering-observations.json", {
            "remove_success_observed_at_utc": "2026-01-01T00:00:01.000000000Z",
            "provider_absence_observed_at_utc": "2026-01-01T00:00:02.000000000Z",
            "survivor_convergence_observed_at_utc": "2026-01-01T00:00:03.000000000Z",
            "remove_success_observed_before_provider_absence": True,
            "provider_absence_observed_before_survivor_convergence": True,
        })
        write("c-delete/port/state-transition.json", {"after": {"status": "DOWN"}})
        write("teardown/management-network-cleanup-status.json", {
            "cleanup_command_status": "PASS", "post_cleanup_inventory_status": "PASS",
            "foreign_state_unchanged": True,
        })
        write("teardown/foreign-state.json", {
            "foreign_networks_unchanged": True, "foreign_domains_unchanged": True,
            "foreign_pools_unchanged": True, "foreign_links_unchanged": True,
            "host_routes_unchanged": True, "host_addresses_unchanged": True,
        })
        write("environment/network-agent-directory.json", [
            {"host_id": f"host-{host}", "agent_id": f"network-agent-{host}",
             "agent_epoch": f"network-epoch-{host}-1"}
            for host in "abc"
        ])
        write("environment/fabric-identities.json", [
            {"host_id": f"host-{host}", "agent_id": f"network-agent-{host}",
             "fabric_generation": 1}
            for host in "abc"
        ])
        write("environment/management-network-plan.json", {
            "addresses": {host: f"192.0.2.{number}" for host, number in zip("abc", (2, 3, 4), strict=True)}
        })
        for host in "abc":
            write(f"management/compute-{host}-ready.json", {
                "agent_id": f"compute-agent-{host}", "agent_epoch": f"compute-epoch-{host}-1",
            })
        rows = [
            (f"compute-{host}", f"domain-{host}", f"192.0.2.{number}", f"02:00:00:00:00:0{number}", f"uuid-{host}")
            for host, number in zip("abc", (2, 3, 4), strict=True)
        ]
        (self.root / "environment/inventory.tsv").parent.mkdir(parents=True, exist_ok=True)
        (self.root / "environment/inventory.tsv").write_text("".join("\t".join(row) + "\n" for row in rows))
        write("before-departure/plans/host-a-fabric-plan.json", {
            "encapsulation": {"provider_segment_id": 5001},
        })
        write("c-delete/operation/request.json", {"server_id": "server-c"})
        for relative in (
            "before-departure/traffic/a-to-b.txt", "before-departure/traffic/b-to-a.txt",
            "before-departure/traffic/a-to-c.txt", "before-departure/traffic/c-to-a.txt",
            "before-departure/traffic/a-to-c-canonical-arp.txt", "endpoint-removal/a-to-b.txt",
            "endpoint-removal/b-to-a.txt", "restart/traffic/a-to-b.txt",
            "restart/traffic/b-to-a.txt", "restart/traffic/a-to-b-canonical-arp.txt",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("PASS\n")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_pass_result_contains_exact_retirement_identities_and_secret_free_refs(self) -> None:
        result, manifest = result_module.build_result(self.root, "controller-run-1", "controller-epoch-1")
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["identities"]["realm_id"], "realm-1")
        self.assertEqual(result["identities"]["vni"], 5001)
        self.assertEqual(result["retirement"]["remove"]["command_id"], "c-remove-9")
        self.assertEqual(result["retirement"]["dispatch_target"]["agent_epoch"], "network-epoch-c-1")
        self.assertIsNone(result["first_failure"])
        self.assertEqual(manifest["campaign_result"], "PASS")
        self.assertEqual(result["controller_restart"]["durable_work_rowid_cutoff"], 14)
        self.assertEqual(
            len(result["evidence_files"]), len(set(result["evidence_files"]))
        )
        encoded = json.dumps(result)
        self.assertNotIn("public_key", encoded)
        self.assertNotIn("private_key", encoded)
        self.assertNotIn("token", encoded)

    def test_failed_foreign_state_proof_cannot_produce_pass(self) -> None:
        path = self.root / "teardown/foreign-state.json"
        state = json.loads(path.read_text())
        state["foreign_domains_unchanged"] = False
        path.write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, "foreign-state preservation"):
            result_module.build_result(self.root, "controller-run-1", "controller-epoch-1")

    def test_empty_provider_absence_cannot_produce_pass(self) -> None:
        path = self.root / "c-delete/provider-absence/result.json"
        path.write_text("{}\n")
        with self.assertRaisesRegex(ValueError, "provider absence"):
            result_module.build_result(self.root, "controller-run-1", "controller-epoch-1")

    def test_provider_absence_must_precede_survivor_convergence(self) -> None:
        path = self.root / "c-delete/retirement-obligation/ordering-observations.json"
        order = json.loads(path.read_text())
        order["provider_absence_observed_before_survivor_convergence"] = False
        path.write_text(json.dumps(order))
        with self.assertRaisesRegex(ValueError, "provider absence was not observed"):
            result_module.build_result(self.root, "controller-run-1", "controller-epoch-1")

    def test_missing_foreign_inventory_predicate_cannot_produce_pass(self) -> None:
        path = self.root / "teardown/foreign-state.json"
        state = json.loads(path.read_text())
        del state["host_addresses_unchanged"]
        path.write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, "foreign-state preservation"):
            result_module.build_result(self.root, "controller-run-1", "controller-epoch-1")


if __name__ == "__main__":
    unittest.main()
