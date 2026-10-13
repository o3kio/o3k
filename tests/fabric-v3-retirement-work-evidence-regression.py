#!/usr/bin/env python3
"""Regression tests for durable C-retirement ordering evidence."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sqlite3
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "fabric_v3_retirement_work_evidence", ROOT / "fabric-v3-retirement-work-evidence.py"
)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class RetirementWorkEvidenceRegression(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = pathlib.Path(self.temp.name) / "campaign.sqlite"
        self.before = pathlib.Path(self.temp.name) / "before.json"
        connection = sqlite3.connect(self.database)
        connection.execute(
            "CREATE TABLE network_plan_work (command_id TEXT, operation_id TEXT, idempotency_key TEXT, "
            "target_host_id TEXT, target_agent_id TEXT, target_agent_epoch TEXT, controller_id TEXT, "
            "controller_epoch TEXT, fencing_token INTEGER, fingerprint_sha256 TEXT, snapshot BLOB, "
            "state TEXT, revision INTEGER, outcome BLOB, created_at TEXT, updated_at TEXT)"
        )
        connection.commit()
        connection.close()
        self.add_row("c-apply", "host-c", "Apply", "succeeded", 4, ["host-a", "host-b", "host-c"])
        self.before.write_text(json.dumps({"realm_id": "realm-1", "realm_generation": 4,
                                           "latest_c_apply_insertion_order": 1,
                                           "latest_apply_by_host": {
                                               "host-c": {"command_id": "c-apply", "action": "Apply",
                                                          "target_agent_id": "network-agent-c",
                                                          "target_agent_epoch": "epoch-host-c"}
                                           }}))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def add_row(self, command: str, host: str, action: str, state: str, generation: int, participants: list[str]) -> None:
        agent = f"network-agent-{host[-1]}"
        plan = {
            "fabric": {
                "realm_id": "realm-1",
                "directory_generation": generation,
                "encapsulation": {"binding_generation": generation},
                "local_fabric_generation": generation,
                "directory": {"entries": [{"selected_host": value} for value in participants]},
                "peers": [{"host_id": value} for value in participants if value != host],
            }
        }
        snapshot = json.dumps({"action": action, "plan": plan}).encode()
        connection = sqlite3.connect(self.database)
        connection.execute(
            "INSERT INTO network_plan_work VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (command, f"operation-{command}", f"idem-{command}", host, agent, f"epoch-{host}",
             "controller-1", "controller-epoch-1", 1, "fingerprint", snapshot, state, 1,
             None, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z"),
        )
        connection.commit()
        connection.close()

    def test_remove_is_a_durable_precondition_for_reduced_survivor_applies(self) -> None:
        self.add_row("c-remove", "host-c", "Remove", "succeeded", 5, ["host-a", "host-b"])
        self.add_row("a-apply", "host-a", "Apply", "succeeded", 5, ["host-a", "host-b"])
        self.add_row("b-apply", "host-b", "Apply", "succeeded", 5, ["host-a", "host-b"])
        result = evidence.verify_order(self.database, "realm-1", self.before)
        self.assertIn("C Remove durable work precedes", result["ordering"])
        self.assertEqual(result["c_remove"]["target_agent_id"], "network-agent-c")

    def test_survivor_apply_admitted_before_remove_fails(self) -> None:
        self.add_row("a-apply", "host-a", "Apply", "succeeded", 5, ["host-a", "host-b"])
        self.add_row("c-remove", "host-c", "Remove", "succeeded", 5, ["host-a", "host-b"])
        self.add_row("b-apply", "host-b", "Apply", "succeeded", 5, ["host-a", "host-b"])
        with self.assertRaisesRegex(ValueError, "before C Remove"):
            evidence.verify_order(self.database, "realm-1", self.before)

    def test_controller_restart_rejects_recreated_c_apply(self) -> None:
        self.add_row("c-remove", "host-c", "Remove", "succeeded", 5, ["host-a", "host-b"])
        cutoff = 2
        self.add_row("c-apply-after-restart", "host-c", "Apply", "succeeded", 4,
                     ["host-a", "host-b", "host-c"])
        with self.assertRaisesRegex(ValueError, "recreated a C Apply"):
            evidence.verify_after_restart(self.database, "realm-1", cutoff)

    def test_sqlite_busy_is_observation_error_not_missing_remove(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.execute("BEGIN EXCLUSIVE")
        try:
            result = evidence.observe_remove_work_row(self.database, "realm-1", timeout=0)
        finally:
            connection.rollback()
            connection.close()
        self.assertFalse(result["found"])
        self.assertEqual(result["observation_status"], "error")
        self.assertEqual(result["operation"], "read_c_remove_work_row")
        self.assertEqual(result["observer_type"], "sqlite_read_only")
        self.assertEqual(result["resource_class"], "durable_network_plan_work")
        self.assertEqual(result["diagnostic"]["sqlite_errorname"], "SQLITE_BUSY")
        self.assertEqual(
            evidence.classify_observation_failure(result, "DURABLE_RETIREMENT_DEFECT"),
            "DURABLE_RETIREMENT_DEFECT",
        )

    def test_non_sqlite_observation_failure_is_harness_gap(self) -> None:
        result = {
            "diagnostic": {"exception_type": "PermissionError", "message": "denied"}
        }
        self.assertEqual(
            evidence.classify_observation_failure(result, "DURABLE_RETIREMENT_DEFECT"),
            "HARNESS_GAP",
        )

    def test_successful_empty_query_is_distinct_from_sqlite_busy(self) -> None:
        result = evidence.observe_remove_work_row(self.database, "realm-1")
        self.assertFalse(result["found"])
        self.assertEqual(result["observation_status"], "complete")

    def write_json(self, directory: pathlib.Path, name: str, value: object) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text(json.dumps(value))

    def test_survivors_use_observed_transport_addresses_and_advance_generation(self) -> None:
        plans = pathlib.Path(self.temp.name) / "plans"
        ownership = pathlib.Path(self.temp.name) / "ownership"
        fdb = pathlib.Path(self.temp.name) / "fdb"
        journals = pathlib.Path(self.temp.name) / "journals"
        for suffix in ("a", "b"):
            host = f"host-{suffix}"
            peer = "host-b" if suffix == "a" else "host-a"
            peer_ip = "198.51.100.22" if suffix == "a" else "198.51.100.11"
            self.write_json(
                plans,
                f"host-{suffix}-fabric-plan.json",
                {
                    "realm_id": "realm-1",
                    "local_host": host,
                    "directory_generation": 5,
                    "directory": {"entries": [{"selected_host": "host-a"}, {"selected_host": "host-b"}]},
                    "peers": [{"host_id": peer, "fabric_transport_ip": peer_ip}],
                },
            )
            self.write_json(
                plans,
                f"host-{suffix}-plan-before.json",
                {"directory_generation": 4},
            )
            self.write_json(
                ownership,
                f"host-{suffix}-ownership.json",
                {"realms": {"realm-1": {"endpoint_taps": {}, "pending_endpoint_taps": {},
                                          "vxlan": {"flood_peers": [peer_ip]}}}},
            )
            (fdb / f"host-{suffix}-her-fdb.txt").parent.mkdir(parents=True, exist_ok=True)
            (fdb / f"host-{suffix}-her-fdb.txt").write_text(
                f"00:00:00:00:00:00 dst {peer_ip} self\n"
            )
            self.write_json(
                journals,
                f"host-{suffix}-command-journal.json",
                {"plans": [{"action": "Apply", "target": {"agent_id": f"network-agent-{suffix}"},
                            "plan": {"fabric": {"realm_id": "realm-1"}}, "status": "Succeeded"}]},
            )
        self.write_json(ownership, "host-c-ownership.json", {"realms": {}})
        self.write_json(
            journals,
            "host-c-command-journal.json",
            {"plans": [{"action": "Remove", "plan": {"fabric": {"realm_id": "realm-1"}},
                        "status": "Succeeded"}]},
        )
        result = evidence.verify_survivors(
            "realm-1", plans, ownership, fdb, journals, "port-c"
        )
        self.assertEqual(result["participants"], ["host-a", "host-b"])
        self.assertEqual(result["survivors"]["host-a"]["transport_ips"], ["198.51.100.22"])

    def test_survivors_reject_generation_that_did_not_advance(self) -> None:
        self.test_survivors_use_observed_transport_addresses_and_advance_generation()
        plans = pathlib.Path(self.temp.name) / "plans"
        (plans / "host-a-plan-before.json").write_text(json.dumps({"directory_generation": 5}))
        with self.assertRaisesRegex(ValueError, "did not advance"):
            evidence.verify_survivors(
                "realm-1",
                plans,
                pathlib.Path(self.temp.name) / "ownership",
                pathlib.Path(self.temp.name) / "fdb",
                pathlib.Path(self.temp.name) / "journals",
                "port-c",
            )


if __name__ == "__main__":
    unittest.main()
