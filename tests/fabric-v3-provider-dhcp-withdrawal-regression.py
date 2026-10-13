#!/usr/bin/env python3
"""Regression tests for observing a durable DHCP withdrawal tombstone."""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "fabric_v3_provider_dhcp_withdrawal",
    ROOT / "fabric-v3-provider-dhcp-withdrawal.py",
)
assert SPEC and SPEC.loader
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class ProviderDhcpWithdrawalRegression(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = {
            "root_exists": True,
            "status": "present",
            "files": [{"path": "fabric-dhcp-ownership.json", "kind": "file"}],
        }
        self.ownership = {"realms": {}}
        self.tombstone = {
            "schema_version": 1,
            "realm_id": "realm-campaign",
            "local_host": "host-c",
            "authority_host": "host-a",
            "realm_generation": 9,
            "directory_generation": 9,
            "binding_generation": 3,
            "local_fabric_generation": 1,
            "dhcp_enabled": False,
            "pending": False,
            "withdrawn": True,
        }
        self.remove_row = {
            "action": "Remove",
            "state": "succeeded",
            "command_id": "remove-c-9",
            "operation_id": "operation-c-9",
            "realm_id": "realm-campaign",
            "target_host_id": "host-c",
            "target_agent_id": "network-agent-c",
            "target_agent_epoch": "network-epoch-c-1",
            "directory_generation": 9,
            "binding_generation": 3,
            "fabric_generation": 1,
            "idempotency_key": "remove-key-c-9",
            "fingerprint_sha256": "remove-fingerprint-c-9",
        }
        self.endpoint_id = "endpoint-c"
        self.agent_journal = {
            "plans": [
                {
                    "action": "Remove",
                    "status": "Succeeded",
                    "command_id": "remove-c-9",
                    "operation_id": "operation-c-9",
                    "idempotency_key": "remove-key-c-9",
                    "target": {"agent_id": "network-agent-c", "agent_epoch": "network-epoch-c-1"},
                    "plan": {
                        "node_id": "host-c",
                        "operation_id": "operation-c-9",
                        "fingerprint_sha256": "remove-fingerprint-c-9",
                        "fabric": {
                            "realm_id": "realm-campaign",
                            "local_host": "host-c",
                            "local_fabric_generation": 1,
                            "directory_generation": 9,
                            "directory": {
                                "realm_id": "realm-campaign",
                                "directory_generation": 9,
                                "entries": [
                                    {"selected_host": "host-a"},
                                    {"selected_host": "host-b"},
                                ],
                            },
                            "encapsulation": {"binding_generation": 3},
                        }
                    },
                }
            ]
        }

    def validate(self):
        return helper.validate_withdrawal(
            self.tree,
            self.ownership,
            self.tombstone,
            self.remove_row,
            self.agent_journal,
            self.endpoint_id,
        )

    def test_matching_durable_tombstone_is_accepted_as_withdrawn(self):
        result = self.validate()
        self.assertTrue(result["active_dhcp_state_absent"])
        self.assertTrue(result["durable_tombstone_present"])
        self.assertTrue(result["withdrawn"])

    def test_active_state_file_is_rejected(self):
        self.tree["files"].append({"path": "state.json", "kind": "file"})
        with self.assertRaisesRegex(helper.EvidenceError, "active state"):
            self.validate()

    def test_symlink_tombstone_is_rejected(self):
        self.tree["files"][0]["kind"] = "symlink"
        with self.assertRaisesRegex(helper.EvidenceError, "non-regular"):
            self.validate()

    def test_missing_tombstone_is_rejected(self):
        self.tree["files"] = []
        self.tree["status"] = "empty"
        with self.assertRaisesRegex(helper.EvidenceError, "tombstone is absent"):
            self.validate()

    def test_provider_realm_ownership_is_rejected(self):
        self.ownership["realms"]["realm-campaign"] = {}
        with self.assertRaisesRegex(helper.EvidenceError, "still contains"):
            self.validate()

    def test_removed_endpoint_in_other_realm_is_rejected(self):
        self.ownership["realms"]["other-realm"] = {
            "endpoint_taps": {"endpoint-c": {}},
            "pending_endpoint_taps": {},
        }
        with self.assertRaisesRegex(helper.EvidenceError, "removed endpoint"):
            self.validate()

    def test_pending_or_live_tombstone_is_rejected(self):
        for field, value in (("pending", True), ("withdrawn", False), ("dhcp_enabled", True)):
            with self.subTest(field=field):
                original = self.tombstone[field]
                self.tombstone[field] = value
                with self.assertRaisesRegex(helper.EvidenceError, "tombstone"):
                    self.validate()
                self.tombstone[field] = original

    def test_tombstone_identity_and_generation_must_match_remove_plan(self):
        for field, value in (
            ("realm_id", "other-realm"),
            ("local_host", "host-a"),
            ("realm_generation", 8),
            ("directory_generation", 8),
            ("binding_generation", 2),
        ):
            with self.subTest(field=field):
                original = self.tombstone[field]
                self.tombstone[field] = value
                with self.assertRaisesRegex(helper.EvidenceError, "tombstone"):
                    self.validate()
                self.tombstone[field] = original

    def test_remove_must_be_observed_successful_and_dispatched_to_c(self):
        self.remove_row["state"] = "applying"
        with self.assertRaisesRegex(helper.EvidenceError, "not successful"):
            self.validate()
        self.remove_row["state"] = "succeeded"
        self.remove_row["target_agent_id"] = "network-agent-b"
        with self.assertRaisesRegex(helper.EvidenceError, "target is not"):
            self.validate()

    def test_durable_row_must_match_journal_generations_and_agent_epoch(self):
        cases = (
            ("realm_id", "other-realm"),
            ("directory_generation", 8),
            ("binding_generation", 2),
            ("fabric_generation", 2),
            ("target_agent_epoch", "stale-epoch"),
            ("fingerprint_sha256", "stale-fingerprint"),
        )
        for field, value in cases:
            with self.subTest(field=field):
                original = self.remove_row[field]
                self.remove_row[field] = value
                with self.assertRaises(helper.EvidenceError):
                    self.validate()
                self.remove_row[field] = original

    def test_durable_row_must_match_journal_idempotency(self):
        self.remove_row["idempotency_key"] = "another-operation"
        with self.assertRaisesRegex(helper.EvidenceError, "identity/generation disagree"):
            self.validate()

    def test_remove_journal_plan_must_be_unique_and_reduced(self):
        self.agent_journal["plans"].append(self.agent_journal["plans"][0])
        with self.assertRaisesRegex(helper.EvidenceError, "exactly one"):
            self.validate()
        self.agent_journal["plans"].pop()
        entries = self.agent_journal["plans"][0]["plan"]["fabric"]["directory"]["entries"]
        entries.append({"selected_host": "host-c"})
        with self.assertRaisesRegex(helper.EvidenceError, "invalid reduced Realm"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
