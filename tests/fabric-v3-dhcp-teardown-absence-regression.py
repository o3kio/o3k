#!/usr/bin/env python3
"""Regression tests for final DHCP provider-state cleanup evidence."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "fabric_v3_dhcp_teardown_absence",
    ROOT / "fabric-v3-dhcp-teardown-absence.py",
)
assert SPEC and SPEC.loader
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class DhcpTeardownAbsenceRegression(unittest.TestCase):
    def setUp(self) -> None:
        self.run_id = "20261013T030336Z-retire-d733-readinessfix"
        self.realm_id = "01a1333c-d8a1-70e0-860f-41361d958d48"
        self.root = f"/var/lib/o3k-fabric-v3/{self.run_id}/network/dhcp"
        self.host = "b"
        self.owner = {
            "schema_version": 1,
            "realm_id": self.realm_id,
            "local_host": "host-b",
            "authority_host": "host-a",
            "realm_generation": 6,
            "directory_generation": 6,
            "binding_generation": 1,
            "dhcp_enabled": False,
            "gateway": None,
            "pending": False,
            "withdrawn": True,
        }
        self.state = {"config": None, "bindings": {}}

    def snapshot(self, filenames=("fabric-dhcp-ownership.json",), state=None, owner=None, processes=""):
        directory = f"{self.root}/fabric/{self.realm_id}"
        paths = [f"f {directory}/{filename}" for filename in filenames]
        paths = [f"d {self.root}/fabric", f"d {self.root}/fabric/{self.realm_id}"] + paths
        state_text = ""
        if "state.json" in filenames:
            state_text = f"{directory}/state.json\n{json.dumps(state or self.state, indent=2)}\n"
        owner_text = ""
        if "fabric-dhcp-ownership.json" in filenames:
            owner_text = (
                f"{directory}/fabric-dhcp-ownership.json\n"
                f"{json.dumps(owner or self.owner, indent=2)}\n"
            )
        return helper.validate_host(
            self.host,
            self.run_id,
            "\n".join(paths) + ("\n" if paths else ""),
            state_text,
            owner_text,
            processes,
        )

    def test_withdrawn_tombstone_only_is_valid_post_teardown(self):
        result = self.snapshot()
        self.assertEqual(result["result"], "PASS")
        self.assertTrue(result["active_dhcp_state_absent"])

    def test_empty_realm_directory_without_tombstone_is_rejected(self):
        listing = f"d {self.root}/fabric\nd {self.root}/fabric/{self.realm_id}\n"
        with self.assertRaisesRegex(helper.EvidenceError, "tombstone is absent"):
            helper.validate_host(self.host, self.run_id, listing, "", "", "")

    def test_cleared_state_and_runtime_files_are_valid(self):
        result = self.snapshot(
            filenames=(
                "dnsmasq.conf",
                "dnsmasq.leases",
                "fabric-dhcp-ownership.json",
                "state.json",
            ),
            state={"config": None, "bindings": {}},
        )
        self.assertEqual(result["result"], "PASS")

    def test_active_dhcp_configuration_is_rejected(self):
        with self.assertRaisesRegex(helper.EvidenceError, "active DHCP state"):
            self.snapshot(
                filenames=("fabric-dhcp-ownership.json", "state.json"),
                state={"config": {"subnet": "active"}, "bindings": {}},
            )

    def test_live_binding_is_rejected(self):
        with self.assertRaisesRegex(helper.EvidenceError, "active DHCP state"):
            self.snapshot(
                filenames=("fabric-dhcp-ownership.json", "state.json"),
                state={"config": None, "bindings": {"port": {}}},
            )

    def test_pending_tombstone_is_rejected(self):
        owner = dict(self.owner, pending=True)
        with self.assertRaisesRegex(helper.EvidenceError, "pending"):
            self.snapshot(owner=owner)

    def test_non_withdrawn_or_enabled_tombstone_is_rejected(self):
        for patch in ({"withdrawn": False}, {"dhcp_enabled": True}):
            with self.subTest(patch=patch), self.assertRaises(helper.EvidenceError):
                self.snapshot(owner=dict(self.owner, **patch))

    def test_unexpected_run_owned_file_is_rejected(self):
        with self.assertRaisesRegex(helper.EvidenceError, "unexpected run-owned DHCP file"):
            self.snapshot(filenames=("fabric-dhcp-ownership.json", "unexpected.db"))

    def test_symlink_or_non_regular_marker_is_rejected(self):
        directory = f"{self.root}/fabric/{self.realm_id}"
        listing = (
            f"d {self.root}/fabric\n"
            f"d {directory}\n"
            f"l {directory}/fabric-dhcp-ownership.json\n"
        )
        with self.assertRaisesRegex(helper.EvidenceError, "non-regular or misplaced"):
            helper.validate_host(self.host, self.run_id, listing, "", "", "")

    def test_runtime_files_without_inactive_state_are_rejected(self):
        with self.assertRaisesRegex(helper.EvidenceError, "no inactive state record"):
            self.snapshot(filenames=("fabric-dhcp-ownership.json", "dnsmasq.conf"))

    def test_run_owned_process_is_rejected(self):
        with self.assertRaisesRegex(helper.EvidenceError, "process remains"):
            self.snapshot(processes=f"/usr/sbin/dnsmasq --conf-file={self.run_id}/dnsmasq.conf")

    def test_path_outside_exact_run_root_is_rejected(self):
        with self.assertRaisesRegex(helper.EvidenceError, "escaped the exact run-owned root"):
            helper.validate_host(
                self.host,
                self.run_id,
                "f /var/lib/o3k-fabric-v3/foreign/network/dhcp/fabric/realm/fabric-dhcp-ownership.json\n",
                "",
                "",
                "",
            )

    def test_missing_tombstone_is_rejected_when_state_remains(self):
        with self.assertRaisesRegex(helper.EvidenceError, "tombstone is absent"):
            self.snapshot(filenames=("state.json",), state=self.state)


if __name__ == "__main__":
    unittest.main()
