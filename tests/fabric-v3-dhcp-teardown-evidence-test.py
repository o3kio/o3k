#!/usr/bin/env python3
"""Regression coverage for Fabric DHCP provider teardown observations."""
from __future__ import annotations

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from fabric_v3_dhcp_teardown_evidence import (  # noqa: E402
    CleanupResidueError,
    HarnessEvidenceError,
    validate_dhcp_teardown,
)

RUN = "campaign-123"
REALM = "realm-456"
HOST = "b"
BASE = f"/var/lib/o3k-fabric-v3/{RUN}/network/dhcp"
FABRIC = f"{BASE}/fabric"
DIRECTORY = f"{FABRIC}/{REALM}"
OWNER_PATH = f"{DIRECTORY}/fabric-dhcp-ownership.json"
STATE_PATH = f"{DIRECTORY}/state.json"
CONFIG_PATH = f"{DIRECTORY}/dnsmasq.conf"
LEASES_PATH = f"{DIRECTORY}/dnsmasq.leases"


def capture(path: str, record: dict) -> str:
    return f"{path}\n{json.dumps(record, indent=2)}\n"


def owner(**overrides: object) -> dict:
    result = {
        "schema_version": 1,
        "realm_id": REALM,
        "local_host": "host-b",
        "authority_host": "host-a",
        "realm_generation": 6,
        "directory_generation": 6,
        "binding_generation": 1,
        "local_fabric_generation": 1,
        "dhcp_enabled": False,
        "gateway": None,
        "tenant_mtu": 1390,
        "pending": False,
        "withdrawn": True,
    }
    result.update(overrides)
    return result


def inventory(files: dict[str, tuple[str, int]] | None = None) -> str:
    files = files or {}
    lines = []
    if files:
        lines.extend((f"d\t{BASE}\t0", f"d\t{FABRIC}\t0", f"d\t{DIRECTORY}\t0"))
    for path, (kind, size) in sorted(files.items()):
        lines.append(f"{kind}\t{path}\t{size}")
    return "\n".join(lines) + ("\n" if lines else "")


def rendered_files(
    config: str | None = None, leases: str | None = None
) -> str:
    return json.dumps({"dnsmasq.conf": config, "dnsmasq.leases": leases})


def authority_config() -> str:
    return (
        "# Managed by o3k-dhcp; do not edit.\n"
        "interface=br-o3k-test\n"
        f"dhcp-leasefile={DIRECTORY}/dnsmasq.leases\n"
        "dhcp-host=02:00:00:00:00:01,10.0.0.2\n"
    )


def dormant_config() -> str:
    return "".join(
        line for line in authority_config().splitlines(keepends=True)
        if not line.startswith("dhcp-host=")
    )


class DhcpTeardownEvidenceTests(unittest.TestCase):
    def validate(
        self,
        files: str,
        state: str = "",
        ownership: str = "",
        rendered: str | None = None,
        expected_config: str | None = None,
    ) -> dict:
        return validate_dhcp_teardown(
            RUN,
            REALM,
            HOST,
            files,
            state,
            ownership,
            rendered if rendered is not None else rendered_files(),
            expected_config,
        )

    def test_absent_root_passes(self):
        result = self.validate("")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["tombstone"], "absent")

    def test_empty_directory_tree_passes(self):
        result = self.validate(f"d\t{BASE}\t0\nd\t{FABRIC}\t0\n")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["tombstone"], "absent")

    def test_withdrawn_tombstone_only_passes(self):
        result = self.validate(
            inventory({OWNER_PATH: ("f", 400)}),
            ownership=capture(OWNER_PATH, owner()),
        )
        self.assertEqual(result["tombstone"], "withdrawn_nonpending")
        self.assertEqual(result["state_json"], "absent")

    def test_withdrawn_tombstone_with_empty_state_passes(self):
        files = inventory({OWNER_PATH: ("f", 400), STATE_PATH: ("f", 50)})
        result = self.validate(
            files,
            capture(STATE_PATH, {"config": None, "bindings": {}}),
            capture(OWNER_PATH, owner()),
        )
        self.assertEqual(result["state_json"], "empty")

    def test_exact_dormant_config_and_empty_lease_file_pass(self):
        files = inventory(
            {
                OWNER_PATH: ("f", 400),
                STATE_PATH: ("f", 50),
                CONFIG_PATH: ("f", 400),
                LEASES_PATH: ("f", 0),
            }
        )
        result = self.validate(
            files,
            capture(STATE_PATH, {"config": None, "bindings": {}}),
            capture(OWNER_PATH, owner()),
            rendered_files(dormant_config(), ""),
            expected_config=authority_config(),
        )
        self.assertEqual(result["rendered_config"], "dormant")
        self.assertEqual(result["lease_file"], "empty")

    def test_active_state_or_bindings_fail(self):
        for state in (
            {"config": {"enabled": True}, "bindings": {}},
            {"config": None, "bindings": {"port-1": {"address": "10.0.0.2"}}},
        ):
            with self.subTest(state=state), self.assertRaises(CleanupResidueError):
                self.validate(
                    inventory({OWNER_PATH: ("f", 400), STATE_PATH: ("f", 80)}),
                    capture(STATE_PATH, state),
                    capture(OWNER_PATH, owner()),
                )

    def test_nonempty_lease_file_fails(self):
        with self.assertRaises(CleanupResidueError):
            self.validate(
                inventory(
                    {
                        OWNER_PATH: ("f", 400),
                        STATE_PATH: ("f", 50),
                        LEASES_PATH: ("f", 24),
                    }
                ),
                capture(STATE_PATH, {"config": None, "bindings": {}}),
                capture(OWNER_PATH, owner()),
            )

    def test_unexpected_files_and_symlinks_fail(self):
        for path, kind in (
            (f"{DIRECTORY}/gateway-address-ownership.json", "f"),
            (f"{DIRECTORY}/unknown.json", "f"),
            (OWNER_PATH, "l"),
        ):
            with self.subTest(path=path, kind=kind), self.assertRaises(CleanupResidueError):
                self.validate(inventory({path: (kind, 10)}))

    def test_rendered_config_requires_empty_canonical_state(self):
        with self.assertRaises(CleanupResidueError):
            self.validate(
                inventory({OWNER_PATH: ("f", 400), CONFIG_PATH: ("f", 400)}),
                ownership=capture(OWNER_PATH, owner()),
                rendered=rendered_files(dormant_config()),
                expected_config=authority_config(),
            )

    def test_dormant_config_must_be_generated_for_exact_run_realm(self):
        files = inventory(
            {
                OWNER_PATH: ("f", 400),
                STATE_PATH: ("f", 50),
                CONFIG_PATH: ("f", 400),
            }
        )
        state = capture(STATE_PATH, {"config": None, "bindings": {}})
        owner_capture = capture(OWNER_PATH, owner())
        for config in (
            "arbitrary content\n",
            dormant_config().replace(
                f"{DIRECTORY}/dnsmasq.leases", "/var/tmp/foreign-leases"
            ),
            dormant_config().replace("# Managed by o3k-dhcp; do not edit.", ""),
            dormant_config() + "dhcp-host=02:00:00:00:00:02,10.0.0.3\n",
        ):
            with self.subTest(config=config), self.assertRaises(CleanupResidueError):
                self.validate(
                    files,
                    state,
                    owner_capture,
                    rendered_files(config),
                    expected_config=authority_config(),
                )

    def test_rendered_file_capture_must_match_inventory(self):
        with self.assertRaises(HarnessEvidenceError):
            self.validate(
                inventory({OWNER_PATH: ("f", 400)}),
                ownership=capture(OWNER_PATH, owner()),
                rendered=rendered_files(dormant_config()),
            )
        with self.assertRaises(HarnessEvidenceError):
            self.validate(
                inventory({OWNER_PATH: ("f", 400), LEASES_PATH: ("f", 0)}),
                ownership=capture(OWNER_PATH, owner()),
                rendered=rendered_files(leases="stale lease record"),
            )

    def test_withdrawn_tombstone_metadata_is_validated(self):
        invalid = (
            {"schema_version": True},
            {"pending": True},
            {"withdrawn": False},
            {"dhcp_enabled": True},
            {"dhcp_enabled": 0},
            {"pending": 0},
            {"withdrawn": 1},
            {"authority_host": "foreign-host"},
            {"realm_generation": True},
            {"directory_generation": 7},
            {"binding_generation": -1},
            {"local_fabric_generation": "1"},
            {"tenant_mtu": 0},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(CleanupResidueError):
                self.validate(
                    inventory({OWNER_PATH: ("f", 400)}),
                    ownership=capture(OWNER_PATH, owner(**changes)),
                )

    def test_wrong_realm_or_host_identity_fails(self):
        for changes in ({"realm_id": "foreign-realm"}, {"local_host": "host-a"}):
            with self.subTest(changes=changes), self.assertRaises(CleanupResidueError):
                self.validate(
                    inventory({OWNER_PATH: ("f", 400)}),
                    ownership=capture(OWNER_PATH, owner(**changes)),
                )

    def test_wrong_run_path_and_extra_realm_are_not_ignored(self):
        foreign = f"/var/lib/o3k-fabric-v3/foreign/network/dhcp/fabric/{REALM}/fabric-dhcp-ownership.json"
        with self.assertRaises(CleanupResidueError):
            self.validate(inventory({foreign: ("f", 400)}))
        extra_realm = f"{FABRIC}/foreign-realm/fabric-dhcp-ownership.json"
        with self.assertRaises(CleanupResidueError):
            self.validate(inventory({extra_realm: ("f", 400)}))

    def test_uncaptured_or_malformed_observation_is_harness_gap(self):
        with self.assertRaises(HarnessEvidenceError):
            self.validate(inventory({OWNER_PATH: ("f", 400)}))
        with self.assertRaises(HarnessEvidenceError):
            self.validate("f\t/path\tbad\n")
        with self.assertRaises(HarnessEvidenceError):
            self.validate(
                inventory({OWNER_PATH: ("f", 400)}),
                ownership=OWNER_PATH + "\nnot-json\n",
            )
        with self.assertRaises(HarnessEvidenceError):
            self.validate(
                inventory({OWNER_PATH: ("f", 400)}),
                ownership=capture(OWNER_PATH, owner()),
                rendered="not-json",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
