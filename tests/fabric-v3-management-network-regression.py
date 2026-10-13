#!/usr/bin/env python3
"""Regression tests for collision-safe, run-owned libvirt management networks."""
from __future__ import annotations

import importlib.util
import ipaddress
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "fabric_v3_management_network", ROOT / "fabric-v3-management-network.py"
)
assert SPEC and SPEC.loader
management = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(management)


def network(name: str, uuid: str, address: str, netmask: str) -> dict[str, str]:
    return {
        "name": name,
        "uuid": uuid,
        "xml": (
            f"<network><name>{name}</name><uuid>{uuid}</uuid>"
            f"<ip address='{address}' netmask='{netmask}'/></network>"
        ),
    }


class ManagementNetworkRegression(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshot = {
            "routes": [
                {"dst": "default", "gateway": "192.0.2.1"},
                {"dst": "172.16.0.0/16", "dev": "docker0"},
            ],
            "networks": [
                network("default", "uuid-default", "192.168.122.1", "255.255.255.0"),
                network("foreign", "uuid-foreign", "172.20.0.1", "255.255.0.0"),
            ],
            "domains": [
                {
                    "name": "foreign-vm",
                    "uuid": "uuid-vm",
                    "interfaces": [
                        {"mac": "52:54:00:00:00:01", "network": "default", "bridge": None}
                    ],
                }
            ],
            "pools": [{"name": "default", "uuid": "pool-default", "target": "/var/lib/libvirt/images"}],
            "addresses": [
                {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
                {"ifname": "virbr0", "addr_info": [{"family": "inet", "local": "192.168.122.1", "prefixlen": 24}]},
            ],
            "neighbors": [{"dst": "192.168.122.2", "dev": "virbr0"}],
            "links": [
                {"ifname": "virbr0", "address": "52:54:00:00:00:02"},
                {"ifname": "docker0", "address": "02:42:ac:11:00:01"},
            ],
        }

    def test_selects_unused_subnet_and_three_addresses_from_inventory(self) -> None:
        plan = management.select_network_plan(self.snapshot, "retirement-run-1")
        selected = ipaddress.ip_network(plan["subnet"])
        occupied = [ipaddress.ip_network("192.168.122.0/24"), ipaddress.ip_network("172.16.0.0/16"), ipaddress.ip_network("172.20.0.0/16")]
        self.assertEqual(selected.prefixlen, 29)
        self.assertTrue(all(not selected.overlaps(item) for item in occupied))
        self.assertEqual(len(plan["addresses"]), 3)
        self.assertEqual(len(set(plan["addresses"].values())), 3)
        self.assertTrue(all(ipaddress.ip_address(value) in selected for value in plan["addresses"].values()))
        self.assertNotIn(plan["gateway"], plan["addresses"].values())
        self.assertEqual(plan["run_id"], "retirement-run-1")

    def test_ignores_default_route_but_rejects_all_overlapping_specific_routes(self) -> None:
        plan = management.select_network_plan(self.snapshot, "retirement-run-2")
        self.assertTrue(ipaddress.ip_network(plan["subnet"]).is_private)
        blocked = dict(self.snapshot)
        blocked["routes"] = [
            {"dst": "10.0.0.0/8"},
            {"dst": "172.16.0.0/12"},
            {"dst": "192.168.0.0/16"},
            {"dst": "default"},
        ]
        with self.assertRaises(management.EnvironmentGap):
            management.select_network_plan(blocked, "no-space")

    def test_existing_network_subnets_are_excluded_even_when_inactive(self) -> None:
        snapshot = dict(self.snapshot)
        snapshot["networks"] = [network("inactive", "uuid-x", "172.16.0.1", "255.240.0.0")]
        plan = management.select_network_plan(snapshot, "inactive-network")
        self.assertFalse(ipaddress.ip_network(plan["subnet"]).overlaps(ipaddress.ip_network("172.16.0.0/12")))

    def test_management_mac_addresses_do_not_collide_with_defined_guest_macs(self) -> None:
        snapshot = dict(self.snapshot)
        first = management.select_network_plan(snapshot, "mac-collision")
        snapshot["domains"] = [
            {
                "name": "foreign-vm",
                "uuid": "uuid-vm",
                "interfaces": [{"mac": next(iter(first["macs"].values()))}],
            }
        ]
        second = management.select_network_plan(snapshot, "mac-collision")
        self.assertTrue(set(first["macs"].values()).isdisjoint(second["macs"].values()))

    def test_management_macs_avoid_host_link_addresses(self) -> None:
        first = management.select_network_plan(self.snapshot, "host-mac-collision")
        snapshot = dict(self.snapshot)
        snapshot["links"] = [
            {"ifname": "foreign0", "address": next(iter(first["macs"].values()))}
        ]
        second = management.select_network_plan(snapshot, "host-mac-collision")
        self.assertTrue(set(first["macs"].values()).isdisjoint(second["macs"].values()))

    def test_duplicate_deterministic_network_uuid_fails_closed(self) -> None:
        plan = management.select_network_plan(self.snapshot, "uuid-collision")
        snapshot = dict(self.snapshot)
        snapshot["networks"] = [*snapshot["networks"], network("foreign-name", plan["network_uuid"], "10.0.0.1", "255.255.255.0")]
        with self.assertRaisesRegex(management.EnvironmentGap, "UUID already exists"):
            management.select_network_plan(snapshot, "uuid-collision")

    def test_post_cleanup_absence_and_foreign_inventory_are_required(self) -> None:
        plan = management.select_network_plan(self.snapshot, "cleanup-run")
        after = dict(self.snapshot)
        result = management.verify_cleanup_snapshot(self.snapshot, after, plan)
        self.assertTrue(result["foreign_networks_unchanged"])
        self.assertTrue(result["foreign_pools_unchanged"])

        remaining_network = dict(after)
        remaining_network["networks"] = [*after["networks"], {
            "name": plan["network_name"], "uuid": plan["network_uuid"],
            "xml": management.network_xml(plan),
        }]
        with self.assertRaisesRegex(management.EnvironmentGap, "network remains"):
            management.verify_cleanup_snapshot(self.snapshot, remaining_network, plan)

        remaining_bridge = dict(after)
        remaining_bridge["links"] = [*after["links"], {"ifname": plan["bridge_name"]}]
        with self.assertRaisesRegex(management.EnvironmentGap, "bridge remains"):
            management.verify_cleanup_snapshot(self.snapshot, remaining_bridge, plan)

    def test_foreign_route_address_pool_link_and_domain_changes_fail(self) -> None:
        plan = management.select_network_plan(self.snapshot, "foreign-change")
        changes = (
            ("routes", [*self.snapshot["routes"], {"dst": "203.0.113.0/24", "dev": "eth9"}]),
            ("addresses", [*self.snapshot["addresses"], {"ifname": "eth9", "addr_info": [{"family": "inet", "local": "203.0.113.2", "prefixlen": 24}]}]),
            ("pools", [*self.snapshot["pools"], {"name": "foreign-pool", "uuid": "pool-2"}]),
            ("links", [*self.snapshot["links"], {"ifname": "foreign1", "address": "02:00:00:00:00:01"}]),
            ("domains", [*self.snapshot["domains"], {"name": "other-vm", "uuid": "other-uuid", "interfaces": []}]),
        )
        for field, value in changes:
            with self.subTest(field=field):
                after = dict(self.snapshot)
                after[field] = value
                with self.assertRaises(management.EnvironmentGap):
                    management.verify_cleanup_snapshot(self.snapshot, after, plan)

    def test_network_identity_and_xml_are_run_owned_and_have_no_dhcp_pool(self) -> None:
        plan = management.select_network_plan(self.snapshot, "xml-run")
        xml = management.network_xml(plan)
        self.assertIn("o3k-fabric-v3-retirement-v1 run=xml-run", xml)
        self.assertIn(f"<name>{plan['network_name']}</name>", xml)
        self.assertIn(f"<bridge name='{plan['bridge_name']}'", xml)
        self.assertIn("<forward mode='nat'", xml)
        self.assertIn(f"address='{plan['gateway']}'", xml)
        self.assertNotIn("<dhcp>", xml)

    def test_libvirt_resource_active_state_is_parsed_and_required(self) -> None:
        self.assertEqual(management._resource_is_active("Name: default\nActive: yes\n", "network", "default"), "yes")
        self.assertEqual(management._resource_is_active("Name: images\nState: running\n", "storage pool", "images"), "yes")
        self.assertEqual(management._resource_is_active("Name: images\nState: inactive\n", "storage pool", "images"), "no")
        with self.assertRaisesRegex(management.EnvironmentGap, "active state is missing or invalid"):
            management._resource_is_active("Name: images\n", "storage pool", "images")
        with self.assertRaisesRegex(management.EnvironmentGap, "active state is missing or invalid"):
            management._resource_is_active("Active: yes\nActive: no\n", "network", "default")


if __name__ == "__main__":
    unittest.main()
