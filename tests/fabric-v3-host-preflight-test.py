#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("fabric-v3-host-preflight.py")
SPEC = importlib.util.spec_from_file_location("fabric_v3_host_preflight", MODULE_PATH)
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


class HostPreflightTests(unittest.TestCase):
    def gateway_observation(self, *args):
        self.assertEqual(args, ("ip", "-j", "-4", "address", "show", "dev", "virbr0"))
        return json.dumps([{"ifname": "virbr0", "addr_info": [
            {"family": "inet", "local": "192.168.122.1", "prefixlen": 24}
        ]}])

    def test_virsh_name_rows_are_trimmed_and_empty_rows_ignored(self):
        self.assertEqual(preflight._names("default     \nforeign      \n\n"), ["default", "foreign"])

    def test_address_selection_uses_live_dhcp_range_and_ignores_failed_lease(self):
        snapshot = {
            "network": "default",
            "network_xml": """<network><name>default</name><bridge name='virbr0'/>
              <ip address='192.168.122.1' netmask='255.255.255.0'><dhcp>
                <range start='192.168.122.100' end='192.168.122.105'/>
                <host mac='52:54:00:00:00:01' ip='192.168.122.100'/>
              </dhcp></ip></network>""",
            "bridge": "virbr0",
            "bridge_addresses": [{"ifname": "virbr0", "address": "52:54:00:09:a6:a0"}],
            "links": [{"ifname": "virbr0", "address": "52:54:00:09:a6:a0"}],
            "dhcp_leases": "192.168.122.101 FAILED\n",
            "neighbors": [{"dst": "192.168.122.102", "state": "FAILED"}],
            "domains": [],
        }
        with patch.object(preflight, "_run", side_effect=self.gateway_observation), \
                patch.object(preflight, "_arp_in_use", return_value=False):
            selected = preflight.select_addresses(snapshot)
        self.assertEqual(selected["selected"], [
            "192.168.122.105", "192.168.122.104", "192.168.122.103"
        ])
        self.assertEqual(selected["network"], "192.168.122.0/24")

    def test_live_arp_response_skips_address(self):
        snapshot = {
            "network": "default",
            "network_xml": """<network><name>default</name><bridge name='virbr0'/>
              <ip address='192.168.122.1' netmask='255.255.255.0'><dhcp>
                <range start='192.168.122.100' end='192.168.122.105'/>
              </dhcp></ip></network>""",
            "bridge": "virbr0",
            "bridge_addresses": [{"ifname": "virbr0", "address": "52:54:00:09:a6:a0"}],
            "links": [{"ifname": "virbr0", "address": "52:54:00:09:a6:a0"}],
            "dhcp_leases": "",
            "neighbors": [],
            "domains": [],
        }

        def arp(_interface, _source_ip, _source_mac, target, _timeout=0.25):
            return str(target) == "192.168.122.105"

        with patch.object(preflight, "_run", side_effect=self.gateway_observation), \
                patch.object(preflight, "_arp_in_use", side_effect=arp):
            selected = preflight.select_addresses(snapshot)
        self.assertEqual(selected["selected"], [
            "192.168.122.104", "192.168.122.103", "192.168.122.102"
        ])

    def test_attached_foreign_domain_blocks_address_selection(self):
        snapshot = {
            "network": "default",
            "network_xml": "<network><bridge name='virbr0'/><ip address='192.168.122.1' netmask='255.255.255.0'><dhcp><range start='192.168.122.100' end='192.168.122.105'/></dhcp></ip></network>",
            "bridge": "virbr0",
            "bridge_addresses": [],
            "links": [{"ifname": "virbr0", "address": "52:54:00:09:a6:a0"}],
            "dhcp_leases": "",
            "neighbors": [],
            "domains": [{"name": "foreign-domain"}],
        }
        domain_xml = "<domain><devices><interface><source network='default'/><mac address='52:54:00:00:00:01'/></interface></devices></domain>"
        def command(*args):
            if args[:3] == ("ip", "-j", "-4"):
                return '[{"ifname":"virbr0","addr_info":[{"family":"inet","local":"192.168.122.1","prefixlen":24}]}]'
            return domain_xml

        with patch.object(preflight, "_run", side_effect=command), patch.object(preflight, "_arp_in_use") as arp:
            with self.assertRaisesRegex(RuntimeError, "pre-existing libvirt domains attached"):
                preflight.select_addresses(snapshot)
        arp.assert_not_called()

    def test_foreign_inventory_diff_is_reported(self):
        before = {"domains": [{"name": "foreign"}], "networks": [], "pools": [], "links": []}
        after = {"domains": [], "networks": [], "pools": [], "links": []}
        self.assertEqual(preflight.compare_inventory(before, after), ["domains"])

    def test_run_owned_addresses_are_excluded_from_foreign_lease_comparison(self):
        before = {"domains": [], "networks": [], "pools": [], "links": [], "dhcp_leases": ""}
        after = {"domains": [], "networks": [], "pools": [], "links": [],
                 "dhcp_leases": "192.168.122.105 52:54:00:00:00:05 ipv4"}
        self.assertEqual(preflight.compare_inventory(before, after, {"192.168.122.105"}), [])

    def test_pool_config_fingerprint_ignores_capacity_telemetry_but_keeps_configuration(self):
        first = """<pool type='dir'><name>images</name><uuid>abc</uuid>
          <capacity unit='bytes'>1000</capacity><allocation unit='bytes'>100</allocation>
          <available unit='bytes'>900</available><target><path>/srv/images</path></target></pool>"""
        changed_capacity = first.replace(">1000<", ">1100<").replace(">100<", ">120<").replace(">900<", ">980<")
        changed_path = changed_capacity.replace("/srv/images", "/srv/other")
        self.assertEqual(preflight._pool_config_sha(first), preflight._pool_config_sha(changed_capacity))
        self.assertNotEqual(preflight._pool_config_sha(first), preflight._pool_config_sha(changed_path))

    def test_bridge_link_fingerprint_ignores_timer_counters_but_keeps_configuration(self):
        def observed(gc_timer, stp_state=1):
            return [{"ifname": "virbr0", "address": "52:54:00:00:00:01", "mtu": 1500,
                     "flags": ["UP"], "linkinfo": {"info_kind": "bridge", "info_data": {
                         "gc_timer": gc_timer, "hello_timer": 0.2, "tcn_timer": 0.0,
                         "topology_change_timer": 0.0, "stp_state": stp_state,
                         "vlan_filtering": 0}}}]

        with patch.object(preflight, "_run", side_effect=lambda *_: json.dumps(observed(1.2))):
            first = preflight._stable_links()
        with patch.object(preflight, "_run", side_effect=lambda *_: json.dumps(observed(9.8))):
            timer_change = preflight._stable_links()
        with patch.object(preflight, "_run", side_effect=lambda *_: json.dumps(observed(9.8, 0))):
            config_change = preflight._stable_links()
        self.assertEqual(first, timer_change)
        self.assertNotEqual(first, config_change)

    def test_foreign_pool_or_link_configuration_change_is_reported(self):
        before = {"domains": [], "networks": [], "pools": [{"name": "foreign-pool", "xml_sha256": "a"}],
                  "links": [{"ifname": "foreign0", "mtu": 1500}]}
        after = {"domains": [], "networks": [], "pools": [{"name": "foreign-pool", "xml_sha256": "b"}],
                 "links": [{"ifname": "foreign0", "mtu": 1400}]}
        self.assertEqual(preflight.compare_inventory(before, after), ["pools", "links"])


if __name__ == "__main__":
    unittest.main()
