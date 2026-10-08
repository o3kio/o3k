#!/usr/bin/env python3
"""Regression for multiline tcpdump DHCP packet correlation."""
import importlib.util
import pathlib
import tempfile
import unittest
from argparse import Namespace
from unittest.mock import patch


HELPER = pathlib.Path(__file__).with_name("fabric-v3-remote-dhcp-boundary-capture.py")
SPEC = importlib.util.spec_from_file_location("boundary_capture", HELPER)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TcpdumpPacketBlockTests(unittest.TestCase):
    def test_real_multiline_discover_keeps_mac_xid_and_option_53_together(self) -> None:
        text = """1791473413.294692 02:61:72:20:f4:77 > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 342:
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 02:61:72:20:f4:77, length 300, xid 0x2e4a6714
      DHCP-Message (53), length 1: Discover
1791473416.815165 02:61:72:20:f4:77 > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 342:
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 02:61:72:20:f4:77, length 300, xid 0x2e4a6714
      DHCP-Message (53), length 1: Discover
"""
        blocks = MODULE.tcpdump_packet_blocks(text)
        self.assertEqual(len(blocks), 2)
        discovers = [block for block in blocks
                     if "02:61:72:20:f4:77" in block and "DHCP-Message (53), length 1: Discover" in block]
        self.assertEqual(len(discovers), 2)
        self.assertTrue(all("xid 0x2e4a6714" in block for block in discovers))

    def test_packet_without_matching_option_is_not_a_discover(self) -> None:
        text = """1791473413.294692 02:61:72:20:f4:77 > ff:ff:ff:ff:ff:ff
    xid 0x2e4a6714
      DHCP-Message (53), length 1: Request
"""
        block, = MODULE.tcpdump_packet_blocks(text)
        self.assertIsNone(__import__("re").search(r"DHCP-Message[^\n]*Discover", block))

    def test_empty_tap_capture_can_use_exact_discover_seen_at_next_observation_point(self) -> None:
        text = """1791473413.294692 02:61:72:20:f4:77 > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 342:
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 02:61:72:20:f4:77, length 300, xid 0x2e4a6714
      DHCP-Message (53), length 1: Discover
"""
        result = MODULE.correlated_discover_xids(
            {"tap": "", "realm-bridge": text}, "02:61:72:20:f4:77")
        self.assertEqual(result["tap"], set())
        self.assertEqual(result["realm-bridge"], {"0x2e4a6714"})

    def test_packet_mac_and_discover_from_different_blocks_do_not_correlate(self) -> None:
        text = """1791473413.294692 02:61:72:20:f4:77 > ff:ff:ff:ff:ff:ff
    xid 0x2e4a6714
1791473416.815165 02:61:72:20:f4:77 > ff:ff:ff:ff:ff:ff
      DHCP-Message (53), length 1: Request
"""
        result = MODULE.correlated_discover_xids({"realm-bridge": text}, "02:61:72:20:f4:77")
        self.assertEqual(result["realm-bridge"], set())


class BridgeTraceTests(unittest.TestCase):
    def test_input_hook_is_distinguished_from_forwarding(self) -> None:
        text = """trace id 123 bridge o3k-dhcp-root-trace input packet: iif \"o3k-c-12345678\" ether saddr 02:61:72:20:f4:77 ether daddr ff:ff:ff:ff:ff:ff ip saddr 0.0.0.0 udp sport 68 udp dport 67
trace id 123 bridge o3k-dhcp-root-trace forward packet: iif \"o3k-c-12345678\" oif \"o3k-t-12345678\" ether saddr 02:61:72:20:f4:77 ip saddr 0.0.0.0 udp sport 68 udp dport 67
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "trace.log"
            path.write_text(text)
            self.assertTrue(MODULE.trace_packet_seen(path, hook="input",
                source_mac="02:61:72:20:f4:77", ingress="o3k-c-12345678"))
            self.assertFalse(MODULE.trace_packet_seen(path, hook="input",
                source_mac="02:61:72:20:f4:77", ingress="o3k-c-87654321"))

    def test_trace_setup_is_owned_and_covers_b_ingress_and_a_local_input(self) -> None:
        args = Namespace(run_id="trace-test")
        maps = {
            "a": {"namespace": "fabric-a", "vxlan": "vx-a", "root_veth": "root-a",
                  "fabric_veth": "fabric-veth-a", "tap": "tap-a"},
            "b": {"namespace": "fabric-b", "vxlan": "vx-b", "root_veth": "root-b",
                  "fabric_veth": "fabric-veth-b", "tap": "tap-b",
                  "guest_mac": "02:61:72:20:f4:77"},
        }
        commands = []
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(MODULE, "ssh", return_value="1"), \
             patch.object(MODULE, "remote_script", side_effect=lambda _args, host, script: commands.append((host, script))):
            evidence = pathlib.Path(tmp)
            MODULE.configure_forward_trace(args, evidence, maps)
            b_script = next(script for host, script in commands if host == "b")
            a_script = next(script for host, script in commands
                            if host == "a" and "o3k-dhcp-root-trace" in script)
            self.assertIn('prerouting iifname "tap-b"', b_script)
            self.assertIn('input iifname "tap-b"', b_script)
            self.assertIn('forward iifname "tap-b"', b_script)
            self.assertIn('input iifname "root-a"', a_script)
            self.assertIn('meta nftrace set 1', b_script)
            self.assertNotIn(' drop', b_script)
            manifest = __import__("json").loads((evidence / "topology/trace-manifest.json").read_text())
            self.assertEqual(manifest["root_trace_hosts"], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
