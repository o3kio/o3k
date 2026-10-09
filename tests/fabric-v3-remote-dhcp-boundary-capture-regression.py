#!/usr/bin/env python3
"""Regression for multiline tcpdump DHCP packet correlation."""
import importlib.util
import pathlib
import subprocess
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
        result = MODULE.correlated_client_xids(
            {"tap": "", "realm-bridge": text}, "02:61:72:20:f4:77")
        self.assertEqual(result["tap"], set())
        self.assertEqual(result["realm-bridge"], {"0x2e4a6714"})

    def test_packet_mac_and_discover_from_different_blocks_do_not_correlate(self) -> None:
        text = """1791473413.294692 02:61:72:20:f4:77 > ff:ff:ff:ff:ff:ff
    xid 0x2e4a6714
1791473416.815165 02:61:72:20:f4:77 > ff:ff:ff:ff:ff:ff
      DHCP-Message (53), length 1: Request
"""
        result = MODULE.correlated_client_xids({"realm-bridge": text}, "02:61:72:20:f4:77")
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


class AuthoritySyscallTests(unittest.TestCase):
    def test_tracer_setup_is_run_scoped_and_shell_valid(self) -> None:
        args = Namespace(run_id="diagnostic-owned", addresses={"a": "192.0.2.1"},
                         key="/tmp/key", known_hosts="/tmp/known")
        maps = {"a": {"realm_id": "realm-owned"}}
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            evidence = pathlib.Path(tmp)
            (evidence / "dhcp").mkdir()
            with patch.object(MODULE, "remote_script",
                              side_effect=lambda _args, host, script: calls.append((host, script))), \
                 patch.object(MODULE, "ssh", return_value="strace 6.8"):
                MODULE.start_dnsmasq_syscall_trace(args, evidence, maps)
            self.assertEqual(len(calls), 1)
            host, script = calls[0]
            self.assertEqual(host, "a")
            self.assertIn("/var/lib/o3k-fabric-v3/diagnostic-owned/network/dhcp/fabric/realm-owned", script)
            self.assertIn("strace -f -tt -yy -s 0", script)
            self.assertIn("dnsmasq-*.pid", script)
            self.assertIn("tr '\\0' ' '", script)
            self.assertNotIn("pkill", script)
            subprocess.run(["bash", "-n"], input=script, text=True, check=True)

    def test_offer_trace_is_scoped_to_a_to_b_dhcp_tuple(self) -> None:
        args = Namespace(run_id="reply-owned")
        maps = {
            h: {"namespace": f"ns-{h}", "realm_bridge": f"realm-{h}",
                "root_veth": f"root-{h}", "fabric_veth": f"fabric-{h}",
                "vxlan": f"vxlan-{h}", "tap": f"tap-{h}"}
            for h in "ab"
        }
        maps["a"]["gateway_ip"] = "10.77.0.1"
        maps["b"]["fixed_ip"] = "10.77.0.3"
        commands = []
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(MODULE, "ssh", return_value="1"), \
             patch.object(MODULE, "remote_script",
                          side_effect=lambda _args, host, script: commands.append((host, script))):
            evidence = pathlib.Path(tmp)
            (evidence / "topology").mkdir()
            MODULE.configure_dhcp_reply_trace(args, evidence, maps)
            self.assertEqual(len(commands), 2)
            for _, script in commands:
                subprocess.run(["bash", "-n"], input=script, text=True, check=True)
            a_script = commands[0][1]
            b_script = commands[1][1]
            self.assertIn("hook output", a_script)
            self.assertIn("ip saddr 10.77.0.1 ip daddr 10.77.0.3 udp sport 67 udp dport 68", a_script)
            self.assertIn('oifname "root-a"', a_script)
            self.assertIn('oifname "fabric-b"', b_script)
            self.assertNotIn("delete table", a_script + b_script)

    def test_bounded_summary_detects_udp_receive_and_send_without_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "syscalls.log"
            path.write_text("""recvmsg(3<UDP:[0.0.0.0:67]>, {msg_name={sa_family=AF_INET, sin_port=htons(68)}, ...}, 0) = 342
sendto(4<UDP:[0.0.0.0:67]>, ..., 548, 0, {sa_family=AF_INET, sin_port=htons(68), sin_addr=inet_addr("10.77.0.3")}, 16) = 548
recvfrom(5<UDP:[127.0.0.1:53]>, ..., 512, 0, NULL, NULL) = 64
""")
            summary = MODULE.dhcp_syscall_summary(path)
            self.assertEqual(summary["receive_count"], 2)
            self.assertEqual(summary["send_count"], 1)
            self.assertEqual(summary["dhcp_port_67_count"], 2)
            self.assertEqual(summary["positive_udp67_send_to_client_count"], 1)
            self.assertNotIn("DHCP-Message", "\n".join(summary["receive_lines"] + summary["send_lines"]))

    def test_missing_syscall_trace_is_not_misreported_as_no_receive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = MODULE.dhcp_syscall_summary(pathlib.Path(tmp) / "missing.log", "10.77.0.3")
            self.assertFalse(summary["trace_present"])


if __name__ == "__main__":
    unittest.main()
