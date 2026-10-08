#!/usr/bin/env python3
"""Regression for multiline tcpdump DHCP packet correlation."""
import importlib.util
import pathlib
import unittest


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


if __name__ == "__main__":
    unittest.main()
