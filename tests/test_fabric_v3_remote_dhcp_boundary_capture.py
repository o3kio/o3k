import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch


HELPER_PATH = pathlib.Path(__file__).with_name("fabric-v3-remote-dhcp-boundary-capture.py")
SPEC = importlib.util.spec_from_file_location("fabric_v3_boundary_capture", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)


class DhcpBoundaryCaptureTests(unittest.TestCase):
    mac = "02:76:2d:20:bf:db"
    xid = "0x9f41ac6"

    def test_correlates_request_by_guest_mac_and_transaction_id(self):
        decoded = (
            f"17:46:36.888092 {self.mac} > ff:ff:ff:ff:ff:ff, ethertype IPv4: "
            f"0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from {self.mac}, "
            f"xid {self.xid}\n\tDHCP-Message (53), length 1: Request\n"
        )
        self.assertEqual(
            boundary.correlated_client_xids({"fabric-veth": decoded}, self.mac),
            {"fabric-veth": {self.xid}},
        )

    def test_requires_matching_ack_at_guest_tap(self):
        decoded = (
            f"17:46:37.000000 76:02:25:e5:70:cb > {self.mac}, ethertype IPv4: "
            f"10.77.0.1.67 > 10.77.0.3.68: BOOTP/DHCP, Reply, xid {self.xid}\n"
            f"\tClient-Ethernet-Address {self.mac}\n"
            "\tDHCP-Message (53), length 1: ACK\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            pcap = pathlib.Path(directory) / "tap.pcap"
            pcap.write_bytes(b"captured pcap")
            with patch.object(boundary, "call", return_value=decoded):
                seen, packets = boundary.dhcp_reply_seen(pcap, self.mac, self.xid, "ACK")
        self.assertTrue(seen)
        self.assertEqual(len(packets), 1)

    def test_rejects_reply_with_different_transaction_id(self):
        decoded = (
            f"17:46:37.000000 76:02:25:e5:70:cb > {self.mac}, ethertype IPv4: "
            f"10.77.0.1.67 > 10.77.0.3.68: BOOTP/DHCP, Reply, xid 0x12345678\n"
            f"\tClient-Ethernet-Address {self.mac}\n"
            "\tDHCP-Message (53), length 1: ACK\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            pcap = pathlib.Path(directory) / "tap.pcap"
            pcap.write_bytes(b"captured pcap")
            with patch.object(boundary, "call", return_value=decoded):
                seen, packets = boundary.dhcp_reply_seen(pcap, self.mac, self.xid, "ACK")
        self.assertFalse(seen)
        self.assertEqual(packets, [])

    def test_requires_same_trace_event_to_forward_reply_through_antispoof(self):
        trace = (
            "trace id d761b110 bridge o3k-dhcp-root-trace forward packet: "
            'iif "o3k-c-0373969d" oif "o3k-t-9ab15e41" '
            f"ether daddr {self.mac} ip saddr 10.77.0.1 ip daddr 10.77.0.3 "
            f"udp sport 67 udp dport 68 @th,64,96 0x201060009f41ac600000000\n"
            "trace id d761b110 bridge o3k-as-bd4deef5 forward rule "
            'iifname "o3k-c-0373969d" '
            f"ether daddr {self.mac} ip saddr 10.77.0.1 ip daddr 10.77.0.3 "
            'udp sport 67 udp dport 68 accept comment "o3k-p11-antispoof" '
            "(verdict accept)\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            trace_path = pathlib.Path(directory) / "trace.log"
            trace_path.write_text(trace)
            seen, packets = boundary.dhcp_reply_forwarded_to_tap(
                trace_path,
                tap="o3k-t-9ab15e41",
                root_veth="o3k-c-0373969d",
                client_mac=self.mac,
                gateway_ip="10.77.0.1",
                client_ip="10.77.0.3",
                xid=self.xid,
            )
        self.assertTrue(seen)
        self.assertEqual(len(packets), 2)
        self.assertIn("(verdict accept)", packets[1])

    def test_capture_filter_includes_guest_destination_mac(self):
        maps = {
            host: {
                "guest_mac": self.mac,
                "fabric_transport_ip": f"100.64.3.{index}",
                "tap": f"tap-{host}",
                "realm_bridge": f"br-{host}",
                "root_veth": f"root-{host}",
                "fabric_veth": f"fabric-{host}",
                "fabric_bridge": f"fbr-{host}",
                "vxlan": f"vxlan-{host}",
                "wireguard": f"wg-{host}",
                "namespace": f"ns-{host}",
                "peers": {
                    ("host-a" if host == "b" else "host-b"): {
                        "underlay_endpoint": "192.168.122.136:65001"
                    }
                },
            }
            for host, index in (("a", 1), ("b", 2))
        }
        filters = [item["filter"] for item in boundary.capture_specs(maps)
                   if item["host"] == "b" and item["label"] == "tap"]
        self.assertEqual(len(filters), 1)
        self.assertIn(f"ether host {self.mac}", filters[0])

    def test_reply_addressing_uses_authority_gateway_and_b_fixed_ip(self):
        self.assertEqual(
            boundary.dhcp_reply_addressing({
                "a": {"gateway_ip": "10.77.0.1"},
                "b": {"fixed_ip": "10.77.0.3"},
            }),
            ("10.77.0.1", "10.77.0.3"),
        )

    def test_reply_addressing_fails_closed_when_canonical_address_missing(self):
        with self.assertRaisesRegex(RuntimeError, "authority gateway"):
            boundary.dhcp_reply_addressing({"a": {}, "b": {"fixed_ip": "10.77.0.3"}})


if __name__ == "__main__":
    unittest.main()
