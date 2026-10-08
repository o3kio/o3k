#!/usr/bin/env python3
"""Regression checks for the Fabric acceptance guest-control contract."""
from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
DRIVER = (ROOT / "fabric-v3-o3k-three-host-campaign.sh").read_text()
SPEC = importlib.util.spec_from_file_location("guest_control", ROOT / "fabric-v3-guest-control.py")
assert SPEC and SPEC.loader
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class GuestControlRegression(unittest.TestCase):
    def inspect(self, serial_xml: str) -> dict:
        with tempfile.NamedTemporaryFile("w", suffix=".xml") as f:
            f.write(serial_xml)
            f.flush()
            return helper.serial_capabilities(f.name)

    def test_file_backed_serial_is_read_only_not_interactive(self):
        result = self.inspect('<domain><devices><serial type="pty"><source path="/dev/pts/2"/></serial><console type="file"><source path="/tmp/serial.log"/></console></devices></domain>')
        self.assertFalse(result["serial_pty_interactive"])
        self.assertTrue(result["file_backed_serial_read_only"])

    def test_pty_requires_live_pty_source_path(self):
        accepted = self.inspect('<domain><devices><serial type="pty"><source path="/dev/pts/9"/></serial><console type="pty"><source path="/dev/pts/9"/></console></devices></domain>')
        absent = self.inspect('<domain><devices><serial type="pty"><source path="/dev/pts/9"/></serial><console type="pty"><source path="/tmp/serial.log"/></console></devices></domain>')
        self.assertTrue(accepted["serial_pty_interactive"])
        self.assertFalse(absent["serial_pty_interactive"])

    def test_agent_vsock_and_extra_nic_inventory_uses_live_devices(self):
        domain = '<domain><devices><channel><target name="org.qemu.guest_agent.0"/></channel><vsock/><interface/><interface/></devices></domain>'
        result = self.inspect(domain)
        self.assertTrue(result["qemu_guest_agent_present"])
        self.assertTrue(result["vsock_present"])
        self.assertTrue(result["dedicated_management_nic_present"])

    def test_missing_ssh_listener_is_harness_gap(self):
        self.assertEqual(helper.failure_class(True, "DATAPLANE_DEFECT"), "HARNESS_GAP")

    def test_link_local_control_target_is_scoped_to_local_bridge(self):
        ll = helper.link_local("02:ee:e0:4e:1a:31")
        target = helper.scoped_target(ll, "br-o3k-local")
        self.assertTrue(ll.startswith("fe80::"))
        self.assertEqual(target, f"cirros@{ll}%br-o3k-local")
        with self.assertRaises(ValueError):
            helper.scoped_target("10.77.0.2", "br-o3k-local")

    def test_healthy_control_then_failed_packet_is_dataplane_defect(self):
        self.assertEqual(helper.failure_class(False, "DATAPLANE_DEFECT"), "DATAPLANE_DEFECT")

    def test_control_transport_is_not_tenant_ipv4_and_has_no_static_fallback(self):
        start = DRIVER.index("guest_control_command() {")
        end = DRIVER.index("\n\nguest_control_preflight() {", start)
        command = DRIVER[start:end]
        self.assertIn("fabric-v3-guest-control.py\" target", command)
        self.assertIn("ssh -6", command)
        self.assertIn("BindInterface", command)
        self.assertNotIn("TENANT_IP", command)
        self.assertNotIn("ip addr add", DRIVER)
        self.assertNotIn("ip route add", DRIVER)
        self.assertNotIn("virsh edit", DRIVER)
        self.assertNotIn("update-device", DRIVER)
        self.assertNotIn("virsh console", DRIVER)
        self.assertNotIn("guest_tunnel_command", DRIVER)

    def test_packet_classifier_uses_control_transport_state(self):
        self.assertIn("LAST_GUEST_CHANNEL_ERROR", DRIVER)
        self.assertIn("failure-class \"$transport_error\" \"$phase_class\"", DRIVER)
        self.assertIn("guest_control_preflight \"$host\"", DRIVER)
        self.assertIn("ip addr show dev eth0", DRIVER)

    def test_link_local_readiness_collects_local_evidence_before_bounded_probe(self):
        start = DRIVER.index("prepare_guest_control() {")
        end = DRIVER.index("\n}\n\nguest_control_command()", start)
        preflight = DRIVER[start:end]
        self.assertLess(preflight.index("host-local-ipv6-state.txt"), preflight.index("ssh-keyscan"))
        self.assertLess(preflight.index("fabric-control.pcap"), preflight.index("ssh-keyscan"))
        self.assertIn("ip -6 route get '$ll' oif '$bridge'", preflight)
        self.assertIn("seq 1 20", preflight)
        self.assertIn('2>>"$errors"', preflight)
        self.assertNotIn('2>/dev/null | awk', preflight)
        self.assertIn("sudo bash -c 'nohup timeout 60", preflight)
        self.assertIn("capture-readiness.txt", preflight)
        self.assertIn("test -s '$capture_root/local-control.pcap'", preflight)

    def test_file_serial_is_captured_read_only_for_control_failure_diagnosis(self):
        self.assertIn("capture_guest_serial_output()", DRIVER)
        self.assertIn('sudo cat \'$serial_path\'', DRIVER)
        self.assertIn("serial-console-output.txt", DRIVER)
        self.assertIn("run-owned file-backed serial path", DRIVER)
        self.assertNotIn("virsh console", DRIVER)

    def test_probe_image_is_pinned_deterministic_and_within_product_upload_limit(self):
        builder = (ROOT / "fabric-v3-build-probe-image.sh").read_text()
        self.assertIn("7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b", builder)
        self.assertIn("64 * 1024 * 1024", builder)
        self.assertIn("home/cirros/.ssh/authorized_keys", builder)
        self.assertIn('DROPBEAR_ARGS="-s -w -p [::]:22"', builder)
        self.assertIn('S40-network', builder)
        self.assertIn('S42-dropbear', builder)
        self.assertIn('S45-cirros-net-ds', builder)
        self.assertIn('before that optional lookup', builder)
        self.assertIn('mv "$WORK_DIR/rootfs/etc/rc3.d/S50-dropbear" "$WORK_DIR/rootfs/etc/rc3.d/S42-dropbear"', builder)
        self.assertIn('[[ -L "$WORK_DIR/rootfs/etc/rc3.d/S42-dropbear"', builder)
        self.assertIn("--reproducible", builder)
        self.assertNotIn("ip addr add", builder)
        self.assertIn("cirros@", (ROOT / "fabric-v3-guest-control.py").read_text())

    def test_campaign_downloads_the_pinned_small_probe_base(self):
        self.assertIn("cirros-0.6.3-x86_64-disk.img", DRIVER)
        self.assertIn("7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b", DRIVER)
        self.assertIn('"$PROBE_BASE_IMAGE"', DRIVER)
        self.assertIn('"$PROBE_BASE_IMAGE" "$PROBE_KEY.pub"', DRIVER)


if __name__ == "__main__":
    unittest.main()
