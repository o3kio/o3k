#!/usr/bin/env python3
"""Regression checks for the Fabric acceptance guest-control contract."""
from __future__ import annotations

import importlib.util
import pathlib
import shlex
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
DRIVER = (ROOT / "fabric-v3-o3k-three-host-campaign.sh").read_text()
CONTRACT = (ROOT.parent / "contracts/real-host-acceptance-evidence.md").read_text()
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
        self.assertNotIn("console_command", DRIVER)
        self.assertNotIn("guest_tunnel_command", DRIVER)

    def test_accepted_contract_and_regression_gate_precede_campaign_provisioning(self):
        self.assertIn("Status: Accepted", CONTRACT)
        self.assertIn(
            "SSH over the canonical tenant IPv4 address MUST NOT be the",
            CONTRACT,
        )
        self.assertIn("does not use VXLAN or WireGuard", CONTRACT)
        self.assertIn("python3 \"$ROOT_DIR/tests/fabric-v3-guest-control-regression.py\"", DRIVER)
        guard = DRIVER.index("fabric-v3-guest-control-regression.py")
        provisioning = DRIVER.index("virsh -c qemu:///system net-info")
        self.assertLess(guard, provisioning)
        self.assertIn('merge-base HEAD "$ACCEPTED_HARNESS_BASE"', DRIVER)
        self.assertIn('PRODUCT_SHA=16789fdd206565456cbd5c7c091ace8fc00f7c48', DRIVER)

    def test_controller_restart_uses_the_frozen_product_binary(self):
        restart = DRIVER[DRIVER.index("# Controller restart while A/B/C are alive."):]
        self.assertIn('"$PRODUCT_SOURCE_DIR/target/release/o3kd"', restart)
        self.assertNotIn('"$ROOT_DIR/target/release/o3kd"', restart)

    def test_mandatory_packet_phases_use_guest_control_abstraction(self):
        self.assertNotIn("console_command", DRIVER)
        self.assertNotIn('virsh console', DRIVER)
        self.assertIn('guest_control_command "$from" "ping -c 1 -W 4 ${TENANT_IP[$to]}"', DRIVER)
        self.assertNotIn("ssh_vm.*TENANT_IP", DRIVER)

    def test_c_removal_records_durable_dispatch_and_observed_provider_absence(self):
        self.assertIn("capture_c_remove_work_row", DRIVER)
        self.assertIn("network_plan_work", DRIVER)
        self.assertIn("c-remove-work-row-history.jsonl", DRIVER)
        self.assertIn("host-c-command-journal.json", DRIVER)
        self.assertIn("row.get('state')=='succeeded'", DRIVER)
        self.assertIn("command.get('status')=='Succeeded'", DRIVER)
        self.assertIn("C endpoint TAP remains after Remove", DRIVER)
        self.assertIn("C Realm namespace remains after final endpoint departure", DRIVER)
        self.assertIn("C durable Realm plan remains after Remove", DRIVER)
        self.assertIn("C port did not reach an unbound DOWN tombstone", DRIVER)
        self.assertIn("A/B failed after C removal", DRIVER)

    def test_teardown_checks_fabric_and_dhcp_owned_state_without_global_cleanup(self):
        self.assertIn("run-owned-provider-objects.json", DRIVER)
        self.assertIn("state.get('realms',{})", DRIVER)
        self.assertIn("host-$host-dhcp-state.txt", DRIVER)
        self.assertIn("host-$host-dnsmasq-processes.txt", DRIVER)
        self.assertIn("run not in processes", DRIVER)
        self.assertIn("foreign libvirt domain inventory changed", DRIVER)
        self.assertNotIn("virsh net-destroy", DRIVER)
        self.assertNotIn("nft flush ruleset", DRIVER)

    def test_packet_classifier_uses_control_transport_state(self):
        self.assertIn("LAST_GUEST_CHANNEL_ERROR", DRIVER)
        self.assertIn("failure-class \"$transport_error\" \"$phase_class\"", DRIVER)
        self.assertIn("guest_control_preflight \"$host\"", DRIVER)
        self.assertIn("ip addr show dev eth0", DRIVER)

    def test_guest_command_wrapper_uses_probe_supported_posix_shell(self):
        start = DRIVER.index("guest_control_command() {")
        end = DRIVER.index("\n\n" + "guest_control_preflight() {", start)
        command = DRIVER[start:end]
        self.assertIn('guest_remote_cmd="sh -c $(printf \'%q\' "$remote_script")"', command)
        self.assertIn("ConnectTimeout=8 %q %q'", command)
        self.assertIn("; sh %q; rc=$?;", command)
        self.assertIn("rm -f %q; exit 0", command)
        self.assertNotIn("bash %q", command)
        self.assertNotIn("bash -lc", command)
        self.assertNotIn("python3 -c", command)

    def test_nested_ssh_preserves_guest_script_as_one_remote_command(self):
        start = DRIVER.index("guest_control_command() {")
        end = DRIVER.index("\n\n" + "guest_control_preflight() {", start)
        command = DRIVER[start:end]
        self.assertIn('guest_remote_cmd="sh -c $(printf \'%q\' "$remote_script")"', command)
        self.assertIn("ConnectTimeout=8 %q %q'", command)

        formatted = subprocess.run(
            [
                "bash",
                "-c",
                'remote_script=$1; guest_remote_cmd="sh -c $(printf \'%q\' "$remote_script")"; '
                "printf -v remote_cmd 'ssh %q %q' probe \"$guest_remote_cmd\"; printf %s \"$remote_cmd\"",
                "bash",
                "printf guest-command-ok; false",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        outer_argv = shlex.split(formatted)
        self.assertEqual(outer_argv[:2], ["ssh", "probe"])
        guest_command = " ".join(outer_argv[2:])
        guest_argv = shlex.split(guest_command)
        self.assertEqual(guest_argv[:2], ["sh", "-c"])
        result = subprocess.run(["sh", "-c", guest_argv[2]], capture_output=True, text=True)
        self.assertEqual(result.stdout, "guest-command-ok")
        self.assertEqual(result.returncode, 1)

    def test_local_control_capture_checks_packets_not_live_capture_summary(self):
        start = DRIVER.index("guest_control_preflight() {")
        end = DRIVER.index("\n}\n\ncreate_server a", start)
        preflight = DRIVER[start:end]
        self.assertIn('grep -Fq "> $ll.22:"', preflight)
        self.assertIn('grep -Fq "$ll.22 >"', preflight)
        self.assertIn('grep -Fq "IP6 $ll."', preflight)
        self.assertNotIn("packets captured", preflight)

    def test_fabric_wireguard_counters_use_owned_fabric_namespace(self):
        self.assertIn("sudo ip netns exec '$fabric_ns' wg show all transfer", DRIVER)
        self.assertIn("host-$host-namespace.txt", DRIVER)
        self.assertNotIn("ssh_vm \"$address\" 'sudo wg show all transfer'", DRIVER)
        self.assertIn("sudo ip netns exec '$fabric_ns' ip -d -j link", DRIVER)

    def test_endpoint_removal_waits_for_bounded_fabric_convergence(self):
        start = DRIVER.index("printf 'attempt,server_absent,ownership_and_plans_converged")
        end = DRIVER.index('guest_control_command a "ping -c 1 -W 4 ${TENANT_IP[b]}" endpoint-removal/a-to-b.txt', start)
        removal = DRIVER[start:end]
        self.assertIn('for attempt in $(seq 1 120)', removal)
        self.assertIn('[[ "$server_status" == 404 ]]', removal)
        self.assertIn('for host in a b c', removal)
        self.assertIn("for host in ('a','b','c')", removal)
        self.assertIn("for host,endpoint in (('a',a),('b',b))", removal)
        self.assertIn("participants=={'host-a','host-b'}", removal)
        self.assertNotIn('host-c-fabric-plan.json', removal)
        self.assertIn('C deletion did not converge to A/B-only Fabric ownership within 120 seconds', removal)

    def test_wireguard_counter_baseline_precedes_packet_generation(self):
        baseline = DRIVER.index('>"$EVIDENCE/wireguard/host-$host-before-traffic.txt"')
        packet_matrix = DRIVER.index('# Cold neighbor resolution and the six required tenant-address ICMP flows.')
        post = DRIVER.index('>"$EVIDENCE/wireguard/host-$host-after-traffic.txt"')
        growth_check = DRIVER.index('WireGuard traffic counters did not grow')
        self.assertLess(baseline, packet_matrix)
        self.assertLess(packet_matrix, post)
        self.assertLess(post, growth_check)
        self.assertIn('assert new>old, (host,old,new)', DRIVER)

    def test_compute_agent_restart_reuses_local_guest_control_and_proves_new_epoch(self):
        start = DRIVER.index('# Restart only compute-agent-b')
        end = DRIVER.index('# Remove C only through the supported API', start)
        restart = DRIVER[start:end]
        self.assertIn('O3K_COMPUTE_DATA_DIR=', DRIVER[DRIVER.index('start_compute_agent() {'):DRIVER.index('\n}', DRIVER.index('start_compute_agent() {'))])
        self.assertIn(r'test "\$host" = host-b', restart)
        self.assertIn("old['agent_epoch']!=new['agent_epoch']", restart)
        self.assertIn('guest_control_command b true', restart)
        self.assertIn('guest_control_command a "ping -c 1 -W 4 ${TENANT_IP[b]}"', restart)
        self.assertIn('guest_control_command b "ping -c 1 -W 4 ${TENANT_IP[a]}"', restart)

    def test_failure_cleanup_retries_only_run_owned_api_ids(self):
        start = DRIVER.index('cleanup_owned_api_resource() {')
        end = DRIVER.index('\n    # Always clean run-created compute guests', start)
        cleanup = DRIVER[start:end]
        self.assertIn('for attempt in $(seq 1 60)', cleanup)
        self.assertIn('for ((i=${#SERVER_IDS[@]}-1; i>=0; i--))', cleanup)
        self.assertIn('for ((i=${#PORT_IDS[@]}-1; i>=0; i--))', cleanup)
        self.assertIn('"/v2.1/$PROJECT_ID/servers/${SERVER_IDS[i]}"', cleanup)
        self.assertIn('"/v2.0/ports/${PORT_IDS[i]}"', cleanup)
        self.assertIn('"/v2.0/subnets/$SUBNET_ID"', cleanup)
        self.assertIn('"/v2.0/networks/$NETWORK_ID"', cleanup)

    def test_wireguard_counter_baseline_precedes_packet_generation(self):
        baseline = DRIVER.index('>"$EVIDENCE/wireguard/host-$host-before-traffic.txt"')
        packet_matrix = DRIVER.index('# Cold neighbor resolution and the six required tenant-address ICMP flows.')
        post = DRIVER.index('>"$EVIDENCE/wireguard/host-$host-after-traffic.txt"')
        growth_check = DRIVER.index('WireGuard traffic counters did not grow')
        self.assertLess(baseline, packet_matrix)
        self.assertLess(packet_matrix, post)
        self.assertLess(post, growth_check)
        self.assertIn('assert new>old, (host,old,new)', DRIVER)

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
        self.assertIn('install -o 1000 -g 1000 -m 0600 "$PROBE_PUBLIC_KEY"', builder)
        self.assertIn('cpio --null --create --format=newc --reproducible', builder)
        self.assertNotIn('--owner=0:0', builder)
        self.assertIn('authorized_keys must remain owned by cirros uid/gid 1000', builder)
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
