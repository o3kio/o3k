#!/usr/bin/env python3
"""Regression coverage for the nested Fabric provider Gate A harness."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
GATE = ROOT / "fabric-v3-three-host-gate.sh"
CAMPAIGN = ROOT / "fabric-v3-o3k-three-host-campaign.sh"
GATE_TEXT = GATE.read_text()
CAMPAIGN_TEXT = CAMPAIGN.read_text()


class ThreeHostGateRegression(unittest.TestCase):
    def run_gate_preflight(self, overrides: dict[str, str]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="fabric-gate-regression-") as evidence_dir:
            env = os.environ.copy()
            env.update(
                {
                    "FABRIC_V3_3H_RUN_ID": "regression-run-1",
                    "FABRIC_V3_3H_HELPER_BIN": "/tmp/helper",
                    "FABRIC_V3_3H_HOST_A_IP": "192.0.2.10",
                    "FABRIC_V3_3H_HOST_B_IP": "192.0.2.11",
                    "FABRIC_V3_3H_HOST_C_IP": "192.0.2.12",
                    "FABRIC_V3_3H_KEY_A": "/tmp/key-a",
                    "FABRIC_V3_3H_KEY_B": "/tmp/key-b",
                    "FABRIC_V3_3H_KEY_C": "/tmp/key-c",
                    "FABRIC_V3_3H_KNOWN_HOSTS_FILE": "/tmp/known-hosts",
                    "FABRIC_V3_3H_HOST_A_PUBLIC_KEY_FILE": "/tmp/a.pub",
                    "FABRIC_V3_3H_HOST_B_PUBLIC_KEY_FILE": "/tmp/b.pub",
                    "FABRIC_V3_3H_HOST_C_PUBLIC_KEY_FILE": "/tmp/c.pub",
                    "FABRIC_V3_3H_EVIDENCE_DIR": evidence_dir,
                }
            )
            env.update(overrides)
            return subprocess.run(
                ["bash", str(GATE)],
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

    def test_provider_resources_and_remote_tools_are_run_scoped(self):
        self.assertIn('REMOTE_TMP_ROOT="/tmp/o3k-fabric-v3-three-host-${FABRIC_V3_3H_RUN_ID}"', GATE_TEXT)
        self.assertIn('RUN_ROOT="/var/lib/o3k-fabric-v3-three-host/${FABRIC_V3_3H_RUN_ID}"', GATE_TEXT)
        self.assertNotIn('FABRIC_V3_3H_REMOTE_ROOT', GATE_TEXT)
        self.assertNotIn('RUN_ROOT="/tmp/o3k-fabric-v3-three-host"', GATE_TEXT)
        self.assertNotIn('/tmp/fabric-v3-host-a.pub', GATE_TEXT)
        self.assertNotIn('/tmp/fabric-v3-host-b.pub', GATE_TEXT)
        self.assertNotIn('/tmp/fabric-v3-host-c.pub', GATE_TEXT)
        self.assertNotIn('/tmp/fabric-v3-', GATE_TEXT.replace('mktemp -d /tmp/fabric-v3-qemu-initrd.XXXXXX', ''))
        self.assertIn('remote_output="$REMOTE_TMP_ROOT/$output"', GATE_TEXT)
        self.assertIn('"$EVIDENCE_DIR/result.json"', GATE_TEXT)

    def test_provider_gate_requires_distinct_ipv4_addresses_and_strict_host_keys(self):
        self.assertIn("ipaddress.ip_address(value)", GATE_TEXT)
        self.assertIn("assert len(set(ips)) == 3", GATE_TEXT)
        self.assertIn("StrictHostKeyChecking=yes", GATE_TEXT)
        self.assertIn('UserKnownHostsFile=$FABRIC_V3_3H_KNOWN_HOSTS_FILE', GATE_TEXT)
        self.assertNotIn("StrictHostKeyChecking=no", GATE_TEXT)
        self.assertNotIn("UserKnownHostsFile=/dev/null", GATE_TEXT)

    def test_invalid_address_and_keep_override_fail_before_remote_mutation(self):
        duplicate = self.run_gate_preflight({"FABRIC_V3_3H_HOST_C_IP": "192.0.2.11"})
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("HARNESS_GAP", duplicate.stderr)
        self.assertNotIn("sudo ssh", duplicate.stderr)

        retained = self.run_gate_preflight({"FABRIC_V3_3H_KEEP": "1"})
        self.assertNotEqual(retained.returncode, 0)
        self.assertIn("retaining provider-gate resources is forbidden", retained.stderr)
        self.assertNotIn("sudo ssh", retained.stderr)

    def test_missing_run_identity_fails_closed_before_remote_mutation(self):
        missing = self.run_gate_preflight({"FABRIC_V3_3H_RUN_ID": ""})
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("FABRIC_V3_3H_RUN_ID", missing.stderr)
        self.assertNotIn("sudo ssh", missing.stderr)

    def test_foreign_canary_is_trapped_compared_then_removed(self):
        add = '"sudo ip link add \'$FOREIGN_CANARY\' type bridge"'
        self.assertIn(add, GATE_TEXT)
        self.assertIn("FOREIGN_CANARY_CREATED=1", GATE_TEXT)
        self.assertIn("trap finish_gate EXIT", GATE_TEXT)
        self.assertIn("sudo ip link del '$FOREIGN_CANARY'", GATE_TEXT)
        compare = GATE_TEXT.index('[[ "$foreign_canary_after" == "$foreign_canary_before" ]]')
        delete = GATE_TEXT.index('"sudo ip link del \'$FOREIGN_CANARY\'"', compare)
        absent = GATE_TEXT.index('"sudo ip -j -d link show dev \'$FOREIGN_CANARY\'"', delete)
        reset = GATE_TEXT.index("FOREIGN_CANARY_CREATED=0", absent)
        self.assertLess(compare, delete)
        self.assertLess(delete, absent)
        self.assertLess(absent, reset)
        self.assertNotIn('if [[ "${FABRIC_V3_3H_KEEP:-0}" != 1 ]]', GATE_TEXT)

    def test_provider_cleanup_always_removes_all_hosts_and_preserves_canary_first(self):
        cleanup_start = GATE_TEXT.index("GATE_PHASE=provider_cleanup")
        cleanup = GATE_TEXT[cleanup_start:]
        for host in ("host-a", "host-b", "host-c"):
            self.assertIn(f"--mode remove --host-id {host}", cleanup)
        self.assertLess(cleanup.index('[[ "$foreign_canary_after" == "$foreign_canary_before" ]]'),
                        cleanup.index('sudo ip link del'))

    def test_full_gate_a_runs_after_api_teardown_and_before_guest_destruction(self):
        self.assertIn('ACCEPTANCE_GATE="FABRIC V3 NESTED CONFORMANCE GATE A"', CAMPAIGN_TEXT)
        self.assertIn('if [[ "$CAMPAIGN_MODE" == full ]]; then', CAMPAIGN_TEXT)
        api_teardown = CAMPAIGN_TEXT.index("API_TEARDOWN_VERIFIED=1")
        provider_gate = CAMPAIGN_TEXT.index('mkdir -p "$EVIDENCE/provider-gate"')
        destroy_guests = CAMPAIGN_TEXT.index('for domain in "${FRESH_DOMAINS[@]}"', provider_gate)
        self.assertLess(api_teardown, provider_gate)
        self.assertLess(provider_gate, destroy_guests)
        self.assertIn("-p o3k-network --example fabric-regression-3host-helper", CAMPAIGN_TEXT)
        self.assertIn('git -C "$ROOT_DIR" worktree add --detach "$PRODUCT_SOURCE_DIR" "$PRODUCT_SHA"', CAMPAIGN_TEXT)
        self.assertIn('FABRIC_V3_3H_RUN_ID="$PROVIDER_GATE_RUN_ID"', CAMPAIGN_TEXT)
        self.assertIn('FABRIC_V3_3H_HOST_A_IP="${MGMT_IP[a]}"', CAMPAIGN_TEXT)
        self.assertIn('FABRIC_V3_3H_HOST_B_IP="${MGMT_IP[b]}"', CAMPAIGN_TEXT)
        self.assertIn('FABRIC_V3_3H_HOST_C_IP="${MGMT_IP[c]}"', CAMPAIGN_TEXT)

    def test_runner_preflights_static_anti_spoof_guest_and_nested_qemu(self):
        self.assertIn('for tool in gcc busybox file; do need "$tool"; done', CAMPAIGN_TEXT)
        self.assertIn('"statically linked"', CAMPAIGN_TEXT)
        self.assertIn('gcc -static -O2 "$ROOT_DIR/tests/fabric-v3-spoof-guest.c" -o /dev/null', CAMPAIGN_TEXT)
        self.assertIn('command -v qemu-system-x86_64 >/dev/null', CAMPAIGN_TEXT)

    def test_nested_guest_bootstrap_uses_available_qemu_and_root_private_kernel_observer(self):
        self.assertIn("  - qemu-system-x86\n", CAMPAIGN_TEXT)
        self.assertNotIn("  - qemu-kvm\n", CAMPAIGN_TEXT)
        self.assertIn('sudo -n test -r "/boot/vmlinuz-$(uname -r)"', CAMPAIGN_TEXT)
        self.assertNotIn('&& test -r "/boot/vmlinuz-$(uname -r)"', CAMPAIGN_TEXT)

    def test_provider_guest_source_is_independent_of_invocation_directory(self):
        self.assertIn('gcc -static -O2 "$SCRIPT_ROOT/fabric-v3-spoof-guest.c"', GATE_TEXT)
        self.assertNotIn('"$PWD/tests/fabric-v3-spoof-guest.c"', GATE_TEXT)

    def test_local_qemu_initrd_scratch_is_removed_on_success_and_failure(self):
        self.assertIn('qemu_root="$(mktemp -d /tmp/fabric-v3-qemu-initrd.XXXXXX)"', GATE_TEXT)
        self.assertIn('QEMU_ROOT="$qemu_root"', GATE_TEXT)
        self.assertIn('if [[ -n "$QEMU_ROOT" ]]; then', GATE_TEXT)
        self.assertIn('rm -rf -- "$QEMU_ROOT"', GATE_TEXT)
        self.assertIn('rm -f -- "$QEMU_ARCHIVE"', GATE_TEXT)
        self.assertIn('QEMU_ROOT=""', GATE_TEXT)
        self.assertIn('QEMU_ARCHIVE=""', GATE_TEXT)
        self.assertIn('"cleanup_status":int(cleanup_status)', GATE_TEXT)
        self.assertIn('failure_classification=CLEANUP_DEFECT', GATE_TEXT)


if __name__ == "__main__":
    unittest.main()
