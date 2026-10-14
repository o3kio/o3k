#!/usr/bin/env python3
"""Regression coverage for the nested Fabric provider Gate A harness."""
from __future__ import annotations

import os
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import re


ROOT = Path(__file__).resolve().parent
GATE = ROOT / "fabric-v3-three-host-gate.sh"
CAMPAIGN = ROOT / "fabric-v3-o3k-three-host-campaign.sh"
GATE_TEXT = GATE.read_text()
CAMPAIGN_TEXT = CAMPAIGN.read_text()


class ThreeHostGateRegression(unittest.TestCase):
    def _extract_function(self, name: str) -> str:
        match = re.search(
            rf"(?ms)^{re.escape(name)}\(\) \{{.*?^\}}\n",
            GATE_TEXT,
        )
        self.assertIsNotNone(match, name)
        return match.group(0)

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

    def test_packet_path_records_each_probe_and_preserves_capture_on_failure(self):
        self.assertIn("record_packet_probe a1", GATE_TEXT)
        self.assertIn("record_packet_probe a2", GATE_TEXT)
        self.assertIn("record_packet_probe b1", GATE_TEXT)
        self.assertIn("record_packet_probe b2", GATE_TEXT)
        self.assertIn('local base="$EVIDENCE_DIR/traffic/packet-path/$label"', GATE_TEXT)
        self.assertIn('>"$base.stdout"', GATE_TEXT)
        self.assertIn('>"$base.stderr"', GATE_TEXT)
        self.assertIn('>"$base.status"', GATE_TEXT)
        self.assertIn('PACKET_FAILED_OPERATION', GATE_TEXT)
        self.assertIn('failed_operation_exit_code', GATE_TEXT)
        self.assertIn('preserve_packet_capture', GATE_TEXT)
        self.assertIn('underlay-packet-path.txt', GATE_TEXT)
        self.assertIn('PACKET_CAPTURE_PID=""', GATE_TEXT)
        self.assertIn('PACKET_CAPTURE_REMOTE=""', GATE_TEXT)

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

    def test_provider_gate_provisions_and_verifies_fresh_run_root_wireguard_identity(self):
        self.assertIn("prepare_fresh_wireguard_identity host-a", GATE_TEXT)
        self.assertIn("prepare_fresh_wireguard_identity host-b", GATE_TEXT)
        self.assertIn("prepare_fresh_wireguard_identity host-c", GATE_TEXT)
        self.assertIn("test -e '$RUN_ROOT' || sudo test -L '$RUN_ROOT'", GATE_TEXT)
        self.assertIn("wireguard-private.key", GATE_TEXT)
        self.assertIn("verify_wireguard_identity host-a", GATE_TEXT)
        self.assertIn("verify_wireguard_identity host-b", GATE_TEXT)
        self.assertIn("verify_wireguard_identity host-c", GATE_TEXT)
        self.assertIn("ip netns exec o3k-fabric wg show o3k-wg public-key", GATE_TEXT)
        self.assertNotIn("cat \"$HOST_A_PUBLIC_KEY_FILE\"", GATE_TEXT)
        self.assertNotIn('AK="$(cat "$HOST_A_PUBLIC_KEY_FILE")"', GATE_TEXT)
        self.assertIn('AK="$(prepare_fresh_wireguard_identity', GATE_TEXT)
        self.assertIn(
            'apply_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" '
            'host-b "$FABRIC_V3_3H_HOST_B_IP" "$BK" host-c "$FABRIC_V3_3H_HOST_C_IP" "$CK"',
            GATE_TEXT,
        )
        self.assertIn(
            'apply_host host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" '
            'host-a "$FABRIC_V3_3H_HOST_A_IP" "$AK" host-c "$FABRIC_V3_3H_HOST_C_IP" "$CK"',
            GATE_TEXT,
        )
        self.assertIn(
            'apply_host host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" '
            'host-a "$FABRIC_V3_3H_HOST_A_IP" "$AK" host-b "$FABRIC_V3_3H_HOST_B_IP" "$BK"',
            GATE_TEXT,
        )

    def test_wireguard_peer_expectations_follow_realm_participation(self):
        self.assertIn(
            'verify_wireguard_identity host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" "$AK" "$BK"',
            GATE_TEXT,
        )
        self.assertIn(
            'verify_wireguard_identity host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" '
            '"$BK" "$AK" "$CK"',
            GATE_TEXT,
        )
        self.assertIn(
            'verify_wireguard_identity host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" "$CK" "$BK"',
            GATE_TEXT,
        )

    def test_wireguard_identity_matches_production_shared_provider_root(self):
        adapter = (ROOT.parent / "crates/o3k-network/src/linux_fabric/shared_provider.rs").read_text()
        backend = (ROOT.parent / "crates/o3k-network/src/linux_fabric/mod.rs").read_text()
        self.assertIn('let root = config.root.join("fabric-provider");', adapter)
        self.assertIn('SharedFabricAdapter::open(&config)', backend)
        self.assertIn("$RUN_ROOT/fabric-provider/wireguard-private.key", GATE_TEXT)
        self.assertNotIn("$RUN_ROOT/wireguard-private.key", GATE_TEXT)
        self.assertIn("test -L '$RUN_ROOT'", GATE_TEXT)
        self.assertIn("test ! -L", GATE_TEXT)
        self.assertIn("stat -c %u:%a:%F", GATE_TEXT)

    def test_wireguard_verification_is_scoped_to_exact_namespace_and_interface(self):
        self.assertIn(
            "ip netns exec o3k-fabric wg show o3k-wg public-key",
            GATE_TEXT,
        )
        self.assertIn(
            "ip netns exec o3k-fabric wg show o3k-wg peers",
            GATE_TEXT,
        )
        self.assertNotIn("wg show all public-key", GATE_TEXT)
        self.assertNotIn("wg show all peers", GATE_TEXT)

    def test_wireguard_prepare_executes_remote_shell_and_derives_real_key(self):
        prepare = self._extract_function("prepare_fresh_wireguard_identity")
        with tempfile.TemporaryDirectory(prefix="fabric-gate-wg-") as tmp:
            root = Path(tmp) / "run"
            fake_python = Path(tmp) / "python3"
            fake_python.write_text("#!/usr/bin/env bash\nif [[ $1 == -c ]]; then exit 0; fi\nexec /usr/bin/python3 \"$@\"\n")
            fake_python.chmod(0o755)
            fake_wg = Path(tmp) / "wg"
            fake_wg.write_text(
                "#!/usr/bin/env bash\n"
                "set -Eeuo pipefail\n"
                "case ${1:-} in\n"
                "  genkey) printf 'TEST_PRIVATE_KEY\\n' ;;\n"
                "  pubkey) read -r key; [[ $key == TEST_PRIVATE_KEY ]] && printf 'TEST_PUBLIC_KEY\\n' || exit 9 ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n"
            )
            fake_wg.chmod(0o755)
            script = f"""
set -Eeuo pipefail
PATH={tmp}:$PATH
RUN_ROOT={root!s}
sudo() {{ if [[ $1 == stat ]]; then if [[ $* == *%u:%a* ]]; then printf '0:600:regular file\\n'; else printf '0\\n'; fi; else "$@"; fi; }}
export -f sudo
ssh_host() {{ shift 3; bash -c "$1"; }}
{prepare}
pub=$(prepare_fresh_wireguard_identity host-a 192.0.2.10 /tmp/key)
test -f "$RUN_ROOT/fabric-provider/wireguard-private.key"
test "$(stat -c '%u %a %F' "$RUN_ROOT/fabric-provider/wireguard-private.key")" = "$(id -u) 600 regular file"
test "$pub" = TEST_PUBLIC_KEY
test -n "$pub"
test "$(cat "$RUN_ROOT/fabric-provider/wireguard-private.key")" = TEST_PRIVATE_KEY
! grep -Fq TEST_PRIVATE_KEY <<<"$pub"
"""
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_wireguard_prepare_rejects_symlink_run_root_and_key(self):
        prepare = self._extract_function("prepare_fresh_wireguard_identity")
        with tempfile.TemporaryDirectory(prefix="fabric-gate-wg-link-") as tmp:
            root = Path(tmp) / "run"
            target = Path(tmp) / "target"
            target.mkdir()
            root.symlink_to(target, target_is_directory=True)
            script = f"""
set -Eeuo pipefail
RUN_ROOT={root!s}
sudo() {{ if [[ $1 == stat ]]; then if [[ $* == *%u:%a* ]]; then printf '0:600:regular file\\n'; else printf '0\\n'; fi; else "$@"; fi; }}
export -f sudo
ssh_host() {{ shift 3; bash -c "$1"; }}
{prepare}
set +e
prepare_fresh_wireguard_identity host-a 192.0.2.10 /tmp/key
status=$?
set -e
test "$status" -ne 0
"""
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_wireguard_verify_rejects_wrong_live_public_key_and_extra_peer(self):
        verify = self._extract_function("verify_wireguard_identity")
        with tempfile.TemporaryDirectory(prefix="fabric-gate-wg-verify-") as tmp:
            fake_ip = Path(tmp) / "ip"
            fake_ip.write_text(
                "#!/usr/bin/env bash\n"
                "[[ ${FAKE_GOOD:-0} == 5 ]] && exit 23\n"
                "[[ ${FAKE_GOOD:-0} == 6 && $* == *peers* ]] && exit 24\n"
                "if [[ $* == *'public-key' ]]; then\n"
                "    [[ ${FAKE_GOOD:-0} != 0 ]] && printf '%s\\n' EXPECTED || printf '%s\\n' WRONG\n"
                "else\n"
                "    case ${FAKE_GOOD:-0} in\n"
                "        1) printf 'PEER-A\\nPEER-C\\n' ;;\n"
                "        3) printf 'PEER-A\\n' ;;\n"
                "        4) printf 'PEER-A\\nPEER-A\\nPEER-C\\n' ;;\n"
                "        *) printf 'PEER-A\\nPEER-C\\nEXTRA\\n' ;;\n"
                "    esac\n"
                "fi\n"
            )
            fake_ip.chmod(0o755)
            script = f"""
set -Eeuo pipefail
PATH={tmp}:$PATH
SCRIPT_ROOT={ROOT}
EVIDENCE_DIR={tmp}
FABRIC_V3_3H_RUN_ID=regression-key
sudo() {{ "$@"; }}
export -f sudo
ssh_host() {{ shift 3; bash -c "$1"; }}
{verify}
set +e
verify_wireguard_identity host-b 192.0.2.11 /tmp/key EXPECTED PEER-A PEER-C
status=$?
set -e
test "$status" -ne 0
"""
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads((Path(tmp) / "wireguard-host-b-identity.json").read_text())
            self.assertEqual(evidence["status"], "failed")
            self.assertFalse(evidence["local_public_key_matches"])
            self.assertEqual(evidence["unexpected_peers"], ["EXTRA"])
            self.assertTrue((Path(tmp) / "wireguard-host-b-runtime-public.key").exists())
            self.assertTrue((Path(tmp) / "wireguard-host-b-runtime-peers.txt").exists())

            control = (
                script.split("set +e\n", 1)[0]
                + "export FAKE_GOOD=1\n"
                + "verify_wireguard_identity host-b 192.0.2.11 /tmp/key EXPECTED PEER-A PEER-C\n"
            )
            control_result = subprocess.run(
                ["bash", "-c", control], capture_output=True, text=True, check=False
            )
            self.assertEqual(control_result.returncode, 0, control_result.stderr)
            evidence = json.loads((Path(tmp) / "wireguard-host-b-identity.json").read_text())
            self.assertEqual(evidence["status"], "passed")

            peer_only = (
                script.split("set +e\n", 1)[0]
                + "export FAKE_GOOD=2\nset +e\n"
                + "verify_wireguard_identity host-b 192.0.2.11 /tmp/key EXPECTED PEER-A PEER-C\n"
                + "status=$?\nset -e\ntest \"$status\" -ne 0\n"
            )
            peer_result = subprocess.run(
                ["bash", "-c", peer_only], capture_output=True, text=True, check=False, timeout=10
            )
            self.assertEqual(peer_result.returncode, 0, peer_result.stderr)
            evidence = json.loads((Path(tmp) / "wireguard-host-b-identity.json").read_text())
            self.assertTrue(evidence["local_public_key_matches"])
            self.assertEqual(evidence["unexpected_peers"], ["EXTRA"])
            for mode, missing, duplicates in ((3, ["PEER-C"], []), (4, [], ["PEER-A"])):
                varied = peer_only.replace("FAKE_GOOD=2", f"FAKE_GOOD={mode}")
                outcome = subprocess.run(["bash", "-c", varied], capture_output=True, text=True, timeout=10)
                self.assertEqual(outcome.returncode, 0, outcome.stderr)
                evidence = json.loads((Path(tmp) / "wireguard-host-b-identity.json").read_text())
                self.assertEqual(evidence["missing_peers"], missing)
                self.assertEqual(evidence["duplicate_peers"], duplicates)
            failed_read = peer_only.replace("FAKE_GOOD=2", "FAKE_GOOD=5")
            failed_read += (
                'test "$GATE_OPERATION" = wireguard_public_key_observe_host_b\n'
                'test "$GATE_OPERATION_EXIT_CODE" = 23\n'
                'test "$GATE_FAILED_HOST" = host-b\n'
            )
            outcome = subprocess.run(["bash", "-c", failed_read], capture_output=True, text=True, timeout=10)
            self.assertEqual(outcome.returncode, 0, outcome.stderr)
            failed_peers = peer_only.replace("FAKE_GOOD=2", "FAKE_GOOD=6")
            failed_peers += (
                'test "$GATE_OPERATION" = wireguard_peers_observe_host_b\n'
                'test "$GATE_OPERATION_EXIT_CODE" = 24\n'
                'test "$GATE_CLASSIFICATION" = HARNESS_GAP\n'
            )
            outcome = subprocess.run(["bash", "-c", failed_peers], capture_output=True, text=True, timeout=10)
            self.assertEqual(outcome.returncode, 0, outcome.stderr)
            # Exercise the real EXIT reporter, not a reconstructed result fixture.
            initial = GATE_TEXT.split("GATE_PHASE=preflight\n", 1)[1].split("ssh_host()", 1)[0]
            reporter = self._extract_function("finish_gate")
            failed_gate = (
                script.split("set +e\n", 1)[0]
                + initial
                + reporter
                + "\ntrap finish_gate EXIT\nGATE_PHASE=wireguard_identity_verify\n"
                + "verify_wireguard_identity host-b 192.0.2.11 /tmp/key EXPECTED PEER-A PEER-B\n"
            )
            outcome = subprocess.run(["bash", "-c", failed_gate], capture_output=True, text=True, timeout=10)
            self.assertEqual(outcome.returncode, 1, outcome.stderr)
            result = json.loads((Path(tmp) / "result.json").read_text())
            self.assertEqual(result["failed_host"], "host-b")
            self.assertEqual(result["failed_operation"], "wireguard_identity_compare_host_b")
            self.assertEqual(result["failed_operation_exit_code"], 1)
            self.assertEqual(result["failed_observer_type"], "local_evidence_comparison")
            self.assertEqual(result["classification"], "PROVIDER_CONFORMANCE_DEFECT")
            self.assertIn("local_public_key_mismatch", result["wireguard_identity_evidence"]["failed_predicates"])
            self.assertNotIn("TEST_PRIVATE_KEY", json.dumps(result))

    def test_wireguard_verify_accepts_one_exact_peer_and_rejects_unexpected_realm_peer(self):
        verify = self._extract_function("verify_wireguard_identity")
        with tempfile.TemporaryDirectory(prefix="fabric-gate-wg-single-peer-") as tmp:
            fake_ip = Path(tmp) / "ip"
            fake_ip.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ $* == *'public-key' ]]; then printf 'EXPECTED\\n'; "
                "elif [[ ${FAKE_MODE:-good} == extra ]]; then printf 'PEER-B\\nPEER-C\\n'; "
                "else printf 'PEER-B\\n'; fi\n"
            )
            fake_ip.chmod(0o755)
            script = f"""
set -Eeuo pipefail
PATH={tmp}:$PATH
SCRIPT_ROOT={ROOT}
EVIDENCE_DIR={tmp}
FABRIC_V3_3H_RUN_ID=regression-single-peer
sudo() {{ "$@"; }}
export -f sudo
ssh_host() {{ shift 3; bash -c "$1"; }}
{verify}
FAKE_MODE=good verify_wireguard_identity host-a 192.0.2.10 /tmp/key EXPECTED PEER-B
FAKE_MODE=extra
export FAKE_MODE
set +e
verify_wireguard_identity host-a 192.0.2.10 /tmp/key EXPECTED PEER-B
status=$?
set -e
test "$status" -eq 1
python3 - {tmp!s}/wireguard-host-a-identity.json <<'PY'
import json,sys
from pathlib import Path
evidence=json.loads(Path(sys.argv[1]).read_text())
assert evidence["expected_peers"] == ["PEER-B"]
assert evidence["unexpected_peers"] == ["PEER-C"]
assert evidence["classification"] == "PROVIDER_CONFORMANCE_DEFECT"
PY
"""
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, check=False, timeout=10
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_wireguard_verify_rejects_invalid_expected_peer_count_with_operation_diagnostics(self):
        verify = self._extract_function("verify_wireguard_identity")
        initial = GATE_TEXT.split("GATE_PHASE=preflight\n", 1)[1].split("ssh_host()", 1)[0]
        reporter = self._extract_function("finish_gate")

        for peer_args in ("", "PEER-A PEER-B PEER-C"):
            with self.subTest(peer_args=peer_args), tempfile.TemporaryDirectory(
                prefix="fabric-gate-wg-invalid-peer-count-"
            ) as tmp:
                script = f"""
set -Eeuo pipefail
SCRIPT_ROOT={ROOT}
EVIDENCE_DIR={tmp}
FABRIC_V3_3H_RUN_ID=regression-invalid-peer-count
{verify}
{initial}{reporter}
trap finish_gate EXIT
GATE_PHASE=wireguard_identity_verify
set +e
verify_wireguard_identity host-a 192.0.2.10 /tmp/key EXPECTED {peer_args}
status=$?
set -e
test "$status" -eq 2
test "$GATE_CLASSIFICATION" = HARNESS_GAP
test "$GATE_OPERATION" = wireguard_expected_peers_validate_host_a
test "$GATE_OPERATION_EXIT_CODE" = 2
test "$GATE_OBSERVER_TYPE" = local_input_validation
test "$GATE_COMMAND_CLASS" = wireguard_expected_peer_contract_validation
exit "$status"
"""
                result = subprocess.run(
                    ["bash", "-c", script], capture_output=True, text=True, check=False, timeout=10
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                evidence = json.loads((Path(tmp) / "result.json").read_text())
                self.assertEqual(evidence["classification"], "HARNESS_GAP")
                self.assertEqual(
                    evidence["failed_operation"], "wireguard_expected_peers_validate_host_a"
                )
                self.assertEqual(evidence["failed_operation_exit_code"], 2)
                self.assertEqual(evidence["failed_observer_type"], "local_input_validation")
                self.assertEqual(
                    evidence["failed_command_class"], "wireguard_expected_peer_contract_validation"
                )

    def test_wireguard_prepare_fails_closed_on_generation_error(self):
        prepare = self._extract_function("prepare_fresh_wireguard_identity")
        with tempfile.TemporaryDirectory(prefix="fabric-gate-wg-gen-") as tmp:
            root = Path(tmp) / "run"
            fake_wg = Path(tmp) / "wg"
            fake_wg.write_text("#!/usr/bin/env bash\nexit 17\n")
            fake_wg.chmod(0o755)
            script = f"""
set -Eeuo pipefail
PATH={tmp}:$PATH
RUN_ROOT={root!s}
sudo() {{ if [[ $1 == stat ]]; then if [[ $* == *%u:%a* ]]; then printf '0:600:regular file\\n'; else printf '0\\n'; fi; else "$@"; fi; }}
export -f sudo
ssh_host() {{ shift 3; bash -c "$1"; }}
{prepare}
set +e
prepare_fresh_wireguard_identity host-a 192.0.2.10 /tmp/key
status=$?
set -e
test "$status" -ne 0
"""
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, check=False, timeout=10
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_identity_comparator_rejects_invalid_inputs_and_missing_evidence(self):
        comparator = ROOT / "fabric-v3-wireguard-identity.py"
        with tempfile.TemporaryDirectory(prefix="fabric-public-identity-") as tmp:
            public_path = Path(tmp) / "public.txt"
            peers_path = Path(tmp) / "peers.txt"
            output = Path(tmp) / "identity.json"
            args = ["host-a", "EXPECTED", "PEER-A", "PEER-B",
                    str(public_path), str(peers_path), str(output)]
            for invalid in ([], ["wrong-host", *args[1:]],
                            [*args[:3], "PEER-A", *args[4:]]):
                result = subprocess.run(["python3", str(comparator), *invalid],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("HARNESS_GAP", result.stderr)
                self.assertFalse(output.exists())
            peers_path.write_text("PEER-B\nPEER-A\n")
            for malformed in ("", "EXPECTED\nEXTRA\n", " EXPECTED\n"):
                public_path.write_text(malformed)
                result = subprocess.run(["python3", str(comparator), *args],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1, result.stderr)
                evidence = json.loads(output.read_text())
                self.assertEqual(evidence["failed_predicates"], ["local_public_key_mismatch"])
                self.assertEqual(evidence["classification"], "PROVIDER_CONFORMANCE_DEFECT")
                self.assertNotIn("private", json.dumps(evidence))

    def test_identity_comparator_accepts_exact_single_peer_and_rejects_missing_or_extra_peer(self):
        comparator = ROOT / "fabric-v3-wireguard-identity.py"
        with tempfile.TemporaryDirectory(prefix="fabric-single-peer-identity-") as tmp:
            public_path = Path(tmp) / "public.txt"
            peers_path = Path(tmp) / "peers.txt"
            output = Path(tmp) / "identity.json"
            public_path.write_text("EXPECTED\n")
            peers_path.write_text("PEER-B\n")
            args = ["host-a", "EXPECTED", "PEER-B", str(public_path), str(peers_path), str(output)]

            result = subprocess.run(
                ["python3", str(comparator), *args], capture_output=True, text=True, timeout=10
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(output.read_text())
            self.assertEqual(evidence["expected_peers"], ["PEER-B"])
            self.assertEqual(evidence["observed_peers"], ["PEER-B"])

            peers_path.write_text("PEER-B\nPEER-C\n")
            result = subprocess.run(
                ["python3", str(comparator), *args], capture_output=True, text=True, timeout=10
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            evidence = json.loads(output.read_text())
            self.assertEqual(evidence["unexpected_peers"], ["PEER-C"])
            self.assertEqual(evidence["classification"], "PROVIDER_CONFORMANCE_DEFECT")

            peers_path.write_text("")
            result = subprocess.run(
                ["python3", str(comparator), *args], capture_output=True, text=True, timeout=10
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            evidence = json.loads(output.read_text())
            self.assertEqual(evidence["missing_peers"], ["PEER-B"])

            peers_path.write_text("PEER-A\nPEER-C\n")
            two_peer_args = [
                "host-b",
                "EXPECTED",
                "PEER-A",
                "PEER-C",
                str(public_path),
                str(peers_path),
                str(output),
            ]
            result = subprocess.run(
                ["python3", str(comparator), *two_peer_args], capture_output=True, text=True, timeout=10
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(output.read_text())
            self.assertEqual(evidence["expected_peers"], ["PEER-A", "PEER-C"])

    def test_wireguard_prepare_fails_closed_on_wrong_owner_or_mode(self):
        prepare = self._extract_function("prepare_fresh_wireguard_identity")
        with tempfile.TemporaryDirectory(prefix="fabric-gate-wg-stat-") as tmp:
            root = Path(tmp) / "run"
            script = f"""
set -Eeuo pipefail
RUN_ROOT={root!s}
sudo() {{ if [[ $1 == stat ]]; then if [[ $* == *%u:%a* ]]; then printf '1000:644:regular file\\n'; else printf '0\\n'; fi; else "$@"; fi; }}
export -f sudo
ssh_host() {{ shift 3; bash -c "$1"; }}
{prepare}
set +e
prepare_fresh_wireguard_identity host-a 192.0.2.10 /tmp/key
status=$?
set -e
test "$status" -ne 0
"""
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_packet_capture_has_bounded_owned_wait_and_preserves_primary_error(self):
        # The capture process must be tied to this run and reaped.  kill -0
        # alone is not a wait and can mistake a zombie or a reused PID for a
        # still-running capture.
        self.assertIn("timeout 12", GATE_TEXT)
        self.assertIn("wait", GATE_TEXT)
        self.assertIn("PACKET_CAPTURE_PID", GATE_TEXT)
        self.assertIn("PACKET_CAPTURE_FAILURE_OPERATION", GATE_TEXT)

    def test_packet_capture_wait_and_failure_preserve_primary_probe(self):
        record = self._extract_function("record_packet_probe")
        preserve = self._extract_function("preserve_packet_capture")
        with tempfile.TemporaryDirectory(prefix="fabric-gate-packet-") as tmp:
            evidence = Path(tmp) / "evidence"
            script = f"""
set -Eeuo pipefail
EVIDENCE_DIR={evidence!s}
PACKET_FAILED_OPERATION=primary_probe
PACKET_FAILED_EXIT_CODE=23
PACKET_CAPTURE_PID=owned-capture
PACKET_CAPTURE_REMOTE=remote-capture
PACKET_CAPTURE_HOST=host-a
PACKET_CAPTURE_IP=192.0.2.10
PACKET_CAPTURE_KEY=/tmp/key
capture_remote_file() {{ return 19; }}
ssh_host() {{ shift 3; bash -c "$1"; }}
{record}
{preserve}
if record_packet_probe a1 host-a 192.0.2.10 /tmp/key 'printf out; printf err >&2; exit 23'; then
    record_status=0
else
    record_status=$?
fi
test "$record_status" -eq 23
test "$PACKET_FAILED_OPERATION" = packet_probe_a1
test "$PACKET_FAILED_EXIT_CODE" -eq 23
sleep 0.01 & PACKET_CAPTURE_LOCAL_PID=$!
if preserve_packet_capture; then
    preserve_status=0
else
    preserve_status=$?
fi
test "$preserve_status" -ne 0
test "$PACKET_CAPTURE_FAILURE_OPERATION" = packet_capture_retrieval
test "$PACKET_FAILED_OPERATION" = packet_probe_a1
test "$(cat "$EVIDENCE_DIR/traffic/packet-path/a1.status")" = 23
grep -Fq out "$EVIDENCE_DIR/traffic/packet-path/a1.stdout"
grep -Fq err "$EVIDENCE_DIR/traffic/packet-path/a1.stderr"
"""
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

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
