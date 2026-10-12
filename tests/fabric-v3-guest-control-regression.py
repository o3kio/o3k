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
RETIREMENT = (ROOT / "fabric-v3-retirement-microgate.sh").read_text()
RETIREMENT_EVIDENCE = (ROOT / "fabric-v3-retirement-evidence.py").read_text()
DELETE_OPERATION_EVIDENCE = (ROOT / "fabric-v3-delete-operation-evidence.py").read_text()
CONTRACT = (ROOT.parent / "contracts/real-host-acceptance-evidence.md").read_text()
SPEC = importlib.util.spec_from_file_location("guest_control", ROOT / "fabric-v3-guest-control.py")
assert SPEC and SPEC.loader
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
RESTART_SPEC = importlib.util.spec_from_file_location(
    "controller_restart_readiness", ROOT / "fabric-v3-controller-restart-readiness.py"
)
assert RESTART_SPEC and RESTART_SPEC.loader
restart_readiness = importlib.util.module_from_spec(RESTART_SPEC)
RESTART_SPEC.loader.exec_module(restart_readiness)


class GuestControlRegression(unittest.TestCase):
    def test_restart_readiness_requires_new_controller_session_and_exact_agent_epochs(self):
        log = "\n".join(
            [
                '{"fields":{"message":"controller session registered","controller_id":"ctrl-new","controller_epoch":"epoch-new"}}',
                '{"fields":{"message":"compute agent registered","agent_id":"compute-a","epoch":"a-2"}}',
                '{"fields":{"message":"compute agent registered","agent_id":"compute-b","epoch":"b-2"}}',
                '{"fields":{"message":"compute agent registered","agent_id":"compute-c","epoch":"c-2"}}',
            ]
        )
        evidence = restart_readiness.parse_readiness(
            log, "ctrl-new", "epoch-new", {"compute-a": "a-2", "compute-b": "b-2", "compute-c": "c-2"}
        )
        self.assertEqual(evidence["status"], "passed")
        self.assertTrue(evidence["controller_session_matches"])
        self.assertTrue(evidence["all_expected_compute_agents_registered"])

    def test_restart_readiness_rejects_stale_controller_session(self):
        evidence = restart_readiness.parse_readiness(
            'controller_id=old controller_epoch=old-epoch message="controller session registered"',
            "new",
            "new-epoch",
            {"compute-a": "a-2"},
        )
        self.assertEqual(evidence["status"], "pending")
        self.assertFalse(evidence["controller_session_matches"])

    def test_restart_readiness_rejects_missing_agent_and_wrong_epoch(self):
        log = "\n".join(
            [
                'controller_id=new controller_epoch=new-epoch message="controller session registered"',
                'agent_id=compute-a epoch=a-old message="compute agent registered"',
            ]
        )
        evidence = restart_readiness.parse_readiness(
            log, "new", "new-epoch", {"compute-a": "a-current", "compute-b": "b-current"}
        )
        self.assertEqual(evidence["status"], "pending")
        self.assertEqual(evidence["missing_compute_agent_ids"], ["compute-b"])
        self.assertEqual(
            evidence["mismatched_compute_agent_epochs"]["compute-a"],
            {"expected_epoch": "a-current", "observed_epoch": "a-old"},
        )

    def test_live_agent_readyz_binds_current_epoch_after_controller_restart(self):
        evidence, status = restart_readiness.capture_agent_readiness(
            '{"status":"ready","agent_id":"compute-a","agent_epoch":"a-restarted"}'
            "\n__O3K_HTTP_STATUS=200\n",
            "host-a",
            "compute-a",
        )
        self.assertEqual(status, 0)
        self.assertEqual(evidence["agent_id"], "compute-a")
        self.assertEqual(evidence["agent_epoch"], "a-restarted")
        log = '\n'.join([
            'controller_id=new controller_epoch=new-epoch message="controller session registered"',
            'agent_id=compute-a epoch=a-old message="compute agent registered"',
        ])
        stale = restart_readiness.parse_readiness(
            log, "new", "new-epoch", {evidence["agent_id"]: evidence["agent_epoch"]}
        )
        self.assertEqual(stale["status"], "pending")
        self.assertEqual(
            stale["mismatched_compute_agent_epochs"]["compute-a"],
            {"expected_epoch": "a-restarted", "observed_epoch": "a-old"},
        )

    def test_live_agent_readyz_503_is_pending_without_retaining_body(self):
        evidence, status = restart_readiness.capture_agent_readiness(
            '{"diagnostic":"controller registration pending"}'
            "\n__O3K_HTTP_STATUS=503\n",
            "host-b",
            "compute-b",
        )
        self.assertEqual(status, 1)
        self.assertEqual(evidence["status"], "pending")
        self.assertEqual(evidence["diagnostic"], "agent_not_ready")
        self.assertNotIn("controller registration pending", repr(evidence))

    def test_live_agent_readyz_rejects_changed_identity_and_malformed_body(self):
        changed, changed_status = restart_readiness.capture_agent_readiness(
            '{"status":"ready","agent_id":"compute-other","agent_epoch":"new"}'
            "\n__O3K_HTTP_STATUS=200\n",
            "host-c",
            "compute-c",
        )
        malformed, malformed_status = restart_readiness.capture_agent_readiness(
            "not-json\n__O3K_HTTP_STATUS=200\n", "host-c", "compute-c"
        )
        unavailable, unavailable_status = restart_readiness.capture_agent_readiness(
            "service unavailable\n__O3K_HTTP_STATUS=500\n", "host-c", "compute-c"
        )
        self.assertEqual(changed_status, 3)
        self.assertEqual(changed["diagnostic"], "agent_identity_changed")
        self.assertEqual(malformed_status, 4)
        self.assertEqual(malformed["diagnostic"], "malformed_ready_json")
        self.assertEqual(unavailable_status, 4)
        self.assertEqual(unavailable["diagnostic"], "unexpected_http_status")

    def test_restart_registration_gate_precedes_post_restart_api_observations(self):
        restart_start = RETIREMENT.index("O3K_CONTROLLER_ID=\"${INITIAL_CONTROLLER_ID}-restart\"")
        replacement_start = RETIREMENT.index('"$PRODUCT_SOURCE_DIR/target/release/o3kd"', restart_start)
        readiness_gate = RETIREMENT.index("current-registration-state.json", replacement_start)
        manifest_bind = RETIREMENT.index("manifest['controller_restart']", readiness_gate)
        survivor_gets = RETIREMENT.index('"$BASE/v2.1/$PROJECT_ID/servers/${SERVER_IDS[$server_index]}"', readiness_gate)
        self.assertLess(restart_start, replacement_start)
        self.assertLess(replacement_start, readiness_gate)
        self.assertLess(readiness_gate, manifest_bind)
        self.assertLess(manifest_bind, survivor_gets)
        self.assertLess(readiness_gate, survivor_gets)
        self.assertIn('O3K_CONTROLLER_EPOCH="${INITIAL_CONTROLLER_EPOCH}-restart"', RETIREMENT)
        self.assertIn('[[ "$new_controller_pid" != "$old_controller_pid" ]]', RETIREMENT)
        self.assertIn("capture-agent-ready", RETIREMENT)
        self.assertIn("compute-$host-current-ready.json", RETIREMENT)
        self.assertIn("observe-controller-restart", RETIREMENT)
        self.assertIn("manifest['controller_restart']", RETIREMENT)
        self.assertIn("current_compute_agents", RETIREMENT)
        self.assertIn('"DURABLE_RECOVERY_DEFECT" ;;', RETIREMENT)

    def test_predelete_manifest_does_not_require_postrestart_artifacts(self):
        start = DRIVER.index('python3 - "$EVIDENCE" "$RUN_ID" "$INITIAL_CONTROLLER_ID"')
        end = DRIVER.index("PY\npython3 - \"$EVIDENCE/endpoint-removal/host-c-ownership-before.json\"", start)
        predelete_manifest = DRIVER[start:end]
        self.assertNotIn("controller-identity-after.txt", predelete_manifest)
        self.assertNotIn("current-registration-state.json", predelete_manifest)
        self.assertNotIn("controller_restart", predelete_manifest)
        self.assertIn("manifest['controller_restart']", RETIREMENT)

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
        self.assertIn('PRODUCT_SHA=d7335166563d28084fbad5ac7f5d0f0e07e000a4', DRIVER)
        self.assertIn('PRODUCT_TREE=d5b75b5674009d8c135218556aa2177371e489a3', DRIVER)
        self.assertIn('PRODUCT_PROTECTED_MAIN_BASE=adaf6168b124111ee62bf53f6eaf6e0f6cab155e', DRIVER)
        self.assertIn('PRODUCT_REMOTE_REF=refs/heads/fabric-v3-retirement-product-candidate', DRIVER)
        self.assertIn('PRODUCT_EXPECTED_PARENT_COMMITS="adaf6168b124111ee62bf53f6eaf6e0f6cab155e"', DRIVER)
        self.assertIn('[[ "$protected_main_tip" == "$PRODUCT_PROTECTED_MAIN_BASE" ]] \\', DRIVER)
        self.assertIn('[[ "$PRODUCT_SHA" != "$protected_main_tip" ]] \\', DRIVER)
        self.assertNotIn('[[ "$PRODUCT_SHA" == "$protected_main_tip" ]] \\', DRIVER)
        self.assertIn('git -C "$ROOT_DIR" merge-base --is-ancestor "$protected_main_tip" "$PRODUCT_SHA"', DRIVER)
        self.assertIn('[[ "$product_parents" == "$PRODUCT_EXPECTED_PARENT_COMMITS" ]] \\', DRIVER)
        self.assertIn("select_management_addresses() {", DRIVER)
        self.assertIn('sudo -n python3 "$HOST_PREFLIGHT" select', DRIVER)
        self.assertIn('--snapshot "$snapshot" --output /dev/stdout', DRIVER)
        self.assertNotIn('sudo -n bash "$ROOT_DIR/tests/fabric-v3-o3k-three-host-campaign.sh"', DRIVER)
        self.assertIn('"product_parent_commits":product_parents.split()', DRIVER)
        self.assertIn('HARNESS_REMOTE_REF=refs/heads/fabric-v3-retirement-successor-harness', DRIVER)
        self.assertIn('ls-remote origin "$PRODUCT_REMOTE_REF"', DRIVER)
        self.assertIn('show -s --format=%P "$PRODUCT_SHA"', DRIVER)
        self.assertIn('"candidate_is_protected_main":product==protected_main', DRIVER)
        self.assertIn('"candidate_is_successor":product!=protected_main', DRIVER)

    def test_departure_micro_gate_stops_before_full_campaign_phases(self):
        self.assertIn('CAMPAIGN_MODE="${1:-full}"', DRIVER)
        self.assertIn('if [[ "$CAMPAIGN_MODE" == departure-micro ]]; then', DRIVER)
        self.assertIn('ACCEPTANCE_GATE="FABRIC V3 DURABLE HOST RETIREMENT MICROGATE"', DRIVER)
        self.assertIn('"acceptance_gate":"$ACCEPTANCE_GATE"', DRIVER)
        self.assertIn('echo "FABRIC V3 DURABLE HOST RETIREMENT MICROGATE: PASS"', DRIVER)
        self.assertIn('echo "FABRIC V3 DURABLE HOST RETIREMENT MICROGATE: FAIL"', DRIVER)
        self.assertIn('if [[ "$CAMPAIGN_MODE" == full ]]; then\n  echo "FABRIC V3 O3K MINIMAL THREE-HOST MILESTONE: PASS"', DRIVER)
        self.assertIn('before-departure/traffic/a-to-b-icmp.txt', DRIVER)
        self.assertIn('before-departure/traffic/b-to-a-icmp.txt', DRIVER)
        self.assertIn('before-departure/traffic/a-to-c-icmp.txt', DRIVER)
        self.assertIn('before-departure/traffic/c-to-a-icmp.txt', DRIVER)
        self.assertIn('before-departure/traffic/a-to-b-canonical-arp.txt', DRIVER)
        self.assertIn('pre-delete-work-history.json', DRIVER)
        full_mode = DRIVER.index('if [[ "$CAMPAIGN_MODE" == full ]]; then')
        remove_c = DRIVER.index('# Remove C only through the supported API')
        history_capture = DRIVER.index('pre-delete-work-history.json')
        delete_request = DRIVER.index('delete_status="$(curl --silent --show-error --max-time 60')
        self.assertLess(full_mode, remove_c)
        self.assertLess(history_capture, delete_request)
        self.assertLess(remove_c, delete_request)
        self.assertIn('-X DELETE \\\n  "$BASE/v2.1/$PROJECT_ID/servers/${SERVER_IDS[2]}"', DRIVER[delete_request:])
        self.assertIn("assert all(latest[h] and latest[h]['action']=='Apply' and latest[h]['state']=='succeeded'", DRIVER)
        self.assertIn('run_retirement_microgate', RETIREMENT)
        self.assertIn('CAMPAIGN_MODE" == departure-micro', RETIREMENT)
        self.assertIn('stop_controller', RETIREMENT)
        self.assertIn('replacement controller did not become ready after retirement', RETIREMENT)

    def test_retirement_poll_distinguishes_convergence_from_harness_failure(self):
        self.assertEqual(RETIREMENT.count('case "$evidence_status" in'), 2)
        self.assertEqual(RETIREMENT.count('case "$registration_status" in'), 1)
        self.assertEqual(RETIREMENT.count('1) ;;'), 2)
        self.assertEqual(RETIREMENT.count('2) fail "retirement evidence schema/observer failure'), 1)
        self.assertEqual(RETIREMENT.count('2) fail "post-restart retirement evidence schema/observer failure'), 1)
        self.assertIn('validator exited unexpectedly ($evidence_status)', RETIREMENT)
        self.assertIn('invalid retirement evidence: {type(error).__name__}', RETIREMENT_EVIDENCE)
        self.assertIn('return 2', RETIREMENT_EVIDENCE)

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
        self.assertIn("fabric-v3-port-detach-evidence.py", DRIVER)
        self.assertIn("assert port.get('status')=='DOWN'", DRIVER)
        self.assertNotIn("value['status']=='down'", DRIVER)
        self.assertIn("fabric-v3-canonical-endpoint-retention-evidence.py", RETIREMENT)
        self.assertIn("c-delete/port/canonical-endpoint-state.json", RETIREMENT)
        self.assertNotIn("departed_endpoint_absent", RETIREMENT)
        self.assertIn("remove.get('local_host')=='host-c'", DRIVER)
        self.assertIn("row.get('local_host')=='host-c'", DRIVER)
        self.assertIn("command.get('plan',{}).get('fabric',{}).get('local_host')=='host-c'", DRIVER)
        self.assertIn("C Remove identity/outcome was not retained across controller restart", RETIREMENT)
        self.assertIn("A/B traffic failed after C retirement", RETIREMENT)
        self.assertIn("B/A traffic failed after C retirement", RETIREMENT)
        self.assertIn("local_host", RETIREMENT_EVIDENCE)

    def test_canonical_endpoint_retention_is_observed_after_remove_before_port_delete(self):
        self.assertIn("source \"$ROOT_DIR/tests/fabric-v3-retirement-microgate.sh\"", DRIVER)
        delete_c = DRIVER.index('[[ "$delete_status" == 204 ]]')
        retirement_call = DRIVER.index('run_retirement_microgate "$REALM_ID"')
        port_delete = DRIVER.index('for id in "${PORT_IDS[@]}"; do curl')
        self.assertLess(delete_c, retirement_call)
        self.assertLess(retirement_call, port_delete)
        self.assertIn(
            '"$EVIDENCE/c-delete/port/canonical-endpoint-state.json"',
            RETIREMENT,
        )
        self.assertIn(
            '"$ROOT_DIR/tests/fabric-v3-canonical-endpoint-retention-evidence.py"',
            RETIREMENT,
        )

    def test_durable_work_history_uses_the_canonical_target_host_field(self):
        start = DRIVER.index("capture_realm_work_history() {")
        end = DRIVER.index("\nfield() {", start)
        capture = DRIVER[start:end]
        self.assertIn("'target_host_id':row['target_host_id']", capture)
        self.assertIn('survivor-convergence/plans/durable-work.json', RETIREMENT)
        self.assertIn('c_latest["target_host_id"] == remove["local_host"]', RETIREMENT_EVIDENCE)
        self.assertNotIn('c_latest["local_host"]', RETIREMENT_EVIDENCE)

    def test_retirement_observer_uses_owned_namespace_and_accepts_namespace_absence(self):
        self.assertIn("fabric-v3-shared-fabric-namespace.py", RETIREMENT)
        self.assertIn("before-departure/host-c/ownership.json", RETIREMENT)
        self.assertIn("shared-fabric-namespace-state.json", RETIREMENT)
        self.assertGreaterEqual(RETIREMENT.count("fabric-v3-shared-fabric-namespace.py"), 2)
        self.assertGreaterEqual(RETIREMENT.count('if [[ "$namespace_state" == absent ]]'), 2)
        self.assertIn("host-c-shared-namespace-state.json", RETIREMENT)
        self.assertNotIn("ip netns exec o3k-fabric", RETIREMENT)
        self.assertIn("ownership returned after controller restart", RETIREMENT)
        self.assertIn("post_ownership_namespace", RETIREMENT)
        self.assertIn("changed namespace identity", RETIREMENT)

    def test_predelete_realm_generation_comes_from_durable_work_snapshot(self):
        provider_start = DRIVER.index('python3 - "$EVIDENCE/endpoint-removal" "$realm_id"')
        durable_start = DRIVER.index('python3 - "$EVIDENCE/controller-data/o3k.sqlite" "$realm_id"', provider_start)
        provider_checks = DRIVER[provider_start:durable_start]
        durable_end = DRIVER.index('cp "$EVIDENCE/endpoint-removal/pre-delete-work-history.json"', durable_start)
        durable_checks = DRIVER[durable_start:durable_end]

        self.assertNotIn("resource_generations", provider_checks)
        self.assertIn("plan.get('resource_generations',{}).get(realm)", durable_checks)
        self.assertIn("realm_generations={latest[h]['realm_generation'] for h in history}", durable_checks)
        self.assertIn("latest[host]['participants']==expected_participants", durable_checks)
        self.assertIn("summary['hosts'][suffix]['realm_generation']=latest[host]['realm_generation']", durable_checks)
        observed = durable_checks.index("status':'observed_before_predicate_checks'")
        first_predicate = durable_checks.index("assert all(latest[h]")
        self.assertLess(observed, first_predicate)

    def test_c_delete_evidence_uses_durable_operation_and_generated_audit_identity(self):
        delete_start = DRIVER.index('delete_started_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"')
        delete_end = DRIVER.index('cp "$EVIDENCE/c-delete/operation/audit-terminal-state.json"', delete_start)
        delete_evidence = DRIVER[delete_start:delete_end]
        self.assertNotIn("delete_request_id", delete_evidence)
        self.assertNotIn("x-request-id:", delete_evidence)
        self.assertIn("fabric-v3-delete-operation-evidence.py", delete_evidence)
        self.assertIn("kind = 'lifecycle:delete'", DELETE_OPERATION_EVIDENCE)
        self.assertIn("action = 'compute:DeleteServer'", DELETE_OPERATION_EVIDENCE)
        self.assertIn("WHERE resource_id = ?", DELETE_OPERATION_EVIDENCE)
        self.assertNotIn("julianday(created_at)", DELETE_OPERATION_EVIDENCE)
        self.assertNotIn("julianday(timestamp)", DELETE_OPERATION_EVIDENCE)
        self.assertIn('"request_id": audit_event["request_id"]', DELETE_OPERATION_EVIDENCE)
        self.assertNotIn("request_id = ?", DELETE_OPERATION_EVIDENCE)
        self.assertIn('operations[0]["state"] != "succeeded"', DELETE_OPERATION_EVIDENCE)
        self.assertIn('audit_events[0]["outcome"] != "succeeded"', DELETE_OPERATION_EVIDENCE)

    def test_teardown_checks_fabric_and_dhcp_owned_state_without_global_cleanup(self):
        self.assertIn("run-owned-provider-objects.json", DRIVER)
        self.assertIn("x.get('realms',{})", DRIVER)
        self.assertIn("host-$host-dhcp-state.txt", DRIVER)
        self.assertIn("host-$host-dnsmasq-processes.txt", DRIVER)
        self.assertIn("run not in processes", DRIVER)
        self.assertIn("foreign libvirt domain inventory changed", DRIVER)
        self.assertIn("final-durable-state.json", DRIVER)
        self.assertIn("vni_binding_released_after_provider_absence", DRIVER)
        self.assertNotIn("virsh net-destroy", DRIVER)
        self.assertNotIn("nft flush ruleset", DRIVER)

    def test_cleanup_refreshes_only_the_libvirt_pool_for_run_image_store(self):
        start = DRIVER.index("refresh_image_store_pool() {")
        end = DRIVER.index("\n}\n\ncleanup_on_success()", start)
        observer = DRIVER[start:end]
        self.assertIn("pool-dumpxml", observer)
        self.assertIn("pathlib.Path(path).resolve(strict=False)==image_store", observer)
        self.assertIn("pool-refresh',pool", observer)
        self.assertIn("multiple libvirt pools target the exact campaign image store", observer)
        self.assertIn("'image_store_pool_refresh': status(pool_refresh)", DRIVER)
        self.assertNotIn("pool-refresh --all", DRIVER)
        refresh = DRIVER.index('refresh_image_store_pool "$EVIDENCE/teardown/image-store-pool-refresh.json"')
        inventory = DRIVER.index('snapshot --network "$NETWORK" \\\n          --output "$EVIDENCE/teardown/host-inventory-after-cleanup.json"')
        self.assertLess(refresh, inventory)

    def test_server_teardown_poll_distinguishes_http_absence_and_is_bounded(self):
        poll = DRIVER[DRIVER.index("servers_remaining=1"):DRIVER.index('for id in "${PORT_IDS[@]}"; do')]
        self.assertIn('--max-time "$request_timeout"', poll)
        self.assertIn("server_poll_deadline=$((SECONDS + 120))", poll)
        self.assertIn('server_poll_deadline - SECONDS', poll)
        self.assertIn("-w '%{http_code}'", poll)
        self.assertIn("404)", poll)
        self.assertIn("200)", poll)
        self.assertIn("unexpected server deletion observation HTTP", poll)
        self.assertIn("server deletion did not converge within 120 seconds", poll)

    def test_nested_domain_cleanup_never_removes_unverified_storage(self):
        self.assertNotIn("--remove-all-storage", DRIVER)
        self.assertIn("fabric-v3-owned-domain-storage.py", DRIVER)
        self.assertIn('rm -- "$disk" "$seed"', DRIVER)
        self.assertIn('owned-domain-storage-check.py"', DRIVER)
        self.assertIn('owned-domain-storage-check.sha256"', DRIVER)

    def test_failure_cleanup_requires_observed_absence_and_has_one_deadline(self):
        start = DRIVER.index("cleanup_owned_api_resource() {")
        end = DRIVER.index("\n  }\n  if [[ -f", start)
        cleanup = DRIVER[start:end]
        self.assertIn("local deadline=$((SECONDS + 120))", cleanup)
        self.assertIn('deadline - SECONDS', cleanup)
        self.assertIn('[[ "$get_status" == 404 ]]', cleanup)
        self.assertNotIn('get_status" == 404 || "$delete_status" == 404', cleanup)
        self.assertNotIn('[[ "$delete_status" == 404 ]]', cleanup)

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
        start = RETIREMENT.index('convergence_deadline=$((SECONDS + 120))')
        end = RETIREMENT.index('guest_control_command a "ping -c 1 -W 4 ${TENANT_IP[b]}" survivor-convergence/traffic/a-to-b-icmp.txt', start)
        removal = RETIREMENT[start:end]
        self.assertIn('while (( SECONDS < convergence_deadline ))', removal)
        self.assertIn('capture_c_remove_work_row "$realm_id"', removal)
        self.assertIn('capture_realm_work_history "$realm_id"', removal)
        self.assertIn('for host in a b', removal)
        self.assertIn('fabric-v3-retirement-evidence.py', removal)
        self.assertIn('A/B did not reach durable reduced-Realm convergence with C retirement retained within 120 seconds', removal)

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

    def test_guest_inventory_mac_is_initialized_before_strict_shell_use(self):
        start = DRIVER.index('for host in a b c; do\n  octet=')
        end = DRIVER.index('  cat >"$ws/user-data"', start)
        guest_setup = DRIVER[start:end]
        self.assertLess(guest_setup.index('mac="${MGMT_MAC[$host]}"'), guest_setup.index('"$mac"'))

    def test_selected_management_address_is_not_rejected_by_stale_octet_range(self):
        installer = (ROOT / "fabric-v3-install-agent-host.sh").read_text()
        self.assertIn('host="$1"; run="$2"; stage="$3"', installer)
        self.assertNotIn("$octet", installer)
        self.assertIn('install-agent-host.sh $host $RUN_ID /tmp/$RUN_ID-stage', DRIVER)


if __name__ == "__main__":
    unittest.main()
