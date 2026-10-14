#!/usr/bin/env bash

# Sourced by the frozen-candidate campaign driver after supported deletion of
# server C. All reads below are observations; resource mutation remains on the
# supported API lifecycle in the caller.
run_retirement_microgate() {
  local realm_id="$1" namespace_name address host object_name fabric_namespace namespace_state
  local convergence_deadline survivor_converged poll old_controller_pid new_controller_pid recovery_ready code evidence_status
  local registration_ready registration_status host address health_port
  local expected_agent_id current_agent_identity current_ready_status all_agents_ready
  local registration_transport_failure registration_observer_pending
  local -A expected_compute_agent_ids=()
  local -a registration_agent_args=()

  for host in a b c; do
    address="${MGMT_IP[$host]}"
    ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json" \
      >"$EVIDENCE/endpoint-removal/host-$host-ownership.json" \
      || fail "post-C-removal ownership unavailable on host-$host" "ENVIRONMENT_GAP"
  done
  cp "$EVIDENCE/endpoint-removal/host-c-ownership.json" \
    "$EVIDENCE/provider-absence/host-c/ownership/ownership.json"

  mkdir -p "$EVIDENCE/foreign-fdb-after-retirement"
  for host in a b c; do
    ssh_vm "${MGMT_IP[$host]}" 'sudo bridge -j fdb show' \
      >"$EVIDENCE/foreign-fdb-after-retirement/host-$host.json" \
      || fail "foreign FDB post-retirement observation failed on host-$host" "ENVIRONMENT_GAP"
    ssh_vm "${MGMT_IP[$host]}" 'sudo ip netns list' \
      >"$EVIDENCE/foreign-fdb-after-retirement/host-$host-namespaces.txt" \
      || fail "foreign namespace post-retirement observation failed on host-$host" "ENVIRONMENT_GAP"
    mkdir -p "$EVIDENCE/foreign-fdb-after-retirement/host-$host-namespaces"
    while IFS= read -r namespace; do
      [[ "$namespace" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "invalid observed namespace identity" "HARNESS_GAP"
      awk -v expected="$namespace" '$1 == expected { found=1 } END { exit found ? 0 : 1 }' \
        "$EVIDENCE/foreign-fdb-after-retirement/host-$host-namespaces.txt" \
        || fail "baseline namespace disappeared after retirement: $host/$namespace" "OWNERSHIP_DEFECT"
      ssh_vm "${MGMT_IP[$host]}" "sudo ip netns exec '$namespace' bridge -j fdb show" \
        >"$EVIDENCE/foreign-fdb-after-retirement/host-$host-namespaces/$namespace.json" \
        || fail "foreign namespace FDB observation failed for $host/$namespace" "ENVIRONMENT_GAP"
      python3 "$ROOT_DIR/tests/fabric-v3-foreign-fdb.py" \
        --before "$EVIDENCE/environment/foreign-fdb-before/host-$host-namespaces/$namespace.json" \
        --after "$EVIDENCE/foreign-fdb-after-retirement/host-$host-namespaces/$namespace.json" \
        >"$EVIDENCE/foreign-fdb-after-retirement/host-$host-namespaces/$namespace-comparison.txt" 2>&1 \
        || fail "foreign namespace FDB changed after retirement: $host/$namespace" "OWNERSHIP_DEFECT"
    done < <(awk '{print $1}' "$EVIDENCE/environment/foreign-fdb-before/host-$host-namespaces.txt")
    devices=()
    while IFS= read -r device; do devices+=(--owned-device "$device"); done < <(
      python3 - "$EVIDENCE/before-departure/host-$host/ownership.json" <<'PYDEV'
import json,sys
state=json.load(open(sys.argv[1]))
for realm in state.get('realms', {}).values():
    vxlan=realm.get('vxlan', {})
    for device in (vxlan.get('interface'), vxlan.get('bridge'), vxlan.get('fabric_veth'),
                   *(item.get('interface') for item in realm.get('endpoint_taps', {}).values())):
        if device: print(device)
PYDEV
    )
    python3 "$ROOT_DIR/tests/fabric-v3-foreign-fdb.py" \
      --before "$EVIDENCE/environment/foreign-fdb-before/host-$host.json" \
      --after "$EVIDENCE/foreign-fdb-after-retirement/host-$host.json" \
      "${devices[@]}" \
      >"$EVIDENCE/foreign-fdb-after-retirement/host-$host-comparison.txt" 2>&1 \
      || fail "foreign FDB state changed outside run-owned Realm interfaces" "OWNERSHIP_DEFECT"
    run_namespace="$(python3 - "$EVIDENCE/before-departure/host-$host/ownership.json" <<'PYNS'
import json,sys
state=json.load(open(sys.argv[1]))
namespaces={state.get('fabric', {}).get('namespace', '')}
for realm in state.get('realms', {}).values():
    namespaces.add(realm.get('namespace', ''))
    namespaces.add(realm.get('fabric_namespace', ''))
    vxlan=realm.get('vxlan')
    if isinstance(vxlan, dict):
        namespaces.add(vxlan.get('namespace', ''))
for namespace in sorted(namespace for namespace in namespaces if namespace):
    print(namespace)
PYNS
)"
    namespace_args=()
    while IFS= read -r namespace; do
      [[ -z "$namespace" ]] || namespace_args+=(--owned-namespace "$namespace")
    done <<<"$run_namespace"
    python3 "$ROOT_DIR/tests/fabric-v3-foreign-fdb.py" \
      --before-namespaces "$EVIDENCE/environment/foreign-fdb-before/host-$host-namespaces.txt" \
      --after-namespaces "$EVIDENCE/foreign-fdb-after-retirement/host-$host-namespaces.txt" \
      "${namespace_args[@]}" \
      >>"$EVIDENCE/foreign-fdb-after-retirement/host-$host-comparison.txt" 2>&1 \
      || fail "foreign namespace state changed after C retirement" "OWNERSHIP_DEFECT"
  done

  ssh_vm "${MGMT_IP[c]}" 'sudo ip -j -d link show' \
    >"$EVIDENCE/provider-absence/host-c/links/root-links.json" \
    || fail "could not observe host-C root links after Remove" "ENVIRONMENT_GAP"
  ssh_vm "${MGMT_IP[c]}" 'sudo ip netns list' \
    >"$EVIDENCE/provider-absence/host-c/links/namespaces.txt" \
    || fail "could not observe host-C network namespaces after Remove" "ENVIRONMENT_GAP"
  ssh_vm "${MGMT_IP[c]}" 'sudo bridge -j fdb show' \
    >"$EVIDENCE/provider-absence/host-c/fdb/root-fdb.json" \
    || fail "could not observe host-C forwarding database after Remove" "ENVIRONMENT_GAP"
  ssh_vm "${MGMT_IP[c]}" 'sudo nft list ruleset' \
    >"$EVIDENCE/provider-absence/host-c/nft/ruleset.txt" \
    || fail "could not observe host-C policy state after Remove" "ENVIRONMENT_GAP"
  python3 "$ROOT_DIR/tests/fabric-v3-shared-fabric-namespace.py" \
    "$EVIDENCE/before-departure/host-c/ownership.json" \
    "$EVIDENCE/provider-absence/host-c/ownership/ownership.json" \
    "$EVIDENCE/provider-absence/host-c/links/namespaces.txt" \
    "$EVIDENCE/provider-absence/host-c/links/shared-fabric-namespace-state.json" \
    || fail "could not reconcile C shared-fabric namespace ownership and inventory" "HARNESS_GAP"
  fabric_namespace="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["namespace"])' \
    "$EVIDENCE/provider-absence/host-c/links/shared-fabric-namespace-state.json")"
  namespace_state="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' \
    "$EVIDENCE/provider-absence/host-c/links/shared-fabric-namespace-state.json")"
  python3 - "$EVIDENCE/provider-absence/host-c/links/shared-fabric-namespace-state.json" <<'PY' \
    || fail "C shared-fabric ownership changed namespace identity during Remove" "PROVIDER_ABSENCE_DEFECT"
import json,sys
state=json.load(open(sys.argv[1])); assert state['post_ownership_namespace'] in (None,state['namespace']), state
PY
  if [[ "$namespace_state" == present ]]; then
    ssh_vm "${MGMT_IP[c]}" "sudo ip netns exec '$fabric_namespace' ip -j -d link show" \
      >"$EVIDENCE/provider-absence/host-c/links/shared-fabric-links.json" \
      || fail "could not observe C shared-fabric links after Remove" "ENVIRONMENT_GAP"
    ssh_vm "${MGMT_IP[c]}" "sudo ip netns exec '$fabric_namespace' bridge -j fdb show" \
      >"$EVIDENCE/provider-absence/host-c/fdb/shared-fabric-fdb.json" \
      || fail "could not observe C shared-fabric FDB after Remove" "ENVIRONMENT_GAP"
    ssh_vm "${MGMT_IP[c]}" "sudo ip netns exec '$fabric_namespace' nft list ruleset" \
      >"$EVIDENCE/provider-absence/host-c/nft/shared-fabric-ruleset.txt" \
      || fail "could not observe C shared-fabric policy after Remove" "ENVIRONMENT_GAP"
  elif [[ "$namespace_state" == absent ]]; then
    python3 - "$EVIDENCE/provider-absence/host-c/links/shared-fabric-namespace-state.json" \
      "$EVIDENCE/provider-absence/host-c/links/shared-fabric-links.json" \
      "$EVIDENCE/provider-absence/host-c/fdb/shared-fabric-fdb.json" \
      "$EVIDENCE/provider-absence/host-c/nft/shared-fabric-ruleset.txt" <<'PY' \
      || fail "C shared-fabric namespace is absent but durable ownership still claims it" "PROVIDER_ABSENCE_DEFECT"
import json,pathlib,sys
state_path,links,fdb,ruleset=sys.argv[1:]
state=json.load(open(state_path)); assert not state['post_ownership_claims_namespace'], state
namespace=state['namespace']
pathlib.Path(links).write_text('[]\n')
pathlib.Path(fdb).write_text('[]\n')
pathlib.Path(ruleset).write_text(f'namespace {namespace} absent after Remove; no namespace-scoped policy exists\n')
PY
  else
    fail "shared-fabric namespace observer returned an invalid state: $namespace_state" "HARNESS_GAP"
  fi
  namespace_name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["namespace"])' \
    "$EVIDENCE/endpoint-removal/c-owned-objects.json")"
  if awk '{print $1}' "$EVIDENCE/provider-absence/host-c/links/namespaces.txt" | grep -Fxq "$namespace_name"; then
    fail "host-C Realm namespace remains after Remove" "PROVIDER_ABSENCE_DEFECT"
  fi
  python3 - "$EVIDENCE/endpoint-removal/c-owned-objects.json" <<'PY' \
    >"$EVIDENCE/provider-absence/host-c/ownership/owned-object-identities.json" \
    || fail "C provider ownership identities could not be parsed" "HARNESS_GAP"
import json,sys
record=json.load(open(sys.argv[1])); vxlan=record.get('vxlan') or {}
json.dump({'realm':record,'root_links':sorted({value for value in (
    record.get('tap'),record.get('bridge'),record.get('host_veth'),record.get('public_host_veth'),
    vxlan.get('host_veth')) if value}),
    'namespace_links':sorted({value for value in (vxlan.get('interface'),vxlan.get('bridge'),vxlan.get('fabric_veth')) if value})},
    sys.stdout,sort_keys=True,indent=2)
print()
PY
  mapfile -t c_root_links < <(python3 - "$EVIDENCE/provider-absence/host-c/ownership/owned-object-identities.json" <<'PYCROOT'
import json,sys
for item in json.load(open(sys.argv[1]))['root_links']: print(item)
PYCROOT
)
  for object_name in "${c_root_links[@]}"; do
    assert_remote_link_absent c "$object_name" \
      "$EVIDENCE/provider-absence/host-c/links/${object_name}.json"
  done
  assert_remote_path_absent c "/var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/plans/$realm_id.json" \
    "$EVIDENCE/provider-absence/host-c/ownership/realm-plan-absence.txt"
  python3 - "$EVIDENCE/provider-absence/host-c" "${TENANT_MAC[c]}" \
    "$EVIDENCE/endpoint-removal/c-owned-objects.json" "$EVIDENCE/environment/fabric-identities.json" <<'PY' \
    || fail "C provider anti-spoof/FDB state remains after Remove" "PROVIDER_ABSENCE_DEFECT"
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); mac=sys.argv[2].lower()
ownership=json.load(open(sys.argv[3])); vxlan=ownership.get('vxlan') or {}
interfaces={value for value in (vxlan.get('interface'),vxlan.get('bridge'),vxlan.get('fabric_veth')) if value}
vni=str(vxlan.get('vni',''))
identities=json.load(open(sys.argv[4])); c_ip=next(row['fabric_transport_ip'] for row in identities if row['host_id']=='host-c')
root_fdb=json.loads((root/'fdb/root-fdb.json').read_text())
fabric_fdb=json.loads((root/'fdb/shared-fabric-fdb.json').read_text())
assert not any(str(row.get('mac','')).lower()==mac for row in root_fdb+fabric_fdb), (root_fdb,fabric_fdb)
assert not any(str(row.get('dst',''))==c_ip for row in fabric_fdb), fabric_fdb
links=json.loads((root/'links/shared-fabric-links.json').read_text())
assert not interfaces.intersection({row.get('ifname') for row in links}), links
nft=(root/'nft/ruleset.txt').read_text().lower()+(root/'nft/shared-fabric-ruleset.txt').read_text().lower()
assert mac not in nft, 'C endpoint anti-spoof rule remains'
  # The shared o3k-fabric namespace legitimately retains VNI admission for
  # surviving A/B. Realm-owned VNI policy is proven absent by deletion of
  # C's exact Realm namespace and all captured Realm-owned interfaces above.
PY

  # Preserve structured DHCP state on the authority and departing host.
  for host in a c; do
    if ! ssh_vm "${MGMT_IP[$host]}" 'sudo python3 -' "$RUN_ID" "$realm_id" \
      >"$EVIDENCE/provider-absence/host-c/${host}-dhcp-state.json" <<'PYDHCP'
import json,pathlib,sys
run,realm=sys.argv[1:]; root=pathlib.Path('/var/lib/o3k-fabric-v3')/run/'network/dhcp/fabric'/realm
result={'root_exists':root.exists(),'root_is_symlink':root.is_symlink(),'files':{}}
for name in ('state.json','fabric-dhcp-ownership.json','gateway-address-ownership.json','dnsmasq.conf','dnsmasq.leases'):
    path=root/name
    if path.is_symlink(): result['files'][name]={'symlink':True}; continue
    if not path.is_file(): result['files'][name]=None; continue
    text=path.read_text()
    try: result['files'][name]=json.loads(text)
    except json.JSONDecodeError: result['files'][name]={'text':text}
json.dump(result,sys.stdout,sort_keys=True,indent=2); print()
PYDHCP
    then
      fail "DHCP provider state observation failed on host-$host" "ENVIRONMENT_GAP"
    fi
  done
  ssh_vm "${MGMT_IP[c]}" "sudo -n true || exit 125; if sudo -n pgrep -a dnsmasq; then exit 0; else status=\$?; if [ \"\$status\" -eq 1 ]; then exit 0; else exit \"\$status\"; fi; fi" \
    >"$EVIDENCE/provider-absence/host-c/dnsmasq-processes.txt" \
    || fail "could not observe dnsmasq process state on host-c" "ENVIRONMENT_GAP"
  python3 - "$EVIDENCE/provider-absence/host-c/a-dhcp-state.json" \
    "$EVIDENCE/provider-absence/host-c/c-dhcp-state.json" "${PORT_IDS[2]}" \
    "$EVIDENCE/provider-absence/host-c/dnsmasq-processes.txt" "$RUN_ID" "$realm_id" <<'PY' \
    || fail "C DHCP binding/process state is not withdrawn" "PROVIDER_ABSENCE_DEFECT"
import json,pathlib,sys
authority,departing=(json.load(open(path)) for path in sys.argv[1:3])
c_port,processes_path,run,realm=sys.argv[3:]
authority_state=authority['files']['state.json'] or {}
assert c_port not in (authority_state.get('bindings') or {}), authority_state
assert c_port not in {binding.get('port_id') for binding in (authority_state.get('bindings') or {}).values()}, authority_state
assert departing.get('root_exists') and departing.get('root_is_symlink') is False, departing
local_state=departing['files']['state.json'] or {}
assert isinstance(local_state,dict), local_state
assert not local_state.get('bindings') and local_state.get('config') is None, local_state
owner=departing['files']['fabric-dhcp-ownership.json']
assert owner is not None, 'C DHCP ownership tombstone is missing'
assert type(owner.get('schema_version')) is int and owner['schema_version']==1 and owner.get('realm_id')==realm, owner
assert owner.get('local_host')=='host-c' and isinstance(owner.get('authority_host'),str) and owner['authority_host'] in {'host-a','host-b','host-c'}, owner
assert owner.get('dhcp_enabled') is False and owner.get('gateway') is None, owner
assert owner.get('withdrawn') is True and owner.get('pending') is False, owner
for field in ('realm_generation','directory_generation','binding_generation','local_fabric_generation'):
    assert type(owner.get(field)) is int and owner[field]>=0, owner
assert owner['realm_generation']==owner['directory_generation'], owner
assert type(owner.get('tenant_mtu')) is int and 1<=owner['tenant_mtu']<=65535, owner
assert departing['files']['gateway-address-ownership.json'] is None, departing['files']
config=departing['files']['dnsmasq.conf']
assert config is None, 'non-authority host C must not retain rendered DHCP configuration'
leases=departing['files']['dnsmasq.leases']
assert leases is None, 'non-authority host C must not retain a DHCP lease file'
assert run not in pathlib.Path(processes_path).read_text(), pathlib.Path(processes_path).read_text()
PY

  if python3 "$ROOT_DIR/tests/fabric-v3-canonical-endpoint-retention-evidence.py" \
    "$EVIDENCE/controller-data/o3k.sqlite" "$realm_id" \
    "${PORT_IDS[0]}" "${PORT_IDS[1]}" "${PORT_IDS[2]}" \
    "$EVIDENCE/c-delete/port/canonical-endpoint-state.json"; then
    :
  else
    endpoint_state_status=$?
    if (( endpoint_state_status == 1 )); then
      fail "caller-supplied canonical endpoint was not retained until supported port DELETE" "DURABLE_RETIREMENT_DEFECT"
    fi
    fail "canonical endpoint state could not be observed" "HARNESS_GAP"
  fi

  # Poll observed A/B plans, ownership, HER, journals, and durable work.
  convergence_deadline=$((SECONDS + 120)); survivor_converged=0; poll=0
  while (( SECONDS < convergence_deadline )); do
    poll=$((poll + 1))
    for host in a b; do
      capture_survivor_host "$host" \
        || fail "survivor runtime/plan observation failed on host-$host" "ENVIRONMENT_GAP"
    done
    capture_c_remove_work_row "$realm_id" >"$EVIDENCE/c-delete/remove-command/c-remove-command-state.txt" \
      || fail "C Remove durable history observation failed during survivor convergence" "HARNESS_GAP"
    cp "$EVIDENCE/endpoint-removal/c-remove-work-row.json" \
      "$EVIDENCE/c-delete/remove-command/c-remove-command.json"
    capture_realm_work_history "$realm_id" "$EVIDENCE/survivor-convergence/plans/durable-work.json" \
      || fail "network-plan durable history observation failed during survivor convergence" "HARNESS_GAP"
    if python3 "$ROOT_DIR/tests/fabric-v3-retirement-evidence.py" \
        --root "$EVIDENCE" --realm "$realm_id" --ports "${PORT_IDS[@]}" \
        --output "$EVIDENCE/survivor-convergence/plans/converged-state.json" \
        >"$EVIDENCE/survivor-convergence/plans/poll-$poll.stdout" \
        2>"$EVIDENCE/survivor-convergence/plans/poll-$poll.stderr"; then
      survivor_converged=1
      break
    else
      evidence_status=$?
      case "$evidence_status" in
        1) ;;
        2) fail "retirement evidence schema/observer failure; see poll-$poll.stderr" "HARNESS_GAP" ;;
        3) fail "survivor convergence retained departing-host FDB state; see poll-$poll.stderr" "SURVIVOR_RECONCILIATION_DEFECT" ;;
        *) fail "retirement evidence validator exited unexpectedly ($evidence_status); see poll-$poll.stderr" "HARNESS_GAP" ;;
      esac
    fi
    sleep 1
  done
  if (( ! survivor_converged )); then
    fail "A/B did not reach durable reduced-Realm convergence with C retirement retained within 120 seconds" \
      "SURVIVOR_RECONCILIATION_DEFECT"
  fi
  cp "$EVIDENCE/survivor-convergence/plans/converged-state.json" \
    "$EVIDENCE/c-delete/retirement-obligation/removal-order-and-survivor-convergence.json"
  guest_control_command a "ping -c 1 -W 4 ${TENANT_IP[b]}" survivor-convergence/traffic/a-to-b-icmp.txt \
    || fail "A/B traffic failed after C retirement" "$(guest_failure_class SURVIVOR_RECONCILIATION_DEFECT)"
  guest_control_command b "ping -c 1 -W 4 ${TENANT_IP[a]}" survivor-convergence/traffic/b-to-a-icmp.txt \
    || fail "B/A traffic failed after C retirement" "$(guest_failure_class SURVIVOR_RECONCILIATION_DEFECT)"
  guest_control_command a "ip neigh flush to ${TENANT_IP[b]} || true" survivor-convergence/traffic/a-to-b-neighbor-flush.txt \
    || fail "could not flush A neighbor entry for post-removal ARP observation" "HARNESS_GAP"
  guest_control_command a "ping -c 1 -W 4 ${TENANT_IP[b]} && ip neigh show to ${TENANT_IP[b]}" \
    survivor-convergence/traffic/a-to-b-canonical-arp.txt \
    || fail "A could not resolve B after C retirement" "SURVIVOR_RECONCILIATION_DEFECT"
  grep -Fqi "${TENANT_MAC[b]}" "$EVIDENCE/survivor-convergence/traffic/a-to-b-canonical-arp.txt" \
    || fail "post-removal ARP did not resolve to B's canonical MAC" "SURVIVOR_RECONCILIATION_DEFECT"

  if [[ "$CAMPAIGN_MODE" == departure-micro ]]; then
    # Keep the raw survivor FDB observed before the controller restart.  The
    # validator below intentionally reuses survivor-convergence/ for the
    # reconstructed post-restart snapshot, so preserve both observations.
    for host in a b; do
      mkdir -p "$EVIDENCE/restart/survivor-fdb-pre-restart"
      cp "$EVIDENCE/survivor-convergence/host-$host/fdb.txt" \
        "$EVIDENCE/restart/survivor-fdb-pre-restart/host-$host.txt"
    done
    old_controller_pid="$O3KD_PID"
    cp "$EVIDENCE/c-delete/remove-command/c-remove-command.json" \
      "$EVIDENCE/c-delete/remove-command/c-remove-command-before-restart.json"
    printf '%s\n' "$old_controller_pid" >"$EVIDENCE/restart/startup-recovery/controller-before.pid"
    printf '%s\n' "$O3K_CONTROLLER_ID" >"$EVIDENCE/restart/startup-recovery/controller-identity.txt"
    printf '%s\n' "$O3K_CONTROLLER_EPOCH" >"$EVIDENCE/restart/startup-recovery/controller-epoch.txt"
    stop_controller \
      || fail "controller could not stop cleanly after C retirement" "DURABLE_RECOVERY_DEFECT"
    [[ ! -e "/proc/$old_controller_pid" ]] \
      || fail "old controller PID remains after stop" "DURABLE_RECOVERY_DEFECT"
    printf '%s\n' absent >"$EVIDENCE/restart/startup-recovery/old-controller-process.txt"
    O3K_CONTROLLER_ID="${INITIAL_CONTROLLER_ID}-restart"
    O3K_CONTROLLER_EPOCH="${INITIAL_CONTROLLER_EPOCH}-restart"
    [[ "$O3K_CONTROLLER_ID" != "$INITIAL_CONTROLLER_ID" \
      && "$O3K_CONTROLLER_EPOCH" != "$INITIAL_CONTROLLER_EPOCH" ]] \
      || fail "replacement controller session did not advance its identity and epoch" "HARNESS_GAP"
    export O3K_CONTROLLER_ID O3K_CONTROLLER_EPOCH
    printf '%s\n' "$O3K_CONTROLLER_ID" >"$EVIDENCE/restart/startup-recovery/controller-identity-expected-after.txt"
    printf '%s\n' "$O3K_CONTROLLER_EPOCH" >"$EVIDENCE/restart/startup-recovery/controller-epoch-expected-after.txt"
    "$PRODUCT_SOURCE_DIR/target/release/o3kd" --listen-addr "$HOST_MGMT_IP:$API_PORT" \
      --data-dir "$EVIDENCE/controller-data" --log-filter info \
      >"$EVIDENCE/restart/startup-recovery/o3kd.log" 2>&1 &
    O3KD_PID=$!
    new_controller_pid="$O3KD_PID"
    printf '%s\n' "$new_controller_pid" >"$EVIDENCE/restart/startup-recovery/controller-after.pid"
    [[ "$new_controller_pid" != "$old_controller_pid" ]] \
      || fail "replacement controller reused the stopped PID" "DURABLE_RECOVERY_DEFECT"
    recovery_ready=0
    for _ in $(seq 1 120); do
      if curl -fsS "$BASE/readyz" >"$EVIDENCE/restart/startup-recovery/ready.json" 2>/dev/null; then
        recovery_ready=1; break
      fi
      kill -0 "$new_controller_pid" 2>/dev/null \
        || fail "replacement controller exited during durable recovery" "DURABLE_RECOVERY_DEFECT"
      sleep 1
    done
    (( recovery_ready == 1 )) \
      || fail "replacement controller did not become ready after retirement" "DURABLE_RECOVERY_DEFECT"
    [[ ! -e "/proc/$old_controller_pid" ]] \
      || fail "old controller process was still present after replacement readiness" "DURABLE_RECOVERY_DEFECT"
    for host in a b c; do
      expected_agent_id="$(python3 - "$EVIDENCE/management/compute-$host-ready.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1])); agent=value.get('agent_id')
assert isinstance(agent,str) and agent.strip(), value
print(agent)
PY
)" || fail "pre-restart compute identity is unavailable for host-$host" "HARNESS_GAP"
      expected_compute_agent_ids[$host]="$expected_agent_id"
    done
    registration_ready=0
    for _ in $(seq 1 120); do
      registration_agent_args=()
      all_agents_ready=1
      registration_transport_failure=0
      registration_observer_pending=0
      for host in a b c; do
        address="${MGMT_IP[$host]}"
        case "$host" in a) health_port=19101;; b) health_port=19102;; c) health_port=19103;; esac
        rm -f "$EVIDENCE/restart/startup-recovery/compute-$host-current-ready.json"
        if ! ssh_vm "$address" \
          "sudo curl --silent --show-error --max-time 5 --write-out '\n__O3K_HTTP_STATUS=%{http_code}\n' http://127.0.0.1:$health_port/readyz" \
          >"$EVIDENCE/restart/startup-recovery/compute-$host-readyz-response.txt" \
          2>"$EVIDENCE/restart/startup-recovery/compute-$host-readyz-ssh.stderr"; then
          registration_transport_failure=1
          all_agents_ready=0
          continue
        fi
        if python3 "$ROOT_DIR/tests/fabric-v3-controller-restart-readiness.py" capture-agent-ready \
          --response "$EVIDENCE/restart/startup-recovery/compute-$host-readyz-response.txt" \
          --host "host-$host" --expected-agent-id "${expected_compute_agent_ids[$host]}" \
          --output "$EVIDENCE/restart/startup-recovery/compute-$host-current-ready.json" \
          >"$EVIDENCE/restart/startup-recovery/compute-$host-readyz-observer.stdout" \
          2>"$EVIDENCE/restart/startup-recovery/compute-$host-readyz-observer.stderr"; then
          current_ready_status=0
        else
          current_ready_status=$?
        fi
        case "$current_ready_status" in
          0)
            current_agent_identity="$(python3 - "$EVIDENCE/restart/startup-recovery/compute-$host-current-ready.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1])); agent=value.get('agent_id'); epoch=value.get('agent_epoch')
assert value.get('status')=='ready' and isinstance(agent,str) and agent.strip()
assert isinstance(epoch,str) and epoch.strip()
print(f'{agent}={epoch}')
PY
)" || fail "live current compute readiness artifact is malformed for host-$host" "HARNESS_GAP"
            registration_agent_args+=(--agent "$current_agent_identity")
            ;;
          1) all_agents_ready=0 ;;
          2) fail "live compute /readyz observer failed for host-$host; see compute-$host-readyz-observer.stderr" "HARNESS_GAP" ;;
          3) fail "compute agent identity changed after controller restart on host-$host" "DURABLE_RECOVERY_DEFECT" ;;
          4) fail "compute agent returned invalid /readyz state after controller restart on host-$host" "DURABLE_RECOVERY_DEFECT" ;;
          *) fail "live compute /readyz observer returned unexpected status $current_ready_status for host-$host" "HARNESS_GAP" ;;
        esac
      done
      python3 - "$EVIDENCE/restart/startup-recovery/current-registration-state.json" \
        "$EVIDENCE/restart/startup-recovery/compute-a-current-ready.json" \
        "$EVIDENCE/restart/startup-recovery/compute-b-current-ready.json" \
        "$EVIDENCE/restart/startup-recovery/compute-c-current-ready.json" <<'PY'
import json,pathlib,sys
path=pathlib.Path(sys.argv[1]); records={}
for host,source in zip('abc',sys.argv[2:]):
    try: records[f'host-{host}']=json.loads(pathlib.Path(source).read_text())
    except (OSError,json.JSONDecodeError): records[f'host-{host}']={'status':'unobserved'}
path.write_text(json.dumps({'schema_version':1,'artifact_type':'fabric-v3-controller-restart-readiness',
    'status':'pending','observer':'live_compute_agent_readyz','compute_agents':records},sort_keys=True,indent=2)+'\n')
PY
      if (( all_agents_ready == 1 )); then
        if python3 "$ROOT_DIR/tests/fabric-v3-controller-restart-readiness.py" observe-controller-restart \
          --log "$EVIDENCE/restart/startup-recovery/o3kd.log" \
          --controller-id "$O3K_CONTROLLER_ID" --controller-epoch "$O3K_CONTROLLER_EPOCH" \
          "${registration_agent_args[@]}" \
          --output "$EVIDENCE/restart/startup-recovery/current-registration-state.json" \
          >"$EVIDENCE/restart/startup-recovery/registration-observer.stdout" \
          2>"$EVIDENCE/restart/startup-recovery/registration-observer.stderr"; then
          registration_ready=1
          break
        else
          registration_status=$?
          case "$registration_status" in
            1) registration_observer_pending=1 ;;
            *) fail "replacement controller registration observer failed; see registration-observer.stderr" "HARNESS_GAP" ;;
          esac
        fi
      fi
      kill -0 "$new_controller_pid" 2>/dev/null \
        || fail "replacement controller exited before all compute agents re-registered" "DURABLE_RECOVERY_DEFECT"
      sleep 1
    done
    if (( registration_ready != 1 )); then
      if (( registration_observer_pending == 1 )); then
        fail "replacement controller log did not confirm the live compute agent epochs within 120 seconds; see current-registration-state.json" "DURABLE_RECOVERY_DEFECT"
      elif (( registration_transport_failure == 1 )); then
        fail "compute-agent management observation remained unavailable during controller restart; see compute-*-readyz-ssh.stderr" "ENVIRONMENT_GAP"
      else
        fail "compute agents did not become ready with the replacement controller within 120 seconds; see current-registration-state.json" "DURABLE_RECOVERY_DEFECT"
      fi
    fi
    printf '%s\n' "$O3K_CONTROLLER_ID" >"$EVIDENCE/restart/startup-recovery/controller-identity-after.txt"
    printf '%s\n' "$O3K_CONTROLLER_EPOCH" >"$EVIDENCE/restart/startup-recovery/controller-epoch-after.txt"
    python3 - "$EVIDENCE/manifest.json" "$INITIAL_CONTROLLER_ID" "$INITIAL_CONTROLLER_EPOCH" \
      "$O3K_CONTROLLER_ID" "$O3K_CONTROLLER_EPOCH" \
      "$EVIDENCE/restart/startup-recovery/current-registration-state.json" \
      "$EVIDENCE/restart/startup-recovery/compute-a-current-ready.json" \
      "$EVIDENCE/restart/startup-recovery/compute-b-current-ready.json" \
      "$EVIDENCE/restart/startup-recovery/compute-c-current-ready.json" <<'PY' \
      || fail "restart identity and current registrations could not be bound into the manifest" "HARNESS_GAP"
import json,pathlib,sys
manifest_path=pathlib.Path(sys.argv[1]); initial_id,initial_epoch,restart_id,restart_epoch=sys.argv[2:6]
readiness=json.loads(pathlib.Path(sys.argv[6]).read_text())
manifest=json.loads(manifest_path.read_text())
assert manifest.get('controller')=={'identity':initial_id,'epoch':initial_epoch}, manifest.get('controller')
assert restart_id and restart_epoch and restart_id!=initial_id and restart_epoch!=initial_epoch
assert readiness.get('status')=='passed' and readiness.get('controller_session_matches'), readiness
assert readiness.get('all_expected_compute_agents_registered'), readiness
assert readiness.get('expected_controller_session')=={'identity':restart_id,'epoch':restart_epoch}, readiness
assert readiness.get('observed_controller_session',{}).get('identity')==restart_id, readiness
assert readiness.get('observed_controller_session',{}).get('epoch')==restart_epoch, readiness
current_agents={}
for host,source in zip('abc',sys.argv[7:10]):
    live=json.loads(pathlib.Path(source).read_text())
    manifest_host=manifest['hosts'][f'host-{host}']
    assert live.get('status')=='ready' and live.get('observer')=='ssh_sudo_local_readyz', live
    assert live.get('agent_id')==manifest_host['compute_agent_id'], (live,manifest_host)
    assert live.get('agent_epoch'), live
    current_agents[manifest_host['compute_agent_id']]=live['agent_epoch']
assert len(current_agents)==3, current_agents
assert readiness.get('expected_compute_agents')==dict(sorted(current_agents.items())), (readiness,current_agents)
assert {agent_id:row.get('epoch') for agent_id,row in readiness.get('registered_compute_agents',{}).items()}==current_agents, readiness
manifest['controller_restart']={'identity':restart_id,'epoch':restart_epoch,'session_advanced':True,
    'readiness_artifact':'restart/startup-recovery/current-registration-state.json',
    'current_compute_agents':{f'host-{host}':{'agent_id':manifest['hosts'][f'host-{host}']['compute_agent_id'],
        'agent_epoch':json.loads(pathlib.Path(source).read_text())['agent_epoch'],
        'readiness_artifact':f'restart/startup-recovery/compute-{host}-current-ready.json'}
        for host,source in zip('abc',sys.argv[7:10])}}
manifest_path.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
PY
    for host in a b; do
      if [[ "$host" == a ]]; then server_index=0; else server_index=1; fi
      code="$(curl --silent --show-error --max-time 20 -o \
        "$EVIDENCE/restart/startup-recovery/server-$host.json" -w '%{http_code}' \
        "$BASE/v2.1/$PROJECT_ID/servers/${SERVER_IDS[$server_index]}" -H "x-auth-token: $TOKEN" || true)"
      [[ "$code" == 200 ]] \
        || fail "survivor server $host unavailable after controller restart (HTTP $code)" "DURABLE_RECOVERY_DEFECT"
    done
    code="$(curl --silent --show-error --max-time 20 -o \
      "$EVIDENCE/restart/startup-recovery/server-c.json" -w '%{http_code}' \
      "$BASE/v2.1/$PROJECT_ID/servers/${SERVER_IDS[2]}" -H "x-auth-token: $TOKEN" || true)"
    [[ "$code" == 404 ]] \
      || fail "retired C server reappeared after controller restart (HTTP $code)" "DURABLE_RECOVERY_DEFECT"
    for attempt in $(seq 1 120); do
      for host in a b; do
        capture_survivor_host "$host" \
          || fail "post-restart survivor observation failed on host-$host" "ENVIRONMENT_GAP"
        mkdir -p "$EVIDENCE/restart/survivor-fdb-post-restart"
        cp "$EVIDENCE/survivor-convergence/host-$host/fdb.txt" \
          "$EVIDENCE/restart/survivor-fdb-post-restart/host-$host.txt"
        ssh_vm "${MGMT_IP[$host]}" 'sudo bridge -j fdb show' \
          >"$EVIDENCE/restart/foreign-fdb/host-$host.json" \
          || fail "post-restart foreign FDB observation failed on host-$host" "ENVIRONMENT_GAP"
        ssh_vm "${MGMT_IP[$host]}" 'sudo ip netns list' \
          >"$EVIDENCE/restart/foreign-fdb/host-$host-namespaces.txt" \
          || fail "post-restart foreign namespace observation failed on host-$host" "ENVIRONMENT_GAP"
        mkdir -p "$EVIDENCE/restart/foreign-fdb/host-$host-namespaces"
        while IFS= read -r namespace; do
          [[ "$namespace" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "invalid post-restart namespace identity" "HARNESS_GAP"
      awk -v expected="$namespace" '$1 == expected { found=1 } END { exit found ? 0 : 1 }' \
        "$EVIDENCE/restart/foreign-fdb/host-$host-namespaces.txt" \
            || fail "baseline namespace disappeared after restart: $host/$namespace" "OWNERSHIP_DEFECT"
          ssh_vm "${MGMT_IP[$host]}" "sudo ip netns exec '$namespace' bridge -j fdb show" \
            >"$EVIDENCE/restart/foreign-fdb/host-$host-namespaces/$namespace.json" \
            || fail "foreign namespace FDB restart observation failed for $host/$namespace" "ENVIRONMENT_GAP"
          python3 "$ROOT_DIR/tests/fabric-v3-foreign-fdb.py" \
            --before "$EVIDENCE/environment/foreign-fdb-before/host-$host-namespaces/$namespace.json" \
            --after "$EVIDENCE/restart/foreign-fdb/host-$host-namespaces/$namespace.json" \
            >"$EVIDENCE/restart/foreign-fdb/host-$host-namespaces/$namespace-comparison.txt" 2>&1 \
            || fail "foreign namespace FDB changed after controller restart: $host/$namespace" "OWNERSHIP_DEFECT"
        done < <(awk '{print $1}' "$EVIDENCE/environment/foreign-fdb-before/host-$host-namespaces.txt")
        devices=()
        while IFS= read -r device; do devices+=(--owned-device "$device"); done < <(
          python3 - "$EVIDENCE/before-departure/host-$host/ownership.json" <<'PYDEV'
import json,sys
state=json.load(open(sys.argv[1]))
for realm in state.get('realms', {}).values():
    vxlan=realm.get('vxlan', {})
    for device in (vxlan.get('interface'), vxlan.get('bridge'), vxlan.get('fabric_veth'),
                   *(item.get('interface') for item in realm.get('endpoint_taps', {}).values())):
        if device: print(device)
PYDEV
        )
        python3 "$ROOT_DIR/tests/fabric-v3-foreign-fdb.py" \
          --before "$EVIDENCE/environment/foreign-fdb-before/host-$host.json" \
          --after "$EVIDENCE/restart/foreign-fdb/host-$host.json" \
          "${devices[@]}" \
          >"$EVIDENCE/restart/foreign-fdb/host-$host-comparison.txt" 2>&1 \
          || fail "foreign FDB state changed after controller restart" "OWNERSHIP_DEFECT"
        namespace_args=()
        while IFS= read -r namespace; do
          [[ -z "$namespace" ]] || namespace_args+=(--owned-namespace "$namespace")
        done < <(python3 - "$EVIDENCE/before-departure/host-$host/ownership.json" <<'PYNS'
import json,sys
state=json.load(open(sys.argv[1])); names={state.get('fabric', {}).get('namespace', '')}
for realm in state.get('realms', {}).values():
    names.update((realm.get('namespace', ''), realm.get('fabric_namespace', '')))
    vxlan=realm.get('vxlan')
    if isinstance(vxlan, dict): names.add(vxlan.get('namespace', ''))
for name in sorted(name for name in names if name): print(name)
PYNS
        )
        python3 "$ROOT_DIR/tests/fabric-v3-foreign-fdb.py" \
          --before-namespaces "$EVIDENCE/environment/foreign-fdb-before/host-$host-namespaces.txt" \
          --after-namespaces "$EVIDENCE/restart/foreign-fdb/host-$host-namespaces.txt" \
          "${namespace_args[@]}" \
          >>"$EVIDENCE/restart/foreign-fdb/host-$host-comparison.txt" 2>&1 \
          || fail "foreign namespace state changed after controller restart" "OWNERSHIP_DEFECT"
      done
      capture_c_remove_work_row "$realm_id" >"$EVIDENCE/c-delete/remove-command/c-remove-command-state.txt" \
        || fail "post-restart C retirement work observation failed" "HARNESS_GAP"
      cp "$EVIDENCE/endpoint-removal/c-remove-work-row.json" \
        "$EVIDENCE/c-delete/remove-command/c-remove-command.json"
      capture_realm_work_history "$realm_id" "$EVIDENCE/restart/durable-work/history.json" \
        || fail "post-restart durable work history unavailable" "HARNESS_GAP"
      cp "$EVIDENCE/restart/durable-work/history.json" \
        "$EVIDENCE/survivor-convergence/plans/durable-work.json"
      if python3 "$ROOT_DIR/tests/fabric-v3-retirement-evidence.py" \
          --root "$EVIDENCE" --realm "$realm_id" --ports "${PORT_IDS[@]}" \
          --output "$EVIDENCE/restart/plans/reconstructed-state.json" \
          >"$EVIDENCE/restart/plans/poll-$attempt.stdout" \
          2>"$EVIDENCE/restart/plans/poll-$attempt.stderr"; then
        break
      else
        evidence_status=$?
        case "$evidence_status" in
          1) ;;
          2) fail "post-restart retirement evidence schema/observer failure; see poll-$attempt.stderr" "HARNESS_GAP" ;;
          3) fail "post-restart survivor convergence retained departing-host FDB state; see poll-$attempt.stderr" "SURVIVOR_RECONCILIATION_DEFECT" ;;
          *) fail "post-restart retirement validator exited unexpectedly ($evidence_status); see poll-$attempt.stderr" "HARNESS_GAP" ;;
        esac
      fi
      (( attempt < 120 )) \
        || fail "C retirement or A/B convergence was not reconstructed after controller restart" "DURABLE_RECOVERY_DEFECT"
      sleep 1
    done
    python3 - "$EVIDENCE/c-delete/remove-command/c-remove-command-before-restart.json" \
      "$EVIDENCE/c-delete/remove-command/c-remove-command.json" \
      "$EVIDENCE/restart/durable-work/history.json" \
      "$EVIDENCE/restart/durable-work/c-retirement-reconstructed.json" <<'PY' \
      || fail "durable C Remove identity/outcome was not retained across controller restart" "DURABLE_RECOVERY_DEFECT"
import json,pathlib,sys
before_path,after_path,history_path,out_path=sys.argv[1:]
before=json.load(open(before_path)); after=json.load(open(after_path)); history=json.load(open(history_path))['history']
assert before.get('found') and after.get('found'), (before,after)
assert before.get('state')=='succeeded' and after.get('state')=='succeeded', (before,after)
assert before.get('command_id')==after.get('command_id'), (before,after)
assert before.get('target_agent_id')==after.get('target_agent_id')=='network-agent-c', (before,after)
assert before.get('target_agent_epoch') and before.get('target_agent_epoch')==after.get('target_agent_epoch'), (before,after)
assert before.get('outcome') and after.get('outcome'), (before,after)
latest=max((row for row in history if row.get('target_host_id')=='host-c'),
           key=lambda row:int(row['insertion_order']))
assert latest.get('action')=='Remove' and latest.get('state')=='succeeded', latest
assert latest.get('command_id')==before.get('command_id'), (latest,before)
assert latest.get('target_agent_epoch')==before.get('target_agent_epoch'), (latest,before)
pathlib.Path(out_path).write_text(json.dumps({'pre_restart':{k:before.get(k) for k in
    ('command_id','target_agent_id','target_agent_epoch','state','outcome')},
    'post_restart':{k:after.get(k) for k in ('command_id','target_agent_id','target_agent_epoch','state','outcome')},
    'latest_durable_C_work':latest,'retirement_reconstructed':True},sort_keys=True,indent=2)+'\n')
PY
    ssh_vm "${MGMT_IP[c]}" 'sudo ip netns list' \
      >"$EVIDENCE/restart/startup-recovery/host-c-namespaces.txt" \
      || fail "could not observe C namespace after controller restart" "ENVIRONMENT_GAP"
    if awk '{print $1}' "$EVIDENCE/restart/startup-recovery/host-c-namespaces.txt" | grep -Fxq "$namespace_name"; then
      fail "controller restart resurrected C's Fabric namespace" "DURABLE_RECOVERY_DEFECT"
    fi
    ssh_vm "${MGMT_IP[c]}" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json" \
      >"$EVIDENCE/restart/startup-recovery/host-c-ownership.json" \
      || fail "could not observe C ownership after controller restart" "ENVIRONMENT_GAP"
    python3 - "$EVIDENCE/restart/startup-recovery/host-c-ownership.json" "$realm_id" <<'PY' \
      || fail "controller restart restored C Realm ownership" "DURABLE_RECOVERY_DEFECT"
import json,sys
state=json.load(open(sys.argv[1])); assert sys.argv[2] not in state.get('realms',{}), state
PY
    python3 "$ROOT_DIR/tests/fabric-v3-shared-fabric-namespace.py" \
      "$EVIDENCE/before-departure/host-c/ownership.json" \
      "$EVIDENCE/restart/startup-recovery/host-c-ownership.json" \
      "$EVIDENCE/restart/startup-recovery/host-c-namespaces.txt" \
      "$EVIDENCE/restart/startup-recovery/host-c-shared-namespace-state.json" \
      || fail "could not reconcile C shared-fabric namespace ownership after controller restart" "HARNESS_GAP"
    fabric_namespace="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["namespace"])' \
      "$EVIDENCE/restart/startup-recovery/host-c-shared-namespace-state.json")"
    namespace_state="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' \
      "$EVIDENCE/restart/startup-recovery/host-c-shared-namespace-state.json")"
    python3 - "$EVIDENCE/restart/startup-recovery/host-c-shared-namespace-state.json" <<'PY' \
      || fail "C shared-fabric ownership changed namespace identity after controller restart" "DURABLE_RECOVERY_DEFECT"
import json,sys
state=json.load(open(sys.argv[1])); assert state['post_ownership_namespace'] in (None,state['namespace']), state
PY
    ssh_vm "${MGMT_IP[c]}" 'sudo ip -j -d link show' \
      >"$EVIDENCE/restart/startup-recovery/host-c-root-links.json" \
      || fail "host-C root link inventory unavailable after controller restart" "ENVIRONMENT_GAP"
    ssh_vm "${MGMT_IP[c]}" 'sudo bridge -j fdb show' \
      >"$EVIDENCE/restart/startup-recovery/host-c-root-fdb.json" \
      || fail "host-C root FDB unavailable after controller restart" "ENVIRONMENT_GAP"
    ssh_vm "${MGMT_IP[c]}" 'sudo nft list ruleset' \
      >"$EVIDENCE/restart/startup-recovery/host-c-root-nft.txt" \
      || fail "host-C root policy state unavailable after controller restart" "ENVIRONMENT_GAP"
    if [[ "$namespace_state" == present ]]; then
      ssh_vm "${MGMT_IP[c]}" "sudo ip netns exec '$fabric_namespace' ip -j -d link show" \
        >"$EVIDENCE/restart/startup-recovery/host-c-shared-links.json" \
        || fail "host-C shared Fabric links unavailable after controller restart" "ENVIRONMENT_GAP"
      ssh_vm "${MGMT_IP[c]}" "sudo ip netns exec '$fabric_namespace' bridge -j fdb show" \
        >"$EVIDENCE/restart/startup-recovery/host-c-shared-fdb.json" \
        || fail "host-C shared Fabric FDB unavailable after controller restart" "ENVIRONMENT_GAP"
      ssh_vm "${MGMT_IP[c]}" "sudo ip netns exec '$fabric_namespace' nft list ruleset" \
        >"$EVIDENCE/restart/startup-recovery/host-c-shared-nft.txt" \
        || fail "host-C shared Fabric policy unavailable after controller restart" "ENVIRONMENT_GAP"
    elif [[ "$namespace_state" == absent ]]; then
      python3 - "$EVIDENCE/restart/startup-recovery/host-c-shared-namespace-state.json" \
        "$EVIDENCE/restart/startup-recovery/host-c-shared-links.json" \
        "$EVIDENCE/restart/startup-recovery/host-c-shared-fdb.json" \
        "$EVIDENCE/restart/startup-recovery/host-c-shared-nft.txt" <<'PY' \
        || fail "C shared-fabric namespace is absent but ownership returned after controller restart" "DURABLE_RECOVERY_DEFECT"
import json,pathlib,sys
state_path,links,fdb,ruleset=sys.argv[1:]
state=json.load(open(state_path)); assert not state['post_ownership_claims_namespace'], state
namespace=state['namespace']
pathlib.Path(links).write_text('[]\n')
pathlib.Path(fdb).write_text('[]\n')
pathlib.Path(ruleset).write_text(f'namespace {namespace} absent after controller restart; no namespace-scoped policy exists\n')
PY
    else
      fail "post-restart shared-fabric namespace observer returned an invalid state: $namespace_state" "HARNESS_GAP"
    fi
    mapfile -t c_root_links < <(python3 - "$EVIDENCE/provider-absence/host-c/ownership/owned-object-identities.json" <<'PYCROOTRESTART'
import json,sys
for item in json.load(open(sys.argv[1]))['root_links']: print(item)
PYCROOTRESTART
)
    for object_name in "${c_root_links[@]}"; do
      assert_remote_link_absent c "$object_name" \
        "$EVIDENCE/restart/startup-recovery/host-c-$object_name-absence.json"
    done
    python3 - "$EVIDENCE/restart/startup-recovery" \
      "$EVIDENCE/provider-absence/host-c/ownership/owned-object-identities.json" \
      "$EVIDENCE/environment/fabric-identities.json" "${TENANT_MAC[c]}" <<'PY' \
      || fail "controller restart resurrected C-side provider state" "DURABLE_RECOVERY_DEFECT"
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); owned=json.load(open(sys.argv[2])); identities=json.load(open(sys.argv[3])); mac=sys.argv[4].lower()
vxlan=(owned['realm'].get('vxlan') or {})
interfaces={x for x in (vxlan.get('interface'),vxlan.get('bridge'),vxlan.get('fabric_veth')) if x}
c_ip=next(row['fabric_transport_ip'] for row in identities if row['host_id']=='host-c')
links=json.load(open(root/'host-c-shared-links.json'))
assert not interfaces.intersection({row.get('ifname') for row in links}), links
for path in (root/'host-c-root-fdb.json',root/'host-c-shared-fdb.json'):
    rows=json.load(open(path)); assert not any(str(row.get('mac','')).lower()==mac for row in rows), (path,rows)
fabric_fdb=json.load(open(root/'host-c-shared-fdb.json'))
assert not any(str(row.get('dst',''))==c_ip for row in fabric_fdb), fabric_fdb
for path in (root/'host-c-root-nft.txt',root/'host-c-shared-nft.txt'):
    assert mac not in path.read_text().lower(), path
PY
    assert_remote_path_absent c "/var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/plans/$realm_id.json" \
      "$EVIDENCE/restart/startup-recovery/host-c-plan-absence.txt"
    ssh_vm "${MGMT_IP[c]}" 'sudo python3 -' "$RUN_ID" "$realm_id" \
      >"$EVIDENCE/restart/startup-recovery/host-c-dhcp-state.json" <<'PYDHCPRESTART'
import json,pathlib,sys
run,realm=sys.argv[1:]; root=pathlib.Path('/var/lib/o3k-fabric-v3')/run/'network/dhcp/fabric'/realm
result={'root_exists':root.exists(),'files':{}}
for name in ('state.json','fabric-dhcp-ownership.json'):
    path=root/name
    result['files'][name]=json.loads(path.read_text()) if path.is_file() else None
json.dump(result,sys.stdout,sort_keys=True,indent=2); print()
PYDHCPRESTART
    python3 - "$EVIDENCE/restart/startup-recovery/host-c-dhcp-state.json" "${PORT_IDS[2]}" <<'PY' \
      || fail "controller restart restored C DHCP allocation state" "DURABLE_RECOVERY_DEFECT"
import json,sys
state=json.load(open(sys.argv[1])); values=state['files']; data=values.get('state.json') or {}; owner=values.get('fabric-dhcp-ownership.json')
assert sys.argv[2] not in (data.get('bindings') or {}), data
assert not data.get('bindings') and data.get('config') is None, data
assert owner is not None and owner.get('withdrawn') is True and owner.get('pending') is False, owner
PY
    guest_control_command a "ping -c 1 -W 4 ${TENANT_IP[b]}" restart/traffic/a-to-b-icmp.txt \
      || fail "A/B traffic failed after post-retirement controller restart" "DURABLE_RECOVERY_DEFECT"
    guest_control_command b "ping -c 1 -W 4 ${TENANT_IP[a]}" restart/traffic/b-to-a-icmp.txt \
      || fail "B/A traffic failed after post-retirement controller restart" "DURABLE_RECOVERY_DEFECT"
    guest_control_command a "ip neigh flush to ${TENANT_IP[b]} || true" restart/traffic/a-to-b-neighbor-flush.txt \
      || fail "could not flush A neighbor entry after controller restart" "HARNESS_GAP"
    guest_control_command a "ping -c 1 -W 4 ${TENANT_IP[b]} && ip neigh show to ${TENANT_IP[b]}" \
      restart/traffic/a-to-b-canonical-arp.txt \
      || fail "A/B canonical ARP failed after controller restart" "DURABLE_RECOVERY_DEFECT"
    grep -Fqi "${TENANT_MAC[b]}" "$EVIDENCE/restart/traffic/a-to-b-canonical-arp.txt" \
      || fail "post-restart ARP did not resolve to B's canonical MAC" "DURABLE_RECOVERY_DEFECT"
  fi
}
