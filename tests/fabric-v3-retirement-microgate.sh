#!/usr/bin/env bash

# Sourced by the frozen-candidate campaign driver after supported deletion of
# server C. All reads below are observations; resource mutation remains on the
# supported API lifecycle in the caller.
run_retirement_microgate() {
  local realm_id="$1" namespace_name address host object_name
  local convergence_deadline survivor_converged poll old_controller_pid new_controller_pid recovery_ready code

  for host in a b c; do
    address="${MGMT_IP[$host]}"
    ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json" \
      >"$EVIDENCE/endpoint-removal/host-$host-ownership.json" \
      || fail "post-C-removal ownership unavailable on host-$host" "ENVIRONMENT_GAP"
  done
  cp "$EVIDENCE/endpoint-removal/host-c-ownership.json" \
    "$EVIDENCE/provider-absence/host-c/ownership/ownership.json"

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
  ssh_vm "${MGMT_IP[c]}" 'sudo ip netns exec o3k-fabric ip -j -d link show' \
    >"$EVIDENCE/provider-absence/host-c/links/shared-fabric-links.json" \
    || fail "could not observe C shared-fabric links after Remove" "ENVIRONMENT_GAP"
  ssh_vm "${MGMT_IP[c]}" 'sudo ip netns exec o3k-fabric bridge -j fdb show' \
    >"$EVIDENCE/provider-absence/host-c/fdb/shared-fabric-fdb.json" \
    || fail "could not observe C shared-fabric FDB after Remove" "ENVIRONMENT_GAP"
  ssh_vm "${MGMT_IP[c]}" 'sudo ip netns exec o3k-fabric nft list ruleset' \
    >"$EVIDENCE/provider-absence/host-c/nft/shared-fabric-ruleset.txt" \
    || fail "could not observe C shared-fabric policy after Remove" "ENVIRONMENT_GAP"
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
result={'root_exists':root.exists(),'files':{}}
for name in ('state.json','fabric-dhcp-ownership.json','gateway-address-ownership.json','dnsmasq.conf','dnsmasq.leases'):
    path=root/name
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
  python3 - "$EVIDENCE/provider-absence/host-c/a-dhcp-state.json" \
    "$EVIDENCE/provider-absence/host-c/c-dhcp-state.json" "${PORT_IDS[2]}" <<'PY' \
    || fail "C DHCP binding/process state is not withdrawn" "PROVIDER_ABSENCE_DEFECT"
import json,sys
authority,departing=(json.load(open(path)) for path in sys.argv[1:3]); c_port=sys.argv[3]
authority_state=authority['files']['state.json'] or {}
assert c_port not in (authority_state.get('bindings') or {}), authority_state
assert c_port not in {binding.get('port_id') for binding in (authority_state.get('bindings') or {}).values()}, authority_state
local_state=departing['files']['state.json'] or {}
assert not local_state.get('bindings') and local_state.get('config') is None, local_state
owner=departing['files']['fabric-dhcp-ownership.json']
assert owner is not None, 'C DHCP ownership tombstone is missing'
assert owner.get('withdrawn') is True and owner.get('pending') is False, owner
PY

  python3 - "$EVIDENCE/controller-data/o3k.sqlite" "$realm_id" \
    "${PORT_IDS[0]}" "${PORT_IDS[1]}" "${PORT_IDS[2]}" \
    "$EVIDENCE/provider-absence/host-c/ownership/canonical-endpoints.json" <<'PY' \
    || fail "canonical endpoint departure state could not be observed" "HARNESS_GAP"
import json,pathlib,sqlite3,sys
database,realm,*rest=sys.argv[1:]; ids=rest[:3]; out=pathlib.Path(rest[3])
db=sqlite3.connect(f'file:{database}?mode=ro',uri=True,timeout=3); db.row_factory=sqlite3.Row
rows=[dict(row) for row in db.execute('SELECT id,realm_id,project_id,fixed_ip,mac,generation,state FROM canonical_endpoints WHERE realm_id=? ORDER BY id',(realm,))]
by_id={row['id']:row for row in rows}
assert ids[0] in by_id and by_id[ids[0]]['state']=='active', by_id
assert ids[1] in by_id and by_id[ids[1]]['state']=='active', by_id
assert ids[2] not in by_id, by_id
out.write_text(json.dumps({'realm_id':realm,'endpoints':rows,'departed_endpoint_absent':True},sort_keys=True,indent=2)+'\n')
PY

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
    printf '%s\n' "$O3K_CONTROLLER_ID" >"$EVIDENCE/restart/startup-recovery/controller-identity-after.txt"
    printf '%s\n' "$O3K_CONTROLLER_EPOCH" >"$EVIDENCE/restart/startup-recovery/controller-epoch-after.txt"
    [[ ! -e "/proc/$old_controller_pid" ]] \
      || fail "old controller process was still present after replacement readiness" "DURABLE_RECOVERY_DEFECT"
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
    ssh_vm "${MGMT_IP[c]}" 'sudo ip -j -d link show' \
      >"$EVIDENCE/restart/startup-recovery/host-c-root-links.json" \
      || fail "host-C root link inventory unavailable after controller restart" "ENVIRONMENT_GAP"
    ssh_vm "${MGMT_IP[c]}" 'sudo bridge -j fdb show' \
      >"$EVIDENCE/restart/startup-recovery/host-c-root-fdb.json" \
      || fail "host-C root FDB unavailable after controller restart" "ENVIRONMENT_GAP"
    ssh_vm "${MGMT_IP[c]}" 'sudo nft list ruleset' \
      >"$EVIDENCE/restart/startup-recovery/host-c-root-nft.txt" \
      || fail "host-C root policy state unavailable after controller restart" "ENVIRONMENT_GAP"
    ssh_vm "${MGMT_IP[c]}" 'sudo ip netns exec o3k-fabric ip -j -d link show' \
      >"$EVIDENCE/restart/startup-recovery/host-c-shared-links.json" \
      || fail "host-C shared Fabric links unavailable after controller restart" "ENVIRONMENT_GAP"
    ssh_vm "${MGMT_IP[c]}" 'sudo ip netns exec o3k-fabric bridge -j fdb show' \
      >"$EVIDENCE/restart/startup-recovery/host-c-shared-fdb.json" \
      || fail "host-C shared Fabric FDB unavailable after controller restart" "ENVIRONMENT_GAP"
    ssh_vm "${MGMT_IP[c]}" 'sudo ip netns exec o3k-fabric nft list ruleset' \
      >"$EVIDENCE/restart/startup-recovery/host-c-shared-nft.txt" \
      || fail "host-C shared Fabric policy unavailable after controller restart" "ENVIRONMENT_GAP"
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
