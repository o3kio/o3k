#!/usr/bin/env bash
# PP.4 campaign — in-VM PHASE 1b: cross-interface canonical-truth scenarios
# (Araf native <-> OpenStack CLI on identical canonical IDs), OpenTofu
# supplemental smoke, browser-evidence merge, secret scans.
#
# Usage: sudo bash in-vm-phase1b.sh <ubuntu|debian> <evidence-dir> <source-sha>
set -Eeuo pipefail
DISTRO="${1:-ubuntu}"
EVID="${2:-/tmp/pp4-evidence}"
SOURCE_SHA="${3:-unknown}"
source /home/tester/pp4-campaign/in-vm-lib.sh
ADMIN_PROJECT_ID="eba29e2d-53de-461d-ae91-ede7402713cb"
DEMO=/usr/local/share/o3k/araf-demo/o3k-araf-demo.sh

# shellcheck disable=SC1091
source /etc/o3k/admin-openrc

wait_server_active_cli() { # name -> id ; waits for ACTIVE via OpenStack CLI
  local name="$1" i id status
  for i in $(seq 1 120); do
    id="$(openstack server list -f json --name "$name" | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0]["ID"] if r else "")')"
    if [ -n "$id" ]; then
      status="$(openstack server show "$id" -c status -f value)"
      if [ "$status" = ACTIVE ]; then printf '%s' "$id"; return 0; fi
    fi
    sleep 5
  done
  die "server $name did not become ACTIVE via OpenStack CLI"
}

wait_server_absent_cli() {
  local name="$1" i
  for i in $(seq 1 60); do
    [ -z "$(openstack server list -f json --name "$name" | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0]["ID"] if r else "")')" ] && return 0
    sleep 5
  done
  die "server $name still visible via OpenStack CLI"
}

bff_server_item() { # name -> JSON item (single)
  bff_get /api/v1/resources/compute.server \
    | python3 -c 'import json,sys
d=json.load(sys.stdin)
items=[i for i in d["items"] if i["name"]=="'"$1"'"]
print(json.dumps(items[0]) if items else "")'
}

wait_bff_status() { # name ready|not-ready
  local name="$1" want="$2" i item status
  for i in $(seq 1 90); do
    item="$(bff_server_item "$name")"
    if [ -n "$item" ]; then
      status="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$item")"
      if [ "$want" = ready ] && [ "$status" = ready ]; then return 0; fi
      if [ "$want" = not-ready ] && [ "$status" != ready ]; then return 0; fi
    fi
    sleep 5
  done
  die "BFF status for $name did not converge (want $want)"
}

wait_bff_absent() {
  local name="$1" i
  for i in $(seq 1 60); do
    [ -z "$(bff_server_item "$name")" ] && return 0
    sleep 5
  done
  die "server $name still visible via Araf BFF"
}

wait_bff_present() {
  local name="$1" i
  for i in $(seq 1 60); do
    [ -n "$(bff_server_item "$name")" ] && return 0
    sleep 5
  done
  die "server $name not visible via Araf BFF"
}

# ---- session: real OIDC login + project scope ---------------------------------------
araf_login tenant
bff_post /api/v1/auth/scope "{\"project_id\":\"${ADMIN_PROJECT_ID}\"}" >/dev/null
CURRENT_CASE=X0 CURRENT_NAME="tenant session + scope" case_ok X0 "tenant BFF session established (real OIDC)"

IMAGE_ID="$(openstack image list -f json | python3 -c 'import json,sys; print([i["ID"] for i in json.load(sys.stdin) if i["Name"]=="cirros-0.6.3"][0])')"
FLAVOR_ID="$(openstack flavor list -f json | python3 -c 'import json,sys; print([f["ID"] for f in json.load(sys.stdin) if f["Name"]=="testlab-flavor"][0])')"
NET_ID="$(openstack network list -f json | python3 -c 'import json,sys; print([n["ID"] for n in json.load(sys.stdin) if n["Name"]=="testlab-network"][0])')"
[ -n "$IMAGE_ID" ] && [ -n "$FLAVOR_ID" ] && [ -n "$NET_ID" ] || die "testlab image/flavor/network lookup failed"

# ---- Scenario A: Araf (native BFF) -> create pp4-native -> canonical -> CLI sees it --
# Observe-before-act: remove leftovers from a previously interrupted run.
if [ -n "$(bff_server_item pp4-native)" ]; then
  log "cleaning up leftover pp4-native from an interrupted run"
  bff_delete /api/v1/resources/compute.server/"$(bff_server_item pp4-native | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')" >/dev/null || true
  wait_bff_absent pp4-native
fi
CREATE_OP="$(bff_post /api/v1/resources/compute.server "{\"name\":\"pp4-native\",\"image_id\":\"${IMAGE_ID}\",\"flavor_id\":\"${FLAVOR_ID}\",\"network_ids\":[\"${NET_ID}\"],\"key_name\":\"testlab-keypair\"}")"
echo "$CREATE_OP" > "$EVID/13-scenarioA-create-op.json"
echo "$CREATE_OP" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("action")=="create", d' || die "scenario A: create did not return a canonical create operation"
wait_bff_present pp4-native
A_ID="$(bff_server_item pp4-native | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
[ -n "$A_ID" ] || die "scenario A: no canonical id"
CURRENT_CASE=A1 CURRENT_NAME="Araf create returns canonical operation" case_ok A1 "Araf native create pp4-native accepted as canonical Operation"
wait_bff_status pp4-native ready
CLI_ID="$(wait_server_active_cli pp4-native)"
[ "$CLI_ID" = "$A_ID" ] || die "scenario A: canonical ID mismatch (Araf $A_ID vs CLI $CLI_ID)"
openstack server show "$CLI_ID" -f json > "$EVID/14-scenarioA-openstack-show.json"
printf 'pp4-native %s\n' "$A_ID" > "$EVID/14-scenarioA-identity.txt"
CURRENT_CASE=A2 CURRENT_NAME="Araf-created resource visible via OpenStack CLI with same canonical ID" \
  case_ok A2 "openstack server list shows pp4-native with identical canonical id $A_ID"
virsh domstate "$A_ID" 2>/dev/null | grep -q running || virsh list --all | grep -q "$A_ID" \
  || die "scenario A: no libvirt domain for pp4-native"
if timeout 180 bash -c "until openstack console log show $A_ID 2>/dev/null | grep -Eiq 'cirros|login:'; do sleep 5; done"; then
  openstack console log show "$A_ID" | tail -30 > "$EVID/14b-scenarioA-console.log"
  case_ok A3 "pp4-native guest boot proof (console marker)"
else
  die "scenario A: pp4-native console boot marker missing"
fi

# ---- Scenario C (part 1): CLI stop -> Araf observes truthfully ------------------------
openstack server stop "$A_ID" || die "scenario C: openstack stop failed"
wait_bff_status pp4-native not-ready
sleep 3
bff_get /api/v1/operations > "$EVID/15-scenarioC-operations.json"
python3 - "$EVID/15-scenarioC-operations.json" "$A_ID" <<'PY' || { die "scenario C: stop operation not visible in Araf operations"; }
import json, sys
d = json.load(open(sys.argv[1]))
items = d.get("items", [])
assert any("stop" in str(i.get("action", "")).lower() for i in items), [i.get("action") for i in items]
PY
CURRENT_CASE=C1 CURRENT_NAME="OpenStack stop observed truthfully by Araf" \
  case_ok C1 "Araf shows pp4-native non-ready + stop Operation after CLI stop"

# ---- Scenario C (part 2): Araf action start -> CLI observes ACTIVE --------------------
START_OP="$(bff_post /api/v1/resources/compute.server/$A_ID/actions '{"action_id":"start"}')"
echo "$START_OP" > "$EVID/15b-scenarioC-start-op.json"
wait_bff_status pp4-native ready
[ "$(openstack server show "$A_ID" -c status -f value)" = ACTIVE ] \
  || die "scenario C: CLI did not observe ACTIVE after Araf start"
CURRENT_CASE=C2 CURRENT_NAME="Araf start action observed via OpenStack CLI" \
  case_ok C2 "Araf-issued start -> openstack server show ACTIVE (same canonical id)"

# ---- Scenario B: CLI create pp4-openstack -> Araf native observes ----------------------
openstack server create --wait --image "$IMAGE_ID" --flavor "$FLAVOR_ID" \
  --nic "net-id=$NET_ID" --config-drive true --key-name testlab-keypair pp4-openstack \
  > "$EVID/16-scenarioB-create.txt" || die "scenario B: openstack server create failed"
B_ID="$(openstack server show pp4-openstack -c id -f value)"
[ -n "$B_ID" ] || die "scenario B: no id"
wait_bff_present pp4-openstack
sleep 2
B_BFF="$(bff_server_item pp4-openstack | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
[ "$B_BFF" = "$B_ID" ] || die "scenario B: canonical ID mismatch (CLI $B_ID vs Araf $B_BFF)"
wait_bff_status pp4-openstack ready
printf 'pp4-openstack %s\n' "$B_ID" >> "$EVID/14-scenarioA-identity.txt"
CURRENT_CASE=B1 CURRENT_NAME="OpenStack-created resource visible in Araf native view" \
  case_ok B1 "Araf native lists pp4-openstack with identical canonical id $B_ID (no import/hack)"

# ---- Scenario D: deletion through one surface, absence verified on all -----------------
bff_delete /api/v1/resources/compute.server/"$B_ID" > "$EVID/17-scenarioD-araf-delete.json" || die "scenario D: Araf delete failed"
wait_bff_absent pp4-openstack
wait_server_absent_cli pp4-openstack
CURRENT_CASE=D1 CURRENT_NAME="Araf-deleted resource absent via OpenStack CLI" \
  case_ok D1 "delete via Araf -> absent in openstack server list"
openstack server delete "$A_ID" || die "scenario D: CLI delete pp4-native failed"
wait_server_absent_cli pp4-native
wait_bff_absent pp4-native
[ -n "$(openstack server list -f json | python3 -c 'import json,sys; print([s["ID"] for s in json.load(sys.stdin) if s["Name"]=="test-vm"][0])')" ] \
  || die "scenario D: test-vm must survive scenario cleanup"
CURRENT_CASE=D2 CURRENT_NAME="CLI-deleted resource absent in Araf; test-vm survives" \
  case_ok D2 "delete via CLI -> absent in Araf; test-vm intact (ONE canonical truth)"
openstack server list -f json > "$EVID/18-servers-final.json"

# ---- tenant/operator separation spot-check ----------------------------------------------
araf_login operator
OP_PROFILE="$(bff_get /api/v1/operator/profile)"
echo "$OP_PROFILE" > "$EVID/19-operator-profile.json"
araf_login tenant
T_CONTEXT="$(bff_get /api/v1/context)"
echo "$T_CONTEXT" > "$EVID/19-tenant-context.json"
# tenant surface must not expose operator-only endpoints
if bff_get /api/v1/operator/platform/overview >/dev/null 2>&1; then
  die "tenant session reached operator-only endpoint"
fi
case_ok S1 "tenant/operator trust surfaces separated (tenant denied operator endpoint)"

# ---- OpenTofu supplemental smoke ---------------------------------------------------------
log "OpenTofu smoke: unmodified provider 3.4.0 + tofu 1.12.6 against this deployment"
TOFU_DIR=/home/tester/pp4-tofu
if [ -f "$TOFU_DIR/tofu" ]; then
  # transparent compatibility-boundary instrumentation (campaign-only)
  mkdir -p /etc/systemd/system/o3kd.service.d
  cat > /etc/systemd/system/o3kd.service.d/pp4-compat-trace.conf <<'EOF'
[Service]
Environment=O3K_COMPATIBILITY_TRACE_PATH=/var/log/o3k/compat-trace.jsonl
EOF
  chmod 644 /etc/systemd/system/o3kd.service.d/pp4-compat-trace.conf
  systemctl daemon-reload
  systemctl restart o3kd
  for i in $(seq 1 60); do curl -sf http://127.0.0.1:18080/readyz >/dev/null 2>&1 && break; sleep 2; done
  curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd did not recover with trace instrumentation"
  ADMIN_PW="${OS_PASSWORD:-}"
  [ -n "$ADMIN_PW" ] || die "cannot resolve demo admin password for tofu provider config"
  AUTH_URL="$(awk '/auth_url:/{print $2}' /etc/o3k/clouds.yaml | head -1)"
  [ -n "$AUTH_URL" ] || AUTH_URL="http://127.0.0.1:18080"
  cd "$TOFU_DIR/project"
  cat > terraform.tfvars <<EOF
auth_url = "$AUTH_URL"
user_name = "admin"
password = "$ADMIN_PW"
project_id = "$ADMIN_PROJECT_ID"
region = "RegionOne"
image_name = "cirros-0.6.3"
flavor_name = "testlab-flavor"
EOF
  ../tofu init -no-color > "$EVID/20-tofu-init.log" 2>&1 || die "tofu init failed"
  ../tofu apply -auto-approve -no-color > "$EVID/20-tofu-apply.log" 2>&1 || die "tofu apply failed"
  TOFU_NET_ID="$(../tofu output -raw network_id 2>/dev/null || true)"
  [ -n "$TOFU_NET_ID" ] || die "tofu produced no network_id output"
  openstack network show "$TOFU_NET_ID" >/dev/null 2>&1 || die "tofu-created network not visible via OpenStack CLI"
  bff_get /api/v1/resources/network.network > "$EVID/20-tofu-araf-networks.json"
  python3 - "$EVID/20-tofu-araf-networks.json" "$TOFU_NET_ID" <<'PY' || { die "tofu-created network not visible in Araf"; }
import json, sys
d = json.load(open(sys.argv[1]))
assert any(i["id"] == sys.argv[2] for i in d.get("items", [])), [i["id"] for i in d.get("items", [])]
PY
  case_ok T1 "OpenTofu provider 3.4.0 created canonical network visible in Araf + CLI"
  ../tofu destroy -auto-approve -no-color > "$EVID/20-tofu-destroy.log" 2>&1 || die "tofu destroy failed"
  openstack network list -f json | grep -q "$TOFU_NET_ID" && die "tofu-destroyed network still visible"
  case_ok T2 "tofu destroy removed the canonical network"
  cp /var/log/o3k/compat-trace.jsonl "$EVID/20-tofu-compat-trace.jsonl" 2>/dev/null || true
  rm -f /etc/systemd/system/o3kd.service.d/pp4-compat-trace.conf
  systemctl daemon-reload
  systemctl restart o3kd
  for i in $(seq 1 60); do curl -sf http://127.0.0.1:18080/readyz >/dev/null 2>&1 && break; sleep 2; done
  curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd did not recover after trace removal"
else
  die "OpenTofu tooling not staged at $TOFU_DIR/tofu"
fi

# ---- secret scan across clients + evidence ------------------------------------------------
SCAN_TARGETS=( "$EVID/01-one-line-install.log" "$EVID/04-verify.log" "$EVID/05-browser-e2e.log" )
[ -f "$EVID/20-tofu-apply.log" ] && SCAN_TARGETS+=( "$EVID/20-tofu-apply.log" )
FAIL=0
for f in "${SCAN_TARGETS[@]}"; do
  [ -f "$f" ] || continue
  if ! secret_scan_file "$f"; then
    log "SECRET SCAN HIT: $f"; FAIL=1
  fi
done > "$EVID/17-secret-scan.txt" 2>&1
[ "$FAIL" -eq 0 ] || die "secret scan found material (see 17-secret-scan.txt)"
# the tofu provider legitimately receives the demo admin password via
# terraform.tfvars; ensure the tfvars never lands in evidence
grep -R "password" "$EVID" --include='*.tfvars' 2>/dev/null && die "tfvars leaked into evidence"
[ "$(stat -c %a /var/lib/o3k/araf-demo/credentials.txt)" = 600 ] || die "credentials file mode is not 0600"
journalctl -u o3kd --no-pager -n 500 > "$EVID/17b-o3kd-journal-tail.log" 2>/dev/null || true
{
  secret_scan_file "$EVID/17b-o3kd-journal-tail.log" || { log "SECRET SCAN HIT: o3kd journal"; FAIL=1; }
} >> "$EVID/17-secret-scan.txt" 2>&1
[ "$FAIL" -eq 0 ] || die "secret material in o3kd journal tail"
case_ok SEC1 "secret scans clean (installer output, verify, browser, tofu logs, o3kd journal)"

# ---- optional Horizon witness (non-blocking; classified in its own evidence) --------------
if [ "${O3K_PP4_HORIZON:-0}" = 1 ] && [ -x /home/tester/pp4-campaign/horizon-witness.sh ]; then
  log "running optional Horizon witness"
  bash /home/tester/pp4-campaign/horizon-witness.sh "$EVID" || log "Horizon witness did not complete (see 30-horizon-*.txt)"
fi

log "PHASE1B-COMPLETE status=passed"
echo "PHASE1B-COMPLETE status=passed" > "$EVID/phase1b-done"
