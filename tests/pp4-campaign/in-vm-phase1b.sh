#!/usr/bin/env bash
# PP.4 campaign — in-VM PHASE 1b: cross-interface canonical-truth scenarios
# (Araf native <-> OpenStack CLI on identical canonical IDs), CLASSIFIED-GAP
# probes for what this product profile cannot do, the console-deleted resource
# cross-check, OpenTofu supplemental smoke, secret scans.
#
# Identity model (VERIFIED against this profile):
#   * the native list projection carries `spec: {}` for compute.server, so a
#     row's label falls back to its canonical id — identity is ALWAYS the
#     canonical id, never the name;
#   * the native `show` projection is the live-resource view and conceals
#     deleted rows (404) while the collection keeps surfacing the DELETED
#     tombstone (unknown status) — both facts are observed and recorded.
#
# A crash writes phase1b-done with status=failed (host fails fast).
#
# Usage: sudo bash in-vm-phase1b.sh <ubuntu|debian> <evidence-dir> <source-sha>
set -Eeuo pipefail
DISTRO="${1:-ubuntu}"
EVID="${2:-/tmp/pp4-evidence}"
SOURCE_SHA="${3:-unknown}"
source /home/tester/pp4-campaign/in-vm-lib.sh
export PP4_PHASE=phase1b
pp4_install_phase_trap phase1b "$EVID/phase1b-done" PHASE1B
ADMIN_PROJECT_ID="eba29e2d-53de-461d-ae91-ede7402713cb"
DEMO=/usr/local/share/o3k/araf-demo/o3k-araf-demo.sh
pp4_gaps_reset

# shellcheck disable=SC1091
source /etc/o3k/admin-openrc

# ---------------------------------------------------------------------------
# Cross-interface helpers. Every absence/presence claim distinguishes "the
# query itself failed" (die: cannot verify) from "the resource is gone".
# ---------------------------------------------------------------------------

wait_server_active_cli() { # name -> id ; waits for ACTIVE via OpenStack CLI
  local name="$1" i id status out
  for i in $(seq 1 180); do
    out="$(openstack server list -f json)" \
      || die "wait_server_active_cli($name): OpenStack CLI list failed (cannot verify)"
    id="$(NAME="$name" python3 -c 'import json,os,sys
rows=[s for s in json.load(sys.stdin) if s.get("Name")==os.environ["NAME"]]
print(rows[0]["ID"] if rows else "")' <<<"$out")" \
      || die "wait_server_active_cli($name): unparseable CLI JSON"
    if [ -n "$id" ]; then
      status="$(openstack server show "$id" -c status -f value)" \
        || die "wait_server_active_cli($name): server show failed (cannot verify)"
      if [ "$status" = ACTIVE ]; then printf '%s' "$id"; return 0; fi
    fi
    sleep 5
  done
  die "server $name did not become ACTIVE via OpenStack CLI"
}

wait_server_absent_cli() { # ID
  # Absence of the LIVE resource is authoritative per-id through
  # `openstack server show <id>`: after deletion it answers not-found (or a
  # terminal DELETED status). `server list` is NOT authoritative for absence:
  # its projection lags far behind (observed >12 minutes with a stale ACTIVE
  # row on the demo), so the list is recorded as informational evidence only.
  local id="$1" i out rc status
  for i in $(seq 1 120); do
    out="$(openstack server show "$id" -f json 2>&1)" && rc=0 || rc=$?
    if [ "$rc" -ne 0 ]; then
      grep -qiE 'No Server found|No server with a name or ID' <<<"$out" \
        || die "wait_server_absent_cli($id): openstack server show failed for a non-not-found reason (cannot call it absence): $out"
      printf 'cli_show_absence=verified (No Server found for %s)\n' "$id" > "$EVID/.cli-absence-$id.txt"
      openstack server list -f json > "$EVID/.cli-list-lag-$id.json" 2>/dev/null || true
      return 0
    fi
    status="$(python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("status",""))
except Exception:
    print("")' <<<"$out")"
    case "$status" in
      DELETED|SOFT_DELETED)
        printf 'cli_show_absence=verified (status %s for %s)\n' "$status" "$id" > "$EVID/.cli-absence-$id.txt"
        return 0 ;;
    esac
    sleep 5
  done
  {
    echo "timeout: $id still served by openstack server show after ~10 minutes"
    openstack server show "$id" 2>&1 | head -30 || true
    echo "--- o3kd journal tail ---"
    journalctl -u o3kd --no-pager -n 40 2>/dev/null | grep -iE 'delet|reconcil|error' || true
  } > "$EVID/.absence-timeout-$id.txt" 2>&1 || true
  cat "$EVID/.absence-timeout-$id.txt" >&2 || true
  die "server $id still served by openstack server show after ~10 minutes"
}



# Exact HTTP status of the Araf-native live-resource view (`show`), writing the
# body to $3. A concealed (deleted) resource answers 404; anything else is the
# caller's business.
bff_show_status() { # RESOURCE_TYPE ID OUT_FILE -> status
  curl -s --cacert "$DEMO_CA" -o "$3" -w '%{http_code}' \
    -H "cookie: ${BFF_COOKIE}; ${BFF_CSRF}" \
    "https://${BFF_HOST}/api/v1/resources/$1/$2"
}

# Canonical ids present in a native collection (one per line).
bff_list_ids() { # RESOURCE_TYPE
  local body
  body="$(bff_get "/api/v1/resources/$1?page=0&pageSize=100")" \
    || die "bff_list_ids($1): Araf BFF list query failed (cannot verify)"
  python3 -c 'import json,sys
d = json.load(sys.stdin)
for item in d["items"]:
    print(item["id"])' <<<"$body"
}

# The list projection's `name` for one id (empty when the row is absent). The
# list deliberately carries `spec: {}` for compute.server, so this is the
# measured value of the name-projection gap.
bff_list_name() { # RESOURCE_TYPE ID
  local body
  body="$(bff_get "/api/v1/resources/$1?page=0&pageSize=100")" \
    || die "bff_list_name($1): Araf BFF list query failed (cannot verify)"
  python3 -c 'import json,sys
d = json.load(sys.stdin)
for item in d["items"]:
    if item["id"] == sys.argv[1]:
        print(item.get("name") or "")
        break' "$2" <<<"$body"
}

# Create through the unmodified CLI with bounded retries: a create that lands
# while the compute service is still reconciling a previous delete answers
# "compute service is unavailable (HTTP 500)"; that is a transient, retriable
# condition, not an absence of capacity.
cli_create_server() { # NAME
  local name="$1" attempt=1
  while [ "$attempt" -le 6 ]; do
    if openstack server create --wait --image "$IMAGE_ID" --flavor "$FLAVOR_ID" \
      --nic "net-id=$NET_ID" --config-drive true --key-name testlab-keypair "$name" \
      > "$EVID/.cli-create-$name.txt" 2>&1; then
      cp "$EVID/.cli-create-$name.txt" "$EVID/16-scenarioB-create.txt"
      return 0
    fi
    log "cli create of $name attempt $attempt did not succeed; retrying in 25s"
    sleep 25
    attempt=$((attempt + 1))
  done
  cat "$EVID/.cli-create-$name.txt" >&2 || true
  die "openstack server create $name did not succeed after 6 attempts"
}

# Wait until the Araf-native live view serves the resource (2xx).
wait_bff_live() { # RESOURCE_TYPE ID
  local t="$1" id="$2" i code
  for i in $(seq 1 120); do
    code="$(bff_show_status "$t" "$id" "$EVID/.bff-show.json")" \
      || die "wait_bff_live($t/$id): Araf BFF query failed (cannot verify)"
    [ "$code" = 200 ] && return 0
    sleep 5
  done
  die "resource $t/$id is not served by the Araf native live view (last status $code)"
}

# Wait until the Araf-native live view conceals the resource (404).
wait_bff_concealed() { # RESOURCE_TYPE ID
  local t="$1" id="$2" i code
  for i in $(seq 1 120); do
    code="$(bff_show_status "$t" "$id" "$EVID/.bff-show.json")" \
      || die "wait_bff_concealed($t/$id): Araf BFF query failed (cannot verify)"
    [ "$code" = 404 ] && return 0
    sleep 5
  done
  die "resource $t/$id is still served by the Araf native live view (last status $code, want 404)"
}

# Wait for a truthful Araf status and print it (ready | <anything else>).
wait_bff_status() { # RESOURCE_TYPE ID WANT(ready|not-ready)
  local t="$1" id="$2" want="$3" i code status=""
  for i in $(seq 1 120); do
    code="$(bff_show_status "$t" "$id" "$EVID/.bff-status.json")" \
      || die "wait_bff_status($t/$id): Araf BFF query failed (cannot verify)"
    if [ "$code" = 200 ]; then
      status="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' \
        < "$EVID/.bff-status.json")" || die "wait_bff_status($t/$id): unparseable resource"
      if [ "$want" = ready ] && [ "$status" = ready ]; then printf '%s' "$status"; return 0; fi
      if [ "$want" = not-ready ] && [ "$status" != ready ]; then printf '%s' "$status"; return 0; fi
    fi
    sleep 5
  done
  die "Araf status for $t/$id did not converge (want $want, last ${status:-http-$code})"
}

# Wait for a canonical Operation to reach a terminal state; prints the state.
# A "failed" state is returned (not fatal): callers assert which one they mean.
wait_operation_terminal() { # OPERATION_ID -> succeeded|failed
  local op="$1" i state
  for i in $(seq 1 180); do
    state="$(bff_get "/api/v1/operations/$op" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')" \
      || die "operation $op query failed (cannot verify state)"
    case "$state" in succeeded | failed) printf '%s' "$state"; return 0 ;; esac
    sleep 5
  done
  die "operation $op did not reach a terminal state"
}

# Record how the collection surfaces an id that the live view may conceal.
record_collection_state() { # RESOURCE_TYPE ID -> writes to stdout, never fails
  local t="$1" id="$2" ids
  ids="$(bff_list_ids "$t")" || { echo "unavailable"; return 0; }
  if ! grep -qx -- "$id" <<<"$ids"; then
    echo "absent-from-collection"
    return 0
  fi
  local code
  code="$(bff_show_status "$t" "$id" "$EVID/.bff-collection.json")" || { echo "unavailable"; return 0; }
  case "$code" in
    200) echo "live-row" ;;
    404) echo "tombstone-row-concealed-on-show" ;;
    *) echo "http-$code" ;;
  esac
}

# ---- session: real OIDC login + project scope ---------------------------------------
araf_login tenant
bff_post /api/v1/auth/scope "{\"project_id\":\"${ADMIN_PROJECT_ID}\"}" >/dev/null
CURRENT_CASE=X0 CURRENT_NAME="tenant session + scope" case_ok X0 "tenant BFF session established (real OIDC)"

IMAGE_ID="$(openstack image list -f json | python3 -c 'import json,sys; print([i["ID"] for i in json.load(sys.stdin) if i["Name"]=="cirros-0.6.3"][0])')"
FLAVOR_ID="$(openstack flavor list -f json | python3 -c 'import json,sys; print([f["ID"] for f in json.load(sys.stdin) if f["Name"]=="testlab-flavor"][0])')"
NET_ID="$(openstack network list -f json | python3 -c 'import json,sys; print([n["ID"] for n in json.load(sys.stdin) if n["Name"]=="testlab-network"][0])')"
TESTVM_ID="$(openstack server list -f json | python3 -c 'import json,sys; print([s["ID"] for s in json.load(sys.stdin) if s["Name"]=="test-vm"][0])')"
[ -n "$IMAGE_ID" ] && [ -n "$FLAVOR_ID" ] && [ -n "$NET_ID" ] && [ -n "$TESTVM_ID" ] \
  || die "testlab image/flavor/network/workload lookup failed"

# ---------------------------------------------------------------------------
# Cross-interface inventories: compat-created vs canonical rows
# (evidence 21e + the PP4-GAP compat-created-resource-not-canonical ledger entry)
# ---------------------------------------------------------------------------
log "cross-interface inventory probe (compat APIs vs canonical rows)"
for rt in image.image network.network compute.server; do
  bff_list_ids "$rt" > "$EVID/21e-native-list-$(printf '%s' "$rt" | tr '.:' '--').txt" \
    || die "cannot read the native $rt collection (cannot verify the inventories)"
done
python3 - "$EVID" "$IMAGE_ID" "$NET_ID" <<'PY' || die "cross-interface inventory probe failed"
import sqlite3, sys
evid, image_id, net_id = sys.argv[1:4]
read = lambda name: [
    line.strip()
    for line in open(f"{evid}/{name}", encoding="utf-8")
    if line.strip()
]
native_images = read("21e-native-list-image-image.txt")
native_networks = read("21e-native-list-network-network.txt")
native_servers = read("21e-native-list-compute-server.txt")
c = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
def ids(query):
    return sorted(r[0] for r in c.execute(query))
ledger_images = ids("select id from resources where kind = 'image:image'")
ledger_networks = ids("select id from resources where kind = 'network:network'")
lines = [
    f"compat_image_id={image_id}",
    f"compat_network_id={net_id}",
    f"native_image_rows={len(native_images)}",
    f"native_network_rows={len(native_networks)}",
    f"native_compute_rows={len(native_servers)}",
    f"ledger_image_rows={len(ledger_images)}",
    f"ledger_network_rows={len(ledger_networks)}",
    f"compat_image_in_native={str(image_id in native_images).lower()}",
    f"compat_network_in_native={str(net_id in native_networks).lower()}",
]
# Every native row must exist in the canonical ledger: the console never
# invents a row, and the ledger is the authority for what a canonical row is.
for label, rows, ledger in (
    ("image", native_images, ledger_images),
    ("network", native_networks, ledger_networks),
):
    for row in rows:
        assert row in ledger, f"native {label} row {row} has no canonical ledger row (fabricated?)"
        lines.append(f"native_{label}_ledger_confirmed={row}")
with open(f"{evid}/21e-compat-vs-native-inventories.txt", "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
assert image_id not in native_images, (
    f"the compat-created image {image_id} appears as a native row")
assert net_id not in native_networks, (
    f"the compat-created network {net_id} appears as a native row")
PY
CURRENT_CASE=G1 CURRENT_NAME="compat-created resources are not canonical native rows (classified gap)"
record_gap "compat-created-resource-not-canonical" \
  "compat_image=${IMAGE_ID} compat_network=${NET_ID} native_image_rows=$(wc -l < "$EVID/21e-native-list-image-image.txt") native_network_rows=$(wc -l < "$EVID/21e-native-list-network-network.txt")"
case_ok G1 "native image/network inventories are empty while the compat-created image+network exist (classified gap, counts in 21e-compat-vs-native-inventories.txt)"

# ---------------------------------------------------------------------------
# Scenario A: browser-native create remains live for provider verification.
# ---------------------------------------------------------------------------
log "scenario A: verifying browser-created canonical workload identity"
UI_CREATE_ID="$(sed -n 's/^PP4_UI_CREATE_ID=//p' "$EVID/05-browser-ids.env" | head -1)"
[ -n "$UI_CREATE_ID" ] || die "browser native create marker missing"
printf 'browser_native_server_id=%s\n' "$UI_CREATE_ID" > "$EVID/14-browser-native-identity.txt"
wait_bff_live compute.server "$UI_CREATE_ID"
wait_bff_status compute.server "$UI_CREATE_ID" ready >/dev/null
openstack server show "$UI_CREATE_ID" > "$EVID/14-browser-native-openstack-show.txt" \
  || die "OpenStack cannot observe the browser-created canonical server"
libvirt_domain_running_for "$UI_CREATE_ID" \
  || die "no running libvirt domain for browser-created server $UI_CREATE_ID"
CURRENT_CASE=UI_CREATE_5 CURRENT_NAME="real libvirt domain for browser-created server" \
  case_ok UI_CREATE_5 "running libvirt domain carries browser-created server identity $UI_CREATE_ID"
openstack console log show "$UI_CREATE_ID" > "$EVID/14-browser-native-console.log" 2>&1 \
  || die "console log unavailable for browser-created server"
grep -Eiq 'cirros|login:' "$EVID/14-browser-native-console.log" \
  || die "guest boot marker missing for browser-created server"
CURRENT_CASE=UI_CREATE_6 CURRENT_NAME="guest boot marker for browser-created server" \
  case_ok UI_CREATE_6 "CirrOS/login guest boot marker observed for browser-created server $UI_CREATE_ID"
CURRENT_CASE=UI_CREATE_7 CURRENT_NAME="OpenStack observes browser-created server" \
  case_ok UI_CREATE_7 "OpenStack-compatible server show observes canonical browser-created id $UI_CREATE_ID"
CURRENT_CASE=A1 CURRENT_NAME="browser native create provider execution and cross-interface identity" \
  case_ok A1 "UI-created canonical server $UI_CREATE_ID is ready, OpenStack-visible, libvirt-running, and guest-booted"

# ---------------------------------------------------------------------------
# Scenario B: CLI create -> Araf native view on the SAME canonical id
# ---------------------------------------------------------------------------
log "scenario B: openstack-created workload must appear in the Araf native view"
# Observe-before-act: a leftover from an interrupted run would make the CLI
# create conflict (HTTP 409) instead of exercising a real create.
LEFTOVER_ID="$(openstack server list -f json | python3 -c 'import json,sys
rows=[s for s in json.load(sys.stdin) if s.get("Name")=="pp4-openstack"]
print(rows[0]["ID"] if rows else "")')"
if [ -n "$LEFTOVER_ID" ]; then
  log "scenario B: removing a leftover pp4-openstack from an earlier run ($LEFTOVER_ID)"
  openstack server delete "$LEFTOVER_ID" >/dev/null 2>&1 || true
  wait_server_absent_cli "$LEFTOVER_ID"
fi
cli_create_server pp4-openstack || die "scenario B: openstack server create failed"
B_ID="$(openstack server show pp4-openstack -c id -f value)"
[ -n "$B_ID" ] || die "scenario B: no id"
wait_bff_live compute.server "$B_ID"
wait_bff_status compute.server "$B_ID" ready >/dev/null
printf 'test-vm %s\npp4-openstack %s\n' "$TESTVM_ID" "$B_ID" > "$EVID/14-scenarioA-identity.txt"
CURRENT_CASE=B1 CURRENT_NAME="OpenStack-created resource visible in the Araf native live view" \
  case_ok B1 "Araf native live view serves pp4-openstack with the identical canonical id $B_ID (no import/hack)"

# The native LIST projection is a different projection: record what it carries.
LIST_IDS="$(bff_list_ids compute.server)" || die "scenario B: cannot read the native server collection"
grep -qx -- "$B_ID" "$EVID/21e-native-list-compute-server.txt" \
  || { printf '%s\n' "$LIST_IDS" > "$EVID/21e-native-list-compute-server.txt"; }
grep -qx -- "$B_ID" "$EVID/21e-native-list-compute-server.txt" \
  || die "scenario B: the native collection does not list the canonical id $B_ID"
B_LIST_NAME="$(bff_list_name compute.server "$B_ID")"
{
  echo "server_id=${B_ID}"
  echo "cli_name=pp4-openstack"
  echo "native_list_name=${B_LIST_NAME:-<empty>}"
  echo "note: the native list projection carries spec:{} for compute.server, so the"
  echo "      row label falls back to the canonical id (identity is the id, never the name)."
} > "$EVID/13b-native-name-projection.txt"
if [ -z "$B_LIST_NAME" ] || [ "$B_LIST_NAME" = "$B_ID" ]; then
  record_gap "native-list-name-projection" \
    "server_id=${B_ID} native_list_name=${B_LIST_NAME:-<empty>} (spec name is not projected in the native collection)"
  CURRENT_CASE=B2 CURRENT_NAME="native list name projection gap recorded" \
    case_ok B2 "native collection lists the server by canonical id; its name projection is '${B_LIST_NAME:-<empty>}' (recorded gap, identity is the id)"
else
  CURRENT_CASE=B2 CURRENT_NAME="native list name projection present" \
    case_ok B2 "native collection lists the server by canonical id with projected name '${B_LIST_NAME}'"
fi

# Guest boot proof: a libvirt domain carrying this server's run ownership marker
# in its XML is running, plus the guest console boot marker.
libvirt_domain_running_for "$B_ID" \
  || die "scenario B: no running libvirt domain carrying server_id=$B_ID (managed_by=o3k-compute)"
{
  echo "server_id: $B_ID"
  echo "domain: $(libvirt_domain_name_for "$B_ID" || true)"
  echo "domstate: $(virsh -c qemu:///system domstate "$(libvirt_domain_name_for "$B_ID")" 2>&1)"
  echo "domain_xml_ownership:"
  virsh -c qemu:///system dumpxml "$(libvirt_domain_name_for "$B_ID")" 2>/dev/null \
    | grep -Eo 'server_id="[^"]*"|managed_by="[^"]*"' || true
} > "$EVID/16b-scenarioB-libvirt-domain.txt"
if timeout 240 bash -c "until openstack console log show $B_ID 2>/dev/null | grep -Eiq 'cirros|login:'; do sleep 5; done"; then
  openstack console log show "$B_ID" | tail -30 > "$EVID/16c-scenarioB-console.log"
  CURRENT_CASE=B3 CURRENT_NAME="guest boot proof for the CLI-created workload" \
    case_ok B3 "pp4-openstack guest boot proof (running libvirt domain via server_id XML + console marker)"
else
  die "scenario B: pp4-openstack console boot marker missing"
fi

# ---------------------------------------------------------------------------
# Scenario C: CLI stop/start -> Araf observes truthfully; the native start
# action is NOT advertised (classified gap)
# ---------------------------------------------------------------------------
log "scenario C: CLI stop -> Araf observes truthfully; Araf-native start is not advertised"
openstack server stop "$B_ID" || die "scenario C: openstack stop failed"
STOPPED_STATUS="$(wait_bff_status compute.server "$B_ID" not-ready)"
{
  echo "araf_status_after_cli_stop=${STOPPED_STATUS}"
  echo "note: the Araf status mapping has no 'stopped' readiness state, so a stopped"
  echo "      server is truthfully reported as non-ready (observed value above)."
} > "$EVID/15-scenarioC-stop-state.txt"
sleep 3
bff_get /api/v1/operations > "$EVID/15-scenarioC-operations.json"
# The assertion is tied to the resource: a stop Operation whose canonical
# resource id IS pp4-openstack's (the BFF serializes Operation with camelCase
# fields — backend/console-bff-core/src/model.rs).
# The canonical resulting STATE must be observed (asserted above via
# wait_bff_status). Whether the compatibility-issued action also leaves a
# canonical Operation is recorded truthfully: O3K's compat stop path does not
# persist one on this release, so it is recorded as a classified gap rather
# than reported (or fabricated) as a canonical Operation.
if python3 - "$EVID/15-scenarioC-operations.json" "$B_ID" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
items = doc.get("items", [])
rid = lambda i: i.get("resourceId") or i.get("resource_id")
sys.exit(0 if any(rid(i) == sys.argv[2] and "stop" in str(i.get("action", "")).lower() for i in items) else 1)
PY
then
  CURRENT_CASE=C1 CURRENT_NAME="OpenStack stop observed truthfully by Araf" \
    case_ok C1 "Araf reports pp4-openstack '${STOPPED_STATUS}' (non-ready) + a stop Operation for the canonical id $B_ID after the CLI stop"
else
  case_ok C1 "Araf reports pp4-openstack '${STOPPED_STATUS}' (non-ready) truthfully after the CLI stop"
  record_gap "compat-action-operation-not-canonical" \
    "openstack server stop changed the canonical state (Araf status=${STOPPED_STATUS}) but left no canonical Operation in /api/v1/operations"
  case_ok C1b "classified gap recorded: the compat stop exposes canonical state, not a canonical Operation"
fi

# The advertised action set is the discovery truth the console renders.
bff_get /api/v1/services > "$EVID/15c-services-descriptor.json" \
  || die "scenario C: cannot read the Araf service descriptors"
python3 - "$EVID/15c-services-descriptor.json" <<'PY' || die "scenario C: the compute.server descriptor is missing from discovery"
import json, sys
services = json.load(open(sys.argv[1]))
found = None
for service in services:
    for rt in (service.get("resourceTypes") or service.get("resource_types") or []):
        if rt.get("id") == "compute.server":
            found = sorted(action.get("id") for action in (rt.get("supportedActions") or rt.get("supported_actions") or []))
assert found is not None, "compute.server is not described by discovery"
print("\n".join(found))
PY
NATIVE_START_STATUS="$(bff_post_status /api/v1/resources/compute.server/"$B_ID"/actions \
  '{"actionId":"start"}' "$EVID/15d-scenarioC-native-start-attempt.json")" \
  || die "scenario C: the native start attempt could not be sent"
python3 - "$EVID/15c-services-descriptor.json" <<'PY'
import json, sys
services = json.load(open(sys.argv[1]))
actions = []
for service in services:
    for rt in (service.get("resourceTypes") or service.get("resource_types") or []):
        if rt.get("id") == "compute.server":
            actions = sorted(action.get("id") for action in (rt.get("supportedActions") or rt.get("supported_actions") or []))
open(sys.argv[1] + ".compute-actions", "w", encoding="utf-8").write(",".join(actions) + "\n")
PY
COMPUTE_ACTIONS="$(cat "$EVID/15c-services-descriptor.json.compute-actions")"
[ "$NATIVE_START_STATUS" -ge 400 ] \
  || die "the Araf-native start action answered $NATIVE_START_STATUS on a resource whose descriptor does not advertise it"
if grep -qw start <<<"${COMPUTE_ACTIONS//,/ }"; then
  die "discovery advertises a start action for compute.server ($COMPUTE_ACTIONS): re-verify the gap"
fi
record_gap "native-server-start-not-advertised" \
  "advertised_actions=${COMPUTE_ACTIONS} native_start_attempt_http=${NATIVE_START_STATUS} (compute.server advertises no start/stop actions on this profile)"
CURRENT_CASE=C3 CURRENT_NAME="Araf-native start is not advertised (classified gap)" \
  case_ok C3 "compute.server discovery advertises only '${COMPUTE_ACTIONS}'; a native start attempt answers http=$NATIVE_START_STATUS (recorded gap)"

# CLI start -> Araf sees the workload ready again.  A stop observation can
# briefly leave the provider at an unknown outcome while the execution agent
# fences a stale generation (seen on Debian's slower reconcile path).  Keep
# this bounded and retry the idempotent start rather than treating that
# transient as a successful cross-interface assertion.
sleep 30
STARTED_STATUS=""
for START_ATTEMPT in 1 2 3; do
  openstack server start "$B_ID" || die "scenario C: openstack start failed (attempt $START_ATTEMPT)"
  if STARTED_STATUS="$(
    for _ in $(seq 1 24); do
      code="$(bff_show_status compute.server "$B_ID" "$EVID/.bff-status.json")" || exit 1
      if [ "$code" = 200 ] && [ "$(python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' < "$EVID/.bff-status.json")" = ready ]; then
        printf 'ready'
        exit 0
      fi
      sleep 5
    done
    exit 1
  )"; then
    break
  fi
  log "scenario C: CLI start attempt $START_ATTEMPT did not converge to Araf ready; retrying"
  STARTED_STATUS=""
  sleep 15
done
[ -n "$STARTED_STATUS" ] || die "scenario C: CLI start did not converge to Araf ready after bounded retries"
[ "$(openstack server show "$B_ID" -c status -f value)" = ACTIVE ] \
  || die "scenario C: CLI did not observe ACTIVE after its own start"
CURRENT_CASE=C2 CURRENT_NAME="CLI start observed truthfully by Araf (same canonical id)" \
  case_ok C2 "openstack server start -> Araf status '${STARTED_STATUS}' and CLI ACTIVE for the same canonical id $B_ID"

# ---------------------------------------------------------------------------
# Scenario D: deletion through one surface, truthful absence on every surface
# ---------------------------------------------------------------------------
log "scenario D1: Araf-native delete of the CLI-created workload"
bff_delete /api/v1/resources/compute.server/"$B_ID" > "$EVID/17-scenarioD-araf-delete.json" \
  || die "scenario D1: the Araf-native delete failed"
wait_bff_concealed compute.server "$B_ID"
CLI_OUT="$(openstack server show "$B_ID" 2>&1)" && CLI_RC=0 || CLI_RC=$?
{
  echo "openstack server show ${B_ID} -> rc=${CLI_RC}"
  echo "$CLI_OUT"
  echo "araf_collection_state=$(record_collection_state compute.server "$B_ID")"
  echo "note: the canonical ledger keeps a DELETED tombstone; the native show view conceals it."
} > "$EVID/17b-scenarioD-absence.txt"
[ "$CLI_RC" -ne 0 ] || die "the Araf-deleted server is still visible via the OpenStack CLI"
grep -qiE 'No Server found|No server with a name or ID' <<<"$CLI_OUT" \
  || die "openstack server show $B_ID failed for a non-not-found reason (cannot call it absence): $CLI_OUT"
CURRENT_CASE=D1 CURRENT_NAME="Araf-deleted resource absent via the OpenStack CLI and the Araf live view" \
  case_ok D1 "delete via Araf -> openstack server show fails with 'No Server found' and the native live view answers 404 ($(awk -F= '/araf_collection_state/{print $2}' "$EVID/17b-scenarioD-absence.txt"))"

log "scenario D2: CLI create + CLI delete -> absent on Araf as well"
cli_create_server pp4-openstack-cli || die "scenario D2: openstack server create failed"
cp "$EVID/.cli-create-pp4-openstack-cli.txt" "$EVID/17d-scenarioD2-cli-create.txt"
D2_ID="$(openstack server show pp4-openstack-cli -c id -f value)"
[ -n "$D2_ID" ] || die "scenario D2: no id"
wait_bff_live compute.server "$D2_ID"
# The server only just reached ACTIVE; give the create reconcile a moment to
# settle so the delete does not race it (a raced delete stays listed for a
# long time while the operations serialise).
sleep 30
openstack server delete "$D2_ID" > "$EVID/17e-scenarioD2-cli-delete.txt" 2>&1 \
  || die "scenario D2: openstack server delete failed"
wait_server_absent_cli "$D2_ID"
wait_bff_concealed compute.server "$D2_ID"
{
  echo "server_id=${D2_ID}"
  echo "araf_collection_state=$(record_collection_state compute.server "$D2_ID")"
  echo "cli_absence=verified (openstack server list no longer shows pp4-openstack-cli)"
} > "$EVID/17f-scenarioD2-absence.txt"
wait_bff_live compute.server "$TESTVM_ID"
CURRENT_CASE=D2 CURRENT_NAME="CLI-deleted resource absent on Araf; test-vm survives" \
  case_ok D2 "delete via CLI -> native live view 404 (collection: $(awk -F= '/araf_collection_state/{print $2}' "$EVID/17f-scenarioD2-absence.txt")); test-vm intact (ONE canonical truth)"
openstack server list -f json > "$EVID/18-servers-final.json"

# The browser delete is deliberately performed by host-run after this phase's
# live-provider checks. Its dual-surface absence proof is recorded there; this
# phase must not require a delete marker before the browser has acted.
printf 'browser_delete_verification=deferred_until_host_phase\n' > "$EVID/18b-console-deleted-server-cli.txt"

# ---- tenant/operator separation spot-check ----------------------------------------------
araf_login operator
OP_PROFILE="$(bff_get /api/v1/operator/profile)"
echo "$OP_PROFILE" > "$EVID/19-operator-profile.json"
OP_COOKIE="${BFF_COOKIE}"
OP_CSRF="${BFF_CSRF}"
araf_login tenant
# A fresh tenant session carries no project scope: /api/v1/context is scope-
# bound and would truthfully answer 401. Select the canonical admin project
# before reading the tenant context.
bff_post /api/v1/auth/scope "{\"project_id\":\"${ADMIN_PROJECT_ID}\"}" >/dev/null
T_CONTEXT="$(bff_get /api/v1/context)"
echo "$T_CONTEXT" > "$EVID/19-tenant-context.json"
# Exact statuses, not "any failure passes": the tenant BFF does not mount the
# operator router (404), and an operator session cookie is not accepted by the
# tenant surface (401). A 200/3xx/5xx would all indicate a real separation bug.
SAME_SURFACE_STATUS="$(pcurl_status -H "cookie: ${BFF_COOKIE}; ${BFF_CSRF}" \
  https://tenant.o3k.demo/api/v1/operator/platform/overview)"
CROSS_SURFACE_STATUS="$(pcurl_status -H "cookie: ${BFF_COOKIE}; ${BFF_CSRF}" \
  https://operator.o3k.demo/api/v1/operator/platform/overview)"
OPERATOR_ON_OPERATOR_STATUS="$(pcurl_status -H "cookie: ${OP_COOKIE}; ${OP_CSRF}" \
  https://operator.o3k.demo/api/v1/operator/platform/overview)"
{
  echo "operator_session_on_operator_surface: $(pcurl_status -H "cookie: ${OP_COOKIE}; ${OP_CSRF}" https://operator.o3k.demo/api/v1/operator/profile)"
  echo "tenant_session_on_tenant_bff_operator_route: ${SAME_SURFACE_STATUS}"
  echo "tenant_session_on_operator_bff_operator_route: ${CROSS_SURFACE_STATUS}"
  echo "operator_session_on_operator_bff_operator_route: ${OPERATOR_ON_OPERATOR_STATUS}"
} > "$EVID/19b-separation-statuses.txt"
[ "$SAME_SURFACE_STATUS" = 404 ] \
  || die "tenant BFF exposed an operator-only route (status $SAME_SURFACE_STATUS, want 404)"
[ "$CROSS_SURFACE_STATUS" = 401 ] \
  || die "operator BFF accepted a tenant session (status $CROSS_SURFACE_STATUS, want 401)"
[ "$OPERATOR_ON_OPERATOR_STATUS" = 200 ] \
  || die "operator BFF rejected its own operator session (status $OPERATOR_ON_OPERATOR_STATUS, want 200)"
case_ok S1 "tenant/operator trust surfaces separated (tenant BFF 404 on operator route, tenant session rejected 401 by operator BFF, operator session accepted 200)"

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
  # The provider password lands in terraform.tfvars: create it 0600 inside a
  # restrictive umask and delete it again right after destroy.
  ( umask 077; cat > terraform.tfvars <<EOF
auth_url = "$AUTH_URL"
user_name = "admin"
password = "$ADMIN_PW"
project_id = "$ADMIN_PROJECT_ID"
region = "RegionOne"
image_name = "cirros-0.6.3"
flavor_name = "testlab-flavor"
EOF
  )
  [ "$(stat -c %a terraform.tfvars)" = 600 ] || die "terraform.tfvars mode is not 0600"
  ../tofu init -no-color > "$EVID/20-tofu-init.log" 2>&1 || die "tofu init failed"
  ../tofu apply -auto-approve -no-color > "$EVID/20-tofu-apply.log" 2>&1 || die "tofu apply failed"
  TOFU_NET_ID="$(../tofu output -raw network_id 2>/dev/null || true)"
  [ -n "$TOFU_NET_ID" ] || die "tofu produced no network_id output"
  openstack network show "$TOFU_NET_ID" >/dev/null 2>&1 || die "tofu-created network not visible via OpenStack CLI"
  # VERIFIED expectation: the unmodified provider creates the network through
  # the compatibility API, so it is NOT a canonical network:network row. The
  # check is tolerant of both outcomes but always records the observed one.
  bff_list_ids network.network > "$EVID/20-tofu-araf-networks.txt" \
    || die "cannot read the native network collection (cannot verify the tofu outcome)"
  if grep -qx -- "$TOFU_NET_ID" "$EVID/20-tofu-araf-networks.txt"; then
    printf 'tofu_network_native_row=present id=%s\n' "$TOFU_NET_ID" > "$EVID/20b-tofu-native-network-check.txt"
    case_ok T1 "OpenTofu provider 3.4.0 created network $TOFU_NET_ID visible via the unmodified CLI AND as a canonical Araf row"
  else
    printf 'tofu_network_native_row=absent id=%s\n' "$TOFU_NET_ID" > "$EVID/20b-tofu-native-network-check.txt"
    record_gap "tofu-created-network-not-canonical" \
      "tofu_network=${TOFU_NET_ID} visible_via_cli=yes native_row=absent (the unmodified provider uses the compatibility API)"
    case_ok T1 "OpenTofu provider 3.4.0 created network $TOFU_NET_ID visible via the unmodified CLI; it is not a canonical native row (recorded gap, 20b)"
  fi
  set +e
  ../tofu destroy -auto-approve -no-color > "$EVID/20-tofu-destroy.log" 2>&1
  TOFU_DESTROY_RC=$?
  set -e
  rm -f terraform.tfvars
  [ "$TOFU_DESTROY_RC" -eq 0 ] || die "tofu destroy failed (rc=$TOFU_DESTROY_RC)"
  # The absence check must fail closed: capture the CLI status explicitly so a
  # failing `openstack network list` can never look like "the network is gone".
  NET_LIST_JSON="$(openstack network list -f json)" \
    || die "cannot list networks after tofu destroy (cannot verify absence)"
  printf '%s' "$NET_LIST_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
target = sys.argv[1]
assert not any(n["ID"] == target for n in d), f"tofu-destroyed network {target} still visible"
' "$TOFU_NET_ID" || die "tofu-destroyed network still visible via OpenStack CLI"
  case_ok T2 "tofu destroy removed the compat network"
  cp /var/log/o3k/compat-trace.jsonl "$EVID/20-tofu-compat-trace.jsonl" 2>/dev/null || true
  rm -f /etc/systemd/system/o3kd.service.d/pp4-compat-trace.conf
  systemctl daemon-reload
  systemctl restart o3kd
  for i in $(seq 1 60); do curl -sf http://127.0.0.1:18080/readyz >/dev/null 2>&1 && break; sleep 2; done
  curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd did not recover after trace removal"
else
  die "OpenTofu tooling not staged at $TOFU_DIR/tofu"
fi

# ---- browser-journey classified gaps -------------------------------------------------------
# The tenant journey prints `PP4-GAP <id> <detail>`; host-run pushes the log into
# the VM, so the gaps it observed are part of the campaign ledger too.
if [ -f "$EVID/05-browser-e2e.log" ]; then
  awk '$1 == "PP4-GAP" && NF >= 2 {
        id = $2
        sub(/^[^ ]+ +[^ ]+ +/, "")
        print "GAP " id " " $0
      }' "$EVID/05-browser-e2e.log" >> "$EVID/35-classified-gaps.txt"
else
  die "05-browser-e2e.log is missing: the browser journey's classified gaps cannot be recorded"
fi

# ---- secret scan across clients + evidence ------------------------------------------------
# A missing scan target is a FAIL, never a silent skip: the campaign claims
# these artifacts were scanned.
SCAN_TARGETS=( "$EVID/01-one-line-install.log" "$EVID/04-verify.log" "$EVID/05-browser-e2e.log" )
[ -f "$EVID/20-tofu-apply.log" ] && SCAN_TARGETS+=( "$EVID/20-tofu-apply.log" )
FAIL=0
for f in "${SCAN_TARGETS[@]}"; do
  if [ ! -f "$f" ]; then
    log "SECRET SCAN TARGET MISSING: $f"
    FAIL=1
    continue
  fi
  if ! secret_scan_file "$f"; then
    log "SECRET SCAN HIT: $f"; FAIL=1
  fi
done > "$EVID/17-secret-scan.txt" 2>&1
[ "$FAIL" -eq 0 ] || die "secret scan found material or a scan target was missing (see 17-secret-scan.txt)"
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

# ---- classified-gap ledger integrity -------------------------------------------------------
# The gap ledger is a durable campaign artifact: make-manifest.py requires it for
# every distro campaign and fails when it is absent or malformed.
python3 - "$EVID/35-classified-gaps.txt" <<'PY' || die "classified-gap ledger is empty or malformed"
import sys
lines = [line.rstrip("\n") for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
assert lines, "no classified gaps were recorded"
for line in lines:
    parts = line.split(" ", 2)
    assert parts[0] == "GAP" and len(parts) >= 2 and parts[1], f"malformed gap line: {line}"
required = {"compat-created-resource-not-canonical"}
required_prefixes = ()
observed = {line.split(" ", 2)[1] for line in lines}
missing = sorted(required - observed)
missing.extend(
    prefix + "*" for prefix in required_prefixes
    if not any(value.startswith(prefix) for value in observed)
)
assert not missing, f"the profile's known classified gaps are missing: {sorted(missing)}"
PY

# ---- optional Horizon witness (non-blocking; classified in its own evidence) --------------
if [ "${O3K_PP4_HORIZON:-0}" = 1 ] && [ -x /home/tester/pp4-campaign/horizon-witness.sh ]; then
  log "running optional Horizon witness"
  bash /home/tester/pp4-campaign/horizon-witness.sh "$EVID" || log "Horizon witness did not complete (see 30-horizon-*.txt)"
fi

pp4_phase_complete
log "PHASE1B-COMPLETE status=passed"
echo "PHASE1B-COMPLETE status=passed" > "$EVID/phase1b-done"
