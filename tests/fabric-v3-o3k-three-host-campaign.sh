#!/usr/bin/env bash
set -Eeuo pipefail

# Supported-HTTP Fabric v3 three-host nested campaign. This script is test
# harness only and refuses to run against a different product source tree.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAMPAIGN_MODE="${1:-full}"
[[ "$CAMPAIGN_MODE" == full || "$CAMPAIGN_MODE" == departure-micro ]] \
  || { echo "HARNESS_GAP: unsupported campaign mode: $CAMPAIGN_MODE" >&2; exit 1; }
if [[ "$CAMPAIGN_MODE" == departure-micro ]]; then
  ACCEPTANCE_GATE="FABRIC V3 DURABLE HOST RETIREMENT MICROGATE"
else
  ACCEPTANCE_GATE="FABRIC V3 O3K MINIMAL THREE-HOST MILESTONE"
fi
PRODUCT_SHA=d7335166563d28084fbad5ac7f5d0f0e07e000a4
PRODUCT_TREE=d5b75b5674009d8c135218556aa2177371e489a3
PRODUCT_PROTECTED_MAIN_BASE=adaf6168b124111ee62bf53f6eaf6e0f6cab155e
PRODUCT_REMOTE_REF=refs/heads/fix/fabric-v3-retirement-provider-016
HARNESS_REMOTE_REF=refs/heads/fabric-v3-retirement-microgate
HOST_PREFLIGHT="$ROOT_DIR/tests/fabric-v3-host-preflight.py"
# Guard the acceptance control contract before creating evidence or guests.
[[ -f "$ROOT_DIR/contracts/real-host-acceptance-evidence.md" ]] \
  || { echo "HARNESS_GAP: accepted real-host evidence contract is missing" >&2; exit 1; }
python3 "$ROOT_DIR/tests/fabric-v3-guest-control-regression.py" \
  || { echo "HARNESS_GAP: guest-control acceptance regression failed" >&2; exit 1; }
python3 "$ROOT_DIR/tests/fabric-v3-owned-domain-storage-test.py" \
  || { echo "HARNESS_GAP: ownership-safe domain cleanup regression failed" >&2; exit 1; }
python3 "$ROOT_DIR/tests/fabric-v3-host-preflight-test.py" \
  || { echo "HARNESS_GAP: live libvirt/address preflight regression failed" >&2; exit 1; }
python3 "$ROOT_DIR/tests/fabric-v3-retirement-evidence-test.py" \
  || { echo "HARNESS_GAP: durable retirement evidence regression failed" >&2; exit 1; }
python3 "$ROOT_DIR/tests/fabric-v3-delete-operation-evidence-test.py" \
  || { echo "HARNESS_GAP: durable server-delete evidence regression failed" >&2; exit 1; }
python3 "$ROOT_DIR/tests/fabric-v3-port-detach-evidence-test.py" \
  || { echo "HARNESS_GAP: durable port-detach evidence regression failed" >&2; exit 1; }
python3 "$ROOT_DIR/tests/fabric-v3-canonical-endpoint-retention-evidence-test.py" \
  || { echo "HARNESS_GAP: canonical endpoint retention evidence regression failed" >&2; exit 1; }
python3 "$ROOT_DIR/tests/fabric-v3-shared-fabric-namespace-test.py" \
  || { echo "HARNESS_GAP: shared Fabric namespace evidence regression failed" >&2; exit 1; }
bash -n "$ROOT_DIR/tests/fabric-v3-retirement-microgate.sh" \
  || { echo "HARNESS_GAP: durable retirement observer syntax failed" >&2; exit 1; }
BASE_IMAGE="${O3K_FABRIC_V3_BASE_IMAGE:-/var/lib/libvirt/images/noble-server-cloudimg-amd64.img}"
BASE_IMAGE_SHA=612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354
PROBE_BASE_URL=https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img
PROBE_BASE_SHA=7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b
RUN_ID="${O3K_FABRIC_V3_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
PREFIX="o3k-fabric-v3-${RUN_ID}"
EVIDENCE_ROOT="${O3K_FABRIC_V3_EVIDENCE_ROOT:-/var/tmp}"
DHCP_BOUNDARY_DIAGNOSTIC="${O3K_FABRIC_V3_DHCP_BOUNDARY_DIAGNOSTIC:-0}"
if [[ "$DHCP_BOUNDARY_DIAGNOSTIC" == 1 ]]; then
  EVIDENCE="$EVIDENCE_ROOT/fabric-v3-remote-dhcp-boundary-$RUN_ID"
else
  EVIDENCE="$EVIDENCE_ROOT/fabric-v3-minimal-three-host-$RUN_ID"
fi
IMAGE_STORE="${O3K_FABRIC_V3_IMAGE_STORE:-/var/lib/libvirt/images}"
NETWORK="${O3K_FABRIC_V3_LIBVIRT_NETWORK:-default}"
SSH_USER=o3k
SSH_PORT=22
API_PORT="${O3K_FABRIC_V3_API_PORT:-18081}"
CONTROL_PORT="${O3K_FABRIC_V3_CONTROL_PORT:-50051}"
PROJECT_ID=eba29e2d-53de-461d-ae91-ede7402713cb
FABRIC_DOMAIN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
SSH_KEY="$EVIDENCE/management/campaign_ed25519"
PROBE_KEY="$EVIDENCE/management/probe_ed25519"
KNOWN_HOSTS="$EVIDENCE/management/known_hosts"
TLS_DIR="$EVIDENCE/management/tls"
STAGE="$EVIDENCE/environment/stage"
PRODUCT_SOURCE_DIR="$EVIDENCE/environment/product-source"
BASE=""
TOKEN=""
O3KD_PID=""
DHCP_CAPTURE_PID=""
DHCP_CAPTURE_HOST=""
DHCP_CAPTURE_CLEANUP_STATUS=NOT_APPLICABLE
CAMPAIGN_FAILURE=""
CLASSIFICATION=""
CAMPAIGN_TEARDOWN_PASS=0
API_TEARDOWN_VERIFIED=0
FRESH_DOMAINS=()
SERVER_IDS=()
PORT_IDS=()
NETWORK_ID=""
SUBNET_ID=""
IMAGE_ID=""
declare -A MGMT_IP=() MGMT_OCTET=() MGMT_MAC=() REALM_BRIDGE=() GUEST_IPV6=() TENANT_IP=() TENANT_MAC=()
HOSTS=(a b c)
LAST_GUEST_CHANNEL_ERROR=0

fail() {
  CAMPAIGN_FAILURE="$*"
  CLASSIFICATION="${2:-HARNESS_GAP}"
  echo "FIRST FAILURE [$CLASSIFICATION]: ${CAMPAIGN_FAILURE%%|*}" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || fail "required command missing: $1"; }
[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || fail "run ID is not safe for ownership-scoped paths" "HARNESS_GAP"
ssh_opts=(-i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" -o ConnectTimeout=8)
# The destination is local shell data; ssh intentionally expands remote command arguments client-side.
# shellcheck disable=SC2029
ssh_vm() { local address="$1"; shift; ssh "${ssh_opts[@]}" "$SSH_USER@$address" "$@"; }
scp_vm() { local address="$1"; shift; scp -i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" "$@" "$SSH_USER@$address:"; }
assert_remote_link_absent() {
  local host="$1" name="$2" output="$3" address="${MGMT_IP[$1]}" remote rc
  [[ "$name" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || fail "invalid interface identity in provider ownership: $name" "OWNERSHIP_DEFECT"
  remote="sudo python3 -c 'import pathlib,sys; sys.exit(10 if pathlib.Path(\"/sys/class/net\",sys.argv[1]).exists() else 0)' '$name'"
  if ssh_vm "$address" "$remote" >"$output.raw" 2>&1; then
    printf '{"host":"host-%s","namespace":"%s","interface":"%s","result":"absent","observer":"ssh+sudo+ip-link"}\n' \
      "$host" "root" "$name" >"$output"
  else
    rc=$?
    if (( rc == 10 )); then
      printf '{"host":"host-%s","namespace":"%s","interface":"%s","result":"present","observer":"ssh+sudo+ip-link"}\n' \
        "$host" "root" "$name" >"$output"
      fail "provider-owned interface remains on host-$host: $name" "PROVIDER_ABSENCE_DEFECT"
    fi
    fail "could not observe interface absence on host-$host ($name), ssh_exit=$rc" "ENVIRONMENT_GAP"
  fi
  rm -f -- "$output.raw"
}
assert_remote_path_absent() {
  local host="$1" path="$2" output="$3" address="${MGMT_IP[$1]}" remote rc
  [[ "$path" == "/var/lib/o3k-fabric-v3/$RUN_ID/"* ]] \
    || fail "refusing to inspect a non-run-owned provider path: $path" "OWNERSHIP_DEFECT"
  remote="sudo python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); print(\"present\" if p.exists() else \"absent\"); sys.exit(10 if p.exists() else 0)' '$path'"
  if ssh_vm "$address" "$remote" >"$output" 2>&1; then
    [[ "$(tail -n 1 "$output")" == absent ]] \
      || fail "provider-owned path unexpectedly present on host-$host: $path" "PROVIDER_ABSENCE_DEFECT"
  else
    rc=$?
    if (( rc == 10 )); then
      fail "provider-owned path unexpectedly present on host-$host: $path" "PROVIDER_ABSENCE_DEFECT"
    fi
    fail "could not observe path absence on host-$host ($path), ssh_exit=$rc" "ENVIRONMENT_GAP"
  fi
}
stop_controller() {
  local pid="$O3KD_PID"
  [[ -n "$pid" ]] || return 0
  kill -TERM "$pid" 2>/dev/null || return 1
  for _ in $(seq 1 30); do
    if [[ ! -r "/proc/$pid/stat" ]] || [[ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" == Z ]]; then
      break
    fi
    sleep 1
  done
  if [[ -r "/proc/$pid/stat" ]] && [[ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" != Z ]]; then return 1; fi
  wait "$pid" 2>/dev/null || true
  [[ ! -e "/proc/$pid" ]] || return 1
  O3KD_PID=""
  return 0
}
capture_survivor_host() {
  local host="$1" address="${MGMT_IP[$1]}" directory="$EVIDENCE/survivor-convergence/host-$1" namespace vxlan_interface
  mkdir -p "$directory"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json" \
    >"$directory/ownership.json" || return 1
  vxlan_interface="$(python3 - "$directory/ownership.json" "$REALM_ID" <<'PYSURVIVOR'
import json,sys
print(json.load(open(sys.argv[1]))['realms'][sys.argv[2]]['vxlan']['interface'])
PYSURVIVOR
)" || return 1
  namespace="$(python3 - "$directory/ownership.json" <<'PYSURVIVORNS'
import json,sys
print(json.load(open(sys.argv[1]))['fabric']['namespace'])
PYSURVIVORNS
)" || return 1
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/plans/$REALM_ID.json" \
    >"$directory/plan.json" || return 1
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/executor/accepted-network-plans.json" \
    >"$directory/command-journal.json" || return 1
  ssh_vm "$address" "sudo ip netns exec '$namespace' bridge fdb show dev '$vxlan_interface'" \
    >"$directory/fdb.txt" || return 1
}
start_compute_agent() {
  local host="$1" health_port="$2" address="${MGMT_IP[$1]}"
  ssh_vm "$address" "sudo bash -c 'nohup env O3K_COMPUTE_DATA_DIR=/var/lib/o3k-fabric-v3/$RUN_ID/compute O3K_COMPUTE_CONTROL_ENDPOINT=https://$HOST_MGMT_IP:$CONTROL_PORT O3K_COMPUTE_SERVER_NAME=o3k-control-plane O3K_COMPUTE_HOST_LABEL=host-$host O3K_COMPUTE_TLS_DIR=/var/lib/o3k-fabric-v3/$RUN_ID/compute/tls O3K_COMPUTE_HEALTH_ADDR=0.0.0.0:$health_port O3K_COMPUTE_MAX_DISK_GB=30 O3K_COMPUTE_NETWORK_EXTERNAL=1 O3K_COMPUTE_NETWORK_ROOT=/var/lib/o3k-fabric-v3/$RUN_ID/network/ownership O3K_COMPUTE_BRIDGE_NAME=o3k-br0 O3K_COMPUTE_DHCP_BINARY=/usr/sbin/dnsmasq O3K_COMPUTE_FABRIC_HOST_ID=host-$host O3K_COMPUTE_FABRIC_STATE_ROOT=/var/lib/o3k-fabric-v3/$RUN_ID/network/fabric RUST_LOG=info /usr/local/bin/o3k-compute-bin >/var/lib/o3k-fabric-v3/$RUN_ID/compute/agent.log 2>&1 </dev/null & echo \$! >/var/lib/o3k-fabric-v3/$RUN_ID/compute/agent.pid'"
}
api() { curl --silent --show-error --fail-with-body --max-time 30 -H "x-auth-token: $TOKEN" "$@"; }
capture_c_remove_work_row() {
  local realm_id="$1"
  python3 - "$EVIDENCE/controller-data/o3k.sqlite" "$realm_id" \
    "$EVIDENCE/endpoint-removal/c-remove-work-row.json" \
    "$EVIDENCE/endpoint-removal/c-remove-work-row-history.jsonl" <<'PYWORK'
import hashlib,json,pathlib,sqlite3,sys
database,realm_id,out_path,history_path=sys.argv[1:]
out=pathlib.Path(out_path); history=pathlib.Path(history_path)
db=sqlite3.connect(f"file:{database}?mode=ro",uri=True,timeout=3)
db.row_factory=sqlite3.Row
rows=db.execute("SELECT rowid AS insertion_order,* FROM network_plan_work WHERE target_host_id='host-c' ORDER BY rowid DESC").fetchall()
matches=[]
for row in rows:
    raw=bytes(row["snapshot"]); command=json.loads(raw)
    plan=command.get("plan",{}); fabric=plan.get("fabric",{}) if isinstance(plan,dict) else {}
    if command.get("action")=="Remove" and fabric.get("realm_id")==realm_id:
        outcome=row["outcome"]
        directory=fabric.get("directory",{}) if isinstance(fabric,dict) else {}
        participants=sorted({entry.get("selected_host") for entry in directory.get("entries",[]) if entry.get("selected_host")})
        her_peers=sorted({peer.get("host_id") for peer in fabric.get("peers",[]) if peer.get("host_id")})
        matches.append({
            "insertion_order":row["insertion_order"],"command_id":row["command_id"],
            "operation_id":row["operation_id"],"idempotency_key":row["idempotency_key"],
            "controller_id":row["controller_id"],"controller_epoch":row["controller_epoch"],
            "target_host_id":row["target_host_id"],"target_agent_id":row["target_agent_id"],
            "target_agent_epoch":row["target_agent_epoch"],"action":"Remove","realm_id":realm_id,
            "directory_generation":fabric.get("directory_generation"),
            "local_host":fabric.get("local_host"),
            "binding_generation":fabric.get("encapsulation",{}).get("binding_generation"),
            "fabric_generation":fabric.get("local_fabric_generation"),
            "participants":participants,"her_peers":her_peers,
            "realm_generation":plan.get("resource_generations",{}).get(realm_id),
            "fingerprint_sha256":row["fingerprint_sha256"],
            "snapshot_sha256":hashlib.sha256(raw).hexdigest(),"state":row["state"],
            "revision":row["revision"],
            "outcome":bytes(outcome).decode("utf-8",errors="replace") if outcome is not None else None,
            "created_at":row["created_at"],"updated_at":row["updated_at"]})
result={"found":bool(matches), "matches":matches, **(matches[0] if matches else {})}
out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
if result.get("found"):
    line=json.dumps({k:result.get(k) for k in ("insertion_order","command_id","operation_id","target_agent_epoch","state","revision","updated_at")},sort_keys=True)
    previous=history.read_text().splitlines() if history.exists() else []
    if not previous or previous[-1]!=line:
        with history.open("a") as stream: stream.write(line+"\n")
print(result.get("state", ""))
PYWORK
}
capture_realm_work_history() {
  local realm_id="$1" output="$2"
  python3 - "$EVIDENCE/controller-data/o3k.sqlite" "$realm_id" "$output" <<'PYHISTORY'
import json,pathlib,sqlite3,sys
database,realm_id,output=sys.argv[1:]
db=sqlite3.connect(f"file:{database}?mode=ro",uri=True,timeout=3); db.row_factory=sqlite3.Row
rows=db.execute("SELECT rowid AS insertion_order,* FROM network_plan_work ORDER BY rowid").fetchall()
history=[]
for row in rows:
    raw=bytes(row['snapshot']); command=json.loads(raw); plan=command.get('plan',{})
    fabric=plan.get('fabric',{}) if isinstance(plan,dict) else {}
    if fabric.get('realm_id')!=realm_id: continue
    directory=fabric.get('directory',{}) if isinstance(fabric,dict) else {}
    participants=sorted({entry.get('selected_host') for entry in directory.get('entries',[]) if entry.get('selected_host')})
    her_peers=sorted({peer.get('host_id') for peer in fabric.get('peers',[]) if peer.get('host_id')})
    outcome=row['outcome']
    history.append({'insertion_order':row['insertion_order'],'command_id':row['command_id'],
        'operation_id':row['operation_id'],'idempotency_key':row['idempotency_key'],
        'controller_id':row['controller_id'],'controller_epoch':row['controller_epoch'],
        'target_host_id':row['target_host_id'],'target_agent_id':row['target_agent_id'],
        'target_agent_epoch':row['target_agent_epoch'],'action':command.get('action'),
        'realm_id':fabric.get('realm_id'),'directory_generation':fabric.get('directory_generation'),
        'binding_generation':fabric.get('encapsulation',{}).get('binding_generation'),
        'fabric_generation':fabric.get('local_fabric_generation'),
        'participants':participants,'her_peers':her_peers,
        'realm_generation':plan.get('resource_generations',{}).get(realm_id),
        'state':row['state'],'revision':row['revision'],
        'outcome':bytes(outcome).decode('utf-8',errors='replace') if outcome is not None else None,
        'created_at':row['created_at'],'updated_at':row['updated_at']})
terminals={'succeeded','failed'}
result={'realm_id':realm_id,'history':history,
    'unresolved':[item for item in history if item['state'] not in terminals],
    'terminal_failures':[item for item in history if item['state']=='failed']}
pathlib.Path(output).write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
PYHISTORY
}
field() { python3 -c 'import json,sys
v=json.load(sys.stdin)
for k in sys.argv[1].split("."): v=v[int(k)] if isinstance(v,list) else v[k]
print(v)' "$1"; }
url_port() { local port="$1"; python3 - "$port" <<'PY'
import socket,sys
s=socket.socket(); s.bind(("0.0.0.0", int(sys.argv[1]))); s.close()
PY
}
find_free_port() {
  local preferred="$1" port
  for port in $(seq "$preferred" "$((preferred + 100))"); do
    if url_port "$port" >/dev/null 2>&1; then printf '%s\n' "$port"; return 0; fi
  done
  return 1
}

if [[ -z "${O3K_FABRIC_V3_API_PORT:-}" ]]; then
  API_PORT="$(find_free_port "$API_PORT")" || fail "no free API port in configured range" "ENVIRONMENT_GAP"
fi
if [[ -z "${O3K_FABRIC_V3_CONTROL_PORT:-}" ]]; then
  CONTROL_PORT="$(find_free_port "$CONTROL_PORT")" || fail "no free compute-control port in configured range" "ENVIRONMENT_GAP"
fi

[[ ! -e "$EVIDENCE" && ! -L "$EVIDENCE" ]] || fail "evidence path already exists: $EVIDENCE" "HARNESS_GAP"
mkdir -p "$EVIDENCE"/{environment,management,api,canonical,plans,attachments,compute-a,compute-b,compute-c,arp,icmp,tcp,udp,wireguard,vxlan,restart,compute-agent-restart,endpoint-removal,teardown,topology/{plans,ownership,fdb,wireguard,links,nft-before,nft-after},a,b,dhcp,departure-micro,before-departure/{plans,durable-work,host-a,host-b,host-c,traffic},c-delete/{operation,port,retirement-obligation,remove-command,agent-journal},provider-absence/host-c/{ownership,links,fdb,nft},survivor-convergence/{host-a,host-b,plans,fdb,traffic},restart/{startup-recovery,durable-work,plans,traffic}}
chmod 0700 "$EVIDENCE"
[[ ! -e "$EVIDENCE/.o3k-fabric-v3-owned" ]] || fail "evidence path collision"
printf 'o3k-fabric-v3-campaign-v1\nrun=%s\nprefix=%s\n' "$RUN_ID" "$PREFIX" >"$EVIDENCE/.o3k-fabric-v3-owned"
chmod 0600 "$EVIDENCE/.o3k-fabric-v3-owned"
git -C "$ROOT_DIR" rev-parse HEAD >"$EVIDENCE/environment/harness_sha.txt"
git -C "$ROOT_DIR" rev-parse 'HEAD^{tree}' >"$EVIDENCE/environment/harness_tree.txt"
git -C "$ROOT_DIR" branch --show-current >"$EVIDENCE/environment/harness_branch.txt"
git -C "$ROOT_DIR" branch -r --contains HEAD >"$EVIDENCE/environment/harness-remote-visibility.txt"
cp "$ROOT_DIR/tests/fabric-v3-o3k-three-host-campaign.sh" "$EVIDENCE/environment/campaign-driver.sh"
cp "$HOST_PREFLIGHT" "$EVIDENCE/environment/host-preflight-helper.py"
cp "$ROOT_DIR/tests/fabric-v3-host-preflight-test.py" "$EVIDENCE/environment/host-preflight-test.py"
cp "$ROOT_DIR/tests/fabric-v3-owned-domain-storage.py" "$EVIDENCE/environment/owned-domain-storage-check.py"
cp "$ROOT_DIR/tests/fabric-v3-build-probe-image.sh" "$EVIDENCE/environment/build-probe-image.sh"
cp "$ROOT_DIR/tests/fabric-v3-guest-control.py" "$EVIDENCE/environment/guest-control-helper.py"
cp "$ROOT_DIR/tests/fabric-v3-install-agent-host.sh" "$EVIDENCE/environment/install-agent-host.sh"
cp "$ROOT_DIR/tests/fabric-v3-remote-dhcp-boundary-capture.py" "$EVIDENCE/environment/boundary-capture-helper.py"
cp "$ROOT_DIR/tests/fabric-v3-retirement-evidence.py" "$EVIDENCE/environment/retirement-evidence-helper.py"
cp "$ROOT_DIR/tests/fabric-v3-retirement-evidence-test.py" "$EVIDENCE/environment/retirement-evidence-test.py"
cp "$ROOT_DIR/tests/fabric-v3-delete-operation-evidence.py" "$EVIDENCE/environment/delete-operation-evidence-helper.py"
cp "$ROOT_DIR/tests/fabric-v3-delete-operation-evidence-test.py" "$EVIDENCE/environment/delete-operation-evidence-test.py"
cp "$ROOT_DIR/tests/fabric-v3-port-detach-evidence.py" "$EVIDENCE/environment/port-detach-evidence-helper.py"
cp "$ROOT_DIR/tests/fabric-v3-port-detach-evidence-test.py" "$EVIDENCE/environment/port-detach-evidence-test.py"
cp "$ROOT_DIR/tests/fabric-v3-shared-fabric-namespace.py" "$EVIDENCE/environment/shared-fabric-namespace-helper.py"
cp "$ROOT_DIR/tests/fabric-v3-shared-fabric-namespace-test.py" "$EVIDENCE/environment/shared-fabric-namespace-test.py"
cp "$ROOT_DIR/tests/fabric-v3-canonical-endpoint-retention-evidence.py" "$EVIDENCE/environment/canonical-endpoint-retention-evidence-helper.py"
cp "$ROOT_DIR/tests/fabric-v3-canonical-endpoint-retention-evidence-test.py" "$EVIDENCE/environment/canonical-endpoint-retention-evidence-test.py"
cp "$ROOT_DIR/tests/fabric-v3-retirement-microgate.sh" "$EVIDENCE/environment/retirement-microgate-helper.sh"
sha256sum "$ROOT_DIR/tests/fabric-v3-o3k-three-host-campaign.sh" >"$EVIDENCE/environment/driver.sha256"
sha256sum "$HOST_PREFLIGHT" >"$EVIDENCE/environment/host-preflight-helper.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-retirement-evidence.py" >"$EVIDENCE/environment/retirement-evidence-helper.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-delete-operation-evidence.py" >"$EVIDENCE/environment/delete-operation-evidence-helper.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-port-detach-evidence.py" >"$EVIDENCE/environment/port-detach-evidence-helper.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-shared-fabric-namespace.py" >"$EVIDENCE/environment/shared-fabric-namespace-helper.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-shared-fabric-namespace-test.py" >"$EVIDENCE/environment/shared-fabric-namespace-test.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-canonical-endpoint-retention-evidence.py" >"$EVIDENCE/environment/canonical-endpoint-retention-evidence-helper.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-canonical-endpoint-retention-evidence-test.py" >"$EVIDENCE/environment/canonical-endpoint-retention-evidence-test.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-retirement-microgate.sh" >"$EVIDENCE/environment/retirement-microgate-helper.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-owned-domain-storage.py" >"$EVIDENCE/environment/owned-domain-storage-check.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-guest-control.py" >"$EVIDENCE/environment/guest-control-helper.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-remote-dhcp-boundary-capture.py" >"$EVIDENCE/environment/boundary-capture-helper.sha256"

refresh_image_store_pool() {
  local output="$1"
  python3 - "$IMAGE_STORE" "$output" <<'PYPOOL'
import json,pathlib,subprocess,sys,xml.etree.ElementTree as ET
image_store=pathlib.Path(sys.argv[1]).resolve(strict=False)
output=pathlib.Path(sys.argv[2])
result={'image_store':str(image_store),'observer':'libvirt_pool_path_match','status':'FAIL'}
def run(*args):
    return subprocess.run(['virsh','-c','qemu:///system',*args],check=True,capture_output=True,text=True).stdout
try:
    matches=[]
    for name in (line.strip() for line in run('pool-list','--all','--name').splitlines() if line.strip()):
        root=ET.fromstring(run('pool-dumpxml',name))
        path=root.findtext('./target/path')
        if path and pathlib.Path(path).resolve(strict=False)==image_store:
            matches.append(name)
    if len(matches)>1:
        raise RuntimeError('multiple libvirt pools target the exact campaign image store')
    if not matches:
        result.update({'status':'NOT_APPLICABLE','reason':'no libvirt pool targets the campaign image store'})
    else:
        pool=matches[0]
        info=run('pool-info',pool)
        state=next((line.split(':',1)[1].strip().lower() for line in info.splitlines()
                    if line.lstrip().startswith('State:')), '')
        result.update({'pool':pool,'pool_state':state})
        if state not in {'running','active'}:
            result.update({'status':'NOT_APPLICABLE','reason':'matching image store pool is inactive'})
        else:
            completed=subprocess.run(['virsh','-c','qemu:///system','pool-refresh',pool],capture_output=True,text=True)
            result.update({'command_class':'refresh_exact_image_store_pool','exit_code':completed.returncode,
                           'status':'PASS' if completed.returncode==0 else 'FAIL'})
            if completed.returncode:
                result['diagnostic']=completed.stderr.strip()[:500]
except (OSError,subprocess.SubprocessError,ET.ParseError,RuntimeError) as error:
    result.update({'status':'FAIL','diagnostic':f'{type(error).__name__}: {error}'[:500]})
output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
if result['status']=='FAIL':
    raise SystemExit(1)
PYPOOL
}

cleanup_on_success() {
  local rc=$? api_ok=-1 guest_ok=-1 controller_ok=-1 host_snapshot_ok=-1 foreign_ok=-1 capture_ok=-1 pool_refresh_ok=-1
  local cleanup_problem=0 cleanup_classification="" cleanup_failure=""
  trap - EXIT
  if declare -F stop_dhcp_capture >/dev/null 2>&1 && [[ "$DHCP_CAPTURE_CLEANUP_STATUS" == PENDING ]]; then
    if stop_dhcp_capture; then capture_ok=1; else
      capture_ok=0
      cleanup_problem=1
      cleanup_classification=CLEANUP_DEFECT
      cleanup_failure="run-owned DHCP capture process could not be stopped and collected"
    fi
  elif [[ "$DHCP_CAPTURE_CLEANUP_STATUS" == PASS ]]; then
    capture_ok=1
  elif [[ "$DHCP_CAPTURE_CLEANUP_STATUS" == FAIL ]]; then
    capture_ok=0
    cleanup_problem=1
    cleanup_classification=CLEANUP_DEFECT
    cleanup_failure="run-owned DHCP capture cleanup failed"
  fi
  cleanup_owned_api_resource() {
    local label="$1" path="$2" attempt delete_status get_status request_timeout
    local deadline=$((SECONDS + 120))
    for attempt in $(seq 1 60); do
      request_timeout=$((deadline - SECONDS))
      (( request_timeout > 0 )) || break
      delete_status="$(curl --silent --show-error --max-time "$request_timeout" -o /dev/null -w '%{http_code}' \
        -X DELETE "$BASE$path" -H "x-auth-token: $TOKEN" 2>>"$EVIDENCE/teardown/failure-api-cleanup-errors.txt" || true)"
      request_timeout=$((deadline - SECONDS))
      (( request_timeout > 0 )) || break
      get_status="$(curl --silent --show-error --max-time "$request_timeout" -o /dev/null -w '%{http_code}' \
        "$BASE$path" -H "x-auth-token: $TOKEN" 2>>"$EVIDENCE/teardown/failure-api-cleanup-errors.txt" || true)"
      printf '%s attempt=%s delete=%s get=%s\n' "$label" "$attempt" "$delete_status" "$get_status" \
        >>"$EVIDENCE/teardown/failure-api-cleanup.txt"
      if [[ "$get_status" == 404 ]]; then return 0; fi
      (( SECONDS < deadline )) || break
      sleep 2
    done
    printf '%s cleanup did not converge within 120 seconds\n' "$label" \
      >>"$EVIDENCE/teardown/failure-api-cleanup.txt"
    return 1
  }
  if [[ -f "$EVIDENCE/.o3k-fabric-v3-owned" ]] && grep -Fqx "run=$RUN_ID" "$EVIDENCE/.o3k-fabric-v3-owned"; then
    date -u +%FT%TZ >"$EVIDENCE/ended_at_utc.txt"
    # Remove any API resources created before a stop-at-first-failure. The
    # reverse order and run-generated IDs keep this on the supported API path.
    if [[ -n "$TOKEN" && -n "$BASE" ]] \
      && { (( rc != 0 )) || [[ "${CAMPAIGN_TEARDOWN_PASS:-0}" != 1 ]]; }; then
      api_ok=1
      : >"$EVIDENCE/teardown/failure-api-cleanup.txt"
      for ((i=${#SERVER_IDS[@]}-1; i>=0; i--)); do
        [[ -n "${SERVER_IDS[i]}" ]] || continue
        cleanup_owned_api_resource "server-${SERVER_IDS[i]}" "/v2.1/$PROJECT_ID/servers/${SERVER_IDS[i]}" || api_ok=0
      done
      for ((i=${#PORT_IDS[@]}-1; i>=0; i--)); do
        [[ -n "${PORT_IDS[i]}" ]] || continue
        cleanup_owned_api_resource "port-${PORT_IDS[i]}" "/v2.0/ports/${PORT_IDS[i]}" || api_ok=0
      done
      [[ -z "$SUBNET_ID" ]] || cleanup_owned_api_resource "subnet-$SUBNET_ID" "/v2.0/subnets/$SUBNET_ID" || api_ok=0
      [[ -z "$NETWORK_ID" ]] || cleanup_owned_api_resource "network-$NETWORK_ID" "/v2.0/networks/$NETWORK_ID" || api_ok=0
      [[ -z "$IMAGE_ID" ]] || cleanup_owned_api_resource "image-$IMAGE_ID" "/v2/images/$IMAGE_ID" || api_ok=0
      if (( api_ok )); then
        printf 'PASS\n' >"$EVIDENCE/teardown/api-resource-cleanup-status.txt"
      else
        printf 'FAIL\n' >"$EVIDENCE/teardown/api-resource-cleanup-status.txt"
        cleanup_problem=1
        cleanup_classification=CLEANUP_DEFECT
        cleanup_failure="run-owned API resource cleanup did not converge"
      fi
    elif [[ "${CAMPAIGN_TEARDOWN_PASS:-0}" == 1 && "${API_TEARDOWN_VERIFIED:-0}" == 1 ]]; then
      api_ok=1
      printf 'PASS\n' >"$EVIDENCE/teardown/api-resource-cleanup-status.txt"
    elif [[ -n "$TOKEN" && -n "$BASE" ]]; then
      # No resource IDs means provisioning did not create an API-owned resource.
      if (( ${#SERVER_IDS[@]} == 0 && ${#PORT_IDS[@]} == 0 )) \
        && [[ -z "$SUBNET_ID" && -z "$NETWORK_ID" && -z "$IMAGE_ID" ]]; then
        api_ok=1
        printf 'PASS (no run-owned API resources had been created)\n' \
          >"$EVIDENCE/teardown/api-resource-cleanup-status.txt"
      else
        printf 'FAIL (API teardown was not verified)\n' >"$EVIDENCE/teardown/api-resource-cleanup-status.txt"
        cleanup_problem=1
        cleanup_classification=CLEANUP_DEFECT
        cleanup_failure="run-owned API resource teardown was not verified"
      fi
    else
      printf 'NOT_APPLICABLE (API campaign had not started)\n' \
        >"$EVIDENCE/teardown/api-resource-cleanup-status.txt"
    fi
    # Always clean run-created compute guests after evidence has been captured.
    # A domain is eligible only when its inventory UUID, name, XML, disk and
    # seed paths all exactly match this run's ownership record.
    if [[ -s "$EVIDENCE/environment/inventory.tsv" ]]; then
      guest_ok=1
      : >"$EVIDENCE/teardown/owned-domain-cleanup.txt"
      for domain in "${FRESH_DOMAINS[@]}"; do
        if [[ ! "$domain" =~ ^${PREFIX}-compute-[abc]$ ]]; then continue; fi
        expected_uuid="$(awk -F '\t' -v n="$domain" '$2==n{print $5}' "$EVIDENCE/environment/inventory.tsv")"
        role="${domain##*-}"
        disk="$IMAGE_STORE/$PREFIX-compute-$role.qcow2"
        seed="$IMAGE_STORE/$PREFIX-compute-$role-seed.iso"
        actual_uuid="$(virsh -c qemu:///system domuuid "$domain" 2>/dev/null || true)"
        if [[ -z "$actual_uuid" ]]; then
          if [[ -n "$expected_uuid" && ! -L "$disk" && ! -L "$seed" ]]; then
            [[ ! -f "$disk" ]] || rm -- "$disk"
            [[ ! -f "$seed" ]] || rm -- "$seed"
            printf 'ABSENT_DOMAIN_REMOVED_PARTIAL_STORAGE %s uuid=%s disk=%s seed=%s\n' \
              "$domain" "$expected_uuid" "$disk" "$seed" \
              >>"$EVIDENCE/teardown/owned-domain-cleanup.txt"
          else
            printf 'CLEANUP_FAILED absent domain has unowned storage identity %s uuid=%s\n' \
              "$domain" "$expected_uuid" >>"$EVIDENCE/teardown/owned-domain-cleanup.txt"
            guest_ok=0
          fi
          continue
        fi
        xml="$(virsh -c qemu:///system dumpxml "$domain" 2>/dev/null || true)"
        if [[ -z "$expected_uuid" || "$actual_uuid" != "$expected_uuid" ]] \
          || ! python3 "$ROOT_DIR/tests/fabric-v3-owned-domain-storage.py" \
            "$domain" "$expected_uuid" "$disk" "$seed" <<<"$xml" \
          || [[ -L "$disk" || -L "$seed" || ! -f "$disk" || ! -f "$seed" ]]; then
          printf 'CLEANUP_FAILED ownership check failed for %s\n' "$domain" >>"$EVIDENCE/teardown/owned-domain-cleanup.txt"
          guest_ok=0
          continue
        fi
        if virsh -c qemu:///system destroy "$domain" >/dev/null 2>&1; then :; fi
        if virsh -c qemu:///system undefine "$domain" >/dev/null 2>&1; then
          if rm -- "$disk" "$seed"; then
            printf 'REMOVED %s uuid=%s disk=%s seed=%s\n' "$domain" "$expected_uuid" "$disk" "$seed" \
              >>"$EVIDENCE/teardown/owned-domain-cleanup.txt"
          else
            printf 'CLEANUP_FAILED storage %s uuid=%s disk=%s seed=%s\n' \
              "$domain" "$expected_uuid" "$disk" "$seed" \
              >>"$EVIDENCE/teardown/owned-domain-cleanup.txt"
            guest_ok=0
          fi
        else
          printf 'CLEANUP_FAILED %s uuid=%s\n' "$domain" "$expected_uuid" \
            >>"$EVIDENCE/teardown/owned-domain-cleanup.txt"
          guest_ok=0
        fi
      done
    fi
    if [[ -n "$O3KD_PID" ]]; then
      controller_ok=1
      if ! stop_controller; then
        controller_ok=0
        kill -KILL "$O3KD_PID" 2>/dev/null || true
        wait "$O3KD_PID" 2>/dev/null || true
        printf 'controller required forced termination during evidence cleanup\n' \
          >>"$EVIDENCE/teardown/controller-stop-failure.txt"
        O3KD_PID=""
      fi
    fi
    if (( ${#FRESH_DOMAINS[@]} > 0 )); then
      if refresh_image_store_pool "$EVIDENCE/teardown/image-store-pool-refresh.json" \
          >"$EVIDENCE/teardown/image-store-pool-refresh.stdout" \
          2>"$EVIDENCE/teardown/image-store-pool-refresh.stderr"; then
        pool_refresh_ok=1
      else
        pool_refresh_ok=0
        cleanup_problem=1
        cleanup_classification=CLEANUP_DEFECT
        cleanup_failure="the exact libvirt image-store pool inventory could not be refreshed after owned storage cleanup"
      fi
    fi
    if [[ -s "$EVIDENCE/environment/host-inventory-before.json" ]]; then
      if python3 "$HOST_PREFLIGHT" snapshot --network "$NETWORK" \
          --output "$EVIDENCE/teardown/host-inventory-after-cleanup.json" \
          >"$EVIDENCE/teardown/host-inventory-after-cleanup.stdout" \
          2>"$EVIDENCE/teardown/host-inventory-after-cleanup.stderr"; then
        host_snapshot_ok=1
        owned_ip_args=()
        for address in "${MGMT_IP[a]:-}" "${MGMT_IP[b]:-}" "${MGMT_IP[c]:-}"; do
          [[ -z "$address" ]] || owned_ip_args+=(--owned-ip "$address")
        done
        if python3 "$HOST_PREFLIGHT" compare \
          --before "$EVIDENCE/environment/host-inventory-before.json" \
          --after "$EVIDENCE/teardown/host-inventory-after-cleanup.json" \
          "${owned_ip_args[@]}" \
          >"$EVIDENCE/teardown/foreign-state-after-cleanup.json" \
          2>"$EVIDENCE/teardown/foreign-state-after-cleanup.stderr"; then
          foreign_ok=1
        else
          foreign_ok=0
          cleanup_problem=1
          cleanup_classification=OWNERSHIP_DEFECT
          cleanup_failure="foreign host inventory changed or could not be compared after cleanup"
        fi
      else
        host_snapshot_ok=0
        cleanup_problem=1
        cleanup_classification=CLEANUP_DEFECT
        cleanup_failure="post-cleanup host inventory could not be captured"
      fi
    fi
    if (( guest_ok == 1 )); then
      if [[ -s "$EVIDENCE/teardown/owned-domain-cleanup.txt" ]] \
        && grep -q '^CLEANUP_FAILED' "$EVIDENCE/teardown/owned-domain-cleanup.txt"; then guest_ok=0; fi
      for domain in "${FRESH_DOMAINS[@]}"; do
        [[ ! "$domain" =~ ^${PREFIX}-compute-[abc]$ ]] && continue
        if virsh -c qemu:///system dominfo "$domain" >/dev/null 2>&1; then guest_ok=0; fi
        role="${domain##*-}"
        if [[ -e "$IMAGE_STORE/$PREFIX-compute-$role.qcow2" || -L "$IMAGE_STORE/$PREFIX-compute-$role.qcow2" \
          || -e "$IMAGE_STORE/$PREFIX-compute-$role-seed.iso" || -L "$IMAGE_STORE/$PREFIX-compute-$role-seed.iso" ]]; then
          guest_ok=0
        fi
      done
    fi
    if (( guest_ok == 0 )); then
      cleanup_problem=1
      [[ -n "$cleanup_classification" ]] || cleanup_classification=CLEANUP_DEFECT
      [[ -n "$cleanup_failure" ]] || cleanup_failure="run-owned guest or storage cleanup did not complete"
    fi
    if (( controller_ok == 0 )); then
      cleanup_problem=1
      [[ -n "$cleanup_classification" ]] || cleanup_classification=CLEANUP_DEFECT
      [[ -n "$cleanup_failure" ]] || cleanup_failure="controller required forced termination during cleanup"
    fi
    if (( pool_refresh_ok == 0 )); then
      cleanup_problem=1
      [[ -n "$cleanup_classification" ]] || cleanup_classification=CLEANUP_DEFECT
      [[ -n "$cleanup_failure" ]] || cleanup_failure="the exact libvirt image-store pool inventory could not be refreshed after owned storage cleanup"
    fi
    if (( host_snapshot_ok == 0 )) && [[ -s "$EVIDENCE/environment/host-inventory-before.json" ]]; then
      cleanup_problem=1
      [[ -n "$cleanup_classification" ]] || cleanup_classification=CLEANUP_DEFECT
      [[ -n "$cleanup_failure" ]] || cleanup_failure="post-cleanup host inventory is unavailable"
    fi
    python3 - "$EVIDENCE/teardown/cleanup-status.json" "$api_ok" "$guest_ok" \
      "$controller_ok" "$host_snapshot_ok" "$foreign_ok" "$capture_ok" "$pool_refresh_ok" \
      "$ACCEPTANCE_GATE" <<'PYSTATUS'
import json,sys
path,api,guests,controller,host,foreign,capture,pool_refresh,acceptance_gate=sys.argv[1:]
def status(value): return 'PASS' if value=='1' else ('FAIL' if value=='0' else 'NOT_APPLICABLE')
value={
  'acceptance_gate': acceptance_gate,
  'api_resources': status(api),
  'owned_guests_and_storage': status(guests),
  'controller_process': status(controller),
  'post_cleanup_host_inventory': status(host),
  'foreign_state_unchanged': status(foreign),
  'run_owned_dhcp_capture': status(capture),
  'image_store_pool_refresh': status(pool_refresh),
}
json.dump(value,open(path,'w'),sort_keys=True,indent=2); open(path,'a').write('\n')
PYSTATUS
    # Remove exact run-owned credentials and staged agent material after all
    # observers have finished; the archive contains fingerprints only.
    rm -f -- "$SSH_KEY" "$PROBE_KEY" "$EVIDENCE/management/known_hosts"
    rm -rf -- "$TLS_DIR/certs" "$STAGE"
    python3 - "$EVIDENCE/manifest.json" "$EVIDENCE/result.json" "$EVIDENCE/ended_at_utc.txt" <<'PYFINAL'
import json,pathlib,sys
manifest,result,ended=sys.argv[1:]
m=json.loads(pathlib.Path(manifest).read_text()) if pathlib.Path(manifest).exists() else {}
try: r=json.loads(pathlib.Path(result).read_text())
except (OSError,json.JSONDecodeError): r={}
m.update(result=r.get('result','FAIL'),ended_at_utc=pathlib.Path(ended).read_text().strip())
for key in ('acceptance_gate','first_failure','classification','harness_sha','harness_tree','product_sha','product_tree'):
    if key in r: m[key]=r[key]
pathlib.Path(manifest).write_text(json.dumps(m,sort_keys=True,indent=2)+'\n')
PYFINAL
    python3 - "$EVIDENCE/result.json" "$EVIDENCE/manifest.json" "$EVIDENCE/teardown/cleanup-status.json" \
      "$RUN_ID" "$PRODUCT_SHA" "$PRODUCT_TREE" "$CAMPAIGN_FAILURE" "$CLASSIFICATION" \
      "$cleanup_problem" "$cleanup_failure" "$cleanup_classification" "$ACCEPTANCE_GATE" <<'PYRESULT'
import json,pathlib,sys
result_path,manifest_path,status_path,run,product,tree,original_failure,original_classification,cleanup_problem,cleanup_failure,cleanup_classification,acceptance_gate=sys.argv[1:]
path=pathlib.Path(result_path)
try: result=json.loads(path.read_text())
except (OSError,json.JSONDecodeError): result={}
try: cleanup=json.loads(pathlib.Path(status_path).read_text())
except (OSError,json.JSONDecodeError): cleanup={}
result.update({'acceptance_gate':acceptance_gate,'run_id':run,'product_sha':product,'product_tree':tree,'cleanup':cleanup})
if original_failure:
    result['result']='FAIL'; result['first_failure']=original_failure
    result['classification']=original_classification or 'HARNESS_GAP'
elif cleanup_problem=='1':
    result['result']='FAIL'; result['first_failure']=cleanup_failure
    result['classification']=cleanup_classification or 'CLEANUP_DEFECT'
elif result.get('result')=='PASS' and any(value not in ('PASS','NOT_APPLICABLE') for value in cleanup.values()):
    result['result']='FAIL'; result['first_failure']='cleanup evidence did not satisfy all required predicates'
    result['classification']='CLEANUP_DEFECT'
elif result.get('result')!='PASS':
    result.setdefault('result','FAIL')
    result.setdefault('first_failure','campaign exited without a passing terminal result')
    result.setdefault('classification','HARNESS_GAP')
path.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
manifest_path=pathlib.Path(manifest_path)
manifest=json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
manifest.update({'acceptance_gate':acceptance_gate,'result':result['result'],'cleanup':cleanup})
if result.get('first_failure'): manifest['first_failure']=result['first_failure']
if result.get('classification'): manifest['classification']=result['classification']
manifest_path.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
PYRESULT
    if [[ "$CAMPAIGN_MODE" == departure-micro ]]; then
      result_status="$(python3 - "$EVIDENCE/result.json" <<'PYSTATUS'
import json,pathlib,sys
try: print(json.loads(pathlib.Path(sys.argv[1]).read_text()).get('result','FAIL'))
except (OSError,json.JSONDecodeError): print('FAIL')
PYSTATUS
)"
      if [[ "$result_status" == PASS ]]; then
        echo "FABRIC V3 DURABLE HOST RETIREMENT MICROGATE: PASS"
      else
        echo "FABRIC V3 DURABLE HOST RETIREMENT MICROGATE: FAIL"
      fi
    fi
  tar --exclude="$(basename "$EVIDENCE")/management/campaign_ed25519" \
      --exclude="$(basename "$EVIDENCE")/management/probe_ed25519" \
      --exclude="$(basename "$EVIDENCE")/management/tls/certs" \
      --exclude="$(basename "$EVIDENCE")/environment/stage" \
      --exclude="$(basename "$EVIDENCE")/environment/product-source" \
      --exclude="$(basename "$EVIDENCE")/controller-data" \
      -C "$EVIDENCE_ROOT" -czf "$EVIDENCE.tar.gz" "$(basename "$EVIDENCE")"
    sha256sum "$EVIDENCE.tar.gz" >"$EVIDENCE.tar.gz.sha256"
    echo "EVIDENCE_ARCHIVE=$EVIDENCE.tar.gz"
    cat "$EVIDENCE.tar.gz.sha256"
  fi
  if [[ -d "$PRODUCT_SOURCE_DIR" && -e "$PRODUCT_SOURCE_DIR/.git" ]]; then
    git -C "$ROOT_DIR" worktree remove --force "$PRODUCT_SOURCE_DIR" >/dev/null 2>&1 || true
  fi
  if (( rc == 0 )) && [[ "${CAMPAIGN_TEARDOWN_PASS:-0}" != 1 ]]; then
    exit 1
  fi
  if (( rc == 0 )) && (( cleanup_problem )); then exit 1; fi
  exit "$rc"
}
trap cleanup_on_success EXIT

if ! command -v cargo >/dev/null 2>&1; then
  cargo_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
  if [[ -n "$cargo_home" && -x "$cargo_home/.cargo/bin/cargo" ]]; then
    PATH="$cargo_home/.cargo/bin:$PATH"
    export PATH
  fi
fi
for tool in cargo curl openssl python3 virsh virt-install qemu-img guestfish virt-ls lsinitramfs cpio gzip genisoimage ssh ssh-keygen ssh-keyscan scp ip wg tcpdump sha256sum tar timeout bridge hostnamectl; do need "$tool"; done
[[ $EUID -eq 0 ]] || fail "campaign must run as root to provision nested libvirt guests" "ENVIRONMENT_GAP"
[[ -c /dev/kvm ]] || fail "/dev/kvm unavailable" "ENVIRONMENT_GAP"
[[ -r "$BASE_IMAGE" ]] || fail "base image unreadable: $BASE_IMAGE" "ENVIRONMENT_GAP"
[[ "$(git -C "$ROOT_DIR" rev-parse "$PRODUCT_SHA^{tree}")" == "$PRODUCT_TREE" ]] || fail "frozen product source tree mismatch" "HARNESS_GAP"
git -C "$ROOT_DIR" fetch --no-tags origin main \
  >"$EVIDENCE/environment/protected-main-fetch.stdout" \
  2>"$EVIDENCE/environment/protected-main-fetch.stderr" \
  || fail "could not refresh protected main for candidate ancestry proof" "HARNESS_GAP"
protected_main_tip="$(git -C "$ROOT_DIR" rev-parse FETCH_HEAD)"
if [[ "$protected_main_tip" != "$PRODUCT_PROTECTED_MAIN_BASE" ]]; then
  git -C "$ROOT_DIR" merge-base --is-ancestor "$PRODUCT_SHA" "$protected_main_tip" \
    || fail "protected main advanced outside the frozen product candidate lineage" "HARNESS_GAP"
  [[ "$(git -C "$ROOT_DIR" rev-parse "$protected_main_tip^{tree}")" == "$PRODUCT_TREE" ]] \
    || fail "protected main advanced beyond the frozen product candidate tree" "HARNESS_GAP"
fi
product_remote_sha="$(git -C "$ROOT_DIR" ls-remote origin "$PRODUCT_REMOTE_REF" | awk 'NR==1 {print $1}')"
[[ "$product_remote_sha" == "$PRODUCT_SHA" ]] \
  || fail "frozen product successor ref is not remotely visible at the exact candidate SHA" "HARNESS_GAP"
git -C "$ROOT_DIR" fetch --no-tags origin "$HARNESS_REMOTE_REF" \
  >"$EVIDENCE/environment/harness-ref-fetch.stdout" \
  2>"$EVIDENCE/environment/harness-ref-fetch.stderr" \
  || fail "frozen harness successor ref is not remotely visible" "HARNESS_GAP"
[[ "$(git -C "$ROOT_DIR" rev-parse FETCH_HEAD)" == "$(git -C "$ROOT_DIR" rev-parse HEAD)" ]] \
  || fail "remote harness ref does not match the running harness commit" "HARNESS_GAP"
[[ -z "$(git -C "$ROOT_DIR" status --porcelain=v1)" ]] \
  || fail "harness source tree has uncommitted changes" "HARNESS_GAP"
git -C "$ROOT_DIR" fetch --no-tags origin "$PRODUCT_REMOTE_REF" \
  >"$EVIDENCE/environment/product-ref-fetch.stdout" \
  2>"$EVIDENCE/environment/product-ref-fetch.stderr" \
  || fail "frozen product successor ref is not remotely visible" "HARNESS_GAP"
[[ "$(git -C "$ROOT_DIR" rev-parse FETCH_HEAD)" == "$PRODUCT_SHA" ]] \
  || fail "remote product successor ref does not match the frozen candidate SHA" "HARNESS_GAP"
product_parents="$(git -C "$ROOT_DIR" show -s --format=%P "$PRODUCT_SHA")"
[[ "$product_parents" == "$PRODUCT_PROTECTED_MAIN_BASE" ]] \
  || fail "frozen product successor is not a direct child of the protected-main baseline" "HARNESS_GAP"
url_port "$API_PORT" || fail "API port is occupied: $API_PORT" "ENVIRONMENT_GAP"
url_port "$CONTROL_PORT" || fail "compute control port is occupied: $CONTROL_PORT" "ENVIRONMENT_GAP"
python3 "$HOST_PREFLIGHT" snapshot --network "$NETWORK" \
  --output "$EVIDENCE/environment/host-inventory-before.json" \
  >"$EVIDENCE/environment/host-inventory-before.stdout" \
  2>"$EVIDENCE/environment/host-inventory-before.stderr" \
  || fail "could not capture the pre-run libvirt/network inventory" "ENVIRONMENT_GAP"
python3 "$HOST_PREFLIGHT" select \
  --snapshot "$EVIDENCE/environment/host-inventory-before.json" \
  --output "$EVIDENCE/environment/management-address-selection.json" \
  >"$EVIDENCE/environment/management-address-selection.stdout" \
  2>"$EVIDENCE/environment/management-address-selection.stderr" \
  || fail "fewer than three safe management addresses could be proved" "ENVIRONMENT_GAP"
mapfile -t selected_addresses < <(python3 - "$EVIDENCE/environment/management-address-selection.json" <<'PYADDR'
import json,sys
for address in json.load(open(sys.argv[1]))['selected']:
    print(address)
PYADDR
)
((${#selected_addresses[@]} == 3)) || fail "management preflight did not select exactly three addresses" "ENVIRONMENT_GAP"
gateway="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["gateway"])' "$EVIDENCE/environment/management-address-selection.json")"
python3 - "$EVIDENCE/environment/host-inventory-before.json" <<'PYDOMAINS' >"$EVIDENCE/environment/libvirt-domains-before.txt"
import json,sys
for domain in json.load(open(sys.argv[1]))['domains']:
    print(domain['name'])
PYDOMAINS
sort -o "$EVIDENCE/environment/libvirt-domains-before.txt" "$EVIDENCE/environment/libvirt-domains-before.txt"
git -C "$ROOT_DIR" rev-parse HEAD >"$EVIDENCE/environment/harness_sha.txt"
git -C "$ROOT_DIR" rev-parse 'HEAD^{tree}' >"$EVIDENCE/environment/harness_tree.txt"
git -C "$ROOT_DIR" rev-parse "$PRODUCT_SHA" >"$EVIDENCE/environment/product_sha.txt"
git -C "$ROOT_DIR" rev-parse "$PRODUCT_SHA^{tree}" >"$EVIDENCE/environment/product_tree.txt"
hostnamectl >"$EVIDENCE/environment/physical-host.txt" 2>&1 || hostname >"$EVIDENCE/environment/physical-host.txt"
date -u +%FT%TZ >"$EVIDENCE/started_at_utc.txt"
python3 - "$EVIDENCE/manifest.json" "$RUN_ID" "$PRODUCT_SHA" "$PRODUCT_TREE" "$(git -C "$ROOT_DIR" rev-parse HEAD)" "$(git -C "$ROOT_DIR" rev-parse 'HEAD^{tree}')" "$EVIDENCE/started_at_utc.txt" "$EVIDENCE/environment/physical-host.txt" "$FABRIC_DOMAIN_ID" "$protected_main_tip" "$PRODUCT_REMOTE_REF" "$HARNESS_REMOTE_REF" <<'PYMANIFEST'
import json,pathlib,sys
path,run,product,product_tree,harness,harness_tree,started,physical,fabric_domain_id,protected_main,product_ref,harness_ref=sys.argv[1:]
doc={"result":"IN_PROGRESS","run_id":run,"product_sha":product,"product_tree":product_tree,
     "harness_sha":harness,"harness_tree":harness_tree,
     "protected_main_at_run":protected_main,
     "product_remote_visible":True,"product_remote_ref":product_ref,
     "harness_remote_visible":True,"harness_remote_ref":harness_ref,
     "product_lineage":{"protected_main_base":"adaf6168b124111ee62bf53f6eaf6e0f6cab155e",
                         "successor_parent":"adaf6168b124111ee62bf53f6eaf6e0f6cab155e",
                         "parent_verified":True},
     "fabric_domain_id":fabric_domain_id,
     "started_at_utc":pathlib.Path(started).read_text().strip(),
     "physical_host_identity":pathlib.Path(physical).read_text(errors='replace').strip()}
pathlib.Path(path).write_text(json.dumps(doc,sort_keys=True,indent=2)+'\n')
PYMANIFEST
sha256sum "$BASE_IMAGE" >"$EVIDENCE/environment/base-image.sha256"
[[ "$(awk '{print $1}' "$EVIDENCE/environment/base-image.sha256")" == "$BASE_IMAGE_SHA" ]] || fail "base image checksum mismatch" "ENVIRONMENT_GAP"
PROBE_BASE_IMAGE="$EVIDENCE/environment/cirros-0.6.3-x86_64-disk.img"
if [[ -n "${O3K_FABRIC_V3_PROBE_BASE_IMAGE:-}" ]]; then
  [[ -r "$O3K_FABRIC_V3_PROBE_BASE_IMAGE" ]] || fail "probe base image unreadable" "ENVIRONMENT_GAP"
  cp --reflink=auto -- "$O3K_FABRIC_V3_PROBE_BASE_IMAGE" "$PROBE_BASE_IMAGE"
else
  curl --fail --silent --show-error --location --max-time 120 \
    "$PROBE_BASE_URL" -o "$PROBE_BASE_IMAGE" \
    || fail "pinned CirrOS probe base download failed" "ENVIRONMENT_GAP"
fi
printf '%s  %s\n' "$PROBE_BASE_SHA" "$PROBE_BASE_IMAGE" | sha256sum --check --status \
  || fail "pinned CirrOS probe base checksum mismatch" "ENVIRONMENT_GAP"
printf 'source=%s\nsha256=%s\n' "$PROBE_BASE_URL" "$PROBE_BASE_SHA" \
  >"$EVIDENCE/environment/probe-image-source.txt"

echo "Building frozen binaries from $PRODUCT_SHA"
git -C "$ROOT_DIR" worktree add --detach "$PRODUCT_SOURCE_DIR" "$PRODUCT_SHA" \
  >"$EVIDENCE/environment/product-worktree.log" 2>&1 \
  || fail "could not materialize the exact frozen product source" "HARNESS_GAP"
[[ "$(git -C "$PRODUCT_SOURCE_DIR" rev-parse HEAD)" == "$PRODUCT_SHA" \
  && "$(git -C "$PRODUCT_SOURCE_DIR" rev-parse 'HEAD^{tree}')" == "$PRODUCT_TREE" ]] \
  || fail "detached product worktree identity differs from the manifest" "HARNESS_GAP"
git -C "$PRODUCT_SOURCE_DIR" status --porcelain -- bins crates Cargo.toml Cargo.lock \
  >"$EVIDENCE/environment/product-source-status.txt"
[[ ! -s "$EVIDENCE/environment/product-source-status.txt" ]] \
  || fail "frozen product source worktree is dirty" "PRODUCT_DEFECT"
CARGO_TARGET_DIR="$PRODUCT_SOURCE_DIR/target" cargo build --release --all-features \
  --manifest-path "$PRODUCT_SOURCE_DIR/Cargo.toml" \
  -p o3kd -p o3k-compute-bin -p o3k-network-bin \
  >"$EVIDENCE/environment/build.log" 2>&1 \
  || fail "frozen product binaries failed to build" "HARNESS_GAP"
for binary in o3kd o3k-compute-bin o3k-network-bin; do
  [[ -x "$PRODUCT_SOURCE_DIR/target/release/$binary" ]] || fail "missing frozen binary $binary" "HARNESS_GAP"
  sha256sum "$PRODUCT_SOURCE_DIR/target/release/$binary" >>"$EVIDENCE/environment/runtime-assets.sha256"
done

echo "Running accepted QEMU storage preflight"
O3K_QEMU_PREFLIGHT_RUN_ID="$RUN_ID" bash "$ROOT_DIR/tests/fabric-v3-qemu-storage-preflight.sh" >"$EVIDENCE/environment/qemu-storage-preflight.txt" 2>&1 || fail "QEMU storage preflight failed" "ENVIRONMENT_GAP"

virsh -c qemu:///system net-info "$NETWORK" >"$EVIDENCE/environment/libvirt-network.txt" 2>&1 || fail "libvirt management network unavailable" "ENVIRONMENT_GAP"
net_active="$(awk -F': *' '/^Active:/{print $2}' "$EVIDENCE/environment/libvirt-network.txt")"
[[ "$net_active" == yes ]] || fail "libvirt management network is inactive" "ENVIRONMENT_GAP"
python3 "$HOST_PREFLIGHT" snapshot --network "$NETWORK" \
  --output "$EVIDENCE/environment/host-inventory-after-preflight.json" \
  >"$EVIDENCE/environment/host-inventory-after-preflight.stdout" \
  2>"$EVIDENCE/environment/host-inventory-after-preflight.stderr" \
  || fail "could not capture host inventory after QEMU preflight" "ENVIRONMENT_GAP"
if ! python3 "$HOST_PREFLIGHT" compare \
    --before "$EVIDENCE/environment/host-inventory-before.json" \
    --after "$EVIDENCE/environment/host-inventory-after-preflight.json" \
    >"$EVIDENCE/environment/qemu-preflight-inventory-comparison.json"; then
  fail "QEMU preflight did not restore the exact pre-run host inventory" "CLEANUP_DEFECT"
fi
python3 "$HOST_PREFLIGHT" select \
  --snapshot "$EVIDENCE/environment/host-inventory-after-preflight.json" \
  --output "$EVIDENCE/environment/management-address-selection-recheck.json" \
  >"$EVIDENCE/environment/management-address-selection-recheck.stdout" \
  2>"$EVIDENCE/environment/management-address-selection-recheck.stderr" \
  || fail "management address selection is no longer collision-safe" "ENVIRONMENT_GAP"
python3 - "$EVIDENCE/environment/management-address-selection.json" \
  "$EVIDENCE/environment/management-address-selection-recheck.json" <<'PY' \
  || fail "management address selection changed during preflight" "ENVIRONMENT_GAP"
import json,sys
before,after=(json.load(open(path)) for path in sys.argv[1:])
assert before['network']==after['network']
assert before['gateway']==after['gateway']
assert before['selected']==after['selected'], (before['selected'],after['selected'])
PY
BRIDGE="$(virsh -c qemu:///system net-dumpxml "$NETWORK" | sed -n "s/.*bridge name='\([^']*\)'.*/\1/p" | head -1)"
[[ -n "$BRIDGE" ]] || fail "cannot identify management bridge" "ENVIRONMENT_GAP"
HOST_MGMT_IP="$(ip -4 -o addr show dev "$BRIDGE" | awk '{split($4,a,"/"); print a[1]; exit}')"
[[ -n "$HOST_MGMT_IP" ]] || fail "management bridge lacks IPv4 address" "ENVIRONMENT_GAP"
BASE="http://$HOST_MGMT_IP:$API_PORT"

umask 077
ssh-keygen -q -t ed25519 -N '' -C "$PREFIX" -f "$SSH_KEY"
ssh-keygen -lf "$SSH_KEY.pub" >"$EVIDENCE/management/ssh-key-fingerprint.txt"
cp "$SSH_KEY.pub" "$EVIDENCE/management/ssh-authorized-key.pub"
chmod 0600 "$SSH_KEY"; chmod 0644 "$SSH_KEY.pub"
ssh-keygen -q -t ed25519 -N '' -C "$PREFIX-probe" -f "$PROBE_KEY"
ssh-keygen -lf "$PROBE_KEY.pub" >"$EVIDENCE/management/probe-key-fingerprint.txt"
chmod 0600 "$PROBE_KEY"; chmod 0644 "$PROBE_KEY.pub"
: >"$KNOWN_HOSTS"; chmod 0600 "$KNOWN_HOSTS"

for index in 0 1 2; do
  host="${HOSTS[$index]}"
  address="${selected_addresses[$index]}"
  octet="${address##*.}"
  MGMT_OCTET[$host]="$octet"
  MGMT_IP[$host]="$address"
  MGMT_MAC[$host]="52:54:00:fa:$(printf '%02x' "$((octet / 256))"):$(printf '%02x' "$((octet % 256))")"
done
printf 'compute-a=%s\ncompute-b=%s\ncompute-c=%s\n' "${MGMT_IP[a]}" "${MGMT_IP[b]}" "${MGMT_IP[c]}" >"$EVIDENCE/environment/management-addresses.txt"
printf 'compute-a=%s\ncompute-b=%s\ncompute-c=%s\n' "${MGMT_MAC[a]}" "${MGMT_MAC[b]}" "${MGMT_MAC[c]}" >"$EVIDENCE/environment/management-macs.txt"

for host in a b c; do
  octet="${MGMT_OCTET[$host]}"; domain="$PREFIX-compute-$host"; address="${MGMT_IP[$host]}"
  ram_mib=4096; vcpus=2
  # The public create API has no per-host placement selector. Give host A one
  # extra schedulable vCPU so the supported scheduler's deterministic free-
  # inventory ranking selects A first; after A's allocation, equal B/C
  # capacity and provider-ID order select B, then C. The live capability
  # preflight below verifies this assumption before tenant creation.
  [[ "$host" != a ]] || vcpus=3
  if virsh -c qemu:///system dominfo "$domain" >/dev/null 2>&1; then fail "fresh domain name collision: $domain" "ENVIRONMENT_GAP"; fi
  disk="$IMAGE_STORE/$PREFIX-compute-$host.qcow2"; seed="$IMAGE_STORE/$PREFIX-compute-$host-seed.iso"; ws="$EVIDENCE/environment/seed-$host"
  [[ ! -e "$disk" && ! -e "$seed" ]] || fail "fresh guest disk/seed collision for $host" "ENVIRONMENT_GAP"
  domain_uuid="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  FRESH_DOMAINS+=("$domain")
  mac="${MGMT_MAC[$host]}"
  printf '%s\t%s\t%s\t%s\t%s\n' "compute-$host" "$domain" "$address" "$mac" "$domain_uuid" \
    >>"$EVIDENCE/environment/inventory.tsv"
  mkdir -m 0700 "$ws"
  cat >"$ws/user-data" <<EOF
#cloud-config
hostname: compute-$host
users:
  - name: $SSH_USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    groups: [sudo, kvm]
    ssh_authorized_keys:
      - $(cat "$SSH_KEY.pub")
disable_root: true
ssh_pwauth: false
package_update: true
packages:
  - qemu-kvm
  - libvirt-daemon-system
  - libvirt-clients
  - qemu-utils
  - wireguard-tools
  - dnsmasq
  - tcpdump
  - nftables
  - curl
runcmd:
  - [systemctl, enable, --now, libvirtd]
  - [usermod, -aG, "libvirt,kvm", o3k]
EOF
  cat >"$ws/network-config" <<EOF
version: 2
ethernets:
  mgmt0:
    match: {macaddress: "$mac"}
    set-name: mgmt0
    addresses: ["$address/24"]
    routes: [{to: default, via: "$gateway"}]
    nameservers: {addresses: ["$gateway", "1.1.1.1"]}
EOF
  printf 'instance-id: %s\nlocal-hostname: compute-%s\n' "$domain" "$host" >"$ws/meta-data"
  genisoimage -quiet -output "$seed" -volid cidata -joliet -rock "$ws/user-data" "$ws/meta-data" "$ws/network-config" || fail "seed ISO creation failed for $host" "HARNESS_GAP"
  qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$disk" 16G || fail "overlay creation failed for $host" "ENVIRONMENT_GAP"
  chgrp kvm "$disk" "$seed"; chmod 0640 "$disk" "$seed"
  virt-install --connect qemu:///system --name "$domain" --uuid "$domain_uuid" --import --ram "$ram_mib" --vcpus "$vcpus" --cpu host-passthrough --disk "path=$disk,format=qcow2,bus=virtio" --disk "path=$seed,device=cdrom" --network "network=$NETWORK,model=virtio,mac=$mac" --os-variant ubuntu24.04 --graphics none --noautoconsole --quiet || fail "libvirt failed to create fresh compute guest $host" "ENVIRONMENT_GAP"
  [[ "$(virsh -c qemu:///system domuuid "$domain")" == "$domain_uuid" ]] \
    || fail "created compute guest UUID did not match the registered ownership record" "OWNERSHIP_DEFECT"
done

for host in a b c; do
  address="${MGMT_IP[$host]}"; domain="$PREFIX-compute-$host"
  ready=0
  for _ in $(seq 1 240); do
    if timeout 4 bash -c "</dev/tcp/$address/$SSH_PORT" >/dev/null 2>&1; then
      ssh-keyscan -T 3 -H "$address" >>"$KNOWN_HOSTS" 2>/dev/null || true
      if ssh_vm "$address" true >/dev/null 2>&1; then ready=1; break; fi
    fi
    virsh -c qemu:///system domstate "$domain" | grep -qi running || fail "guest $host is not running" "ENVIRONMENT_GAP"
    sleep 5
  done
  (( ready == 1 )) || fail "authenticated SSH readiness timed out for compute-$host" "ENVIRONMENT_GAP"
  packages_ready=0
  for _ in $(seq 1 240); do
    # Ubuntu may run libvirtd on demand through systemd sockets and let the
    # daemon exit while idle. Exercise the actual qemu:///system API instead
    # of requiring the monolithic service process to remain active.
    if ssh_vm "$address" 'command -v virsh >/dev/null && command -v wg >/dev/null && command -v bridge >/dev/null && command -v nft >/dev/null && command -v tcpdump >/dev/null && test -c /dev/kvm && sudo virsh -c qemu:///system list --all >/dev/null 2>&1' >/dev/null 2>&1; then
      packages_ready=1
      break
    fi
    sleep 5
  done
  (( packages_ready == 1 )) || fail "guest $host did not finish installing the required nested compute tools" "ENVIRONMENT_GAP"
  # The remote $PRETTY_NAME expansion is required for guest OS identification.
  # shellcheck disable=SC2016
  ssh_vm "$address" 'printf "boot_id="; cat /proc/sys/kernel/random/boot_id; printf "kernel="; uname -r; printf "os="; . /etc/os-release; echo "$PRETTY_NAME"; ip -j link; ip -j route; bridge -j link; bridge -j fdb; (wg show || true); (sudo nft list ruleset || true); (sudo find /var/lib/o3k-fabric-v3 -maxdepth 5 -type f -print 2>/dev/null || true); sudo virsh list --all --name' >"$EVIDENCE/environment/baseline-compute-$host.txt" || fail "baseline collection failed for compute-$host" "ENVIRONMENT_GAP"
  echo "compute-$host management PASS $address domain=$domain"
done
ssh-keygen -lf "$KNOWN_HOSTS" >"$EVIDENCE/management/known-hosts-fingerprints.txt"

install -d -m 0700 "$TLS_DIR" "$STAGE"
extra_ids=(--agent-id compute-agent-a --extra-agent-id compute-agent-b --extra-agent-id compute-agent-c --extra-agent-id network-agent-a --extra-agent-id network-agent-b --extra-agent-id network-agent-c --extra-agent-id controller-network)
bash "$ROOT_DIR/packaging/bootstrap-certs.sh" --output-dir "$TLS_DIR/certs" --server-name o3k-control-plane "${extra_ids[@]}" >"$EVIDENCE/management/cert-generation.txt" 2>&1 || fail "campaign TLS identity generation failed" "HARNESS_GAP"
cp "$PRODUCT_SOURCE_DIR/target/release/o3k-network-bin" "$STAGE/o3k-network"
cp "$PRODUCT_SOURCE_DIR/target/release/o3k-compute-bin" "$STAGE/o3k-compute"
cp "$ROOT_DIR/tests/fabric-v3-install-agent-host.sh" "$STAGE/install-agent-host.sh"
cp "$TLS_DIR/certs/ca.pem" "$STAGE/ca.pem"
for host in a b c; do
  cp "$TLS_DIR/certs/server.pem" "$STAGE/network-agent-$host.pem"
  cp "$TLS_DIR/certs/server-key.pem" "$STAGE/network-agent-$host-key.pem"
  if [[ "$host" == a ]]; then
    compute_cert_dir="$TLS_DIR/certs"
  else
    compute_cert_dir="$TLS_DIR/certs/agents/compute-agent-$host"
  fi
  cp "$compute_cert_dir/agent.pem" "$STAGE/compute-agent-$host.pem"
  cp "$compute_cert_dir/agent-key.pem" "$STAGE/compute-agent-$host-key.pem"
done
cp "$TLS_DIR/certs/agents/controller-network/agent.pem" "$STAGE/controller-network.pem"
cp "$TLS_DIR/certs/agents/controller-network/agent-key.pem" "$STAGE/controller-network-key.pem"

for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo install -d -o o3k -g o3k -m 0700 /tmp/$RUN_ID-stage"
  scp -i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" "$STAGE"/* "$SSH_USER@$address:/tmp/$RUN_ID-stage/"
  if ! ssh_vm "$address" "sudo bash /tmp/$RUN_ID-stage/install-agent-host.sh $host $RUN_ID /tmp/$RUN_ID-stage" \
    >"$EVIDENCE/management/install-$host.log" 2>&1; then
    if grep -Fq 'invalid host identity' "$EVIDENCE/management/install-$host.log"; then
      fail "agent installer rejected the collision-safe selected management address" "HARNESS_GAP"
    fi
    fail "network agent installation failed on compute-$host; see install-$host.log" "ENVIRONMENT_GAP"
  fi
  scp -i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" "$PROBE_KEY" "$SSH_USER@$address:/tmp/$RUN_ID-probe-key"
  ssh_vm "$address" "sudo install -d -o root -g root -m 0700 /var/lib/o3k-fabric-v3/$RUN_ID/control && sudo install -o root -g root -m 0600 /tmp/$RUN_ID-probe-key /var/lib/o3k-fabric-v3/$RUN_ID/control/probe_ed25519 && sudo python3 -c 'import pathlib; pathlib.Path(\"/tmp/$RUN_ID-probe-key\").unlink()'"
  case "$host" in a) health_port=19101;; b) health_port=19102;; c) health_port=19103;; esac
  ssh_vm "$address" "sudo install -m 0755 /tmp/$RUN_ID-stage/o3k-compute /usr/local/bin/o3k-compute-bin; sudo install -d -m 0700 /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls; sudo install -m 0644 /tmp/$RUN_ID-stage/compute-agent-$host.pem /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls/agent.pem; sudo install -m 0600 /tmp/$RUN_ID-stage/compute-agent-$host-key.pem /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls/agent-key.pem; sudo install -m 0644 /tmp/$RUN_ID-stage/ca.pem /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls/ca.pem; sudo chown -R root:root /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls; sudo bash -c 'umask 077; printf compute-agent-$host > /var/lib/o3k-fabric-v3/$RUN_ID/compute/agent-id'"
  case "$host" in a) health_port=19101;; b) health_port=19102;; c) health_port=19103;; esac
  start_compute_agent "$host" "$health_port"
done

for host in a b c; do
  address="${MGMT_IP[$host]}"; ready=0
  ssh_vm "$address" "sudo ip -j -d link show dev mgmt0; sudo wg show; sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/fabric-provider/wireguard-public.key" >"$EVIDENCE/management/compute-$host.txt" || fail "host-$host runtime observation failed" "ENVIRONMENT_GAP"
done

WG_A="$(ssh_vm "${MGMT_IP[a]}" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/fabric-provider/wireguard-public.key")"
WG_B="$(ssh_vm "${MGMT_IP[b]}" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/fabric-provider/wireguard-public.key")"
WG_C="$(ssh_vm "${MGMT_IP[c]}" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/fabric-provider/wireguard-public.key")"
for host in a b c; do
  case "$host" in a) expected="$WG_A";; b) expected="$WG_B";; c) expected="$WG_C";; esac
  [[ "$expected" =~ ^[A-Za-z0-9+/]{43}=$ ]] \
    || fail "host-$host provider WireGuard public key is malformed" "HARNESS_GAP"
done
cat >"$EVIDENCE/environment/fabric-identities.json" <<JSON
[
 {"host_id":"host-a","agent_id":"network-agent-a","public_key":"$WG_A","underlay_endpoint":"${MGMT_IP[a]}:65001","fabric_transport_ip":"100.64.3.1","provider_version":"wireguard-v1","fabric_generation":1,"underlay_mtu":1500,"fabric_mtu":1440,"administrative_state":"enabled"},
 {"host_id":"host-b","agent_id":"network-agent-b","public_key":"$WG_B","underlay_endpoint":"${MGMT_IP[b]}:65001","fabric_transport_ip":"100.64.3.2","provider_version":"wireguard-v1","fabric_generation":1,"underlay_mtu":1500,"fabric_mtu":1440,"administrative_state":"enabled"},
 {"host_id":"host-c","agent_id":"network-agent-c","public_key":"$WG_C","underlay_endpoint":"${MGMT_IP[c]}:65001","fabric_transport_ip":"100.64.3.3","provider_version":"wireguard-v1","fabric_generation":1,"underlay_mtu":1500,"fabric_mtu":1440,"administrative_state":"enabled"}
]
JSON
DIRECTORY="$(python3 - "${MGMT_IP[a]}" "${MGMT_IP[b]}" "${MGMT_IP[c]}" <<'PY'
import json,sys
print(json.dumps([{"host_id":f"host-{x}","agent_id":f"network-agent-{x}","agent_epoch":f"network-epoch-{x}-1","endpoint":f"https://{ip}:50061","tls_server_name":"o3k-control-plane"} for x,ip in zip("abc",sys.argv[1:])],separators=(",",":")))
PY
)"
AUTHORIZED=""
for host in a b c; do
  if [[ "$host" == a ]]; then
    compute_cert="$TLS_DIR/certs/agent.pem"
  else
    compute_cert="$TLS_DIR/certs/agents/compute-agent-$host/agent.pem"
  fi
  fp="$(openssl x509 -in "$compute_cert" -outform DER | sha256sum | awk '{print $1}')"
  [[ -z "$AUTHORIZED" ]] || AUTHORIZED+=,
  AUTHORIZED+="compute-agent-$host=$fp"
done
SIGNING_KEY="$(openssl rand -hex 48)"
FABRIC_HOST_IDENTITIES="$(cat "$EVIDENCE/environment/fabric-identities.json")"
install -d -m 0700 "$EVIDENCE/controller-data"
export O3K_PROVIDER=agent O3K_DATA_DIR="$EVIDENCE/controller-data" O3K_CONTROLLER_ID="controller-$RUN_ID" O3K_CONTROLLER_EPOCH="controller-epoch-1" O3K_BOOTSTRAP_PASSWORD="campaign-$RUN_ID" O3K_TOKEN_SIGNING_KEY="$SIGNING_KEY"
export O3K_FABRIC_DOMAIN_ID="$FABRIC_DOMAIN_ID" O3K_FABRIC_HOST_IDENTITIES="$FABRIC_HOST_IDENTITIES" O3K_NETWORK_AGENT_DIRECTORY="$DIRECTORY"
export O3K_NETWORK_AGENT_CA="$TLS_DIR/certs/ca.pem" O3K_NETWORK_AGENT_CLIENT_CERT="$TLS_DIR/certs/agents/controller-network/agent.pem" O3K_NETWORK_AGENT_CLIENT_KEY="$TLS_DIR/certs/agents/controller-network/agent-key.pem"
export O3K_COMPUTE_CONTROL_ADDR="0.0.0.0:$CONTROL_PORT" O3K_COMPUTE_SERVER_CERTIFICATE="$TLS_DIR/certs/server.pem" O3K_COMPUTE_SERVER_PRIVATE_KEY="$TLS_DIR/certs/server-key.pem" O3K_COMPUTE_CLIENT_CA="$TLS_DIR/certs/ca.pem" O3K_COMPUTE_AUTHORIZED_AGENTS="$AUTHORIZED"
"$PRODUCT_SOURCE_DIR/target/release/o3kd" --listen-addr "$HOST_MGMT_IP:$API_PORT" --data-dir "$EVIDENCE/controller-data" --log-filter info >"$EVIDENCE/management/o3kd.log" 2>&1 &
O3KD_PID=$!
for _ in $(seq 1 120); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; kill -0 "$O3KD_PID" 2>/dev/null || fail "o3kd exited during startup" "ENVIRONMENT_GAP"; sleep 1; done
curl -fsS "$BASE/readyz" >"$EVIDENCE/management/o3kd-ready.json" || fail "o3kd failed readiness" "ENVIRONMENT_GAP"

# Compute /readyz includes the authenticated controller registration state, so
# defer this check until o3kd is listening and ready. Checking it before the
# controller starts would make a healthy agent report 503 by design.
for host in a b c; do
  address="${MGMT_IP[$host]}"; ready=0
  case "$host" in a) health_port=19101;; b) health_port=19102;; c) health_port=19103;; esac
  for _ in $(seq 1 60); do
    if ssh_vm "$address" "sudo curl -fsS http://127.0.0.1:$health_port/readyz" >/dev/null 2>&1; then ready=1; break; fi
    sleep 2
  done
  (( ready == 1 )) || fail "compute agent did not register with the ready controller on host-$host" "HARNESS_GAP"
  ssh_vm "$address" "sudo curl -fsS http://127.0.0.1:$health_port/readyz" \
    >"$EVIDENCE/management/compute-$host-ready.json" \
    || fail "could not capture registered compute capacity for host-$host" "HARNESS_GAP"
done
python3 - "$EVIDENCE/management" <<'PY' || fail "live compute capacities do not produce deterministic A/B/C scheduler order" "HARNESS_GAP"
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
capacity={}
for host in "abc":
    body=json.loads((root/f"compute-{host}-ready.json").read_text())
    assert body["agent_id"]==f"compute-agent-{host}", body
    c=body["capabilities"]
    capacity[host]=sum(int(c[k]) for k in ("max_vcpus","max_memory_mib","max_disk_gb"))
assert capacity["a"]==capacity["b"]+1 and capacity["b"]==capacity["c"], capacity
print(json.dumps({"scheduler_capacity_score":capacity},sort_keys=True))
PY

auth_status="$(curl --silent --show-error --max-time 30 -X POST "$BASE/v3/auth/tokens" -H 'content-type: application/json' -D "$EVIDENCE/api/auth.headers" -o /dev/null -w '%{http_code}' --data "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"admin\",\"password\":\"campaign-$RUN_ID\"}}},\"scope\":{\"project\":{\"name\":\"admin\"}}}}")" \
  || fail "supported HTTP authentication request failed" "SUPPORTED_API_GAP"
[[ "$auth_status" == 201 ]] || fail "supported HTTP authentication returned HTTP $auth_status" "SUPPORTED_API_GAP"
printf 'HTTP %s; response body intentionally omitted\n' "$auth_status" >"$EVIDENCE/api/auth.body"
TOKEN="$(awk 'tolower($1)=="x-subject-token:"{print $2}' "$EVIDENCE/api/auth.headers" | tr -d '\r')"
[[ -n "$TOKEN" ]] || fail "authentication returned no token" "SUPPORTED_API_GAP"
python3 - "$EVIDENCE/api/auth.headers" <<'PY'
import pathlib,re,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text(errors="replace")
p.write_text(re.sub(r'(?im)^(x-subject-token:\s*).+$',r'\1[REDACTED]',s))
PY

O3K_PROBE_IMAGE="$EVIDENCE/environment/o3k-fabric-probe.qcow2"
bash "$ROOT_DIR/tests/fabric-v3-build-probe-image.sh" "$PROBE_BASE_IMAGE" "$PROBE_KEY.pub" "$O3K_PROBE_IMAGE" "$EVIDENCE/environment" \
  || fail "deterministic guest probe image build failed" "HARNESS_GAP"
sha256sum "$O3K_PROBE_IMAGE" >"$EVIDENCE/environment/probe-image.sha256"
printf 'source_image=%s\nsource_sha256=%s\nrecipe_revision=%s\n' \
  "$PROBE_BASE_URL" "$PROBE_BASE_SHA" "$(git -C "$ROOT_DIR" rev-parse HEAD)" \
  >"$EVIDENCE/environment/probe-image-identity.txt"
python3 - "$EVIDENCE/environment/control-channel-capabilities.json" "$EVIDENCE/environment/probe-image.sha256" <<'PY'
import json,pathlib,sys
probe_sha=pathlib.Path(sys.argv[2]).read_text().split()[0]
doc={"status":"capability_discovery_complete",
 "mechanisms":{
  "serial_pty":{"present":False,"interactive":False,"read_only":False,"bidirectional":False,"depends_on_tenant_dhcp":False,"depends_on_cross_host_fabric":False,"accepted_for_control":False,"discovery":"not configured by the frozen product domain definition; each live domain is inspected before control preflight"},
  "file_backed_serial":{"present":True,"interactive":False,"read_only":True,"bidirectional":False,"depends_on_tenant_dhcp":False,"depends_on_cross_host_fabric":False,"accepted_for_control":False,"discovery":"verified on the frozen product domain in the preserved prior campaign; every fresh domain is checked against live XML before guest commands"},
  "qemu_guest_agent":{"present":False,"interactive":False,"read_only":False,"bidirectional":False,"depends_on_tenant_dhcp":False,"depends_on_cross_host_fabric":False,"accepted_for_control":False},
  "vsock":{"present":False,"interactive":False,"read_only":False,"bidirectional":False,"depends_on_tenant_dhcp":False,"depends_on_cross_host_fabric":False,"accepted_for_control":False},
  "dedicated_management_nic":{"present":False,"interactive":False,"read_only":False,"bidirectional":False,"depends_on_tenant_dhcp":False,"depends_on_cross_host_fabric":False,"accepted_for_control":False},
  "guest_ipv6_link_local_host_local_realm_bridge":{"present":True,"interactive":True,"read_only":False,"bidirectional":True,"depends_on_tenant_dhcp":False,"depends_on_cross_host_fabric":False,"accepted_for_control":"pending per-guest readiness/locality preflight"}},
 "probe_image":{"recipe":"tests/fabric-v3-build-probe-image.sh","sha256":probe_sha}}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc,sort_keys=True,indent=2)+"\n")
PY
python3 - "$EVIDENCE/manifest.json" "$EVIDENCE/environment/probe-image.sha256" "$(git -C "$ROOT_DIR" rev-parse HEAD)" <<'PYMANIFEST'
import json,pathlib,sys
manifest,sha_file,recipe_revision=sys.argv[1:]
data=json.loads(pathlib.Path(manifest).read_text())
data['probe_image_sha256']=pathlib.Path(sha_file).read_text().split()[0]
data['probe_image_recipe_revision']=recipe_revision
pathlib.Path(manifest).write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')
PYMANIFEST
curl --fail --silent --show-error --max-time 30 -X POST "$BASE/v2/images" -H "x-auth-token: $TOKEN" -H 'content-type: application/json' -d "{\"name\":\"$PREFIX-probe\",\"disk_format\":\"qcow2\",\"container_format\":\"bare\",\"visibility\":\"private\"}" >"$EVIDENCE/api/image-create.response.json" || fail "supported image create failed" "SUPPORTED_API_GAP"
IMAGE_ID="$(field id <"$EVIDENCE/api/image-create.response.json")"
curl --fail --silent --show-error --max-time 900 -X PUT "$BASE/v2/images/$IMAGE_ID/file" -H "x-auth-token: $TOKEN" -H 'content-type: application/octet-stream' --data-binary "@$O3K_PROBE_IMAGE" >"$EVIDENCE/api/image-upload.response.txt" || fail "supported probe image upload failed" "SUPPORTED_API_GAP"

curl --fail --silent --show-error -X POST "$BASE/v2.0/networks" -H "x-auth-token: $TOKEN" -H 'content-type: application/json' -d "{\"network\":{\"name\":\"$PREFIX-network\"}}" >"$EVIDENCE/api/network-create.response.json" || fail "supported network create failed" "SUPPORTED_API_GAP"
NETWORK_ID="$(field network.id <"$EVIDENCE/api/network-create.response.json")"
curl --fail --silent --show-error -X POST "$BASE/v2.0/subnets" -H "x-auth-token: $TOKEN" -H 'content-type: application/json' -d "{\"subnet\":{\"name\":\"$PREFIX-subnet\",\"network_id\":\"$NETWORK_ID\",\"cidr\":\"10.77.0.0/24\"}}" >"$EVIDENCE/api/subnet-create.response.json" || fail "supported subnet create failed" "SUPPORTED_API_GAP"
SUBNET_ID="$(field subnet.id <"$EVIDENCE/api/subnet-create.response.json")"
FLAVOR_ID="$(api "$BASE/v2.1/$PROJECT_ID/flavors" | python3 -c 'import json,sys; print(json.load(sys.stdin)["flavors"][0]["id"])')"
[[ -n "$FLAVOR_ID" ]] || fail "supported flavor listing returned no flavor" "SUPPORTED_API_GAP"

start_dhcp_capture() {
  local port_id="$1" address="${MGMT_IP[a]}" remote_capture
  remote_capture="/var/lib/o3k-fabric-v3/$RUN_ID/network/dhcp-capture"
  ssh_vm "$address" "sudo install -d -m 0700 '$remote_capture' && sudo bash -c 'nohup tcpdump -i any -nn -e -U -w \"$remote_capture/dora.pcap\" \"udp and (port 67 or port 68)\" >\"$remote_capture/tcpdump.log\" 2>&1 </dev/null & echo \$! >\"$remote_capture/tcpdump.pid\"'"
  DHCP_CAPTURE_PID="$(ssh_vm "$address" "sudo cat '$remote_capture/tcpdump.pid'")"
  [[ "$DHCP_CAPTURE_PID" =~ ^[0-9]+$ ]] || fail "run-owned DHCP packet capture did not start" "HARNESS_GAP"
  DHCP_CAPTURE_HOST=a
  DHCP_CAPTURE_CLEANUP_STATUS=PENDING
  ssh_vm "$address" "sudo test -r /proc/$DHCP_CAPTURE_PID/cmdline && sudo cat /proc/$DHCP_CAPTURE_PID/cmdline | tr '\\0' ' '" >"$EVIDENCE/attachments/dhcp-capture-command.txt" \
    || fail "DHCP capture process identity could not be observed" "HARNESS_GAP"
  grep -Fq "$remote_capture/dora.pcap" "$EVIDENCE/attachments/dhcp-capture-command.txt" \
    || fail "DHCP capture PID is not bound to the run-owned evidence path" "OWNERSHIP_DEFECT"
  printf 'authority_host=host-a\ninterface=any\nport_id=%s\npid=%s\n' \
    "$port_id" "$DHCP_CAPTURE_PID" >"$EVIDENCE/attachments/dhcp-capture-identity.txt"
}

stop_dhcp_capture() {
  if [[ -z "$DHCP_CAPTURE_PID" ]]; then
    [[ "$DHCP_CAPTURE_CLEANUP_STATUS" != PENDING ]] || return 1
    return 0
  fi
  [[ "$DHCP_CAPTURE_HOST" == a ]] || { DHCP_CAPTURE_CLEANUP_STATUS=FAIL; return 1; }
  local address="${MGMT_IP[a]:-}" remote_capture local_capture
  [[ -n "$address" ]] || { DHCP_CAPTURE_CLEANUP_STATUS=FAIL; return 1; }
  remote_capture="/var/lib/o3k-fabric-v3/$RUN_ID/network/dhcp-capture"
  local_capture="$EVIDENCE/attachments/dhcp-dora.pcap"
  if ! ssh_vm "$address" "if sudo test -r /proc/$DHCP_CAPTURE_PID/cmdline; then sudo cat /proc/$DHCP_CAPTURE_PID/cmdline | tr '\\0' ' ' | grep -Fq '$remote_capture/dora.pcap' || exit 42; test \"\$(sudo cat /proc/$DHCP_CAPTURE_PID/comm)\" = tcpdump || exit 43; sudo kill -INT '$DHCP_CAPTURE_PID'; fi" \
      >"$EVIDENCE/attachments/dhcp-capture-stop-command.txt" 2>&1; then
    printf 'capture_stop_command=FAIL\n' >"$EVIDENCE/attachments/dhcp-capture-stop-status.txt"
    DHCP_CAPTURE_CLEANUP_STATUS=FAIL
    return 1
  fi
  local process_state
  for _ in $(seq 1 30); do
    if ! process_state="$(ssh_vm "$address" "sudo sh -c 'if test -e /proc/$DHCP_CAPTURE_PID; then printf PRESENT; else printf ABSENT; fi'")"; then
      printf 'capture_process=UNKNOWN observer=ssh_sudo_proc exit_status=unavailable\n' >"$EVIDENCE/attachments/dhcp-capture-stop-status.txt"
      DHCP_CAPTURE_CLEANUP_STATUS=FAIL
      return 1
    fi
    [[ "$process_state" == PRESENT || "$process_state" == ABSENT ]] || {
      printf 'capture_process=UNKNOWN observer_output=%s\n' "$process_state" >"$EVIDENCE/attachments/dhcp-capture-stop-status.txt"
      DHCP_CAPTURE_CLEANUP_STATUS=FAIL
      return 1
    }
    [[ "$process_state" == ABSENT ]] && break
    sleep 1
  done
  if [[ "$process_state" != ABSENT ]]; then
    printf 'capture_process=STILL_RUNNING pid=%s\n' "$DHCP_CAPTURE_PID" >"$EVIDENCE/attachments/dhcp-capture-stop-status.txt"
    DHCP_CAPTURE_CLEANUP_STATUS=FAIL
    return 1
  fi
  printf 'capture_process=ABSENT pid=%s\n' "$DHCP_CAPTURE_PID" >"$EVIDENCE/attachments/dhcp-capture-stop-status.txt"
  local capture_file_state
  if ! capture_file_state="$(ssh_vm "$address" "sudo python3 -c 'import pathlib,sys; print(\"PRESENT\" if pathlib.Path(sys.argv[1]).is_file() else \"ABSENT\")' '$remote_capture/dora.pcap'")"; then
    printf 'capture_file=UNKNOWN observer=ssh_sudo_python exit_status=unavailable\n' >>"$EVIDENCE/attachments/dhcp-capture-stop-status.txt"
    DHCP_CAPTURE_CLEANUP_STATUS=FAIL
    return 1
  fi
  if [[ "$capture_file_state" == PRESENT ]]; then
    if ! ssh_vm "$address" "sudo cp '$remote_capture/dora.pcap' /tmp/$RUN_ID-dhcp-dora.pcap && sudo chown '$SSH_USER:$SSH_USER' /tmp/$RUN_ID-dhcp-dora.pcap && sudo chmod 0600 /tmp/$RUN_ID-dhcp-dora.pcap" \
        >"$EVIDENCE/attachments/dhcp-capture-copy-command.txt" 2>&1; then
      DHCP_CAPTURE_CLEANUP_STATUS=FAIL
      return 1
    fi
    if ! scp -i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
      -o "UserKnownHostsFile=$KNOWN_HOSTS" "$SSH_USER@$address:/tmp/$RUN_ID-dhcp-dora.pcap" \
      "$local_capture" >"$EVIDENCE/attachments/dhcp-capture-copy-scp.stdout" \
      2>"$EVIDENCE/attachments/dhcp-capture-copy-scp.stderr"; then
      DHCP_CAPTURE_CLEANUP_STATUS=FAIL
      return 1
    fi
    if ! ssh_vm "$address" "sudo rm -f /tmp/$RUN_ID-dhcp-dora.pcap && sudo cat '$remote_capture/tcpdump.log'" \
        >"$EVIDENCE/attachments/dhcp-tcpdump.log" 2>"$EVIDENCE/attachments/dhcp-tcpdump-log.stderr"; then
      DHCP_CAPTURE_CLEANUP_STATUS=FAIL
      return 1
    fi
  elif [[ "$capture_file_state" == ABSENT ]]; then
    printf 'capture_file=ABSENT (capture stopped before packet evidence was produced)\n' \
      >>"$EVIDENCE/attachments/dhcp-capture-stop-status.txt"
  else
    printf 'capture_file=UNKNOWN observer_output=%s\n' "$capture_file_state" \
      >>"$EVIDENCE/attachments/dhcp-capture-stop-status.txt"
    DHCP_CAPTURE_CLEANUP_STATUS=FAIL
    return 1
  fi
  DHCP_CAPTURE_PID=""
  DHCP_CAPTURE_CLEANUP_STATUS=PASS
}

create_server() {
  local host="$1" port_id response server_id status request
  port_id="$(api -X POST "$BASE/v2.0/ports" -H 'content-type: application/json' -d "{\"port\":{\"name\":\"$PREFIX-port-$host\",\"network_id\":\"$NETWORK_ID\"}}" | tee "$EVIDENCE/api/port-$host.response.json" | field port.id)"
  TENANT_IP[$host]="$(field port.fixed_ips.0.ip_address <"$EVIDENCE/api/port-$host.response.json")"
  TENANT_MAC[$host]="$(field port.mac_address <"$EVIDENCE/api/port-$host.response.json")"
  PORT_IDS+=("$port_id")
  if [[ "$host" == a ]]; then start_dhcp_capture "$port_id"; fi
  request="$EVIDENCE/api/server-$host.create.json"
  python3 - "$request" "$PREFIX" "$host" "$IMAGE_ID" "$FLAVOR_ID" "$port_id" <<'PY'
import json,sys
path,prefix,host,image,flavor,port=sys.argv[1:]
json.dump({"server":{"name":f"{prefix}-server-{host}","image":{"id":image},"flavor":{"id":flavor},"networks":[{"uuid":port}],"config_drive":False}},open(path,"w"),sort_keys=True)
PY
  # Storage was preflighted before guests/server creation. Record a second
  # read-only proof immediately before each public server create.
  bash "$ROOT_DIR/tests/fabric-v3-qemu-storage-preflight.sh" >"$EVIDENCE/environment/qemu-storage-preflight-server-$host.txt" 2>&1 || fail "QEMU storage preflight failed before server $host" "ENVIRONMENT_GAP"
  response="$(curl --silent --show-error --max-time 60 -X POST "$BASE/v2.1/$PROJECT_ID/servers" -H "x-auth-token: $TOKEN" -H 'content-type: application/json' -H "x-openstack-request-id: $PREFIX-server-$host" --data-binary "@$request")"
  printf '%s\n' "$response" >"$EVIDENCE/api/server-$host.create.response.json"
  server_id="$(printf '%s' "$response" | field server.id 2>/dev/null || true)"
  [[ -n "$server_id" ]] || fail "server $host create was rejected: $response" "SUPPORTED_API_GAP"
  SERVER_IDS+=("$server_id")
  for _ in $(seq 1 240); do
    status="$(api "$BASE/v2.1/$PROJECT_ID/servers/$server_id" | tee "$EVIDENCE/api/server-$host.current.json" | field server.status)"
    [[ "$status" == ACTIVE ]] && break
    [[ "$status" == ERROR ]] && fail "server $host entered ERROR" "ATTACHMENT_DEFECT"
    sleep 2
  done
  [[ "$status" == ACTIVE ]] || fail "server $host did not reach ACTIVE (last=$status)" "ATTACHMENT_DEFECT"
  echo "server $host ACTIVE id=$server_id"
  local response_host expected_host address domain="" tap ownership tap_mac guest_mac current_mac bridge realm_id
  expected_host="compute-agent-$host"
  response_host="$(api "$BASE/v2.1/$PROJECT_ID/servers/$server_id" | tee "$EVIDENCE/api/server-$host-placement.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["server"].get("OS-EXT-SRV-ATTR:host", ""))')"
  [[ "$response_host" == "$expected_host" ]] || fail "server $host placed on $response_host, expected $expected_host" "DISPATCH_DEFECT"
  address="${MGMT_IP[$host]}"
  for _ in $(seq 1 60); do
    domain="$(ssh_vm "$address" "sudo virsh -c qemu:///system list --all --name | while read -r n; do [ -n \"\$n\" ] || continue; x=\$(sudo virsh -c qemu:///system dumpxml \"\$n\" 2>/dev/null || true); if printf '%s' \"\$x\" | grep -Fq 'server_id=\"$server_id\"' && printf '%s' \"\$x\" | grep -Fq 'managed_by=\"o3k-compute\"'; then printf '%s\\n' \"\$n\"; fi; done" | head -1)"
    [[ -n "$domain" ]] && break
    sleep 1
  done
  [[ -n "$domain" ]] || fail "server $host ACTIVE but no matching owned VM domain found on $expected_host" "PRODUCT_DEFECT"
  printf '%s\n' "$domain" >"$EVIDENCE/compute-$host/domain.txt"
  ssh_vm "$address" "sudo virsh -c qemu:///system dumpxml '$domain'" >"$EVIDENCE/compute-$host/domain.xml"
  capture_guest_serial_output "$host" || fail "file-backed guest serial observation unavailable for $host" "HARNESS_GAP"
  ssh_vm "$address" "sudo virsh -c qemu:///system domstate '$domain'" >"$EVIDENCE/compute-$host/domain-state.txt"
  [[ "$(tr -d '\r' <"$EVIDENCE/compute-$host/domain-state.txt")" == running ]] || fail "server $host domain is not running" "PRODUCT_DEFECT"
  ownership="/var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json"
  ssh_vm "$address" "sudo cat '$ownership'" >"$EVIDENCE/attachments/server-$host-provider-ownership.json" || fail "Fabric ownership observation failed for $host" "OWNERSHIP_DEFECT"
  guest_mac="$(field port.mac_address <"$EVIDENCE/api/port-$host.response.json")"
  tap_contract="$(python3 - "$EVIDENCE/compute-$host/domain.xml" "$EVIDENCE/attachments/server-$host-provider-ownership.json" "$port_id" "$guest_mac" <<'PY'
import json,sys,xml.etree.ElementTree as ET
domain=ET.parse(sys.argv[1]).getroot()
ownership=json.load(open(sys.argv[2])); endpoint,guest_mac=sys.argv[3:]
matches=[(rid,r) for rid,r in ownership.get('realms',{}).items() if endpoint in r.get('endpoint_taps',{})]
assert len(matches)==1, matches
realm_id,realm=matches[0]
record=realm['endpoint_taps'][endpoint]
assert endpoint not in realm.get('pending_endpoint_taps',{})
tap=record['interface']; assert tap
interfaces=[]
for interface in domain.findall('./devices/interface'):
    target=interface.find('target')
    if target is not None and target.get('dev')==tap: interfaces.append(interface)
assert len(interfaces)==1, (tap,len(interfaces))
mac=interfaces[0].find('mac').get('address','').lower()
assert mac==guest_mac.lower(), (mac,guest_mac)
print('\t'.join((tap,record['mac'],realm_id,realm['bridge'],mac)))
PY
)" || fail "domain TAP target or durable provider ownership did not match" "ATTACHMENT_DEFECT"
  IFS=$'\t' read -r tap tap_mac realm_id bridge guest_domain_mac <<<"$tap_contract"
  REALM_BRIDGE[$host]="$bridge"
  ssh_vm "$address" "sudo ip -j -d link show dev '$tap'" >"$EVIDENCE/attachments/server-$host-live-tap.json" || fail "real Fabric TAP disappeared for $host" "ATTACHMENT_DEFECT"
  ssh_vm "$address" "sudo cat '/var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/plans/$realm_id.json'" >"$EVIDENCE/attachments/server-$host-fabric-plan.json" || fail "current Fabric plan observation failed for $host" "ATTACHMENT_DEFECT"
  ssh_vm "$address" "sudo cat '/var/lib/o3k-fabric-v3/$RUN_ID/network/executor/accepted-network-plans.json'" >"$EVIDENCE/attachments/server-$host-execution-plans.json" || fail "network execution plan observation failed for $host" "ATTACHMENT_DEFECT"
  python3 - "$EVIDENCE/attachments/server-$host-live-tap.json" "$tap" "$tap_mac" "$bridge" "$EVIDENCE/attachments/server-$host-provider-ownership.json" "$EVIDENCE/attachments/server-$host-fabric-plan.json" "$EVIDENCE/attachments/server-$host-execution-plans.json" "$port_id" "$guest_mac" "$expected_host" "$realm_id" <<'PY' || fail "live TAP, plan, or committed ownership attestation failed for $host" "ATTACHMENT_DEFECT"
import json,sys
live=json.load(open(sys.argv[1])); name,provider_mac,bridge=sys.argv[2:5]
ownership=json.load(open(sys.argv[5])); plan=json.load(open(sys.argv[6])); accepted=json.load(open(sys.argv[7]))
endpoint,guest_mac,agent,realm_id=sys.argv[8:]
realms=ownership.get('realms',{}); assert realm_id in realms
realm=realms[realm_id]; record=realm.get('endpoint_taps',{}).get(endpoint)
assert record and endpoint not in realm.get('pending_endpoint_taps',{})
assert record.get('interface')==name and record.get('mac','').lower()==provider_mac.lower()
assert len(live)==1 and live[0].get('ifname')==name and int(live[0].get('ifindex',0))>0
assert live[0].get('address','').lower()==provider_mac.lower()
linkinfo=live[0].get('linkinfo',{}); assert linkinfo.get('info_kind')=='tun' and linkinfo.get('info_data',{}).get('type')=='tap'
assert live[0].get('master')==bridge==realm.get('bridge')
assert plan.get('realm_id')==realm_id and plan.get('local_host')=='host-'+agent[-1]
assert plan.get('directory_generation')==realm.get('directory_generation')
entries=[e for e in plan.get('directory',{}).get('entries',[]) if e.get('endpoint_id')==endpoint]
assert len(entries)==1 and entries[0].get('selected_host')=='host-'+agent[-1]
assert entries[0].get('mac','').lower()==guest_mac.lower()
success=[]
for item in accepted.get('plans',[]):
    command=item.get('plan',{}); fabric=command.get('fabric',{})
    intents=command.get('intents',[])
    has_endpoint=any('EndpointAttachment' in intent and intent['EndpointAttachment'].get('endpoint_id')==endpoint for intent in intents)
    if item.get('status')=='Succeeded' and item.get('target',{}).get('agent_id')=='network-agent-'+agent[-1] and fabric.get('realm_id')==realm_id and has_endpoint:
        success.append(item)
assert success, 'no succeeded endpoint apply plan for target agent'
assert live[0].get('address','').lower()!=guest_mac.lower()
PY
  bridge="$(python3 - "$EVIDENCE/attachments/server-$host-live-tap.json" <<'PY'
import json,sys; print(json.load(open(sys.argv[1]))[0].get('master',''))
PY
)"
  current_mac="$(python3 - "$EVIDENCE/attachments/server-$host-live-tap.json" <<'PY'
import json,sys; print(json.load(open(sys.argv[1]))[0].get('address',''))
PY
)"
  [[ "$current_mac" == "$tap_mac" && "$current_mac" != "$guest_mac" && "$guest_domain_mac" == "$guest_mac" ]] || fail "provider TAP and canonical guest MAC identities were not preserved" "SECURITY_DEFECT"
  printf 'provider_tap_mac=%s\ncanonical_guest_mac=%s\n' "$current_mac" "$guest_mac" >"$EVIDENCE/attachments/server-$host-mac-separation.txt"
  # The accepted compute attachment resolver ran during API create. Its PASS is
  # evidenced by successful VM realization; preserve the live observation too.
  echo "REAL-HOST FABRIC TAP ATTESTATION: PASS" >"$EVIDENCE/attachments/server-$host-attestation.txt"
  echo "tap=$tap info_kind=tun info_data.type=tap master=$bridge" >>"$EVIDENCE/attachments/server-$host-attestation.txt"
}

mac_link_local() {
  python3 "$ROOT_DIR/tests/fabric-v3-guest-control.py" link-local "$1"
}

capture_guest_serial_output() {
  local host="$1" address="${MGMT_IP[$1]}" serial_path
  serial_path="$(python3 - "$EVIDENCE/compute-$host/domain.xml" "$RUN_ID" <<'PYSERIAL'
import sys,xml.etree.ElementTree as ET
root=ET.parse(sys.argv[1]).getroot()
serial=root.find("./devices/serial")
source=serial.find("source") if serial is not None else None
path=source.get("path") if source is not None else ""
prefix=f"/var/lib/o3k-fabric-v3/{sys.argv[2]}/compute/console/"
if serial is None or serial.get("type") != "file" or not path.startswith(prefix):
    raise SystemExit("live domain has no run-owned file-backed serial path")
print(path)
PYSERIAL
)" || return 1
  printf '%s\n' "$serial_path" >"$EVIDENCE/compute-$host/serial-console-path.txt"
  ssh_vm "$address" "sudo cat '$serial_path'" \
    >"$EVIDENCE/compute-$host/serial-console-output.txt" \
    2>"$EVIDENCE/compute-$host/serial-console-output.stderr"
}

collect_guest_control_diagnostics() {
  local host="$1" address="${MGMT_IP[$1]}" bridge="${REALM_BRIDGE[$1]}" ll="${GUEST_IPV6[$1]}"
  local capture_root="/var/lib/o3k-fabric-v3/$RUN_ID/control/$host" fabric_ns
  fabric_ns="$(python3 - "$EVIDENCE/attachments/server-$host-provider-ownership.json" <<'PYNS'
import json,sys
print(json.load(open(sys.argv[1]))['fabric']['namespace'])
PYNS
)" || return 1
  ssh_vm "$address" "sudo timeout 3 tcpdump -nn -r '$capture_root/local-control.pcap'; sudo timeout 3 ip netns exec '$fabric_ns' tcpdump -nn -r '$capture_root/fabric-control.pcap'; sudo cat '$capture_root/local-control-tcpdump.log' '$capture_root/fabric-control-tcpdump.log' '$capture_root/keyscan.stderr' 2>/dev/null || true; sudo cp '$capture_root/local-control.pcap' /tmp/$RUN_ID-$host-local-control.pcap; sudo cp '$capture_root/fabric-control.pcap' /tmp/$RUN_ID-$host-fabric-control.pcap; sudo chown '$SSH_USER:$SSH_USER' /tmp/$RUN_ID-$host-local-control.pcap /tmp/$RUN_ID-$host-fabric-control.pcap" \
    >"$EVIDENCE/management/guest-$host-local-control-capture.txt" 2>&1 || true
  scp -i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" \
    "$SSH_USER@$address:/tmp/$RUN_ID-$host-local-control.pcap" "$EVIDENCE/management/guest-$host-local-control.pcap" \
    || return 1
  scp -i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" \
    "$SSH_USER@$address:/tmp/$RUN_ID-$host-fabric-control.pcap" "$EVIDENCE/management/guest-$host-fabric-control.pcap" \
    || return 1
}

prepare_guest_control() {
  local host="$1" address="${MGMT_IP[$1]}" bridge="${REALM_BRIDGE[$1]}" ll="${GUEST_IPV6[$1]}"
  local ownership="$EVIDENCE/attachments/server-$1-provider-ownership.json" fabric_ns alias remote_known route capture_root tap scan_error endpoint_id host_index fabric_capture_pid bridge_capture_pid
  alias="o3k-probe-$host"
  fabric_ns="$(python3 - "$ownership" <<'PYNS'
import json,sys
print(json.load(open(sys.argv[1]))['fabric']['namespace'])
PYNS
)" || return 1
  case "$host" in a) host_index=0 ;; b) host_index=1 ;; c) host_index=2 ;; *) return 1 ;; esac
  endpoint_id="${PORT_IDS[$host_index]}"
  tap="$(python3 - "$ownership" "$endpoint_id" <<'PYTAP'
import json,sys
ownership=json.load(open(sys.argv[1])); endpoint=sys.argv[2]
matches=[record['interface'] for realm in ownership.get('realms',{}).values()
         for candidate,record in realm.get('endpoint_taps',{}).items() if candidate == endpoint]
assert len(matches)==1, matches
print(matches[0])
PYTAP
)" || return 1
  [[ "$bridge" =~ ^[a-zA-Z0-9_.-]{1,15}$ && "$fabric_ns" =~ ^[a-zA-Z0-9_.-]{1,15}$ && "$tap" =~ ^[a-zA-Z0-9_.-]{1,15}$ && "$ll" == fe80::* ]] || return 1
  remote_known="/var/lib/o3k-fabric-v3/$RUN_ID/control/known_hosts-$host"
  capture_root="/var/lib/o3k-fabric-v3/$RUN_ID/control/$host"
  scan_error="$capture_root/keyscan.stderr"
  ssh_vm "$address" "sudo install -d -m 0700 '$capture_root'; { sudo ip -j -6 address show dev '$bridge'; sudo ip -6 route show table all; sudo bridge -j link show dev '$tap'; sudo ip -6 route get '$ll' oif '$bridge'; sudo sysctl net.ipv6.conf.$bridge.disable_ipv6; }" \
    >"$EVIDENCE/management/guest-$host-host-local-ipv6-state.txt" 2>&1 || true
  route="$(ssh_vm "$address" "sudo ip -6 route get '$ll' oif '$bridge'" 2>&1 || true)"
  printf '%s\n' "$route" >"$EVIDENCE/management/guest-$host-local-route.txt"
  fabric_capture_pid="$(ssh_vm "$address" "sudo bash -c 'nohup timeout 60 ip netns exec $fabric_ns tcpdump -nn -i any -U -w $capture_root/fabric-control.pcap ip6 and host $ll and tcp port 22 >$capture_root/fabric-control-tcpdump.log 2>&1 </dev/null & echo \$!'")" \
    || return 1
  printf '%s\n' "$fabric_capture_pid" >"$EVIDENCE/management/guest-$host-fabric-capture.pid"
  bridge_capture_pid="$(ssh_vm "$address" "sudo bash -c 'nohup timeout 60 tcpdump -nn -i $bridge -U -w $capture_root/local-control.pcap ip6 and host $ll and tcp port 22 >$capture_root/local-control-tcpdump.log 2>&1 </dev/null & echo \$!'")" \
    || return 1
  printf '%s\n' "$bridge_capture_pid" >"$EVIDENCE/management/guest-$host-bridge-capture.pid"
  sleep 1
  [[ "$fabric_capture_pid" =~ ^[0-9]+$ && "$bridge_capture_pid" =~ ^[0-9]+$ ]] || return 1
  ssh_vm "$address" "sudo kill -0 '$fabric_capture_pid' && sudo test -s '$capture_root/fabric-control.pcap' && sudo kill -0 '$bridge_capture_pid' && sudo test -s '$capture_root/local-control.pcap'" \
    >"$EVIDENCE/management/guest-$host-capture-readiness.txt" 2>&1 || return 1
  if ! ssh_vm "$address" "sudo bash -s -- '$ll' '$bridge' '$alias' '$remote_known' '$scan_error'" \
    >"$EVIDENCE/management/guest-$host-keyscan.txt" 2>&1 <<'REMOTE_SCAN'
set -o pipefail
ll="$1"; bridge="$2"; alias="$3"; known="$4"; errors="$5"
tmp="${known}.tmp"
rm -f "$tmp" "$known" "$errors"
for attempt in $(seq 1 20); do
  if ssh-keyscan -6 -T 2 -t ed25519 "$ll%$bridge" 2>>"$errors" \
      | awk -v alias="$alias" '{$1=alias; print}' >"$tmp" && [[ -s "$tmp" ]]; then
    install -m 0600 "$tmp" "$known"
    rm -f "$tmp"
    printf 'listener_ready=yes\nattempt=%s\n' "$attempt"
    exit 0
  fi
  sleep 2
done
printf 'listener_ready=no\nattempts=20\n'
cat "$errors" 2>/dev/null || true
exit 1
REMOTE_SCAN
  then
    collect_guest_control_diagnostics "$host" || true
    return 1
  fi
  ssh_vm "$address" "sudo ssh-keygen -lf '$remote_known'" >"$EVIDENCE/management/guest-$host-hostkey-fingerprint.txt" 2>&1 || return 1
  grep -Fq "dev $bridge" <<<"$route" || return 1
}

guest_control_command() {
  local host="$1" command="$2" label="$3" address="${MGMT_IP[$1]}" bridge="${REALM_BRIDGE[$1]}" ll="${GUEST_IPV6[$1]}"
  local control_root="/var/lib/o3k-fabric-v3/$RUN_ID/control" remote_known="/var/lib/o3k-fabric-v3/$RUN_ID/control/known_hosts-$1"
  local encoded tmp remote_script remote_cmd guest_remote_cmd rc marker target
  LAST_GUEST_CHANNEL_ERROR=0
  encoded="$(printf '%s' "$command" | base64 -w0)"
  tmp="/tmp/o3k-$RUN_ID-guest-command"
  target="$(python3 "$ROOT_DIR/tests/fabric-v3-guest-control.py" target "$ll" "$bridge")"
  # shellcheck disable=SC2016
  printf -v remote_script 'printf %%s %q | base64 -d >%q; sh %q; rc=$?; printf "\\n__O3K_GUEST_RC=%%d__\\n" "$rc"; rm -f %q; exit 0' \
    "$encoded" "$tmp" "$tmp" "$tmp"
  guest_remote_cmd="sh -c $(printf '%q' "$remote_script")"
  printf -v remote_cmd 'sudo timeout 60 ssh -6 -i %q -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%q -o HostKeyAlias=%q -o BindInterface=%q -o ConnectTimeout=8 %q %q' \
    "$control_root/probe_ed25519" "$remote_known" "o3k-probe-$host" "$bridge" "$target" "$guest_remote_cmd"
  if ! ssh_vm "$address" "$remote_cmd" >"$EVIDENCE/$label" 2>"$EVIDENCE/$label.stderr"; then
    LAST_GUEST_CHANNEL_ERROR=1
    printf 'transport=FAIL\n' >"$EVIDENCE/$label.status"
    return 1
  fi
  marker="$(grep -Eo '__O3K_GUEST_RC=[0-9]+' "$EVIDENCE/$label" | tail -1 | cut -d= -f2 || true)"
  if [[ ! "$marker" =~ ^[0-9]+$ ]]; then
    LAST_GUEST_CHANNEL_ERROR=1
    printf 'transport=FAIL\nmissing_guest_exit_marker=yes\n' >"$EVIDENCE/$label.status"
    return 1
  fi
  rc="$marker"
  printf 'transport=PASS\nguest_exit_code=%s\ncontrol_destination=%s\ncontrol_interface=%s\n' "$rc" "$ll" "$bridge" >"$EVIDENCE/$label.status"
  (( rc == 0 ))
}

guest_control_preflight() {
  local host="$1" address="${MGMT_IP[$1]}" bridge="${REALM_BRIDGE[$1]}" ll="${GUEST_IPV6[$1]}"
  local capture_root="/var/lib/o3k-fabric-v3/$RUN_ID/control/$host" fabric_ns
  fabric_ns="$(python3 - "$EVIDENCE/attachments/server-$host-provider-ownership.json" <<'PYNS'
import json,sys
print(json.load(open(sys.argv[1]))['fabric']['namespace'])
PYNS
)"
  if ! prepare_guest_control "$host"; then
    capture_guest_serial_output "$host" || true
    fail "host-local IPv6 link-local SSH unavailable for guest $host" "HARNESS_GAP"
  fi
  if ! guest_control_command "$host" true "compute-$host/control-true.txt"; then
    collect_guest_control_diagnostics "$host" || true
    fail "guest $host control true failed" "HARNESS_GAP"
  fi
  guest_control_command "$host" 'ip link show dev eth0' "compute-$host/control-ip-link.txt" || fail "guest $host ip link preflight failed" "HARNESS_GAP"
  guest_control_command "$host" 'ip addr show dev eth0' "compute-$host/control-ip-address.txt" || fail "guest $host interface address preflight failed" "HARNESS_GAP"
  guest_control_command "$host" 'ip -o -4 addr show dev eth0' "compute-$host/control-ipv4.txt" || fail "guest $host IPv4 preflight failed" "HARNESS_GAP"
  guest_control_command "$host" 'ip -o -6 addr show dev eth0 scope link' "compute-$host/control-ipv6-linklocal.txt" || fail "guest $host IPv6 link-local preflight failed" "HARNESS_GAP"
  grep -Fq "${TENANT_IP[$host]}/" "$EVIDENCE/compute-$host/control-ipv4.txt" || fail "guest $host lacks canonical DHCP IPv4 on eth0" "HARNESS_GAP"
  grep -Fq "${TENANT_IP[$host]}/" "$EVIDENCE/compute-$host/control-ip-address.txt" || fail "guest $host ip addr show lacks canonical DHCP IPv4" "HARNESS_GAP"
  grep -Fqi "$ll" "$EVIDENCE/compute-$host/control-ipv6-linklocal.txt" || fail "guest $host link-local did not match canonical MAC derivation" "HARNESS_GAP"
  sleep 10
  ssh_vm "$address" "sudo timeout 2 tcpdump -nn -r '$capture_root/local-control.pcap'" \
    >"$EVIDENCE/management/guest-$host-local-control-capture.txt" 2>&1 || true
  ssh_vm "$address" "sudo timeout 2 ip netns exec '$fabric_ns' tcpdump -nn -r '$capture_root/fabric-control.pcap'" \
    >"$EVIDENCE/management/guest-$host-fabric-control-capture.txt" 2>&1 || true
  ssh_vm "$address" "sudo cp '$capture_root/fabric-control.pcap' /tmp/$RUN_ID-$host-fabric.pcap && sudo chown '$SSH_USER:$SSH_USER' /tmp/$RUN_ID-$host-fabric.pcap" \
    || fail "guest $host Fabric control capture unavailable" "HARNESS_GAP"
  scp -i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" \
    "$SSH_USER@$address:/tmp/$RUN_ID-$host-fabric.pcap" "$EVIDENCE/management/guest-$host-fabric-control.pcap" \
    || fail "guest $host Fabric capture retrieval failed" "HARNESS_GAP"
  if grep -Fq "IP6 $ll." "$EVIDENCE/management/guest-$host-fabric-control-capture.txt"; then
    fail "guest $host control packet entered VXLAN/WireGuard namespace" "HARNESS_GAP"
  fi
  if ! grep -Fq "IP6 " "$EVIDENCE/management/guest-$host-local-control-capture.txt" \
    || ! grep -Fq "> $ll.22:" "$EVIDENCE/management/guest-$host-local-control-capture.txt" \
    || ! grep -Fq "$ll.22 >" "$EVIDENCE/management/guest-$host-local-control-capture.txt"; then
    fail "guest $host local Realm bridge did not observe control SSH" "HARNESS_GAP"
  fi
  printf 'guest_control=PASS\ncontrol_destination=%s\ncontrol_scope=%s\ncanonical_ipv4=%s\nlocal_bridge_capture=PASS\nfabric_namespace_capture=EMPTY\n' \
    "$ll" "$bridge" "${TENANT_IP[$host]}" >"$EVIDENCE/compute-$host/guest-control-result.txt"
  serial_report="$(python3 "$ROOT_DIR/tests/fabric-v3-guest-control.py" serial "$EVIDENCE/compute-$host/domain.xml")" \
  || fail "could not inspect live serial devices for $host" "HARNESS_GAP"
python3 - "$EVIDENCE/environment/control-channel-capabilities.json" "$host" "$serial_report" <<'PYCAP'
import json,pathlib,sys
path=pathlib.Path(sys.argv[1]); doc=json.loads(path.read_text()); host=sys.argv[2]; live=json.loads(sys.argv[3])
if live['serial_pty_interactive']:
    doc['mechanisms']['serial_pty'].update(present=True,interactive=True,bidirectional=True,accepted_for_control=False,discovery='live domain XML verified; profile selects the separately preflighted host-local link-local channel')
if live['file_backed_serial_read_only']:
    doc['mechanisms']['file_backed_serial'].update(present=True,read_only=True,discovery='live domain XML verified')
else:
    doc['mechanisms']['file_backed_serial'].update(present=False,read_only=False,discovery='live domain XML verified')
doc['mechanisms']['qemu_guest_agent'].update(present=live['qemu_guest_agent_present'],discovery='live domain XML channel targets inspected')
doc['mechanisms']['vsock'].update(present=live['vsock_present'],discovery='live domain XML devices inspected')
doc['mechanisms']['dedicated_management_nic'].update(present=live['dedicated_management_nic_present'],discovery='live domain XML network interface count inspected')
doc['mechanisms']['guest_ipv6_link_local_host_local_realm_bridge'].update(interactive=False,accepted_for_control=True,discovery='per-guest SSH/readiness/address checks passed; local bridge capture contains control flow and Fabric namespace capture is empty')
doc.setdefault('live_domains',{})[host]={**live,'guest_control':'host-local IPv6 link-local SSH','accepted_for_control':True}
path.write_text(json.dumps(doc,sort_keys=True,indent=2)+'\n')
PYCAP
  echo "GUEST CONTROL $host: PASS"
}

create_server a
GUEST_IPV6[a]="$(mac_link_local "${TENANT_MAC[a]}")"
if [[ "$DHCP_BOUNDARY_DIAGNOSTIC" != 1 ]]; then guest_control_preflight a; fi
create_server b
GUEST_IPV6[b]="$(mac_link_local "${TENANT_MAC[b]}")"
if [[ "$DHCP_BOUNDARY_DIAGNOSTIC" != 1 ]]; then guest_control_preflight b; fi
create_server c
GUEST_IPV6[c]="$(mac_link_local "${TENANT_MAC[c]}")"
if [[ "$DHCP_BOUNDARY_DIAGNOSTIC" != 1 ]]; then guest_control_preflight c; fi
printf 'server,host,tenant_ip,guest_mac\n' >"$EVIDENCE/canonical/endpoints.csv"
for host in a b c; do printf '%s,host-%s,%s,%s\n' "$host" "$host" "${TENANT_IP[$host]}" "${TENANT_MAC[$host]}" >>"$EVIDENCE/canonical/endpoints.csv"; done
python3 - "$EVIDENCE/manifest.json" "$EVIDENCE/environment/control-channel-capabilities.json" <<'PYMANIFEST'
import csv,json,pathlib,sys
manifest=pathlib.Path(sys.argv[1]); caps=json.loads(pathlib.Path(sys.argv[2]).read_text()); data=json.loads(manifest.read_text())
with (manifest.parent/'canonical/endpoints.csv').open() as stream:
    data['canonical_endpoints']={r['server']:{'host':r['host'],'fixed_ip':r['tenant_ip'],'canonical_guest_mac':r['guest_mac'],'dhcp':'PASS'} for r in csv.DictReader(stream)}
addresses=(manifest.parent/'environment/management-addresses.txt').read_text().splitlines()
data['management_addresses']={line.split('=',1)[0].split('-')[-1]:line.split('=',1)[1] for line in addresses}
data['stable_host_ids']={h:f'host-{h}' for h in 'abc'}
data['compute_agent_ids']={h:f'compute-agent-{h}' for h in 'abc'}
data['network_agent_ids']={h:f'network-agent-{h}' for h in 'abc'}
data['guest_control']='PASS A/B/C; host-local IPv6 link-local SSH; local Realm bridge scoped; Fabric namespace capture empty'
data['control_channel_capabilities']=caps['mechanisms']
data['live_domains']=caps.get('live_domains',{})
data['server_status']={h:'ACTIVE' for h in 'abc'}
manifest.write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')
PYMANIFEST

run_dhcp_boundary_tool() {
  local action="$1" harness_sha
  harness_sha="$(git -C "$ROOT_DIR" rev-parse HEAD)"
  python3 "$ROOT_DIR/tests/fabric-v3-remote-dhcp-boundary-capture.py" "$action" \
    --evidence "$EVIDENCE" --run-id "$RUN_ID" --key "$SSH_KEY" --known-hosts "$KNOWN_HOSTS" \
    --address-a "${MGMT_IP[a]}" --address-b "${MGMT_IP[b]}" --address-c "${MGMT_IP[c]}" \
    --endpoint-a "${PORT_IDS[0]}" --endpoint-b "${PORT_IDS[1]}" --endpoint-c "${PORT_IDS[2]}" \
    --mac-a "${TENANT_MAC[a]}" --mac-b "${TENANT_MAC[b]}" --mac-c "${TENANT_MAC[c]}" \
    --product-sha "$PRODUCT_SHA" --product-tree "$PRODUCT_TREE" --harness-sha "$harness_sha"
}

if [[ "$DHCP_BOUNDARY_DIAGNOSTIC" == 1 ]]; then
  # All three public creates have reached ACTIVE. Preserve the initial authority
  # capture, then take fresh ownership/plan-derived topology and verify HER and
  # WireGuard before observing one bounded B retry window.
  for host in a b c; do guest_control_preflight "$host"; done
  stop_dhcp_capture || fail "run-owned DHCP packet capture failed to stop or collect" "CLEANUP_DEFECT"
  [[ -s "$EVIDENCE/attachments/dhcp-dora.pcap" ]] \
    || fail "server A DHCP packet capture is absent before the B boundary run" "HARNESS_GAP"
  tcpdump -nn -e -tt -vvv -r "$EVIDENCE/attachments/dhcp-dora.pcap" 'udp and (port 67 or port 68)' \
    >"$EVIDENCE/dhcp/a-dora-before-b.txt" 2>&1 \
    || fail "server A DORA capture could not be decoded" "HARNESS_GAP"
  python3 - "$EVIDENCE/dhcp/a-dora-before-b.txt" "${TENANT_MAC[a]}" <<'PY' \
    || fail "A did not complete DHCP DORA before B packet tracing" "DATAPLANE_DEFECT"
import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text(errors='replace').lower(); mac=sys.argv[2].lower()
assert mac in text
for label in ('discover','offer','request','ack'):
    assert re.search(r'dhcp-message[^\n]*'+label,text,re.I),label
PY
  set +e
  run_dhcp_boundary_tool prepare >"$EVIDENCE/topology/prepare-result.json"
  prepare_rc=$?
  set -e
  cat "$EVIDENCE/topology/prepare-result.json"
  if (( prepare_rc != 0 )); then
    CAMPAIGN_TEARDOWN_PASS=1
    exit 0
  fi
  python3 - "$EVIDENCE/manifest.json" "$EVIDENCE/environment/inventory.tsv" "$EVIDENCE/environment" \
    "$EVIDENCE/compute-a/domain.txt" "$EVIDENCE/compute-b/domain.txt" "$EVIDENCE/compute-c/domain.txt" \
    "${MGMT_IP[a]}" "${MGMT_IP[b]}" "${MGMT_IP[c]}" <<'PY'
import json,pathlib,re,sys
manifest,inventory,environment,*rest=sys.argv[1:]
domains=[pathlib.Path(p).read_text().strip() for p in rest[:3]]
addresses=rest[3:]
outer={}
for line in pathlib.Path(inventory).read_text().splitlines():
    host,domain,address,mac,uuid=line.split('\t')
    outer[host[-1]]={"domain":domain,"domain_uuid":uuid,"management_ip":address,"management_mac":mac}
for i,h in enumerate('abc'):
    baseline=(pathlib.Path(environment)/f'baseline-compute-{h}.txt').read_text(errors='replace')
    def value(name):
        m=re.search(rf'(?m)^{re.escape(name)}=(.*)$',baseline)
        return m.group(1) if m else None
    outer[h].update({"boot_id":value('boot_id'),"kernel":value('kernel'),"os_release":value('os')})
canonical={}
for h in 'abc':
    port=json.load(open(pathlib.Path(manifest).parent/'api'/f'port-{h}.response.json'))['port']
    server=json.load(open(pathlib.Path(manifest).parent/'api'/f'server-{h}.create.response.json'))['server']
    canonical[h]={"server_id":server['id'],"endpoint_id":port['id'],"canonical_guest_mac":port['mac_address'],
                  "fixed_ip":port['fixed_ips'][0]['ip_address'],"status":"ACTIVE"}
data=json.load(open(manifest)); data.update({
    "started_at_utc":(pathlib.Path(environment)/'../started_at_utc.txt').resolve().read_text().strip(),
    "physical_host_identity":(pathlib.Path(environment)/'physical-host.txt').read_text(errors='replace').strip(),
    "canonical_endpoints":canonical,
    "fresh_nested_hosts":outer,
    "nested_compute_domains":{"a":domains[0],"b":domains[1],"c":domains[2]},
    "server_status":{"a":"ACTIVE","b":"ACTIVE","c":"ACTIVE"},
    "management_addresses":{"a":addresses[0],"b":addresses[1],"c":addresses[2]},
    "compute_agent_ids":{"a":"compute-agent-a","b":"compute-agent-b","c":"compute-agent-c"},
    "network_agent_ids":{"a":"network-agent-a","b":"network-agent-b","c":"network-agent-c"},
    "stable_host_ids":{"a":"host-a","b":"host-b","c":"host-c"},
    "database_backend":"SQLite (campaign controller data directory)",
})
json.dump(data,open(manifest,'w'),sort_keys=True,indent=2); open(manifest,'a').write('\n')
PY
  # Serial device capability was inventoried and the fresh live domain XML was
  # checked before use. This diagnostic uses serial only as read-only evidence.
  # Trigger a fresh B boot through the supported compute HTTP action;
  # B has no DHCP lease yet, so its normal boot client must issue DISCOVER.
  # Preserve both the exact request/response and the bounded state poll.
  python3 - "$EVIDENCE/api/server-b-dhcp-trigger.request.json" <<'PY'
import json,sys
json.dump({"reboot":{"type":"HARD"}},open(sys.argv[1],"w"),sort_keys=True)
open(sys.argv[1],"a").write("\n")
PY
  reboot_http_status="$(curl --silent --show-error --max-time 30 \
    --output "$EVIDENCE/api/server-b-dhcp-trigger.response.json" \
    --write-out '%{http_code}' -X POST \
    "$BASE/v2.1/$PROJECT_ID/servers/${SERVER_IDS[1]}/action" \
    -H "x-auth-token: $TOKEN" -H 'content-type: application/json' \
    --data-binary "@$EVIDENCE/api/server-b-dhcp-trigger.request.json")" \
    || fail "supported server-B reboot request failed at transport" "HARNESS_GAP"
  printf '%s\n' "$reboot_http_status" >"$EVIDENCE/api/server-b-dhcp-trigger.http-status"
  [[ "$reboot_http_status" == 202 ]] \
    || fail "supported server-B reboot returned HTTP $reboot_http_status" "HARNESS_GAP"
  reboot_seen_status=0
  for _ in $(seq 1 30); do
    api "$BASE/v2.1/$PROJECT_ID/servers/${SERVER_IDS[1]}" \
      >"$EVIDENCE/api/server-b-dhcp-trigger.current.json" \
      || fail "could not observe server B after accepted reboot" "HARNESS_GAP"
    reboot_status="$(field server.status <"$EVIDENCE/api/server-b-dhcp-trigger.current.json")"
    printf '%s\t%s\n' "$(date -u +%FT%TZ)" "$reboot_status" \
      >>"$EVIDENCE/api/server-b-dhcp-trigger.status-timeline.tsv"
    [[ "$reboot_status" == REBOOT || "$reboot_status" == REBOOTING ]] && reboot_seen_status=1
    [[ "$reboot_status" == ACTIVE ]] && break
    [[ "$reboot_status" == ERROR ]] && fail "server B entered ERROR during DHCP trigger reboot" "HARNESS_GAP"
    sleep 1
  done
  [[ "$reboot_status" == ACTIVE ]] \
    || fail "server B did not return ACTIVE after the accepted DHCP trigger reboot" "HARNESS_GAP"
  printf 'HTTP 202 accepted; returned ACTIVE; intermediate reboot status observed=%s\n' "$reboot_seen_status" \
    >"$EVIDENCE/api/server-b-dhcp-trigger.result.txt"
  set +e
  run_dhcp_boundary_tool finish >"$EVIDENCE/topology/finish-result.json"
  finish_rc=$?
  set -e
  cat "$EVIDENCE/topology/finish-result.json"
  # Preserve the exact authority configuration/process/lease state at the
  # packet boundary, without treating it as the cause unless its bridge capture
  # is the first present boundary.
  realm_id="$(python3 - "$EVIDENCE/topology/topology-map.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['a']['realm_id'])
PY
)"
  dhcp_root="/var/lib/o3k-fabric-v3/$RUN_ID/network/dhcp/fabric/$realm_id"
  ssh_vm "${MGMT_IP[a]}" "sudo cat '$dhcp_root/dnsmasq.conf'; sudo cat '$dhcp_root/state.json'" \
    >"$EVIDENCE/dhcp/generated-config-and-state.txt" 2>&1 || true
  ssh_vm "${MGMT_IP[a]}" "sudo cat '$dhcp_root/dnsmasq.leases' 2>/dev/null || true; sudo pgrep -a dnsmasq || true; sudo ss -lunp | grep -E ':(67|68)\\b' || true" \
    >"$EVIDENCE/dhcp/binding-process-state.txt" 2>&1 || true
  if ssh_vm "${MGMT_IP[b]}" "ip -j -4 address show" \
      >"$EVIDENCE/compute-b/dhcp-after-trigger-network.json"; then
    printf 'PASS\n' >"$EVIDENCE/compute-b/dhcp-after-trigger-network-status.txt"
  else
    printf '[]\n' >"$EVIDENCE/compute-b/dhcp-after-trigger-network.json"
    printf 'UNAVAILABLE\n' >"$EVIDENCE/compute-b/dhcp-after-trigger-network-status.txt"
  fi
  python3 - "$EVIDENCE/compute-b/dhcp-after-trigger-network.json" "${TENANT_IP[b]}" "$EVIDENCE/topology/finish-result.json" <<'PY'
import json,pathlib,sys
path,address,result_path=sys.argv[1:]
data=json.load(open(path))
addresses=[item.get('local') for iface in data for item in iface.get('addr_info',[])
           if item.get('family')=='inet']
leased=address in addresses
result=json.load(open(result_path))
result['b_guest_fixed_ip_after_trigger']=address
result['b_guest_ipv4_addresses_after_trigger']=addresses
result['b_guest_dhcp_address_confirmed']=leased
if result.get('reply_path_pass') and not leased:
    result['result']='BOUNDARY_ESTABLISHED'
    result['classification']='GUEST_DHCP_LEASE_NOT_CONFIRMED'
    result['first_absent_boundary']='B guest DHCP lease/address after reply delivery'
json.dump(result,open(result_path,'w'),sort_keys=True,indent=2); open(result_path,'a').write('\n')
PY
  if (( finish_rc != 0 )); then
    CAMPAIGN_TEARDOWN_PASS=1
    exit 0
  fi
  CAMPAIGN_TEARDOWN_PASS=1
  exit 0
fi

# Canonical guest IPv4 acquisition was proven through the host-local control
# channel before entering any packet predicate; serial output is evidence-only.
for host in a b c; do
  grep -Fq "${TENANT_IP[$host]}/" "$EVIDENCE/compute-$host/control-ipv4.txt" \
    || fail "guest $host did not receive its canonical fixed IP through DHCP" "HARNESS_GAP"
  python3 - "${TENANT_IP[$host]}" "${TENANT_MAC[$host]}" "$EVIDENCE/compute-$host/control-ipv4.txt" "$EVIDENCE/compute-$host/guest-ip.txt" <<'PYIP'
import pathlib,sys
address,mac,source,output=sys.argv[1:]
text=pathlib.Path(source).read_text(); assert address+'/' in text
pathlib.Path(output).write_text(f'guest_mac={mac}\ncanonical_fixed_ip={address}\ndhcp=PASS\n')
PYIP
done

stop_dhcp_capture || fail "run-owned DHCP packet capture failed to stop or collect" "CLEANUP_DEFECT"
[[ -s "$EVIDENCE/attachments/dhcp-dora.pcap" ]] \
  || fail "DHCP capture is empty" "DATAPLANE_DEFECT"
REALM_ID="$(python3 - "$EVIDENCE/attachments/server-a-provider-ownership.json" "${PORT_IDS[0]}" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); endpoint=sys.argv[2]
matches=[rid for rid,r in x.get('realms',{}).items() if endpoint in r.get('endpoint_taps',{})]
assert len(matches)==1,matches
print(matches[0])
PY
)" || fail "canonical DHCP Realm could not be resolved" "OWNERSHIP_DEFECT"
for host in a b c; do
  address="${MGMT_IP[$host]}"
  dhcp_root="/var/lib/o3k-fabric-v3/$RUN_ID/network/dhcp/fabric/$REALM_ID"
  ssh_vm "$address" "sudo cat '$dhcp_root/fabric-dhcp-ownership.json'" \
    >"$EVIDENCE/attachments/dhcp-host-$host-ownership.json" \
    || fail "host-$host has no durable Fabric DHCP ownership record" "DATAPLANE_DEFECT"
  if [[ "$host" == a ]]; then
    ssh_vm "$address" "sudo cat '$dhcp_root/state.json'" \
      >"$EVIDENCE/attachments/dhcp-host-$host-state.json" \
      || fail "selected authority has no Fabric DHCP state snapshot" "DATAPLANE_DEFECT"
  else
    ssh_vm "$address" "sudo find '$dhcp_root' -maxdepth 1 -type f -name 'dnsmasq-*.pid' -print 2>/dev/null || true" \
      >"$EVIDENCE/attachments/dhcp-host-$host-owned-pids.txt"
    [[ ! -s "$EVIDENCE/attachments/dhcp-host-$host-owned-pids.txt" ]] \
      || fail "non-authority host runs a competing Fabric DHCP authority" "SECURITY_DEFECT"
  fi
  if [[ "$host" == a ]]; then
    ssh_vm "$address" "sudo find '$dhcp_root' -maxdepth 1 -type f -name 'dnsmasq-*.pid' -print 2>/dev/null || true" \
      >"$EVIDENCE/attachments/dhcp-host-$host-owned-pids.txt"
  fi
done
ssh_vm "${MGMT_IP[a]}" "sudo cat '/var/lib/o3k-fabric-v3/$RUN_ID/network/dhcp/fabric/$REALM_ID/dnsmasq.conf'" \
  >"$EVIDENCE/attachments/dhcp-authority.conf" \
  || fail "authority DHCP configuration is absent" "DATAPLANE_DEFECT"
ssh_vm "${MGMT_IP[a]}" "sudo cat '/var/lib/o3k-fabric-v3/$RUN_ID/network/dhcp/fabric/$REALM_ID/dnsmasq.leases' 2>/dev/null || true" \
  >"$EVIDENCE/attachments/dhcp-authority.leases"
python3 - "$EVIDENCE/attachments" "$EVIDENCE/api" "${REALM_BRIDGE[a]}" <<'PY' \
  || fail "single DHCP authority, remote bindings, or MTU evidence failed" "DATAPLANE_DEFECT"
import json,pathlib,sys
root,api=map(pathlib.Path,sys.argv[1:3]); bridge=sys.argv[3]
expected={}
for host in 'abc':
    port=json.load(open(api/f'port-{host}.response.json'))['port']
    expected[port['id']]={'mac':port['mac_address'].lower(),'ip':port['fixed_ips'][0]['ip_address']}
    pids=[line for line in (root/f'dhcp-host-{host}-owned-pids.txt').read_text().splitlines() if line.strip()]
    assert len(pids)==(1 if host=='a' else 0),(host,pids)
for host in 'abc':
    owner=json.load(open(root/f'dhcp-host-{host}-ownership.json'))
    assert owner['local_host']==f'host-{host}',owner
    assert owner['authority_host']=='host-a' and owner['dhcp_enabled'] and not owner['pending'] and not owner['withdrawn'],owner
    assert owner['tenant_mtu']==1390,owner
state=json.load(open(root/'dhcp-host-a-state.json'))
assert state['config']['interface']==bridge,state['config']
assert state['config']['mtu']==1390,state['config']
bindings=state['bindings']
assert set(bindings)==set(expected),(bindings,expected)
for endpoint,want in expected.items():
    got=bindings[endpoint]
    assert got['mac'].lower()==want['mac'] and got['address']==want['ip'],(endpoint,got,want)
conf=(root/'dhcp-authority.conf').read_text()
assert f'interface={bridge}' in conf and 'dhcp-option=26,1390' in conf,conf
for value in expected.values():
    assert f"dhcp-host={value['mac']},{value['ip']}" in conf,(value,conf)
PY
tcpdump -nn -e -tt -vvv -r "$EVIDENCE/attachments/dhcp-dora.pcap" 'udp and (port 67 or port 68)' \
  >"$EVIDENCE/attachments/dhcp-dora-decoded.txt" 2>&1 \
  || fail "captured DHCP DORA pcap could not be decoded" "HARNESS_GAP"
python3 - "$EVIDENCE/attachments/dhcp-dora-decoded.txt" "$EVIDENCE/api" <<'PY' \
  || fail "DHCP DORA/cross-host broadcast/single-offer proof failed" "DATAPLANE_DEFECT"
import json,pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text(errors='replace')
api=pathlib.Path(sys.argv[2]); expected={}
for host in 'abc':
    p=json.load(open(api/f'port-{host}.response.json'))['port']
    expected[p['mac_address'].lower()]=p['fixed_ips'][0]['ip_address']
assert all(mac in text.lower() for mac in expected),(expected,text[:5000])
labels={'DISCOVER':r'DHCP-Message[^\n]*Discover','OFFER':r'DHCP-Message[^\n]*Offer',
        'REQUEST':r'DHCP-Message[^\n]*Request','ACK':r'DHCP-Message[^\n]*(?:ACK|Ack)'}
for name,pattern in labels.items(): assert re.search(pattern,text,re.I),(name,text[:5000])
blocks=re.split(r'(?m)(?=^\d+\.\d+\s)',text); offers=[]
for block in blocks:
    if not re.search(r'DHCP-Message[^\n]*Offer',block,re.I): continue
    xid=re.search(r' xid 0x([0-9a-f]+)',block,re.I)
    client=re.search(r'Client-Ethernet-Address:?\s+([0-9a-f:]{17})',block,re.I)
    server=re.search(r'Server-ID[^\n]*?([0-9]+(?:\.[0-9]+){3})',block,re.I)
    if xid and client and server: offers.append((xid.group(1).lower(),client.group(1).lower(),server.group(1)))
assert {client for _,client,_ in offers}==set(expected),offers
assert len({(xid,client,server) for xid,client,server in offers})==3,offers
assert len({server for _,_,server in offers})==1,offers
PY
echo 'FABRIC DHCP DORA: PASS (one authority; endpoint bindings A/B/C)' \
  >"$EVIDENCE/attachments/dhcp-dora-result.txt"

# A/B/C control preflight completed immediately after each ACTIVE create.
for host in a b c; do
  grep -Fq 'guest_control=PASS' "$EVIDENCE/compute-$host/guest-control-result.txt" \
    || fail "guest $host control channel did not pass preflight" "HARNESS_GAP"
done

guest_failure_class() {
  local phase_class="$1" transport_error=no
  (( LAST_GUEST_CHANNEL_ERROR )) && transport_error=yes
  python3 "$ROOT_DIR/tests/fabric-v3-guest-control.py" failure-class "$transport_error" "$phase_class"
}

if [[ "$CAMPAIGN_MODE" == departure-micro ]]; then
  guest_control_command a "ping -c 1 -W 4 ${TENANT_IP[b]}" before-departure/traffic/a-to-b-icmp.txt \
    || fail "micro-gate baseline A->B ICMP failed" "$(guest_failure_class DATAPLANE_DEFECT)"
  guest_control_command b "ping -c 1 -W 4 ${TENANT_IP[a]}" before-departure/traffic/b-to-a-icmp.txt \
    || fail "micro-gate baseline B->A ICMP failed" "$(guest_failure_class DATAPLANE_DEFECT)"
  guest_control_command a "ping -c 1 -W 4 ${TENANT_IP[c]}" before-departure/traffic/a-to-c-icmp.txt \
    || fail "micro-gate baseline A->C ICMP failed" "$(guest_failure_class DATAPLANE_DEFECT)"
  guest_control_command c "ping -c 1 -W 4 ${TENANT_IP[a]}" before-departure/traffic/c-to-a-icmp.txt \
    || fail "micro-gate baseline C->A ICMP failed" "$(guest_failure_class DATAPLANE_DEFECT)"
  guest_control_command a "ip neigh flush to ${TENANT_IP[b]} || true" before-departure/traffic/a-to-b-neighbor-flush.txt \
    || fail "could not clear A's cached B neighbor before canonical ARP proof" "HARNESS_GAP"
  guest_control_command a "ping -c 1 -W 4 ${TENANT_IP[b]} && ip neigh show to ${TENANT_IP[b]}" \
    before-departure/traffic/a-to-b-canonical-arp.txt \
    || fail "A could not resolve B's canonical remote ARP entry" "DATAPLANE_DEFECT"
  grep -Fqi "${TENANT_MAC[b]}" "$EVIDENCE/before-departure/traffic/a-to-b-canonical-arp.txt" \
    || fail "A's remote ARP entry did not resolve to B's canonical MAC" "DATAPLANE_DEFECT"
fi

if [[ "$CAMPAIGN_MODE" == full ]]; then
for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo ip -j -d link; sudo bridge -j link; sudo bridge -j fdb; sudo wg show; sudo nft list ruleset" >"$EVIDENCE/$([ "$host" = a ] && echo compute-a || ([ "$host" = b ] && echo compute-b || echo compute-c))/runtime-state.txt" || fail "runtime evidence failed for host-$host" "ENVIRONMENT_GAP"
done

for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json" >"$EVIDENCE/plans/host-$host-ownership.json" || fail "Fabric ownership snapshot failed on $host" "OWNERSHIP_DEFECT"
  realm_id="$(python3 - "$EVIDENCE/plans/host-$host-ownership.json" "${PORT_IDS[@]}" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); endpoints=set(sys.argv[2:])
matches=[rid for rid,r in x.get('realms',{}).items() if endpoints.intersection(r.get('endpoint_taps',{}))]
assert len(matches)==1, matches
print(matches[0])
PY
)" || fail "current Realm ownership could not be resolved on $host" "OWNERSHIP_DEFECT"
  echo "$realm_id" >"$EVIDENCE/plans/host-$host-realm-id.txt"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/plans/$realm_id.json" >"$EVIDENCE/plans/host-$host-fabric-plan.json" || fail "current Fabric plan snapshot failed on $host" "OWNERSHIP_DEFECT"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/executor/accepted-network-plans.json" >"$EVIDENCE/plans/host-$host-execution-plans.json" || fail "network execution plan snapshot failed on $host" "OWNERSHIP_DEFECT"
  fabric_ns="$(python3 - "$EVIDENCE/plans/host-$host-ownership.json" <<'PYNS'
import json,sys
print(json.load(open(sys.argv[1]))['fabric']['namespace'])
PYNS
)" || fail "Fabric namespace identity missing on host-$host" "OWNERSHIP_DEFECT"
  [[ "$fabric_ns" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || fail "invalid Fabric namespace identity on host-$host" "OWNERSHIP_DEFECT"
  printf '%s\n' "$fabric_ns" >"$EVIDENCE/wireguard/host-$host-namespace.txt"
  host_dir="$EVIDENCE/compute-$host"
  ssh_vm "$address" "sudo ip netns exec '$fabric_ns' ip -j -d link; sudo ip netns exec '$fabric_ns' bridge -j link; sudo ip netns exec '$fabric_ns' bridge -j fdb; sudo ip netns exec '$fabric_ns' wg show; sudo ip netns exec '$fabric_ns' ip route; sudo ip netns exec '$fabric_ns' nft list ruleset" >"$host_dir/fabric-runtime-state.txt" \
    || fail "Fabric namespace runtime evidence failed for host-$host" "ENVIRONMENT_GAP"
  ssh_vm "$address" "sudo ip netns exec '$fabric_ns' wg show all transfer; sudo ip netns exec '$fabric_ns' ip -d -j link" \
    >"$EVIDENCE/wireguard/host-$host-before-traffic.txt" || fail "WireGuard/VXLAN snapshot failed on host-$host" "ENVIRONMENT_GAP"
done

# Confirm HER converged to every remote participant in each durable current
# provider plan. Runtime link/FDB/WireGuard records above are retained beside it.
python3 - "$EVIDENCE/plans" <<'PY' || fail "HER participant convergence failed" "DATAPLANE_DEFECT"
import glob,json,sys
files=glob.glob(sys.argv[1]+"/host-*-fabric-plan.json")
assert len(files)==3
for path in files:
    x=json.load(open(path)); hosts={e["selected_host"] for e in x["directory"]["entries"]}
    assert hosts=={"host-a","host-b","host-c"}, (path,hosts)
PY

for host in a b c; do
  domain="$(cat "$EVIDENCE/compute-$host/domain.txt")"
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo virsh -c qemu:///system domiflist '$domain'" >"$EVIDENCE/compute-$host/interfaces.txt"
done

# Cold neighbor resolution and the six required tenant-address ICMP flows.
for pair in a:b b:a a:c c:a b:c c:b; do
  from="${pair%%:*}"; to="${pair##*:}"
  guest_control_command "$from" "ping -c 1 -W 4 ${TENANT_IP[$to]}" "icmp/$from-to-$to.txt" || fail "ICMP $from->$to failed" "$(guest_failure_class DATAPLANE_DEFECT)"
  guest_control_command "$from" "ip neigh show ${TENANT_IP[$to]}" "arp/$from-to-$to.txt" || fail "ARP observation $from->$to failed" "$(guest_failure_class DATAPLANE_DEFECT)"
  grep -Fqi "${TENANT_MAC[$to]}" "$EVIDENCE/arp/$from-to-$to.txt" || fail "ARP $from->$to resolved to wrong MAC" "DATAPLANE_DEFECT"
done

# Bounded TCP and UDP listeners run inside B/C probe guests; sender commands
# originate inside A over tenant addresses.
guest_control_command b 'rm -f /tmp/o3k-tcp-data; nohup nc -l -p 18081 >/tmp/o3k-tcp-data 2>&1 </dev/null &' tcp-listener.txt || fail "TCP listener setup failed" "$(guest_failure_class DATAPLANE_DEFECT)"
sleep 1
guest_control_command a "echo o3k-tcp-$RUN_ID | nc -w 5 ${TENANT_IP[b]} 18081" tcp/sender.txt || fail "TCP A->B failed" "$(guest_failure_class DATAPLANE_DEFECT)"
guest_control_command b 'grep -F o3k-tcp- /tmp/o3k-tcp-data' tcp/receiver.txt || fail "TCP payload did not arrive at B" "$(guest_failure_class DATAPLANE_DEFECT)"
guest_control_command c 'rm -f /tmp/o3k-udp-data; nohup nc -u -l -p 18082 >/tmp/o3k-udp-data 2>&1 </dev/null &' udp-listener.txt || fail "UDP listener setup failed" "$(guest_failure_class DATAPLANE_DEFECT)"
sleep 1
guest_control_command a "echo o3k-udp-$RUN_ID | nc -u -w 3 ${TENANT_IP[c]} 18082" udp/sender.txt || fail "UDP A->C failed" "$(guest_failure_class DATAPLANE_DEFECT)"
guest_control_command c 'sleep 1; grep -F o3k-udp- /tmp/o3k-udp-data' udp/receiver.txt || fail "UDP payload did not arrive at C" "$(guest_failure_class DATAPLANE_DEFECT)"

# Compare against the pre-traffic WireGuard snapshot. Private keys never enter
# the evidence bundle.
for host in a b c; do
  address="${MGMT_IP[$host]}"
  fabric_ns="$(cat "$EVIDENCE/wireguard/host-$host-namespace.txt")"
  ssh_vm "$address" "sudo ip netns exec '$fabric_ns' wg show all transfer" >"$EVIDENCE/wireguard/host-$host-after-traffic.txt" \
    || fail "Fabric namespace WireGuard counters unavailable on host-$host" "ENVIRONMENT_GAP"
done
python3 - "$EVIDENCE/wireguard" <<'PY' || fail "WireGuard traffic counters did not grow" "DATAPLANE_DEFECT"
import glob,sys
for before in glob.glob(sys.argv[1]+"/host-*-before-traffic.txt"):
    host=before.rsplit("/",1)[-1].split("-")[1]
    after=sys.argv[1]+f"/host-{host}-after-traffic.txt"
    old=sum(int(x.split()[2])+int(x.split()[3]) for x in open(before) if len(x.split())>=4 and x.split()[2].isdigit() and x.split()[3].isdigit())
    new=sum(int(x.split()[2])+int(x.split()[3]) for x in open(after) if len(x.split())>=4 and x.split()[2].isdigit() and x.split()[3].isdigit())
    assert new>old, (host,old,new)
PY

python3 - "$EVIDENCE/plans" "$EVIDENCE/wireguard" <<'PY' || fail "VXLAN VNI/link realization did not match Fabric plan" "DATAPLANE_DEFECT"
import glob,json,sys
vnis=set()
for path in glob.glob(sys.argv[1]+"/host-*-fabric-plan.json"):
    host=path.rsplit("/",1)[-1].split("-")[1]
    plan=json.load(open(path)); expected=plan["encapsulation"]["provider_segment_id"]
    vnis.add(expected)
    observation=open(sys.argv[2]+f"/host-{host}-before-traffic.txt").read()
    links=json.loads(observation[observation.index("["):])
    assert any(i.get("linkinfo",{}).get("info_kind")=="vxlan" and int(i.get("linkinfo",{}).get("info_data",{}).get("id",-1))==expected for i in links), (host,expected)
assert len(vnis)==1, vnis
PY

# Controller restart while A/B/C are alive. No tenant/API mutation wakes
# reconciliation; all six tenant flows are rerun after agents reconnect.
kill -TERM "$O3KD_PID"; wait "$O3KD_PID" 2>/dev/null || true; O3KD_PID=""
"$PRODUCT_SOURCE_DIR/target/release/o3kd" --listen-addr "$HOST_MGMT_IP:$API_PORT" --data-dir "$EVIDENCE/controller-data" --log-filter info >"$EVIDENCE/restart/o3kd.log" 2>&1 & O3KD_PID=$!
for _ in $(seq 1 120); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; kill -0 "$O3KD_PID" 2>/dev/null || fail "controller restart failed" "DURABLE_RECONCILIATION_GAP"; sleep 1; done
curl -fsS "$BASE/readyz" >"$EVIDENCE/restart/ready.json" || fail "controller did not become ready after restart" "DURABLE_RECONCILIATION_GAP"
for pair in a:b b:a a:c c:a b:c c:b; do
  from="${pair%%:*}"; to="${pair##*:}"
  guest_control_command "$from" "ping -c 1 -W 4 ${TENANT_IP[$to]}" "restart/$from-to-$to.txt" || fail "post-controller-restart ICMP $from->$to failed" "$(guest_failure_class DURABLE_RECONCILIATION_GAP)"
done
api "$BASE/v2.1/$PROJECT_ID/servers" >"$EVIDENCE/restart/servers.json" || fail "API unavailable after controller restart" "DURABLE_RECONCILIATION_GAP"
for host in a b c; do grep -Fq "$PREFIX-server-$host" "$EVIDENCE/restart/servers.json" || fail "server $host missing after controller recovery" "DURABLE_RECONCILIATION_GAP"; done

# Restart only compute-agent-b, preserving its run-owned domain. Prove process
# ownership before signaling it, then verify a new current epoch and tenant
# traffic through the same local guest-control abstraction.
old_ready="$EVIDENCE/compute-agent-restart/before-ready.json"
new_ready="$EVIDENCE/compute-agent-restart/after-ready.json"
ssh_vm "${MGMT_IP[b]}" 'sudo curl -fsS http://127.0.0.1:19102/readyz' >"$old_ready" \
  || fail "compute-agent-b pre-restart readiness unavailable" "HARNESS_GAP"
ssh_vm "${MGMT_IP[b]}" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/compute/agent.log" \
  >"$EVIDENCE/compute-agent-restart/agent-before.log" || fail "compute-agent-b log unavailable before restart" "HARNESS_GAP"
ssh_vm "${MGMT_IP[b]}" 'sudo bash -s' >"$EVIDENCE/compute-agent-restart/owned-process-stop.txt" <<EOF \
  || fail "compute-agent-b process ownership or bounded stop check failed" "OWNERSHIP_DEFECT"
pid=\$(cat /var/lib/o3k-fabric-v3/$RUN_ID/compute/agent.pid)
exe=\$(readlink -f /proc/\$pid/exe)
data=\$(tr '\0' '\n' </proc/\$pid/environ | sed -n 's/^O3K_COMPUTE_DATA_DIR=//p')
host=\$(tr '\0' '\n' </proc/\$pid/environ | sed -n 's/^O3K_COMPUTE_HOST_LABEL=//p')
test "\$exe" = /usr/local/bin/o3k-compute-bin
test "\$data" = /var/lib/o3k-fabric-v3/$RUN_ID/compute
test "\$host" = host-b
printf 'pid=%s\\nexe=%s\\ndata=%s\\nhost=%s\\n' "\$pid" "\$exe" "\$data" "\$host"
kill -TERM "\$pid"
for n in \$(seq 1 30); do curl -fsS http://127.0.0.1:19102/readyz >/dev/null 2>&1 || exit 0; sleep 1; done
exit 42
EOF
sleep 2
start_compute_agent b 19102 || fail "compute-agent-b restart launch failed" "HARNESS_GAP"
agent_ready=0
for _ in $(seq 1 120); do
  if ssh_vm "${MGMT_IP[b]}" 'sudo curl -fsS http://127.0.0.1:19102/readyz' >"$new_ready.tmp" 2>/dev/null; then
    mv "$new_ready.tmp" "$new_ready"
    agent_ready=1
    break
  fi
  sleep 1
done
(( agent_ready )) || fail "compute-agent-b did not re-register after restart" "DURABLE_RECONCILIATION_GAP"
python3 - "$old_ready" "$new_ready" <<'PY' || fail "compute-agent-b epoch did not advance while stable identity remained" "DURABLE_RECONCILIATION_GAP"
import json,sys
old,new=(json.load(open(p)) for p in sys.argv[1:])
assert old['agent_id']==new['agent_id']=='compute-agent-b', (old,new)
assert old.get('agent_epoch') and new.get('agent_epoch') and old['agent_epoch']!=new['agent_epoch'], (old,new)
PY
api "$BASE/v2.1/$PROJECT_ID/servers/${SERVER_IDS[1]}" >"$EVIDENCE/compute-agent-restart/server-b.json" \
  || fail "server B unavailable after compute-agent restart" "DURABLE_RECONCILIATION_GAP"
python3 - "$EVIDENCE/compute-agent-restart/server-b.json" <<'PY' || fail "server B placement changed after compute-agent restart" "DURABLE_RECONCILIATION_GAP"
import json,sys
s=json.load(open(sys.argv[1]))['server']
assert s['status']=='ACTIVE' and s.get('OS-EXT-SRV-ATTR:host')=='compute-agent-b', s
PY
ssh_vm "${MGMT_IP[b]}" "sudo virsh -c qemu:///system domstate '$(cat "$EVIDENCE/compute-b/domain.txt")'" \
  >"$EVIDENCE/compute-agent-restart/domain-state.txt" || fail "server B domain observation failed after compute-agent restart" "ENVIRONMENT_GAP"
[[ "$(tr -d '\r' <"$EVIDENCE/compute-agent-restart/domain-state.txt")" == running ]] \
  || fail "server B domain stopped during compute-agent restart" "DURABLE_RECONCILIATION_GAP"
guest_control_command b true compute-agent-restart/b-control-true.txt \
  || fail "guest control B failed after compute-agent restart" "$(guest_failure_class HARNESS_GAP)"
guest_control_command a "ping -c 1 -W 4 ${TENANT_IP[b]}" compute-agent-restart/a-to-b.txt \
  || fail "A->B failed after compute-agent restart" "$(guest_failure_class DURABLE_RECONCILIATION_GAP)"
guest_control_command b "ping -c 1 -W 4 ${TENANT_IP[a]}" compute-agent-restart/b-to-a.txt \
  || fail "B->A failed after compute-agent restart" "$(guest_failure_class DURABLE_RECONCILIATION_GAP)"

fi

# Remove C only through the supported API and prove HER/local endpoint
# withdrawal, then exercise A/B before final API teardown.
realm_id="$REALM_ID"
api "$BASE/v2.0/ports/${PORT_IDS[2]}" >"$EVIDENCE/endpoint-removal/port-c-before.json" \
  || fail "C port unavailable before removal" "SUPPORTED_API_GAP"
cp "$EVIDENCE/endpoint-removal/port-c-before.json" "$EVIDENCE/before-departure/host-c/port.json"
for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json" \
    >"$EVIDENCE/endpoint-removal/host-$host-ownership-before.json" \
    || fail "pre-removal ownership unavailable on $host" "OWNERSHIP_DEFECT"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/plans/$realm_id.json" \
    >"$EVIDENCE/endpoint-removal/host-$host-plan-before.json" \
    || fail "pre-removal Fabric plan unavailable on $host" "OWNERSHIP_DEFECT"
  cp "$EVIDENCE/endpoint-removal/host-$host-ownership-before.json" "$EVIDENCE/before-departure/host-$host/ownership.json"
  cp "$EVIDENCE/endpoint-removal/host-$host-plan-before.json" "$EVIDENCE/before-departure/plans/host-$host.json"
done
python3 - "$EVIDENCE/endpoint-removal" "$realm_id" "${PORT_IDS[@]}" <<'PY' \
  || fail "pre-delete canonical participant/HER state is not a healthy three-host Realm" "SURVIVOR_RECONCILIATION_DEFECT"
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); realm=sys.argv[2]; endpoints=sys.argv[3:]
assert len(endpoints)==3
expected={endpoint:f'host-{host}' for endpoint,host in zip(endpoints,'abc')}
plans={}
summary={}
for host in 'abc':
    owner=json.loads((root/f'host-{host}-ownership-before.json').read_text())
    assert realm in owner.get('realms',{}), (host,realm,owner.get('realms',{}).keys())
    local=owner['realms'][realm]
    plan=json.loads((root/f'host-{host}-plan-before.json').read_text())
    assert plan.get('realm_id')==realm and plan.get('local_host')==f'host-{host}', (host,plan)
    directory=plan.get('directory',{}).get('entries',[])
    observed={entry.get('endpoint_id'):entry.get('selected_host') for entry in directory}
    assert observed==expected, (host,observed,expected)
    peers={peer.get('host_id') for peer in plan.get('peers',[])}
    assert peers==set(f'host-{other}' for other in 'abc' if other!=host), (host,peers)
    assert int(plan.get('directory_generation',0))==int(local.get('directory_generation',-1)), (host,plan,local)
    assert int(plan.get('local_fabric_generation',0))==int(local.get('local_fabric_generation',-1)), (host,plan,local)
    vxlan=local.get('vxlan') or {}
    assert int(plan.get('encapsulation',{}).get('binding_generation',0))==int(vxlan.get('binding_generation',-1)), (host,plan,vxlan)
    assert local.get('endpoint_taps') and not local.get('pending_endpoint_taps'), (host,local)
    plans[host]=plan
    summary[host]={"local_host":plan['local_host'],"participants":sorted(set(observed.values())),
        "HER_peers":sorted(peers),"directory_generation":plan['directory_generation'],
        "binding_generation":plan['encapsulation']['binding_generation'],
        "local_fabric_generation":plan['local_fabric_generation'],
        "vni":plan['encapsulation']['provider_segment_id']}
assert len({summary[h]['vni'] for h in 'abc'})==1, summary
pathlib.Path(root/'pre-delete-plan-summary.json').write_text(json.dumps({"realm_id":realm,
    "hosts":summary},sort_keys=True,indent=2)+'\n')
PY
python3 - "$EVIDENCE/controller-data/o3k.sqlite" "$realm_id" \
  "$EVIDENCE/endpoint-removal/pre-delete-work-history.json" \
  "$EVIDENCE/endpoint-removal/pre-delete-plan-summary.json" <<'PY' \
  || fail "pre-delete durable Apply state or shared Realm generation is not current across A/B/C" "SURVIVOR_RECONCILIATION_DEFECT"
import json,pathlib,sqlite3,sys
path,realm,out,summary_path=sys.argv[1:]
db=sqlite3.connect(f"file:{path}?mode=ro",uri=True,timeout=3); db.row_factory=sqlite3.Row
rows=db.execute("SELECT rowid AS insertion_order,* FROM network_plan_work WHERE target_host_id IN ('host-a','host-b','host-c') ORDER BY rowid").fetchall()
history={host:[] for host in ('host-a','host-b','host-c')}
for row in rows:
    raw=bytes(row['snapshot']); command=json.loads(raw); plan=command.get('plan',{})
    fabric=plan.get('fabric',{}) if isinstance(plan,dict) else {}
    if fabric.get('realm_id')!=realm: continue
    outcome=row['outcome']
    history[row['target_host_id']].append({'insertion_order':row['insertion_order'],
        'command_id':row['command_id'],'operation_id':row['operation_id'],
        'idempotency_key':row['idempotency_key'],'controller_id':row['controller_id'],
        'controller_epoch':row['controller_epoch'],'target_host_id':row['target_host_id'],
        'target_agent_id':row['target_agent_id'],'target_agent_epoch':row['target_agent_epoch'],
        'action':command.get('action'),'realm_id':fabric.get('realm_id'),
        'directory_generation':fabric.get('directory_generation'),
        'local_host':fabric.get('local_host'),
        'binding_generation':fabric.get('encapsulation',{}).get('binding_generation'),
        'fabric_generation':fabric.get('local_fabric_generation'),
        'participants':sorted({entry.get('selected_host') for entry in fabric.get('directory',{}).get('entries',[])}),
        'her_peers':sorted({peer.get('host_id') for peer in fabric.get('peers',[])}),
        'realm_generation':plan.get('resource_generations',{}).get(realm),
        'state':row['state'],'revision':row['revision'],
        'outcome':bytes(outcome).decode('utf-8',errors='replace') if outcome is not None else None,
        'created_at':row['created_at'],'updated_at':row['updated_at']})
latest={host:(items[-1] if items else None) for host,items in history.items()}
# Persist the raw durable work observation before evaluating predicates so an
# unsuccessful pre-delete check still has enough evidence to diagnose.
pathlib.Path(out).write_text(json.dumps({'realm_id':realm,'status':'observed_before_predicate_checks',
    'history':history,'latest':latest,'c_prior_apply':latest['host-c']},sort_keys=True,indent=2)+'\n')
assert all(latest[h] and latest[h]['action']=='Apply' and latest[h]['state']=='succeeded' for h in history),latest
assert all(latest[h]['target_agent_id']==f'network-agent-{h[-1]}' for h in history),latest
realm_generations={latest[h]['realm_generation'] for h in history}
assert len(realm_generations)==1 and None not in realm_generations,latest
expected_participants=['host-a','host-b','host-c']
summary=json.loads(pathlib.Path(summary_path).read_text())
for host in history:
    suffix=host[-1]
    assert latest[host]['participants']==expected_participants,latest[host]
    assert latest[host]['her_peers']==[peer for peer in expected_participants if peer!=host],latest[host]
    assert latest[host]['directory_generation']==summary['hosts'][suffix]['directory_generation'],(latest[host],summary['hosts'][suffix])
    summary['hosts'][suffix]['realm_generation']=latest[host]['realm_generation']
summary['realm_generation']=next(iter(realm_generations))
pathlib.Path(summary_path).write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
pathlib.Path(out).write_text(json.dumps({'realm_id':realm,'history':history,'latest':latest,
    'c_prior_apply':latest['host-c']},sort_keys=True,indent=2)+'\n')
PY
cp "$EVIDENCE/endpoint-removal/pre-delete-work-history.json" "$EVIDENCE/before-departure/durable-work/history.json"
cp "$EVIDENCE/endpoint-removal/pre-delete-work-history.json" "$EVIDENCE/c-delete/retirement-obligation/c-prior-apply.json"
python3 - "$EVIDENCE" "$RUN_ID" "$O3K_CONTROLLER_ID" "$O3K_CONTROLLER_EPOCH" "$FABRIC_DOMAIN_ID" <<'PY' \
  || fail "retirement manifest could not bind the live host and controller identities" "HARNESS_GAP"
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); run,controller_id,controller_epoch,fabric_domain_id=sys.argv[2:]
manifest_path=root/'manifest.json'; manifest=json.loads(manifest_path.read_text())
assert manifest.get('fabric_domain_id')==fabric_domain_id, manifest.get('fabric_domain_id')
summary=json.loads((root/'endpoint-removal/pre-delete-plan-summary.json').read_text())
work=json.loads((root/'endpoint-removal/pre-delete-work-history.json').read_text())
identities=json.loads((root/'environment/fabric-identities.json').read_text())
inventory={}
for line in (root/'environment/inventory.tsv').read_text().splitlines():
    role,domain,address,mac,guest_uuid=line.split('\t')
    inventory[role[-1]]={'domain':domain,'guest_uuid':guest_uuid,'management_ip':address,'management_mac':mac}
hosts={}
for host in 'abc':
    baseline=(root/f'environment/baseline-compute-{host}.txt').read_text()
    values={line.split('=',1)[0]:line.split('=',1)[1] for line in baseline.splitlines()
            if '=' in line and line.split('=',1)[0] in {'boot_id','kernel','os'}}
    ready=json.loads((root/f'management/compute-{host}-ready.json').read_text())
    latest=work['latest'][f'host-{host}']
    provider=next(item for item in identities if item['host_id']==f'host-{host}')
    assert ready.get('agent_id')==f'compute-agent-{host}' and ready.get('agent_epoch'), ready
    assert latest.get('target_agent_id')==f'network-agent-{host}' and latest.get('target_agent_epoch'), latest
    assert values.get('boot_id') and values.get('kernel'), values
    hosts[f'host-{host}']={
        **inventory[host], 'kernel':values['kernel'],'boot_id':values['boot_id'],
        'compute_agent_id':ready['agent_id'],'compute_agent_epoch':ready['agent_epoch'],
        'network_agent_id':latest['target_agent_id'],'network_agent_epoch':latest['target_agent_epoch'],
        'stable_host_id':provider['host_id'],'fabric_generation':provider['fabric_generation'],
        'local_fabric_generation':summary['hosts'][host]['local_fabric_generation']}
assert len({value['guest_uuid'] for value in hosts.values()})==3, hosts
assert len({value['management_ip'] for value in hosts.values()})==3, hosts
assert len({value['boot_id'] for value in hosts.values()})==3, hosts
assert len({value['compute_agent_id'] for value in hosts.values()})==3, hosts
assert len({value['network_agent_id'] for value in hosts.values()})==3, hosts
assert len({value['stable_host_id'] for value in hosts.values()})==3, hosts
assert all(value['compute_agent_epoch'] and value['network_agent_epoch'] for value in hosts.values()), hosts
manifest.update({'database_backend':'sqlite','controller':{'identity':controller_id,'epoch':controller_epoch},
    'fabric_domain_id':fabric_domain_id,'realm_id':summary['realm_id'],
    'vni':summary['hosts']['a']['vni'],'realm_generation':summary['realm_generation'],
    'hosts':hosts})
manifest_path.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
PY
python3 - "$EVIDENCE/endpoint-removal/host-c-ownership-before.json" "$realm_id" "${PORT_IDS[2]}" <<'PY' >"$EVIDENCE/endpoint-removal/c-owned-objects.json" \
  || fail "C endpoint or local Realm ownership missing before removal" "OWNERSHIP_DEFECT"
import json,sys
state=json.load(open(sys.argv[1])); realm=state['realms'][sys.argv[2]]; endpoint=sys.argv[3]
tap=realm['endpoint_taps'][endpoint]['interface']
json.dump({"endpoint":endpoint,"tap":tap,"namespace":realm["namespace"],"bridge":realm["bridge"],
 "host_veth":realm["host_veth"],"public_host_veth":realm.get("public_host_veth"),
 "vxlan":realm.get("vxlan")},sys.stdout,sort_keys=True,indent=2)
print()
PY
ssh_vm "${MGMT_IP[c]}" 'sudo nft list ruleset' >"$EVIDENCE/endpoint-removal/c-nft-before.txt" \
  || fail "C anti-spoof pre-removal state unavailable" "ENVIRONMENT_GAP"
delete_started_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
printf '%s\n' "$delete_started_at" >"$EVIDENCE/c-delete/operation/request-started-at-utc.txt"
delete_status="$(curl --silent --show-error --max-time 60 -D "$EVIDENCE/c-delete/operation/response-headers.txt" \
  -o "$EVIDENCE/c-delete/operation/response-body.txt" -w '%{http_code}' -X DELETE \
  "$BASE/v2.1/$PROJECT_ID/servers/${SERVER_IDS[2]}" -H "x-auth-token: $TOKEN")" \
  || fail "supported server C deletion request failed" "CLEANUP_DEFECT"
printf '%s\n' "$delete_status" >"$EVIDENCE/c-delete/operation/http-status.txt"
[[ "$delete_status" == 204 ]] || fail "supported server C deletion returned HTTP $delete_status" "CLEANUP_DEFECT"
if python3 "$ROOT_DIR/tests/fabric-v3-delete-operation-evidence.py" \
  "$EVIDENCE/controller-data/o3k.sqlite" "${SERVER_IDS[2]}" "$delete_started_at" "$delete_status" \
  "$EVIDENCE/c-delete/operation/audit-terminal-state.json"; then
  :
else
  evidence_status=$?
  if [[ "$evidence_status" == 2 ]]; then
    fail "supported C deletion evidence source could not be read safely" "HARNESS_GAP"
  fi
  fail "supported C deletion lacks successful durable lifecycle and audit records" "CLEANUP_DEFECT"
fi
cp "$EVIDENCE/c-delete/operation/audit-terminal-state.json" "$EVIDENCE/endpoint-removal/server-c-delete.txt"
printf 'observed_at_utc,state,revision,command_id\n' >"$EVIDENCE/endpoint-removal/c-remove-work-row-observations.csv"
printf 'attempt,server_absent,c_remove_found,c_remove_state\n' >"$EVIDENCE/endpoint-removal/convergence-attempts.csv"
converged=0
for attempt in $(seq 1 120); do
  server_absent=0
  server_status="$(curl --silent --show-error --max-time 10 -o "$EVIDENCE/endpoint-removal/server-c-final.json" \
      -w '%{http_code}' "$BASE/v2.1/$PROJECT_ID/servers/${SERVER_IDS[2]}" -H "x-auth-token: $TOKEN" || true)"
  [[ "$server_status" == 404 ]] && server_absent=1
  durable_state="$(capture_c_remove_work_row "$realm_id")" \
    || fail "read_c_remove_durable_work_history failed" "HARNESS_GAP"
  remove_found="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("found",False))' "$EVIDENCE/endpoint-removal/c-remove-work-row.json")"
  if [[ "$remove_found" == True ]]; then
    printf '%s,%s,%s,%s\n' "$(date -u +%FT%TZ)" "$durable_state" \
      "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("revision",""))' "$EVIDENCE/endpoint-removal/c-remove-work-row.json")" \
      "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("command_id",""))' "$EVIDENCE/endpoint-removal/c-remove-work-row.json")" \
      >>"$EVIDENCE/endpoint-removal/c-remove-work-row-observations.csv"
  fi
  printf '%s,%s,%s,%s\n' "$attempt" "$server_absent" "$remove_found" "$durable_state" \
    >>"$EVIDENCE/endpoint-removal/convergence-attempts.csv"
  if (( server_absent )) && [[ "$remove_found" == True && "$durable_state" == succeeded ]]; then converged=1; break; fi
  sleep 1
done
if (( ! converged )); then
  remove_found="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("found",False))' "$EVIDENCE/endpoint-removal/c-remove-work-row.json" 2>/dev/null || echo false)"
  if [[ "$remove_found" != True ]]; then
    fail "C server deletion reached terminal absence without a durable C Remove obligation" "DURABLE_RETIREMENT_DEFECT"
  fi
  remove_state="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("state",""))' "$EVIDENCE/endpoint-removal/c-remove-work-row.json")"
  if [[ "$remove_state" != succeeded ]]; then
    fail "C Remove did not reach successful observed completion on network-agent-c within 120 seconds (state=$remove_state)" "REMOVE_DISPATCH_DEFECT"
  fi
  fail "server C deletion did not reach API absence within 120 seconds" "CLEANUP_DEFECT"
fi
cp "$EVIDENCE/endpoint-removal/c-remove-work-row.json" "$EVIDENCE/c-delete/remove-command/c-remove-command.json"
python3 - "$EVIDENCE/endpoint-removal/pre-delete-work-history.json" \
  "$EVIDENCE/endpoint-removal/c-remove-work-row.json" \
  "$EVIDENCE/c-delete/retirement-obligation/c-durable-obligation.json" <<'PY' \
  || fail "durable C retirement obligation does not follow C's latest successful Apply" "DURABLE_RETIREMENT_DEFECT"
import json,pathlib,sys
before=json.load(open(sys.argv[1])); remove=json.load(open(sys.argv[2])); prior=before['c_prior_apply']
assert prior['action']=='Apply' and prior['state']=='succeeded', prior
assert remove.get('found') and remove.get('action')=='Remove' and remove.get('state')=='succeeded', remove
assert remove.get('target_host_id')=='host-c' and remove.get('target_agent_id')=='network-agent-c', remove
assert remove.get('local_host')=='host-c', remove
assert int(remove['insertion_order'])>int(prior['insertion_order']), (prior,remove)
assert remove.get('target_agent_epoch') and remove.get('operation_id') and remove.get('idempotency_key'), remove
assert remove.get('realm_generation') is not None, remove
pathlib.Path(sys.argv[3]).write_text(json.dumps({'latest_c_apply':prior,
    'durable_retirement_obligation_detected':True,'c_remove':remove,
    'ordering':'C Apply history precedes durable C Remove'},sort_keys=True,indent=2)+'\n')
PY
api "$BASE/v2.0/ports/${PORT_IDS[2]}" >"$EVIDENCE/endpoint-removal/port-c-after.json" \
  || fail "C port tombstone unavailable after server deletion" "PORT_STATUS_DEFECT"
cp "$EVIDENCE/endpoint-removal/port-c-after.json" "$EVIDENCE/c-delete/port/api-after.json"
python3 - "$EVIDENCE/endpoint-removal/port-c-after.json" <<'PY' \
  || fail "C port did not reach an unbound DOWN tombstone" "PORT_STATUS_DEFECT"
import json,sys
obj=json.load(open(sys.argv[1])); port=obj.get('port',obj)
assert port.get('status')=='DOWN', port
assert not port.get('device_id'), port
assert not port.get('binding:host_id'), port
PY
if python3 "$ROOT_DIR/tests/fabric-v3-port-detach-evidence.py" \
  "$EVIDENCE/controller-data/o3k.sqlite" "${PORT_IDS[2]}" \
  "$EVIDENCE/c-delete/port/durable-after.json"; then
  :
else
  durable_port_status=$?
  if (( durable_port_status == 1 )); then
    fail "C port durable binding tombstone is not unbound DOWN" "PORT_STATUS_DEFECT"
  fi
  fail "C port durable binding observation unavailable" "HARNESS_GAP"
fi
capture_c_remove_work_row "$realm_id" >"$EVIDENCE/endpoint-removal/c-remove-work-row-final-state.txt" \
  || fail "final C Remove durable work read failed" "HARNESS_GAP"
ssh_vm "${MGMT_IP[c]}" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/executor/accepted-network-plans.json" \
  >"$EVIDENCE/endpoint-removal/host-c-command-journal.json" \
  || fail "C Remove command journal unavailable" "REMOVE_DISPATCH_DEFECT"
cp "$EVIDENCE/endpoint-removal/host-c-command-journal.json" "$EVIDENCE/c-delete/agent-journal/network-agent-c.json"
ssh_vm "${MGMT_IP[c]}" "sudo tail -n 500 /var/lib/o3k-fabric-v3/$RUN_ID/network/agent.log" \
  >"$EVIDENCE/endpoint-removal/host-c-network-agent.log" \
  || fail "C network-agent removal log unavailable" "REMOVE_DISPATCH_DEFECT"
cp "$EVIDENCE/endpoint-removal/host-c-network-agent.log" "$EVIDENCE/c-delete/agent-journal/network-agent-c.log"
python3 - "$EVIDENCE/endpoint-removal/c-remove-work-row.json" \
  "$EVIDENCE/endpoint-removal/host-c-command-journal.json" "$realm_id" <<'PY' \
  || fail "C Remove was not durably dispatched, admitted, and observed successful" "REMOVE_DISPATCH_DEFECT"
import json,sys
row_path,journal_path,realm=sys.argv[1:]
row=json.load(open(row_path)); assert row.get('found') and row.get('state')=='succeeded', row
assert row.get('target_host_id')=='host-c' and row.get('target_agent_id')=='network-agent-c', row
assert row.get('action')=='Remove' and row.get('realm_id')==realm, row
assert row.get('local_host')=='host-c', row
journal=json.load(open(journal_path))
matches=[p for p in journal.get('plans',[]) if p.get('action')=='Remove' and p.get('plan',{}).get('fabric',{}).get('realm_id')==realm]
assert matches, 'executor journal has no C Remove'
command=matches[-1]
assert command.get('target',{}).get('agent_id')=='network-agent-c', command
assert command.get('plan',{}).get('fabric',{}).get('local_host')=='host-c', command
assert command.get('status')=='Succeeded', command
assert command.get('command_id')==row.get('command_id'), (command,row)
print(json.dumps({k:command.get(k) for k in ('command_id','operation_id','action','target','status')},sort_keys=True,indent=2))
PY
python3 - "$EVIDENCE/endpoint-removal/c-owned-objects.json" >"$EVIDENCE/endpoint-removal/c-owned-objects-after.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); json.dump({"tap":x["tap"],"bridge":x["bridge"],"namespace":x["namespace"],
 "host_veth":x["host_veth"],"public_host_veth":x.get("public_host_veth"),"vxlan":x.get("vxlan")},sys.stdout,sort_keys=True,indent=2)
print()
PY
tap_name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tap"])' "$EVIDENCE/endpoint-removal/c-owned-objects.json")"
if ssh_vm "${MGMT_IP[c]}" "sudo ip -j -d link show dev '$tap_name'" >"$EVIDENCE/endpoint-removal/c-tap-after.json" 2>&1; then
  fail "C endpoint TAP remains after Remove: $tap_name" "CLEANUP_DEFECT"
fi
for field_name in bridge host_veth public_host_veth; do
  object_name="$(python3 - "$EVIDENCE/endpoint-removal/c-owned-objects.json" "$field_name" <<'PY'
import json,sys
print(json.load(open(sys.argv[1])).get(sys.argv[2]) or '')
PY
)"
  [[ -z "$object_name" ]] && continue
  if ssh_vm "${MGMT_IP[c]}" "sudo ip -j -d link show dev '$object_name'" >"$EVIDENCE/endpoint-removal/c-$field_name-after.json" 2>&1; then
    fail "C Realm link remains after final endpoint departure: $object_name" "CLEANUP_DEFECT"
  fi
done
namespace_name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["namespace"])' "$EVIDENCE/endpoint-removal/c-owned-objects.json")"
ssh_vm "${MGMT_IP[c]}" 'sudo ip netns list' >"$EVIDENCE/endpoint-removal/c-namespaces-after.txt" \
  || fail "C namespace state unavailable after Remove" "ENVIRONMENT_GAP"
if awk '{print $1}' "$EVIDENCE/endpoint-removal/c-namespaces-after.txt" | grep -Fxq "$namespace_name"; then
  fail "C Realm namespace remains after final endpoint departure" "CLEANUP_DEFECT"
fi
vxlan_host_veth="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1])).get("vxlan") or {}).get("host_veth", ""))' "$EVIDENCE/endpoint-removal/c-owned-objects.json")"
if [[ -n "$vxlan_host_veth" ]] && ssh_vm "${MGMT_IP[c]}" "sudo ip -j -d link show dev '$vxlan_host_veth'" >"$EVIDENCE/endpoint-removal/c-vxlan-host-veth-after.json" 2>&1; then
  fail "C host-side VXLAN attachment remains after final endpoint departure" "CLEANUP_DEFECT"
fi
for field_name in interface bridge fabric_veth; do
  object_name="$(python3 - "$EVIDENCE/endpoint-removal/c-owned-objects.json" "$field_name" <<'PY'
import json,sys
print(((json.load(open(sys.argv[1])).get('vxlan') or {}).get(sys.argv[2])) or '')
PY
)"
  [[ -z "$object_name" ]] && continue
  if ssh_vm "${MGMT_IP[c]}" "sudo ip netns exec '$namespace_name' ip -j -d link show dev '$object_name'" \
      >"$EVIDENCE/endpoint-removal/c-fabric-$object_name-after.json" 2>&1; then
    fail "C Realm VXLAN consumer remains after final endpoint departure: $object_name" "CLEANUP_DEFECT"
  fi
done
if ssh_vm "${MGMT_IP[c]}" "sudo test -e /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/plans/$realm_id.json"; then
  fail "C durable Realm plan remains after Remove" "CLEANUP_DEFECT"
fi
ssh_vm "${MGMT_IP[c]}" 'sudo nft list ruleset' >"$EVIDENCE/endpoint-removal/c-nft-after.txt" \
  || fail "C anti-spoof post-removal state unavailable" "ENVIRONMENT_GAP"
if grep -Fqi "${TENANT_MAC[c]}" "$EVIDENCE/endpoint-removal/c-nft-after.txt"; then
  fail "C endpoint anti-spoof state remains after Remove" "CLEANUP_DEFECT"
fi
source "$ROOT_DIR/tests/fabric-v3-retirement-microgate.sh"
run_retirement_microgate "$REALM_ID"

# Supported API teardown; provider state is never manually repaired/deleted.
python3 - "$EVIDENCE/endpoint-removal" "$EVIDENCE/teardown/run-owned-provider-objects.json" "$REALM_ID" <<'PY' \
  || fail "run-owned provider identity snapshot failed before teardown" "OWNERSHIP_DEFECT"
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2]); realm_id=sys.argv[3]
objects={}
for host in ('a','b'):
    state=json.loads((root/f'host-{host}-ownership.json').read_text())
    realm=state['realms'][realm_id]
    objects[host]={"namespace":realm["namespace"],"links":[realm["bridge"],realm["host_veth"]],
                   "endpoint_taps":[entry["interface"] for entry in realm.get("endpoint_taps",{}).values()],
                   "vxlan":realm.get("vxlan")}
for host in ('a','b'):
    vxlan=objects[host].get('vxlan') or {}
    objects[host]['links'] += [vxlan.get('host_veth'),vxlan.get('interface'),vxlan.get('bridge'),vxlan.get('fabric_veth')]
    objects[host]['links']=[value for value in objects[host]['links'] if value]
c=json.loads((root/'c-owned-objects.json').read_text())
objects['c']={"namespace":c["namespace"],"links":[c.get("bridge"),c.get("host_veth"),c.get("public_host_veth"),
                 (c.get("vxlan") or {}).get("host_veth"),(c.get("vxlan") or {}).get("interface"),
                 (c.get("vxlan") or {}).get("bridge"),(c.get("vxlan") or {}).get("fabric_veth")],
              "endpoint_taps":[c["tap"]]}
objects['c']['links']=[value for value in objects['c']['links'] if value]
out.write_text(json.dumps(objects,sort_keys=True,indent=2)+'\n')
PY
for index in 1 0; do
  id="${SERVER_IDS[$index]}"
  curl --fail --silent --show-error --max-time 60 -X DELETE "$BASE/v2.1/$PROJECT_ID/servers/$id" -H "x-auth-token: $TOKEN" >"$EVIDENCE/teardown/server-${id}.delete.txt" || fail "supported server delete failed: $id" "CLEANUP_DEFECT"
done
servers_remaining=1
server_poll_deadline=$((SECONDS + 120))
for attempt in $(seq 1 120); do
  (( SECONDS < server_poll_deadline )) || break
  left=0
  poll_complete=1
  for id in "${SERVER_IDS[@]}"; do
    request_timeout=$((server_poll_deadline - SECONDS))
    if (( request_timeout <= 0 )); then poll_complete=0; break; fi
    response_file="$EVIDENCE/teardown/server-$id.poll-$attempt.response.txt"
    if ! status="$(curl --silent --show-error --max-time "$request_timeout" -o "$response_file" -w '%{http_code}' \
      "$BASE/v2.1/$PROJECT_ID/servers/$id" -H "x-auth-token: $TOKEN")"; then
      fail "server deletion observation failed for $id" "CLEANUP_DEFECT"
    fi
    case "$status" in
      404) ;;
      200) left=1 ;;
      *) fail "unexpected server deletion observation HTTP $status for $id" "CLEANUP_DEFECT" ;;
    esac
  done
  (( poll_complete == 1 )) || break
  if (( left == 0 )); then servers_remaining=0; break; fi
  (( SECONDS < server_poll_deadline )) || break
  sleep 1
done
(( servers_remaining == 0 )) || fail "server deletion did not converge within 120 seconds" "CLEANUP_DEFECT"
for id in "${PORT_IDS[@]}"; do curl --fail --silent --show-error --max-time 30 -X DELETE "$BASE/v2.0/ports/$id" -H "x-auth-token: $TOKEN" >"$EVIDENCE/teardown/port-$id.delete.txt" || fail "supported port delete failed: $id" "CLEANUP_DEFECT"; done
curl --fail --silent --show-error --max-time 30 -X DELETE "$BASE/v2.0/subnets/$SUBNET_ID" -H "x-auth-token: $TOKEN" >"$EVIDENCE/teardown/subnet-delete.txt" || fail "supported subnet delete failed" "CLEANUP_DEFECT"
curl --fail --silent --show-error --max-time 30 -X DELETE "$BASE/v2.0/networks/$NETWORK_ID" -H "x-auth-token: $TOKEN" >"$EVIDENCE/teardown/network-delete.txt" || fail "supported network delete failed" "CLEANUP_DEFECT"
curl --fail --silent --show-error --max-time 30 -X DELETE "$BASE/v2/images/$IMAGE_ID" -H "x-auth-token: $TOKEN" >"$EVIDENCE/teardown/image-delete.txt" || fail "supported image delete failed" "CLEANUP_DEFECT"
verify_api_resource_absent() {
  local label="$1" path="$2" status attempt output="$EVIDENCE/teardown/api-absence-$1.txt"
  for attempt in $(seq 1 60); do
    if ! status="$(curl --silent --show-error --max-time 20 -o "$output.body" -w '%{http_code}' \
      "$BASE$path" -H "x-auth-token: $TOKEN")"; then
      fail "could not observe supported API absence for $label" "CLEANUP_DEFECT"
    fi
    printf '%s\t%s\n' "$attempt" "$status" >>"$output"
    if [[ "$status" == 404 ]]; then
      printf 'PASS\n' >>"$output"
      rm -f -- "$output.body"
      return 0
    fi
    [[ "$status" == 200 ]] \
      || fail "unexpected HTTP $status while proving API absence for $label" "CLEANUP_DEFECT"
    sleep 2
  done
  fail "run-owned API resource remains after supported teardown: $label" "CLEANUP_DEFECT"
}
: >"$EVIDENCE/teardown/api-resource-absence.txt"
for id in "${SERVER_IDS[@]}"; do
  verify_api_resource_absent "server-$id" "/v2.1/$PROJECT_ID/servers/$id"
  printf 'server\t%s\tabsent\n' "$id" >>"$EVIDENCE/teardown/api-resource-absence.txt"
done
for id in "${PORT_IDS[@]}"; do
  verify_api_resource_absent "port-$id" "/v2.0/ports/$id"
  printf 'port\t%s\tabsent\n' "$id" >>"$EVIDENCE/teardown/api-resource-absence.txt"
done
verify_api_resource_absent "subnet-$SUBNET_ID" "/v2.0/subnets/$SUBNET_ID"
printf 'subnet\t%s\tabsent\n' "$SUBNET_ID" >>"$EVIDENCE/teardown/api-resource-absence.txt"
verify_api_resource_absent "network-$NETWORK_ID" "/v2.0/networks/$NETWORK_ID"
printf 'network\t%s\tabsent\n' "$NETWORK_ID" >>"$EVIDENCE/teardown/api-resource-absence.txt"
verify_api_resource_absent "image-$IMAGE_ID" "/v2/images/$IMAGE_ID"
printf 'image\t%s\tabsent\n' "$IMAGE_ID" >>"$EVIDENCE/teardown/api-resource-absence.txt"
API_TEARDOWN_VERIFIED=1
for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" 'sudo virsh -c qemu:///system list --all --name' >"$EVIDENCE/teardown/host-$host-domains.txt"
  for server_host in a b c; do
    domain="$(cat "$EVIDENCE/compute-$server_host/domain.txt")"
    if grep -Fxq "$domain" "$EVIDENCE/teardown/host-$host-domains.txt"; then
      fail "server domain $domain leaked on host-$host" "CLEANUP_DEFECT"
    fi
  done
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json 2>/dev/null || true" >"$EVIDENCE/teardown/host-$host-ownership.json"
  ssh_vm "$address" "sudo find /var/lib/o3k-fabric-v3/$RUN_ID/network/dhcp -maxdepth 3 -type f -print 2>/dev/null | sort" \
    >"$EVIDENCE/teardown/host-$host-dhcp-files.txt"
  ssh_vm "$address" "sudo find /var/lib/o3k-fabric-v3/$RUN_ID/network/dhcp -name state.json -type f -print -exec cat {} \; 2>/dev/null" \
    >"$EVIDENCE/teardown/host-$host-dhcp-state.txt"
  ssh_vm "$address" "sudo find /var/lib/o3k-fabric-v3/$RUN_ID/network/dhcp -name fabric-dhcp-ownership.json -type f -print -exec cat {} \; 2>/dev/null" \
    >"$EVIDENCE/teardown/host-$host-dhcp-ownership.txt"
  ssh_vm "$address" 'sudo pgrep -a dnsmasq || true' >"$EVIDENCE/teardown/host-$host-dnsmasq-processes.txt"
  ssh_vm "$address" 'sudo ip -j -d link; sudo ip netns list; sudo bridge -j fdb; sudo nft list ruleset' \
    >"$EVIDENCE/teardown/host-$host-runtime-after.txt" \
    || fail "post-teardown provider runtime snapshot failed on host-$host" "ENVIRONMENT_GAP"
done
python3 - "$EVIDENCE/teardown" "$RUN_ID" "$EVIDENCE/teardown/run-owned-provider-objects.json" <<'PY' \
  || fail "run-owned Fabric/DHCP provider state leaked after teardown" "CLEANUP_DEFECT"
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]); run=sys.argv[2]; expected=json.loads(pathlib.Path(sys.argv[3]).read_text())
for path in root.glob('host-*-ownership.json'):
    if path.stat().st_size:
        x=json.loads(path.read_text())
        assert not x.get('realms',{}), (str(path),x.get('realms'))
for host,record in expected.items():
    runtime=(root/f'host-{host}-runtime-after.txt').read_text()
    for name in record['endpoint_taps']+record['links']:
        assert not re.search(rf'(?m)^\s*\d+:\s+{re.escape(name)}(?:@|:|\s)',runtime), (host,name)
    assert record['namespace'] not in runtime, (host,record['namespace'])
    dhcp=(root/f'host-{host}-dhcp-state.txt').read_text()
    states=re.findall(r'(?m)^\{.*?^\}',dhcp,re.S)
    for state in states:
        parsed=json.loads(state)
        assert parsed.get('config') is None and not parsed.get('bindings'), (host,parsed)
    ownership=(root/f'host-{host}-dhcp-ownership.txt').read_text()
    dhcp_owners=re.findall(r'(?m)^\{.*?^\}',ownership,re.S)
    for owner in dhcp_owners:
        parsed=json.loads(owner)
        assert parsed.get('withdrawn') is True and parsed.get('pending') is False, (host,parsed)
    owned=(root/f'host-{host}-dhcp-files.txt').read_text()
    assert f'/var/lib/o3k-fabric-v3/{run}/network/dhcp/' not in owned or 'state.json' in owned, (host,owned)
    processes=(root/f'host-{host}-dnsmasq-processes.txt').read_text()
    assert run not in processes, (host,processes)
PY
date -u +%FT%TZ >"$EVIDENCE/teardown/provider-absence-observed-at.txt"
python3 - "$EVIDENCE/controller-data/o3k.sqlite" "$realm_id" "$NETWORK_ID" \
  "$EVIDENCE/teardown/provider-absence-observed-at.txt" \
  "$EVIDENCE/teardown/final-durable-state.json" <<'PY' \
  || fail "canonical Realm/VNI/work teardown did not converge after provider absence" "CLEANUP_DEFECT"
import json,pathlib,sqlite3,sys
database,realm_id,network_id,absence_path,output=sys.argv[1:]
db=sqlite3.connect(f"file:{database}?mode=ro",uri=True,timeout=3)
db.row_factory=sqlite3.Row
def rows(sql,*args): return [dict(row) for row in db.execute(sql,args).fetchall()]
realms=rows("SELECT id,network_id,state,generation FROM canonical_address_realms WHERE id=?",realm_id)
endpoints=rows("SELECT id,realm_id,state FROM canonical_endpoints WHERE realm_id=? ORDER BY id",realm_id)
pools=rows("SELECT id,realm_id,state FROM canonical_address_pools WHERE realm_id=? ORDER BY id",realm_id)
bindings=rows("SELECT fabric_domain_id,realm_id,provider_kind,provider_segment_id,binding_generation,state FROM canonical_realm_encapsulation_bindings WHERE realm_id=? ORDER BY fabric_domain_id",realm_id)
network=rows("SELECT id,state,generation FROM canonical_networks WHERE id=?",network_id)
work=[]
for row in db.execute("SELECT rowid AS insertion_order,command_id,target_host_id,target_agent_id,target_agent_epoch,state,revision,outcome,snapshot,created_at,updated_at FROM network_plan_work ORDER BY rowid"):
    command=json.loads(bytes(row['snapshot']))
    fabric=(command.get('plan') or {}).get('fabric') or {}
    if fabric.get('realm_id')!=realm_id: continue
    outcome=bytes(row['outcome']).decode('utf-8',errors='replace') if row['outcome'] is not None else None
    work.append({'insertion_order':row['insertion_order'],'command_id':row['command_id'],
        'target_host_id':row['target_host_id'],'target_agent_id':row['target_agent_id'],
        'target_agent_epoch':row['target_agent_epoch'],'action':command.get('action'),
        'local_host':fabric.get('local_host'),'state':row['state'],'revision':row['revision'],
        'outcome':outcome,'created_at':row['created_at'],'updated_at':row['updated_at']})
unresolved=[row for row in work if row['state'].lower() not in {'succeeded','failed'}]
latest={}
for host in ('host-a','host-b','host-c'):
    matches=[row for row in work if row['target_host_id']==host]
    latest[host]=max(matches,key=lambda row:row['insertion_order']) if matches else None
result={'database_backend':'sqlite','provider_absence_observed_at':pathlib.Path(absence_path).read_text().strip(),
    'realm_id':realm_id,'network_id':network_id,'canonical_realm_rows':realms,
    'canonical_endpoint_rows':endpoints,'canonical_pool_rows':pools,
    'canonical_network_rows':network,'encapsulation_bindings':bindings,
    'network_plan_work':work,'unresolved_network_plan_work':unresolved,
    'latest_remove_by_host':latest,'vni_binding_released_after_provider_absence':not bindings}
pathlib.Path(output).write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
assert not realms, realms
assert not endpoints, endpoints
assert not pools, pools
assert not bindings, bindings
assert not network, network
assert not unresolved, unresolved
for host,row in latest.items():
    assert row is not None and row['action']=='Remove' and row['state'].lower()=='succeeded' \
        and row['local_host']==host and row['outcome'], (host,row)
PY
# Remove only the three exact fresh compute guests after proving their API
# resources and server domains are gone. Then compare the physical libvirt
# inventory to the pre-run inventory to detect any foreign-domain mutation.
for domain in "${FRESH_DOMAINS[@]}"; do
  expected_uuid="$(awk -F '\t' -v n="$domain" '$2==n{print $5}' "$EVIDENCE/environment/inventory.tsv")"
  xml="$(virsh -c qemu:///system dumpxml "$domain" 2>/dev/null || true)"
  actual_uuid="$(virsh -c qemu:///system domuuid "$domain" 2>/dev/null || true)"
  role="${domain##*-}"
  disk="$IMAGE_STORE/$PREFIX-compute-$role.qcow2"
  seed="$IMAGE_STORE/$PREFIX-compute-$role-seed.iso"
  if [[ -z "$expected_uuid" || "$actual_uuid" != "$expected_uuid" ]] \
    || ! python3 "$ROOT_DIR/tests/fabric-v3-owned-domain-storage.py" \
      "$domain" "$expected_uuid" "$disk" "$seed" <<<"$xml" \
    || [[ -L "$disk" || -L "$seed" || ! -f "$disk" || ! -f "$seed" ]]; then
    fail "fresh compute guest ownership could not be re-proven for $domain" "OWNERSHIP_DEFECT"
  fi
  virsh -c qemu:///system destroy "$domain" >/dev/null 2>&1 || true
  virsh -c qemu:///system undefine "$domain" >/dev/null \
    || fail "could not remove owned fresh compute guest $domain" "CLEANUP_DEFECT"
  rm -- "$disk" "$seed" || fail "could not remove exact owned storage for $domain" "CLEANUP_DEFECT"
done
virsh -c qemu:///system list --all --name | sed '/^$/d' | sort >"$EVIDENCE/teardown/libvirt-domains-after.txt"
diff -u "$EVIDENCE/environment/libvirt-domains-before.txt" "$EVIDENCE/teardown/libvirt-domains-after.txt" >"$EVIDENCE/teardown/libvirt-domains.diff" \
  || fail "foreign libvirt domain inventory changed during campaign" "OWNERSHIP_DEFECT"
git -C "$ROOT_DIR" rev-parse HEAD >"$EVIDENCE/environment/harness_sha.txt"
git -C "$ROOT_DIR" rev-parse 'HEAD^{tree}' >"$EVIDENCE/environment/harness_tree.txt"
sha256sum "$ROOT_DIR/tests/fabric-v3-o3k-three-host-campaign.sh" >"$EVIDENCE/environment/driver.sha256"
sha256sum "$ROOT_DIR/tests/fabric-v3-guest-control.py" >"$EVIDENCE/environment/guest-control-helper.sha256"
CAMPAIGN_TEARDOWN_PASS=1

cat >"$EVIDENCE/result.json" <<JSON
{"result":"PASS","acceptance_gate":"$ACCEPTANCE_GATE","run_id":"$RUN_ID","product_sha":"$PRODUCT_SHA","product_tree":"$PRODUCT_TREE","harness_sha":"$(git -C "$ROOT_DIR" rev-parse HEAD)","fabric_domain_id":"$FABRIC_DOMAIN_ID","servers":["${SERVER_IDS[0]}","${SERVER_IDS[1]}","${SERVER_IDS[2]}"],"teardown":"PASS"}
JSON
if [[ "$CAMPAIGN_MODE" == full ]]; then
  echo "FABRIC V3 O3K MINIMAL THREE-HOST MILESTONE: PASS"
fi
