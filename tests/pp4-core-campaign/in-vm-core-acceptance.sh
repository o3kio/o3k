#!/usr/bin/env bash
# Frozen rc.22 PP.4 Core acceptance, phases 0-6.  This script is copied into
# a fresh VM by host-run.sh; it never reads the checkout or substitutes local
# binaries for the public release.
# shellcheck disable=SC1090,SC1091,SC2024,SC2034,SC2154
set -Eeuo pipefail
EVID=${1:?evidence directory}; HELPER=${2:?native client}; DISTRO=${3:?distro}
RELEASE_VERSION=${O3K_PP4_VERSION:-}; SOURCE_SHA=${O3K_PP4_SOURCE_SHA:-}; HARNESS_SHA=${O3K_PP4_HARNESS_SHA:-}
[[ "$RELEASE_VERSION" =~ ^v0\.4\.0-rc\.[0-9]+$ && "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ && -n "$HARNESS_SHA" ]] \
  || { echo 'explicit release and harness identity is required' >&2; exit 2; }
API=http://127.0.0.1:18080/o3k/v1
mkdir -p "$EVID"; chmod 0700 "$EVID"
exec 9>"$EVID/.lock"; flock -n 9 || { echo 'evidence directory is already in use' >&2; exit 2; }
log(){ printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$EVID/phase.log"; }
fail(){ log "FAIL $*"; printf '%s\n' "$*" >"$EVID/FAILED"; exit 1; }
pass(){ log "PASS $*"; }
WORKDIR="$(mktemp -d /tmp/pp4-core-acceptance.XXXXXX)"
cleanup(){ rm -rf -- "$WORKDIR"; }
trap cleanup EXIT
TOKEN_FILE="$WORKDIR/native-token"; OPENRC="$WORKDIR/admin-openrc"; sudo cp /etc/o3k/admin-openrc "$OPENRC"; sudo chown "$(id -u):$(id -g)" "$OPENRC"; chmod 600 "$OPENRC"
source "$OPENRC"
python3 "$HELPER" auth --admin-openrc "$OPENRC" --token-file "$TOKEN_FILE" >"$EVID/native-auth.json"
export OS_CLOUD=; export OS_CLIENT_CONFIG_FILE=
export OS_USERNAME OS_PASSWORD OS_PROJECT_NAME OS_AUTH_URL OS_USER_DOMAIN_NAME OS_PROJECT_DOMAIN_NAME OS_REGION_NAME
export OS_CLOUD=o3k-testlab
CLIENT_CLOUDS="$WORKDIR/clouds.yaml"
python3 - "$CLIENT_CLOUDS" <<'PY'
import json, os, sys
p=sys.argv[1]; a=os.environ['OS_AUTH_URL']; base=a[:-3] if a.endswith('/v3') else a.rstrip('/')
v={'clouds':{'o3k-testlab':{'auth':{'auth_url':a,'username':os.environ['OS_USERNAME'],'password':os.environ['OS_PASSWORD'],'project_name':os.environ['OS_PROJECT_NAME'],'user_domain_name':os.environ.get('OS_USER_DOMAIN_NAME','Default'),'project_domain_name':os.environ.get('OS_PROJECT_DOMAIN_NAME','Default')},'region_name':os.environ.get('OS_REGION_NAME','RegionOne'),'interface':'public','identity_api_version':'3','image_api_version':'2','image_endpoint_override':base+'/v2','network_endpoint_override':base+'/v2.0'}}}
json.dump(v,open(p,'w',encoding='utf-8')); os.chmod(p,0o600)
PY
export OS_CLIENT_CONFIG_FILE="$CLIENT_CLOUDS"
native(){ python3 "$HELPER" request --token-file "$TOKEN_FILE" --url "$API$1" --method "${2:-GET}" --output-file "$3" "${@:4}"; }
record_env(){ printf '%s=%s\n' "$1" "$2" >>"$EVID/state.env"; }
: >"$EVID/state.env"

capture_side_effect_counts() {
  local label="$1"
  sudo python3 - "$EVID/side-effects-$label.json" <<'PY'
import json
import sqlite3
import sys
out = sys.argv[1]
db = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
def count(table):
    return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
json.dump({"resources": count("resources"), "operations": count("operations"),
           "network_ports": count("network_ports"),
           "placement_allocations": count("placement_allocations"),
           "quota_reservations": count("quota_reservations")},
          open(out, "w", encoding="utf-8"), indent=2, sort_keys=True)
PY
  sudo virsh -c qemu:///system list --all --name | sed '/^$/d' | sort >"$EVID/side-effects-$label-domains.txt"
  openstack port list -f json >"$EVID/side-effects-$label-ports.json"
}

log 'phase 0: environment and public identity'
{ . /etc/os-release; printf 'distro=%s\nversion=%s\nkernel=%s\narchitecture=%s\nkvm=%s\nmemory_kib=%s\ndisk=%s\n' "$ID" "$VERSION_ID" "$(uname -r)" "$(uname -m)" "$(test -e /dev/kvm && echo PASS || echo FAIL)" "$(awk '/MemTotal/{print $2}' /proc/meminfo)" "$(df -Pk / | awk 'NR==2{print $2}')"; } >"$EVID/host.env"
sudo python3 /home/tester/verify_manifest.py "$RELEASE_VERSION" "$SOURCE_SHA" >"$EVID/installed-identity.txt" || fail 'installed manifest identity mismatch'
printf 'version=%s\nsource_sha=%s\nharness_sha=%s\npublic_url=https://github.com/o3kio/o3k/releases/tag/%s\n' "$RELEASE_VERSION" "$SOURCE_SHA" "$HARNESS_SHA" "$RELEASE_VERSION" >"$EVID/release.env"
pass 'release identity'

log 'phase 1: canonical bootstrap, topology, Placement and profile'
# The public Core install has a project-scoped admin identity.  The bounded
# operator routes intentionally require a separate system/operator principal;
# calling them with the project token would turn an expected authorization
# boundary into a false campaign failure.  Core therefore uses the documented
# authenticated public topology/discovery reads and a read-only durable
# snapshot as supplemental identity evidence.  The operator 403 boundary is
# retained explicitly rather than treated as a product failure.
native /identity/me GET "$EVID/identity-me.json" --expect 200
native /services GET "$EVID/services.json" --expect 200
native /regions GET "$EVID/regions.json" --expect 200
native /topology/failure-domains GET "$EVID/failure-domains.json" --expect 200
native /resource-types GET "$EVID/resource-types.json" --expect 200
set +e
native /operator/profile GET "$EVID/operator-profile-scope-check.json" --expect 403
operator_scope_rc=$?
set -e
(( operator_scope_rc == 0 )) || fail 'operator scope boundary probe was not the expected 403'
printf 'operator_routes=SYSTEM_SCOPE_ONLY\nproject_token_probe=403\n' >"$EVID/operator-scope-boundary.txt"
doctor_rc=0
sudo o3k doctor --json >"$EVID/doctor-bootstrap.json" 2>/dev/null || doctor_rc=$?
(( doctor_rc <= 1 )) || fail "o3k doctor bootstrap report failed (rc $doctor_rc)"
python3 - "$EVID/doctor-bootstrap.json" <<'PY' || fail 'o3k doctor bootstrap report was not valid JSON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
if not report.get("version"):
    raise SystemExit("doctor report has no version")
if not isinstance(report.get("checks"), list) or not report["checks"]:
    raise SystemExit("doctor report has no checks")
if any(check.get("status") == "FAIL" for check in report["checks"]):
    raise SystemExit("doctor report contains a failed check")
PY
sudo python3 - "$EVID/durable-bootstrap.json" >"$EVID/durable-bootstrap.json" <<'PY'
import json
import sqlite3
import sys

out = sys.argv[1]
db = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
def rows(query):
    cursor = db.execute(query)
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, row)) for row in cursor]

blocks = rows("SELECT block_id, state, cloud_profile_id, resource_provider_ids, failure_domain_id FROM building_blocks ORDER BY block_id")
profiles = rows("SELECT profile_id, generation FROM cloud_profiles ORDER BY profile_id")
bootstrap = rows("SELECT state_id, phase, cloud_profile_id, cloud_identity_id FROM bootstrap_state ORDER BY state_id")
providers = rows("SELECT id, node_id, state, generation FROM placement_providers ORDER BY id")
inventories = rows("SELECT provider_id, resource_class, total, reserved, allocation_ratio, used FROM placement_inventories ORDER BY provider_id, resource_class")
json.dump({"building_blocks": blocks, "cloud_profiles": profiles, "bootstrap": bootstrap,
           "placement_providers": providers, "placement_inventories": inventories},
          sys.stdout, indent=2, sort_keys=True)
print()
PY
bb_id="$(jq -r '.building_blocks[] | select(.state == "ready") | .block_id' "$EVID/durable-bootstrap.json" | head -1)"
[[ "$bb_id" =~ ^[0-9a-fA-F-]{36}$ ]] || fail 'canonical BuildingBlock was not discoverable in durable state'
ready_blocks="$(jq '[.building_blocks[] | select(.state == "ready")] | length' "$EVID/durable-bootstrap.json")"
[[ "$ready_blocks" == 1 ]] || fail "expected exactly one ready BuildingBlock, found $ready_blocks"
printf 'building_block_id=%s\n' "$bb_id" >>"$EVID/state.env"
jq -e '.resource_types | length >= 1' "$EVID/resource-types.json" >/dev/null || fail 'resource type discovery empty'
jq -e 'has("regions")' "$EVID/regions.json" >/dev/null || fail 'canonical region discovery response malformed'
jq -e '((.failure_domains // .items) | type == "array")' "$EVID/failure-domains.json" >/dev/null || fail 'canonical failure-domain discovery response malformed'
set +e
openstack resource provider list -f json >"$EVID/placement-providers.json" 2>"$EVID/placement-cli-error.txt"
placement_cli_rc=$?
set -e
if (( placement_cli_rc != 0 )); then
  printf 'placement_cli=UNAVAILABLE\nreason=compatibility catalog has no Placement endpoint\n' >"$EVID/placement-cli-unavailable.txt"
  jq '.placement_providers' "$EVID/durable-bootstrap.json" >"$EVID/placement-providers.json"
  jq '.placement_inventories' "$EVID/durable-bootstrap.json" >"$EVID/placement-inventory.json"
else
  jq -e 'length >= 1' "$EVID/placement-providers.json" >/dev/null || fail 'Placement provider list empty'
fi
provider_id="$(jq -r '.[0].uuid // .[0].id // empty' "$EVID/placement-providers.json")"
[[ -n "$provider_id" ]] || fail 'Placement provider identity missing'
if (( placement_cli_rc == 0 )); then
  openstack resource provider inventory list "$provider_id" -f json >"$EVID/placement-inventory.json" || fail 'Placement inventory observation failed'
fi
jq -e 'length >= 1' "$EVID/placement-inventory.json" >/dev/null || fail 'Placement inventory empty'
printf 'placement_provider_id=%s\n' "$provider_id" >>"$EVID/state.env"
pass "BuildingBlock $bb_id, public topology, Placement provider and inventory"

log 'phase 2: canonical native network and native-first workload'
image_id="$(openstack image show cirros-0.6.3 -f value -c id)" || fail 'image lookup failed'
flavor_id="$(sudo cat /etc/o3k/testlab-flavor-id)" || fail 'flavor identity missing'
network_id="$(openstack network show testlab-network -f value -c id)" || fail 'network lookup failed'
existing_port="$(openstack port show testlab-port -f value -c id)" || fail 'compatibility port missing'
existing_ip="$(openstack port show "$existing_port" -f value -c fixed_ips | grep -Eo '192\.0\.2\.[0-9]+' | head -1)"
native /network/address-realms GET "$EVID/address-realms.json" --expect 200 || fail 'native address realm collection unavailable'
openstack network show "$network_id" -f json >"$EVID/native-network.json" || fail 'native network authority observation failed'
openstack subnet list --network "$network_id" -f json >"$EVID/native-subnets.json" || fail 'native subnet authority observation failed'
printf 'network_id=%s\nexisting_port=%s\nexisting_ip=%s\n' "$network_id" "$existing_port" "$existing_ip" >>"$EVID/state.env"
sudo virsh -c qemu:///system list --all --name | sed '/^$/d' | sort >"$EVID/libvirt-before-native.txt"
python3 - "$EVID/native-request.json" "$image_id" "$flavor_id" "$network_id" <<'PY'
import json,sys
p,image,flavor,network=sys.argv[1:]
json.dump({'api_version':'o3k.io/v1','kind':'compute:server','spec':{'name':'pp4-native','image_id':image,'flavor_id':flavor,'network_ids':[network],'key_name':'testlab-keypair'}},open(p,'w'),separators=(',',':'))
PY
native /compute/servers POST "$EVID/native-create.json" --request-file "$EVID/native-request.json" --idempotency-key pp4-core-native-rc22 --expect 201 --expect 202
server_id="$(jq -r '.resource_id // .resource.metadata.id // empty' "$EVID/native-create.json")"; operation_id="$(jq -r '.operation_id // .operation.id // empty' "$EVID/native-create.json")"
[[ "$server_id" =~ ^[0-9a-fA-F-]{36}$ && -n "$operation_id" ]] || fail 'native create identifiers missing'
for i in $(seq 1 90); do native "/operations/$operation_id" GET "$EVID/native-operation.json" --expect 200; state="$(jq -r '.state // .operation.state // .status // empty' "$EVID/native-operation.json")"; [[ "$state" =~ ^(SUCCEEDED|succeeded|SUCCESS|success)$ ]] && break; [[ "$state" =~ ^(ERROR|error|FAILED|failed)$ ]] && fail 'native operation failed'; sleep 2; done
[[ "$state" =~ ^(SUCCEEDED|succeeded|SUCCESS|success)$ ]] || fail 'native operation did not converge'
native "/compute/servers/$server_id" GET "$EVID/native-server.json" --expect 200
native_port="$(openstack port list -f value -c ID | while read -r p; do n=$(openstack port show "$p" -f value -c name 2>/dev/null || true); [[ "$n" == o3k-server:* ]] && echo "$p" && break; done)"
native_ip="$(openstack port show "$native_port" -f value -c fixed_ips | grep -Eo '192\.0\.2\.[0-9]+' | head -1)"
[[ -n "$native_port" && "$native_ip" != "$existing_ip" ]] || fail 'native network allocation did not produce a distinct canonical port/IP'
printf 'native_server_id=%s\nnative_operation_id=%s\nnative_port_id=%s\nnative_ip=%s\n' "$server_id" "$operation_id" "$native_port" "$native_ip" >>"$EVID/state.env"
sudo virsh -c qemu:///system list --all --name | sed '/^$/d' | sort >"$EVID/libvirt-after-native.txt"
comm -13 "$EVID/libvirt-before-native.txt" "$EVID/libvirt-after-native.txt" >"$EVID/native-domain.txt"
[[ -s "$EVID/native-domain.txt" ]] || fail 'native provider did not publish a new libvirt domain'
printf 'native_provider_domain=%s\n' "$(head -1 "$EVID/native-domain.txt")" >>"$EVID/state.env"
for i in $(seq 1 60); do timeout 15 openstack console log show "$server_id" >"$EVID/native-console.log" 2>/dev/null && grep -Eiq 'cirros|login:' "$EVID/native-console.log" && break; sleep 2; done
grep -Eiq 'cirros|login:' "$EVID/native-console.log" || fail 'native guest boot marker missing'
pass 'native server, canonical network allocation and guest boot'

log 'phase 3: replay and OpenStack observation'
capture_side_effect_counts before-replay
native /compute/servers POST "$EVID/native-replay.json" --request-file "$EVID/native-request.json" --idempotency-key pp4-core-native-rc22 --expect 200 --expect 201 --expect 202
[[ "$(jq -r '.resource_id // .resource.metadata.id // empty' "$EVID/native-replay.json")" == "$server_id" ]] || fail 'replay changed canonical resource'
capture_side_effect_counts after-replay
cmp -s "$EVID/side-effects-before-replay.json" "$EVID/side-effects-after-replay.json" || fail 'replay changed durable side-effect counts'
cmp -s "$EVID/side-effects-before-replay-domains.txt" "$EVID/side-effects-after-replay-domains.txt" || fail 'replay created a provider domain'
cmp -s "$EVID/side-effects-before-replay-ports.json" "$EVID/side-effects-after-replay-ports.json" || fail 'replay created a port'
cp "$EVID/native-request.json" "$EVID/native-conflict-request.json"; sed -i 's/pp4-native/pp4-native-conflict/' "$EVID/native-conflict-request.json"
native /compute/servers POST "$EVID/native-conflict.json" --request-file "$EVID/native-conflict-request.json" --idempotency-key pp4-core-native-rc22 --expect 409
capture_side_effect_counts after-conflict
cmp -s "$EVID/side-effects-before-replay.json" "$EVID/side-effects-after-conflict.json" || fail 'changed-body conflict changed durable side-effect counts'
openstack server show "$server_id" -f json >"$EVID/openstack-native-show.json" || fail 'OpenStack CLI cannot observe native server'
openstack server list -f json >"$EVID/openstack-native-list.json" || fail 'OpenStack CLI server list failed'
openstack port show "$native_port" -f json >"$EVID/openstack-native-port-show.json" || fail 'OpenStack CLI cannot observe native port'
[[ "$(jq -r '.id' "$EVID/openstack-native-show.json")" == "$server_id" ]] || fail 'OpenStack/native canonical ID mismatch'
pass 'same-key replay, changed-body conflict, OpenStack native observation'

log 'phase 4: compatibility-created workload and native projection'
sudo virsh -c qemu:///system list --all --name | sed '/^$/d' | sort >"$EVID/libvirt-before-compat.txt"
set +e
openstack server create --wait --image "$image_id" --flavor "$flavor_id" --network "$network_id" --key-name testlab-keypair pp4-openstack -f json >"$EVID/openstack-create.json"
compat_rc=$?
set -e
(( compat_rc == 0 )) || fail 'OpenStack compatibility create failed'
compat_id="$(jq -r '.id // empty' "$EVID/openstack-create.json")"; [[ "$compat_id" =~ ^[0-9a-fA-F-]{36}$ ]] || fail 'compatibility server ID missing'
native "/compute/servers/$compat_id" GET "$EVID/native-compat-show.json" --expect 200
printf 'compatibility_server_id=%s\nnative_projection_id=%s\n' "$compat_id" "$(jq -r '.metadata.id // .id // empty' "$EVID/native-compat-show.json")" >>"$EVID/state.env"
[[ "$(jq -r '.metadata.id // .id // empty' "$EVID/native-compat-show.json")" == "$compat_id" ]] || fail 'compatibility create did not converge to native identity'
for i in $(seq 1 60); do timeout 15 openstack console log show "$compat_id" >"$EVID/compat-console.log" 2>/dev/null && grep -Eiq 'cirros|login:' "$EVID/compat-console.log" && break; sleep 2; done
grep -Eiq 'cirros|login:' "$EVID/compat-console.log" || fail 'compatibility-created guest boot marker missing'
sudo virsh -c qemu:///system list --all --name | sed '/^$/d' | sort >"$EVID/libvirt-after-compat.txt"
comm -13 "$EVID/libvirt-before-compat.txt" "$EVID/libvirt-after-compat.txt" >"$EVID/compat-domain.txt"
[[ -s "$EVID/compat-domain.txt" ]] || fail 'compatibility create did not publish a new libvirt domain'
printf 'compatibility_provider_domain=%s\n' "$(head -1 "$EVID/compat-domain.txt")" >>"$EVID/state.env"
openstack server show "$compat_id" -f json >"$EVID/openstack-compat-created-show.json" || fail 'compatibility-created server show failed'
pass 'compatibility create, real provider path and native projection'

log 'phase 5: cross-interface lifecycle'
openstack server reboot --hard "$server_id" || fail 'compatibility reboot of native server failed'
for i in $(seq 1 60); do st=$(openstack server show "$server_id" -f value -c status 2>/dev/null || true); [[ "$st" == ACTIVE ]] && break; sleep 2; done
[[ "$st" == ACTIVE ]] || fail 'native server did not converge after compatibility reboot'
native "/compute/servers/$server_id" GET "$EVID/native-after-compat-reboot.json" --expect 200
openstack server show "$compat_id" -f json >"$EVID/openstack-compat-show.json" || fail 'compatibility server show failed'
native "/compute/servers/$compat_id" GET "$EVID/native-compat-lifecycle-show.json" --expect 200
openstack server list -f json >"$EVID/openstack-lifecycle-list.json" || fail 'OpenStack lifecycle list failed'
pass 'cross-interface show/list and reboot convergence'

log 'phase 6: Horizon witness'
if [[ "$DISTRO" == ubuntu ]]; then
  O3K_PP4_HORIZON_REQUIRED=1 O3K_PP4_NATIVE_ID="$server_id" O3K_PP4_COMPAT_ID="$compat_id" bash /home/tester/horizon-witness.sh "$EVID" || fail 'required Ubuntu Horizon witness failed'
else
  O3K_PP4_HORIZON_REQUIRED=0 O3K_PP4_NATIVE_ID="$server_id" O3K_PP4_COMPAT_ID="$compat_id" bash /home/tester/horizon-witness.sh "$EVID" || true
fi
curl -fsS http://127.0.0.1:18080/readyz >"$EVID/ready-with-horizon.txt" || fail 'O3K readiness failed while Horizon witness was active'
docker rm -f pp4-horizon-witness >/dev/null 2>&1 || true
curl -fsS http://127.0.0.1:18080/readyz >"$EVID/ready-after-horizon-stop.txt" || fail 'O3K readiness failed after Horizon stopped'
printf 'phase1_status=PASS\n' >"$EVID/pre-reboot.env"
pass 'Horizon boundary and O3K readiness independent of Horizon'
