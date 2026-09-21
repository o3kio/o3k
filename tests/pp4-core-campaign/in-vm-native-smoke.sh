#!/usr/bin/env bash
# Public-release native-first PP.4 Core smoke. The caller copies this file
# and native_client.py into a fresh VM; no product source tree is used.
set -Eeuo pipefail

EVID=${1:?usage: in-vm-native-smoke.sh evidence-dir helper.py}
HELPER=${2:?usage: in-vm-native-smoke.sh evidence-dir helper.py}
API=http://127.0.0.1:18080/o3k/v1
echo 'PP4 native smoke: start'
mkdir -p "$EVID"
chmod 0700 "$EVID"
TOKEN_FILE="$(mktemp "$EVID/native-token.XXXXXX")"
REQUEST_FILE="$(mktemp "$EVID/native-request.XXXXXX.json")"
OPENRC_FILE="$(mktemp "$EVID/admin-openrc.XXXXXX")"
CLIENT_CLOUDS="$(mktemp "$EVID/clouds.XXXXXX.yaml")"
CREATE_RESPONSE="$EVID/native-create-response.json"
trap 'rm -f -- "$TOKEN_FILE" "$REQUEST_FILE" "$OPENRC_FILE" "$CLIENT_CLOUDS"' EXIT
chmod 0600 "$TOKEN_FILE" "$REQUEST_FILE"
sudo cp /etc/o3k/admin-openrc "$OPENRC_FILE"
sudo chown "$(id -u):$(id -g)" "$OPENRC_FILE"
chmod 0600 "$OPENRC_FILE"

die() { echo "PP4 CORE NATIVE SMOKE: $*" >&2; exit 1; }
record() {
  sed -E 's/(Authorization: Bearer )[A-Za-z0-9._~+\\/-]+/\\1<redacted>/Ig; s/("(token|password|secret|private_key)"[[:space:]]*:[[:space:]]*")[^"]*/\\1<redacted>/Ig' \
    <<<"$1" >>"$EVID/native-evidence.log"
}

[[ -f "$OPENRC_FILE" ]] || die 'admin-openrc missing'
python3 "$HELPER" auth --admin-openrc "$OPENRC_FILE" --token-file "$TOKEN_FILE" \
  >"$EVID/native-auth-result.json"
chmod 0600 "$EVID/native-auth-result.json"
record 'native auth: PASS (project-scoped Keystone password -> native token exchange)'

source "$OPENRC_FILE"
# Recreate the supported client profile locally rather than relying on a
# persistent OS_CLOUD path from the installer.  This keeps the harness
# self-contained while retaining the documented versioned image/network
# endpoint overrides.
python3 - "$CLIENT_CLOUDS" "$OS_AUTH_URL" "$OS_USERNAME" "$OS_PROJECT_NAME" <<'PY'
import json, os, sys
path, auth_url, username, project = sys.argv[1:]
base = auth_url[:-3] if auth_url.endswith('/v3') else auth_url.rstrip('/')
config = {'clouds': {'o3k-testlab': {'auth': {
    'auth_url': auth_url, 'username': username, 'password': os.environ['OS_PASSWORD'],
    'project_name': project, 'user_domain_name': os.environ.get('OS_USER_DOMAIN_NAME', 'Default'),
    'project_domain_name': os.environ.get('OS_PROJECT_DOMAIN_NAME', 'Default')},
    'region_name': os.environ.get('OS_REGION_NAME', 'RegionOne'), 'interface': 'public',
    'identity_api_version': '3', 'image_api_version': '2',
    'image_endpoint_override': f'{base}/v2', 'network_endpoint_override': f'{base}/v2.0'}}}
with open(path, 'w', encoding='utf-8') as stream:
    json.dump(config, stream)
    stream.write('\n')
PY
chmod 0600 "$CLIENT_CLOUDS"
export OS_CLOUD=o3k-testlab OS_CLIENT_CONFIG_FILE="$CLIENT_CLOUDS"
openstack_error="$EVID/openstack-error.log"
image_id="$(openstack image show cirros-0.6.3 -f value -c id 2>"$openstack_error")" || die "image lookup failed: $(tr '\n' ' ' <"$openstack_error")"
flavor_id="$(cat /etc/o3k/testlab-flavor-id 2>/dev/null || true)"
if [[ -z "$flavor_id" ]]; then
  flavor_id="$(openstack flavor show testlab-flavor -f value -c id 2>>"$openstack_error" || true)"
fi
network_id="$(openstack network show testlab-network -f value -c id 2>>"$openstack_error")" || die "network lookup failed: $(tr '\n' ' ' <"$openstack_error")"
existing_port="$(openstack port show testlab-port -f value -c id 2>>"$openstack_error")" || die "port lookup failed: $(tr '\n' ' ' <"$openstack_error")"
existing_ip="$(openstack port show "$existing_port" -f value -c fixed_ips 2>>"$openstack_error" | grep -Eo '192\.0\.2\.[0-9]+' | head -1)"
key_name=testlab-keypair
[[ "$flavor_id" =~ ^[0-9a-fA-F-]{36}$ && -n "$image_id" && -n "$network_id" && -n "$existing_port" && -n "$existing_ip" ]] \
  || die 'bounded TestLab resources unavailable'
record "precondition image=$image_id flavor=$flavor_id network=$network_id compatibility_port=$existing_port compatibility_ip=$existing_ip keypair=$key_name"

python3 - "$REQUEST_FILE" "$image_id" "$flavor_id" "$network_id" "$key_name" <<'PY'
import json, sys
path, image, flavor, network, key = sys.argv[1:]
body = {
    "api_version": "o3k.io/v1",
    "kind": "compute:server",
    "spec": {
        "name": "pp4-native",
        "image_id": image,
        "flavor_id": flavor,
        "network_ids": [network],
        "key_name": key,
    },
}
with open(path, "w", encoding="utf-8") as stream:
    json.dump(body, stream, separators=(",", ":"))
    stream.write("\n")
PY
chmod 0600 "$REQUEST_FILE"
cp "$REQUEST_FILE" "$EVID/native-request-redacted.json"
chmod 0600 "$EVID/native-request-redacted.json"

idempotency=pp4-core-native-create-rc18
python3 "$HELPER" request --token-file "$TOKEN_FILE" --url "$API/compute/servers" \
  --method POST --request-file "$REQUEST_FILE" --output-file "$CREATE_RESPONSE" \
  --idempotency-key "$idempotency" --expect 201 --expect 202 >/dev/null
record "native create response: $(cat "$CREATE_RESPONSE")"
server_id="$(jq -r '.resource_id // .resource.metadata.id // empty' "$CREATE_RESPONSE")"
operation_id="$(jq -r '.operation_id // .operation.id // empty' "$CREATE_RESPONSE")"
[[ "$server_id" =~ ^[0-9a-fA-F-]{36}$ && -n "$operation_id" ]] || die 'native create did not return canonical resource and Operation IDs'
record "native create: server=$server_id operation=$operation_id"

operation_file="$EVID/native-operation.json"
for attempt in $(seq 1 90); do
  python3 "$HELPER" request --token-file "$TOKEN_FILE" --url "$API/operations/$operation_id" \
    --method GET --output-file "$operation_file" --expect 200 >/dev/null
  state="$(jq -r '.state // .operation.state // .status // empty' "$operation_file")"
  case "$state" in
    SUCCEEDED|succeeded|SUCCESS|success) break ;;
    ERROR|error|FAILED|failed) record "native operation: ERROR $(cat "$operation_file")"; die 'native Operation reached terminal failure' ;;
  esac
  [[ "$attempt" -lt 90 ]] || die 'native Operation did not reach terminal success'
  sleep 2
done
record "native operation: SUCCEEDED $(cat "$operation_file")"

server_file="$EVID/native-server.json"
python3 "$HELPER" request --token-file "$TOKEN_FILE" --url "$API/compute/servers/$server_id" \
  --method GET --output-file "$server_file" --expect 200 >/dev/null
[[ "$(jq -r '.metadata.id // .id // empty' "$server_file")" == "$server_id" ]] || die 'native show did not return same canonical server'
record "native show: $(cat "$server_file")"

native_port=""
while read -r candidate; do
  [[ -n "$candidate" ]] || continue
  name="$(openstack port show "$candidate" -f value -c name 2>/dev/null || true)"
  if [[ "$name" == o3k-server:* ]]; then native_port="$candidate"; break; fi
done < <(openstack port list -f value -c ID 2>/dev/null)
[[ -n "$native_port" ]] || die 'native-owned port not visible through OpenStack compatibility'
native_ip="$(openstack port show "$native_port" -f value -c fixed_ips | grep -Eo '192\.0\.2\.[0-9]+' | head -1)"
[[ -n "$native_ip" && "$native_ip" != "$existing_ip" ]] || die 'native allocator reused compatibility IP or returned no IP'
record "collision-safe port: native_port=$native_port native_ip=$native_ip existing_port=$existing_port existing_ip=$existing_ip"

replay_file="$EVID/native-replay-response.json"
python3 "$HELPER" request --token-file "$TOKEN_FILE" --url "$API/compute/servers" \
  --method POST --request-file "$REQUEST_FILE" --output-file "$replay_file" \
  --idempotency-key "$idempotency" --expect 200 --expect 201 --expect 202 >/dev/null
replay_server="$(jq -r '.resource_id // .resource.metadata.id // empty' "$replay_file")"
replay_operation="$(jq -r '.operation_id // .operation.id // empty' "$replay_file")"
[[ "$replay_server" == "$server_id" ]] || die 'idempotent replay returned a different canonical server'
[[ -z "$replay_operation" || "$replay_operation" == "$operation_id" ]] || die 'idempotent replay returned a different Operation'
record "replay: same_server=$replay_server same_operation=${replay_operation:-same-or-complete} same_port=$native_port same_ip=$native_ip"

domain=""
while read -r candidate; do
  [[ -n "$candidate" ]] || continue
  xml="$(virsh -c qemu:///system dumpxml "$candidate" 2>/dev/null || true)"
  if grep -Fq "server_id=\"$server_id\"" <<<"$xml" && grep -Fq 'managed_by="o3k-compute"' <<<"$xml"; then
    domain="$candidate"; break
  fi
done < <(virsh -c qemu:///system list --all --name)
[[ -n "$domain" ]] || die 'managed_by=o3k-compute libvirt domain not found'
[[ "$(virsh -c qemu:///system domstate "$domain")" == running ]] || die 'libvirt domain is not running'
record "libvirt: domain=$domain state=running server_id=$server_id"
if virsh -c qemu:///system console "$domain" --force 2>/dev/null | timeout 8 grep -Eiq 'cirros|login:'; then
  record 'guest boot: PASS (console marker)'
else
  die 'guest console did not expose a CirrOS/login boot marker'
fi

if grep -RniE 'Authorization:|Bearer |access_token|refresh_token|bootstrap_secret|enrollment_token|BEGIN .*PRIVATE KEY' "$EVID" >/dev/null; then
  die 'secret pattern found in native evidence'
fi
record 'secret scan: PASS'
printf 'PP4-NATIVE-SMOKE PASS server=%s operation=%s native_port=%s native_ip=%s\n' "$server_id" "$operation_id" "$native_port" "$native_ip"
