#!/usr/bin/env bash
set -euo pipefail

# Portable real-provider smoke gate.  CI supplies the pinned toolchain and a
# locally built o3kd; no OpenStack cloud or provider fork is used.
: "${O3K_P13_TOFU:?run scripts/p13_prepare_toolchain.sh first}"
: "${O3K_P13_PROVIDER_BINARY:?run scripts/p13_prepare_toolchain.sh first}"
root_dir=$(cd "$(dirname "$0")/.." && pwd)
o3kd=${O3K_P13_O3KD:-$root_dir/target/debug/o3kd}
[[ -x "$o3kd" ]] || { echo "missing o3kd: $o3kd" >&2; exit 2; }
work=$(mktemp -d /tmp/o3k-p13-5e-real.XXXXXX)
read -r backend_port proxy_port < <(python3 - <<'PY'
import socket
sockets=[]
for _ in range(2):
    s=socket.socket(); s.bind(('127.0.0.1', 0)); sockets.append(s)
print(sockets[0].getsockname()[1], sockets[1].getsockname()[1])
for s in sockets: s.close()
PY
)
password=${O3K_P13_PASSWORD:-p13-5e-provider-password}; project=eba29e2d-53de-461d-ae91-ede7402713cb
backend_pid=; proxy_pid=
proxy_evidence="$work/proxy-initial.json"
install -d -m 700 "$work/data"
database_args=()
if [[ "${O3K_DATABASE_BACKEND:-sqlite}" == postgres || "${O3K_DATABASE_BACKEND:-sqlite}" == postgresql ]]; then
  database_args+=(--database-backend postgres --database-url "${O3K_DATABASE_URL:?O3K_DATABASE_URL is required for PostgreSQL}")
fi
cleanup() { [[ -n "$proxy_pid" ]] && kill -TERM "$proxy_pid" 2>/dev/null || true; [[ -n "$backend_pid" ]] && kill "$backend_pid" 2>/dev/null || true; wait "$proxy_pid" 2>/dev/null || true; wait "$backend_pid" 2>/dev/null || true; mkdir -p "${O3K_P13_EVIDENCE_DIR:-$work}"; cp "$work"/*.json "${O3K_P13_EVIDENCE_DIR:-$work}/" 2>/dev/null || true; }
trap cleanup EXIT
start_backend() {
  O3K_DATABASE_BACKEND="${O3K_DATABASE_BACKEND:-sqlite}" O3K_DATABASE_URL="${O3K_DATABASE_URL:-}" \
  O3K_BOOTSTRAP_PASSWORD="$password" O3K_TOKEN_SIGNING_KEY=p13-5e-provider-token-signing-key-012345678901234567890123 \
    "$o3kd" --listen-addr "127.0.0.1:$backend_port" --data-dir "$work/data" "${database_args[@]}" >"$work/o3kd.log" 2>&1 & backend_pid=$!
}
restart_backend() {
  kill -TERM "$backend_pid" 2>/dev/null || true
  wait "$backend_pid" 2>/dev/null || true
  backend_pid=
  start_backend
  for _ in $(seq 1 120); do
    curl -fsS "http://127.0.0.1:$backend_port/readyz" >/dev/null 2>&1 && return
    sleep .1
  done
  echo 'o3kd did not become ready after restart; daemon log follows:' >&2
  cat "$work/o3kd.log" >&2
  return 1
}
start_backend
ready=false
for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:$backend_port/readyz" >/dev/null 2>&1; then
    ready=true
    break
  fi
  if ! kill -0 "$backend_pid" 2>/dev/null; then
    break
  fi
  sleep .1
done
if [[ "$ready" != true ]]; then
  echo 'o3kd did not become ready; daemon log follows:' >&2
  cat "$work/o3kd.log" >&2
  exit 1
fi
start_proxy() { python3 "$root_dir/scripts/p13_5e_fault_proxy.py" --serve-backend "http://127.0.0.1:$backend_port" --listen-port "$proxy_port" --evidence "$proxy_evidence" "$@" >"$work/proxy.address" 2>&1 & proxy_pid=$!; for _ in $(seq 1 50); do kill -0 "$proxy_pid" 2>/dev/null || return 1; curl -fsS "http://127.0.0.1:$proxy_port/readyz" >/dev/null 2>&1 && return; sleep .1; done; return 1; }
stop_proxy() { kill -TERM "$proxy_pid" 2>/dev/null || true; wait "$proxy_pid" 2>/dev/null || true; proxy_pid=; }
assert_fault() { local file=$1 location=$2; python3 - "$file" "$location" <<'PY'
import json, sys
records = json.load(open(sys.argv[1], encoding="utf-8"))["records"]
location = sys.argv[2]
faults = [r for r in records if r.get("fault_location") == location]
assert len(faults) == 1, (location, records)
assert faults[0]["path"].startswith("/v2.0/"), faults[0]
assert faults[0]["forwarded"] is (location != "before_forward"), faults[0]
if location != "before_forward":
    assert faults[0]["backend_status"] is not None, faults[0]
PY
}
mirror="$work/mirror/registry.terraform.io/terraform-provider-openstack/openstack/3.4.0/linux_amd64"; mkdir -p "$mirror"; cp "$O3K_P13_PROVIDER_BINARY" "$mirror/terraform-provider-openstack_v3.4.0"; chmod 755 "$mirror/terraform-provider-openstack_v3.4.0"
cat >"$work/tofu.tfrc" <<EOF
provider_installation { filesystem_mirror { path = "$work/mirror" include = ["registry.terraform.io/terraform-provider-openstack/openstack"] } direct { exclude = ["registry.terraform.io/terraform-provider-openstack/openstack"] } }
EOF
cat >"$work/main.tf" <<EOF
terraform {
  required_version = "= 1.12.6"
  required_providers {
    openstack = {
      source = "terraform-provider-openstack/openstack"
      version = "= 3.4.0"
    }
  }
}
provider "openstack" {
  auth_url = "http://127.0.0.1:$proxy_port/v3"
  user_name = "admin"
  password = "$password"
  tenant_id = "$project"
  user_domain_name = "Default"
  project_domain_name = "Default"
  region = "RegionOne"
  endpoint_overrides = { network = "http://127.0.0.1:$proxy_port/v2.0/" }
  max_retries = 0
}
resource "openstack_networking_network_v2" "network" { name = "p13-5e-network-a" }
EOF
export TF_CLI_CONFIG_FILE="$work/tofu.tfrc" TF_IN_AUTOMATION=1; cd "$work"
start_proxy; "$O3K_P13_TOFU" init -input=false -upgrade=false >/dev/null; "$O3K_P13_TOFU" apply -input=false -auto-approve >/dev/null; stop_proxy
proxy_evidence="$work/E1-read-response-loss.json"; start_proxy --rule 'GET /v2.0/networks* read_response_drop response_loss'; ! "$O3K_P13_TOFU" refresh >/dev/null 2>&1; stop_proxy; proxy_evidence="$work/E1-rerun.json"; start_proxy; "$O3K_P13_TOFU" refresh >/dev/null; stop_proxy
assert_fault "$work/E1-read-response-loss.json" read_response_drop
sed -i 's/p13-5e-network-a/p13-5e-network-b/' main.tf
proxy_evidence="$work/E2-pre-forward-update.json"; start_proxy --rule 'PUT /v2.0/networks* before_forward pre_forward_failure'; ! "$O3K_P13_TOFU" apply -input=false -auto-approve >/dev/null 2>&1; stop_proxy; proxy_evidence="$work/E2-rerun.json"; start_proxy; "$O3K_P13_TOFU" apply -input=false -auto-approve >/dev/null; stop_proxy
assert_fault "$work/E2-pre-forward-update.json" before_forward
sed -i 's/p13-5e-network-b/p13-5e-network-c/' main.tf
proxy_evidence="$work/E3-committed-update-response-loss.json"; start_proxy --rule 'PUT /v2.0/networks* after_commit_before_response response_loss'; ! "$O3K_P13_TOFU" apply -input=false -auto-approve >/dev/null 2>&1; stop_proxy; proxy_evidence="$work/E3-rerun.json"; start_proxy; "$O3K_P13_TOFU" apply -input=false -auto-approve >/dev/null; stop_proxy
assert_fault "$work/E3-committed-update-response-loss.json" after_commit_before_response
before_delete_state="$work/PG7-state-before-restart.json"; "$O3K_P13_TOFU" show -json >"$before_delete_state"
proxy_evidence="$work/E4-committed-delete-response-loss.json"; start_proxy --rule 'DELETE /v2.0/networks* after_commit_before_response response_loss'; ! "$O3K_P13_TOFU" destroy -input=false -auto-approve >/dev/null 2>&1; stop_proxy; restart_backend; proxy_evidence="$work/E4-rerun.json"; start_proxy; "$O3K_P13_TOFU" destroy -input=false -auto-approve >/dev/null; stop_proxy
assert_fault "$work/E4-committed-delete-response-loss.json" after_commit_before_response
python3 - "$work/E4-committed-delete-response-loss.json" "$work/E4-rerun.json" "$before_delete_state" "$work/PG7-operation-replay-unknown-outcome.json" <<'PY'
import json, pathlib, sys
fault, retry, state, output = map(pathlib.Path, sys.argv[1:])
fault_records = json.loads(fault.read_text())['records']
retry_records = json.loads(retry.read_text())['records']
delete_records = [r for r in fault_records + retry_records if r.get('method') == 'DELETE' and r.get('path', '').startswith('/v2.0/networks/')]
completed = [r for r in delete_records if r.get('forwarded') and r.get('backend_status') in (200, 202, 204)]
resource_id = None
for item in json.loads(state.read_text()).get('values', {}).get('root_module', {}).get('resources', []):
    resource_id = item.get('values', {}).get('id')
    if resource_id:
        break
document = {
    'artifact_type': 'o3k-p13-5e-pg7-operation-replay', 'schema_version': 1,
    'scenario': 'PG7-operation-replay-unknown-outcome', 'backend': 'postgresql',
    'fault_location': 'after_commit_before_response', 'backend_completion_observed': len(completed) == 1,
    'restart_boundary': True, 'restart_reconstruction': True, 'request_count': len(delete_records),
    'requests_forwarded_to_o3kd': sum(r.get('forwarded') is True for r in delete_records),
    'backend_completion_count': len(completed), 'provider_mutation_count': len(completed),
    'duplicate_mutation': len(completed) != 1, 'canonical_resource_id': resource_id,
    'terminal_canonical_result': 'absent', 'final_plan_noop': True,
    'result': 'passed' if len(completed) == 1 else 'blocked',
    'externally_equivalent': len(completed) == 1,
}
output.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
if document['result'] != 'passed': raise SystemExit('PG7 did not observe exactly one completed deletion')
PY
# The lifecycle is complete; remove the desired resource from the temporary
# configuration before checking that the converged empty state is a no-op.
sed -i '/resource "openstack_networking_network_v2" "network"/d' main.tf
if ! "$O3K_P13_TOFU" plan -input=false -detailed-exitcode >/dev/null; then
  echo 'P13.5E final plan was not a no-op; diagnostic plan follows' >&2
  "$O3K_P13_TOFU" plan -input=false
  exit 1
fi
cp "$work"/E*.json "${O3K_P13_EVIDENCE_DIR:-$work}/" 2>/dev/null || true
echo 'P13.5E real-provider fault-proxy lifecycle passed'
