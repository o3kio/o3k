#!/usr/bin/env bash
set -euo pipefail

# Bounded P13.5C compatibility-surface drift. This is deliberately not native
# drift: the out-of-band mutation uses the existing OpenStack PUT projection.
root_dir="$(cd "$(dirname "$0")/.." && pwd)"
contract="$root_dir/docs/compatibility/p13-5/p13-5a-convergence-contract.json"
output="$(printenv O3K_P13_5C_OUT_OF_BAND_EVIDENCE_OUTPUT || true)"
if [[ -z "$output" ]]; then output="$root_dir/target/p13-5c/canonical-out-of-band-drift-evidence.json"; fi
if [[ "$output" != /* ]]; then output="$root_dir/$output"; fi
mkdir -p "$(dirname "$output")"
head_sha="$(git -C "$root_dir" rev-parse HEAD)"
baseline_manifest="$(printenv P13_5B_BASELINE_MANIFEST || true)"

blocked() {
  local reason="$1"
  python3 - "$contract" "$output" "$head_sha" "$reason" <<'PY'
import hashlib, json, pathlib, sys
contract, output, head, reason = sys.argv[1:]
c = json.loads(pathlib.Path(contract).read_text())
d = {
  "artifact_type": "o3k-p13-5c-canonical-out-of-band-drift-evidence",
  "schema_version": 1, "phase": "P13.5C",
  "profile": "p13-iac-compatibility-v1", "status": "blocked",
  "surface": "canonical_out_of_band", "native_claim": False,
  "canonical_authority": "o3k", "provider_modified": False,
  "p13_5a_contract_sha256": hashlib.sha256(pathlib.Path(contract).read_bytes()).hexdigest(),
  "tested_o3k_head_sha": head,
  "toolchain": {"opentofu": c["toolchain"]["opentofu"], "provider": c["toolchain"]["provider"], "provider_modified": False},
  "scenario": {
    "resource": "openstack_networking_network_v2",
    "scenario": "canonical_out_of_band_mutable_drift",
    "operation": "mutable",
    "surface": "canonical_out_of_band", "native_claim": False,
    "result": "blocked", "reason": reason,
    "terraform_address": "openstack_networking_network_v2.managed",
    "mutation_route": "PUT /v2.0/networks/{id}",
    "refresh_only_actions": [], "normal_plan_actions": [], "final_plan_noop": False,
  },
}
pathlib.Path(output).write_text(json.dumps(d, indent=2, sort_keys=True) + "\n")
print("P13.5C canonical_out_of_band evidence written:", output)
PY
  echo "P13.5C canonical_out_of_band BLOCKED: $reason" >&2
  exit 2
}

missing_names=""
for name in O3K_P13_TOFU O3K_P13_PROVIDER_BINARY O3K_P13_PROVIDER_ARCHIVE O3K_P13_TOFU_ARCHIVE O3K_P13_PROVIDER_SHA256; do
  value="$(printenv "$name" || true)"
  [[ -n "$value" ]] || missing_names="$missing_names $name"
done
if [[ -n "$missing_names" ]]; then blocked "required P13 toolchain environment is missing:$missing_names"; fi
if [[ -z "$baseline_manifest" || ! -f "$baseline_manifest" ]]; then blocked "verified P13.2-P13.4 baseline manifest is required"; fi
if [[ "${P13_5C_ALLOW_BLOCKED_BASELINE:-0}" != 1 ]] && ! python3 - "$baseline_manifest" <<'PY'
import json, sys
if json.load(open(sys.argv[1])).get("status") != "verified": raise SystemExit(1)
PY
then blocked "P13.2-P13.4 baseline manifest is not verified"; fi

if [[ "${O3K_DATABASE_BACKEND:-sqlite}" == postgres ]]; then
  if [[ "${O3K_P13_ALLOW_DESTRUCTIVE_POSTGRES_RESET:-0}" != 1 ]]; then
    blocked "PostgreSQL scenario isolation requires explicit disposable-schema reset opt-in"
  fi
  if ! O3K_TEST_DATABASE_PURPOSE="${O3K_TEST_DATABASE_PURPOSE:-}" \
      O3K_DATABASE_URL="${O3K_DATABASE_URL:-}" \
      python3 "$root_dir/scripts/assert_disposable_postgres_test_database.py"; then
    blocked "PostgreSQL scenario reset requires an owned P13 test database"
  fi
  psql "$O3K_DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    'DROP SCHEMA public CASCADE; CREATE SCHEMA public;' >/dev/null
fi

tofu="$(printenv O3K_P13_TOFU)"
provider_binary="$(printenv O3K_P13_PROVIDER_BINARY)"
provider_archive="$(printenv O3K_P13_PROVIDER_ARCHIVE)"
tofu_archive="$(printenv O3K_P13_TOFU_ARCHIVE)"
provider_sha="$(printenv O3K_P13_PROVIDER_SHA256)"
o3kd="$(printenv O3K_P13_O3KD || true)"
if [[ -z "$o3kd" ]]; then o3kd="$root_dir/target/debug/o3kd"; fi
password="$(printenv O3K_P13_PASSWORD || true)"
if [[ -z "$password" ]]; then password="p13-5c-out-of-band-password"; fi
project_id="eba29e2d-53de-461d-ae91-ede7402713cb"
port="$(printenv O3K_P13_PORT || true)"
if [[ -z "$port" ]]; then port="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"; fi
tmp_base="$(printenv TMPDIR || true)"
if [[ -z "$tmp_base" ]]; then tmp_base="/var/tmp"; fi
work_dir="$(mktemp -d "$tmp_base/o3k-p13-5c-out-of-band.XXXXXX")"
trace_path="$work_dir/trace.jsonl"
mirror_dir="$work_dir/mirror/registry.terraform.io/terraform-provider-openstack/openstack/3.4.0/linux_amd64"
project_dir="$work_dir/project"
pid=""
network_id=""
token=""
cleanup() {
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  rm -rf "$work_dir"
}
trap cleanup EXIT

[[ -x "$tofu" ]] || blocked "OpenTofu executable is missing or not executable: $tofu"
[[ -x "$o3kd" ]] || blocked "o3kd executable is missing or not executable: $o3kd"
[[ -f "$provider_binary" && -f "$provider_archive" && -f "$tofu_archive" ]] ||
  blocked "pinned OpenTofu/provider archive or provider binary path is missing"
if ! python3 "$root_dir/scripts/p13_provider_contract.py" --verify-tools; then
  blocked "pinned P13 toolchain/provider verification failed"
fi
tofu_version="$("$tofu" version | head -n1)"
[[ "$tofu_version" == *"OpenTofu v1.12.6"* ]] || blocked "unexpected OpenTofu version: $tofu_version"

mkdir -p "$mirror_dir" "$project_dir"
cp "$provider_binary" "$mirror_dir/terraform-provider-openstack_v3.4.0"
chmod 0755 "$mirror_dir/terraform-provider-openstack_v3.4.0"
cat >"$work_dir/tofu.tfrc" <<EOF
provider_installation {
  filesystem_mirror {
    path = "$work_dir/mirror"
    include = ["registry.terraform.io/terraform-provider-openstack/openstack"]
  }
  direct { exclude = ["registry.terraform.io/terraform-provider-openstack/openstack"] }
}
EOF
O3K_BOOTSTRAP_PASSWORD="$password" O3K_TOKEN_SIGNING_KEY="p13-5c-out-of-band-token-signing-key-012345678901234567890123" \
O3K_COMPATIBILITY_TRACE_PATH="$trace_path" "$o3kd" --listen-addr "127.0.0.1:$port" \
  --data-dir "$work_dir/data" >"$work_dir/o3kd.log" 2>&1 &
pid=$!
for _ in $(seq 1 120); do curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1 && break; sleep 0.1; done
curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null
curl -fsS -D "$work_dir/auth.headers" -o /dev/null -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:$port/v3/auth/tokens" \
  --data "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"admin\",\"password\":\"$password\"}}},\"scope\":{\"project\":{\"name\":\"admin\"}}}}"
token="$(awk 'tolower($1)=="x-subject-token:" {print $2}' "$work_dir/auth.headers" | tr -d '\r')"
[[ -n "$token" ]] || blocked "authentication did not return X-Subject-Token"

restart_backend() {
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  O3K_BOOTSTRAP_PASSWORD="$password" O3K_TOKEN_SIGNING_KEY="p13-5c-out-of-band-token-signing-key-012345678901234567890123" \
    O3K_COMPATIBILITY_TRACE_PATH="$trace_path" "$o3kd" --listen-addr "127.0.0.1:$port" \
    --data-dir "$work_dir/data" >"$work_dir/o3kd-restart.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 120); do curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1 && break; sleep 0.1; done
  curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null
}

cat >"$project_dir/main.tf" <<EOF
terraform {
  required_version = "= 1.12.6"
  required_providers {
    openstack = { source = "terraform-provider-openstack/openstack", version = "= 3.4.0" }
  }
}
provider "openstack" {
  auth_url = "http://127.0.0.1:$port"
  user_name = "admin"
  password = "$password"
  tenant_id = "$project_id"
  max_retries = 0
}
resource "openstack_networking_network_v2" "managed" {
  name = "p13-5c-network-desired"
  admin_state_up = true
  tags = []
}
EOF
export TF_CLI_CONFIG_FILE="$work_dir/tofu.tfrc" TF_IN_AUTOMATION=1
cd "$project_dir"
"$tofu" init -input=false -upgrade=false >/dev/null
plan_json() {
  local label="$1" mode="$2"
  local plan="$work_dir/$label.tfplan"
  set +e
  if [[ "$mode" == refresh-only ]]; then "$tofu" plan -input=false -refresh-only -out="$plan" >/dev/null
  else "$tofu" plan -input=false -out="$plan" >/dev/null; fi
  local status=$?
  set -e
  [[ "$status" == 0 || "$status" == 2 ]] || return "$status"
  "$tofu" show -json "$plan" >"$work_dir/$label.json"
  python3 - "$work_dir/$label.json" <<'PY'
import json, sys
path = sys.argv[1]
secret_keys = {"password", "token", "access_token", "secret", "private_key"}
def redact(value):
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if key.lower() in secret_keys else redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value
document = json.load(open(path))
open(path, "w").write(json.dumps(redact(document), sort_keys=True))
PY
}
canonical_snapshot() {
  python3 - "${O3K_DATABASE_BACKEND:-sqlite}" "${O3K_DATABASE_URL:-}" "$work_dir/data/o3k.sqlite" "$project_id" "$1" "$2" <<'PY'
import json, sqlite3, subprocess, sys
backend, database_url, db, project, identity, phase = sys.argv[1:]
if backend == "postgres":
    def literal(value):
        return "'" + value.replace("'", "''") + "'"
    query = (
        "SELECT id, project_id, name, state FROM canonical_networks "
        f"WHERE id = {literal(identity)} AND project_id = {literal(project)} AND state <> 'deleted'; "
        f"SELECT count(*) FROM canonical_networks WHERE project_id = {literal(project)} AND state <> 'deleted'"
    )
    result = subprocess.run(
        ["psql", database_url, "-At", "-v", "ON_ERROR_STOP=1", "-c", query],
        check=True, capture_output=True, text=True,
    )
    values = result.stdout.splitlines()
    rows = [tuple(line.split("|", 3)) for line in values[:-1] if line]
    project_count = int(values[-1]) if values else 0
    store = "canonical_store:postgres:canonical_networks"
else:
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    rows = c.execute("SELECT id, project_id, name, state FROM canonical_networks WHERE id=? AND project_id=? AND state <> 'deleted'", (identity, project)).fetchall()
    project_count = c.execute("SELECT count(*) FROM canonical_networks WHERE project_id=? AND state <> 'deleted'", (project,)).fetchone()[0]
    c.close()
    store = "canonical_store:sqlite:canonical_networks"
print(json.dumps({"source":"canonical_store","store":store,"phase":phase,"requested_id":identity,"owner_scope":project,"count":len(rows),"project_resource_count":project_count,"records":[{"resource_id":r[0],"owner_scope":r[1],"name":r[2],"state":r[3]} for r in rows]}, sort_keys=True))
PY
}

"$tofu" apply -input=false -auto-approve >/dev/null
network_id="$("$tofu" show -json | python3 -c 'import json,sys;print(next(x["values"]["id"] for x in json.load(sys.stdin)["values"]["root_module"]["resources"] if x["address"]=="openstack_networking_network_v2.managed"))')"
initial_network_id="$network_id"
canonical_before="$(canonical_snapshot "$network_id" before)"
plan_json initial-normal normal
python3 - "$work_dir/initial-normal.json" <<'PY'
import json, sys
p=json.load(open(sys.argv[1]))
if [x for x in p.get("resource_changes",[]) if x.get("change",{}).get("actions") != ["no-op"]]: raise SystemExit("initial plan was not no-op")
PY
remote_deletion_result="not_run"
remote_deletion_old_id=""
remote_deletion_old_status=""
remote_deletion_new_id=""
if [[ "${P13_5C_REMOTE_DELETE:-0}" == 1 ]]; then
  remote_deletion_old_id="$network_id"
  curl -fsS -H "X-Auth-Token: $token" -X DELETE "http://127.0.0.1:$port/v2.0/networks/$network_id" >/dev/null
  remote_deletion_old_status="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-Auth-Token: $token" "http://127.0.0.1:$port/v2.0/networks/$network_id")"
  [[ "$remote_deletion_old_status" == 404 ]] || { echo "remote deletion did not remove the network: $remote_deletion_old_status" >&2; exit 1; }
  plan_json remote-deletion normal
  python3 - "$work_dir/remote-deletion.json" <<'PY'
import json, sys
p=json.load(open(sys.argv[1]))
rows=[x for x in p.get("resource_changes",[]) if x.get("address")=="openstack_networking_network_v2.managed"]
if len(rows) != 1 or rows[0].get("change",{}).get("actions") != ["create"]:
    raise SystemExit("remote deletion did not produce a single create action")
PY
  "$tofu" apply -input=false -auto-approve >/dev/null
  remote_deletion_new_id="$($tofu show -json | python3 -c 'import json,sys;print(next(x["values"]["id"] for x in json.load(sys.stdin)["values"]["root_module"]["resources"] if x["address"]=="openstack_networking_network_v2.managed"))')"
  [[ "$remote_deletion_new_id" != "$remote_deletion_old_id" ]] || { echo "remote deletion recreation reused the old identity" >&2; exit 1; }
  remote_deletion_result="passed"
  network_id="$remote_deletion_new_id"
  canonical_before="$(canonical_snapshot "$network_id" before-recreation)"
fi
curl -fsS -H "X-Auth-Token: $token" -H 'Content-Type: application/json' -X PUT \
  "http://127.0.0.1:$port/v2.0/networks/$network_id" \
  --data '{"network":{"name":"p13-5c-network-drifted"}}' >"$work_dir/mutation-response.json"
compat_after_mutation="$(curl -fsS -H "X-Auth-Token: $token" "http://127.0.0.1:$port/v2.0/networks/$network_id")"
canonical_after_mutation="$(canonical_snapshot "$network_id" after_mutation)"
python3 - "$canonical_before" "$canonical_after_mutation" "$compat_after_mutation" <<'PY'
import json, sys
b,a,p=map(json.loads,sys.argv[1:])
if b["count"] != 1 or a["count"] != 1 or b["records"][0]["resource_id"] != a["records"][0]["resource_id"]: raise SystemExit("canonical identity/count changed")
if p["network"]["name"] != "p13-5c-network-drifted": raise SystemExit("mutation not projected")
PY
plan_json drift-refresh-only refresh-only
plan_json drift-normal normal
python3 - "$work_dir/drift-refresh-only.json" "$work_dir/drift-normal.json" <<'PY'
import json, sys
r,n=map(lambda x:json.load(open(x)),sys.argv[1:])
a="openstack_networking_network_v2.managed"
c=[x for x in n.get("resource_changes",[]) if x.get("address")==a]
u=[x for x in n.get("resource_changes",[]) if x.get("address")!=a and x.get("change",{}).get("actions")!=["no-op"]]
if not c or c[0].get("change",{}).get("actions") != ["update"]: raise SystemExit("drift did not produce exact update")
if c[0].get("change",{}).get("replace",False): raise SystemExit("drift proposed replacement")
if u: raise SystemExit("drift produced unrelated changes")
# Refresh-only is expected to report the remote drift as an update.  It must
# not contain a create/delete replacement or any unrelated resource action;
# the command itself is observational and does not apply the change.
for x in r.get("resource_drift",[]):
    actions=x.get("change",{}).get("actions",[])
    if actions not in ([],["no-op"],["update"]): raise SystemExit("refresh-only contained create/delete mutation intent")
if [x for x in r.get("resource_changes",[]) if x.get("change",{}).get("actions") not in ([],["no-op"],["update"])]: raise SystemExit("refresh-only contained invalid resource action")
drift=[x for x in r.get("resource_drift",[]) if x.get("address")==a and x.get("change",{}).get("actions")==["update"]]
if len(drift) != 1 or len(r.get("resource_drift",[])) != 1: raise SystemExit("refresh-only did not report exactly the managed drift")
PY
"$tofu" apply -input=false -auto-approve >/dev/null
canonical_after_reapply="$(canonical_snapshot "$network_id" after_reapply)"
canonical_after_cleanup=""
compat_after_reapply="$(curl -fsS -H "X-Auth-Token: $token" "http://127.0.0.1:$port/v2.0/networks/$network_id")"
restart_backend
plan_json final-normal normal
python3 - "$work_dir/final-normal.json" "$canonical_before" "$canonical_after_reapply" "$compat_after_reapply" <<'PY'
import json, sys
p=json.load(open(sys.argv[1])); b,a,c=map(json.loads,sys.argv[2:])
if [x for x in p.get("resource_changes",[]) if x.get("change",{}).get("actions") != ["no-op"]]: raise SystemExit("final plan was not no-op")
if b["records"][0]["resource_id"] != a["records"][0]["resource_id"] or a["count"] != 1: raise SystemExit("identity/count changed after reapply")
if c["network"]["name"] != "p13-5c-network-desired" or c["network"]["admin_state_up"] is not True: raise SystemExit("reapply did not restore desired state")
PY
"$tofu" destroy -input=false -auto-approve >/dev/null
cleanup_status="$(curl -sS -o /dev/null -w '%{http_code}' -H "X-Auth-Token: $token" "http://127.0.0.1:$port/v2.0/networks/$network_id")"
[[ "$cleanup_status" == 404 ]] || { echo "cleanup did not remove network: $cleanup_status" >&2; exit 1; }
canonical_after_cleanup="$(canonical_snapshot "$network_id" after_cleanup)"
python3 - "$canonical_after_cleanup" <<'PY'
import json, sys
if json.loads(sys.argv[1])["count"] != 0: raise SystemExit("canonical cleanup left a resource")
PY

python3 - "$contract" "$output" "$head_sha" "$tofu_version" "$provider_binary" "$provider_archive" "$tofu_archive" "$provider_sha" "$network_id" "$initial_network_id" "$canonical_before" "$canonical_after_mutation" "$canonical_after_reapply" "$canonical_after_cleanup" "$compat_after_mutation" "$compat_after_reapply" "$work_dir/initial-normal.json" "$work_dir/drift-refresh-only.json" "$work_dir/drift-normal.json" "$work_dir/final-normal.json" "$cleanup_status" "$baseline_manifest" "$remote_deletion_result" "$remote_deletion_old_id" "$remote_deletion_old_status" "$remote_deletion_new_id" <<'PY'
import hashlib, json, pathlib, sys
(contract, output, head, tofu_version, provider_binary, provider_archive, tofu_archive, provider_sha, network_id, initial_network_id, before, after_mutation, after_reapply, after_cleanup, compat_mutation, compat_reapply, initial, refresh, normal, final, cleanup, baseline_manifest, remote_result, remote_old_id, remote_old_status, remote_new_id) = sys.argv[1:]
c=json.loads(pathlib.Path(contract).read_text())
def digest(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for b in iter(lambda:f.read(1048576),b""): h.update(b)
 return h.hexdigest()
def j(p): return json.loads(pathlib.Path(p).read_text())
def s(x): return json.loads(x)
b,a,r=s(before),s(after_mutation),s(after_reapply)
cleanup_observation=s(after_cleanup)
refresh_document = j(refresh)
normal_document = j(normal)
normal_changes = [x for x in normal_document.get("resource_changes", []) if x.get("address") == "openstack_networking_network_v2.managed"]
d={"artifact_type":"o3k-p13-5c-canonical-out-of-band-drift-evidence","schema_version":1,"phase":"P13.5C","profile":"p13-iac-compatibility-v1","status":"passed","surface":"canonical_out_of_band","native_claim":False,"canonical_authority":"o3k","provider_modified":False,"p13_5a_contract_sha256":hashlib.sha256(pathlib.Path(contract).read_bytes()).hexdigest(),"tested_o3k_head_sha":head,"baseline":{"status":json.loads(pathlib.Path(baseline_manifest).read_text())["status"],"source_commit":json.loads(pathlib.Path(baseline_manifest).read_text())["source_commit"]},"toolchain":{"opentofu":c["toolchain"]["opentofu"],"opentofu_version_output":tofu_version,"opentofu_archive_sha256":digest(tofu_archive),"provider":c["toolchain"]["provider"],"provider_archive_sha256":digest(provider_archive),"provider_binary_sha256":digest(provider_binary),"provider_sha256_expected":provider_sha,"provider_modified":False},"scenario":{"resource":"openstack_networking_network_v2","scenario":"canonical_out_of_band_mutable_drift","operation":"mutable","surface":"canonical_out_of_band","native_claim":False,"terraform_address":"openstack_networking_network_v2.managed","canonical_id_before":initial_network_id,"canonical_id_after_mutation":a["records"][0]["resource_id"],"canonical_id_after_reapply":r["records"][0]["resource_id"],"owner_scope":b["owner_scope"],"native_change":"name","mutation_route":"PUT /v2.0/networks/{id}","remote_deletion_recreation":{"result":remote_result,"old_resource_id":remote_old_id,"old_http_status":remote_old_status,"new_resource_id":remote_new_id,"old_resource_absent":remote_old_status == "404","identity_changed":bool(remote_old_id and remote_new_id and remote_new_id != remote_old_id)},"refresh_only_actions":[x.get("change",{}).get("actions",[]) for x in refresh_document.get("resource_drift",[])],"normal_plan_actions":[{"address":x.get("address"),"actions":x.get("change",{}).get("actions",[]),"replacement":x.get("change",{}).get("replace",False)} for x in normal_changes],"unrelated_changes_count":0,"old_resource_absent":remote_old_status == "404","new_resource_count":1,"canonical_same_id_count":1 if not remote_new_id else 0,"final_plan_noop":True,"cleanup_http_status":int(cleanup),"canonical_observations":{"before":b,"after_mutation":a,"after_reapply":r,"after_cleanup":s(after_cleanup)},"compatibility_observations":{"after_mutation":s(compat_mutation),"after_reapply":s(compat_reapply)},"plan_observation":{"initial_normal":j(initial),"refresh_only":refresh_document,"normal":normal_document,"final_normal":j(final)},"result":"passed"}}
# When remote deletion/recreation is enabled, the mutable drift portion runs
# against recreated B. Keep its identity/count fields distinct from the
# nested A->B deletion evidence.
d["scenario"]["canonical_id_before"] = b["records"][0]["resource_id"]
d["scenario"]["old_resource_absent"] = False
d["scenario"]["canonical_same_id_count"] = 1
d["scenario"]["restart_reconstruction"] = True
pathlib.Path(output).write_text(json.dumps(d,indent=2,sort_keys=True)+"\n")
PY
python3 - "$output" "$baseline_manifest" <<'PY'
import json, sys
path = sys.argv[1]
baseline_manifest = sys.argv[2]
document = json.loads(open(path).read())
scenario = document["scenario"]
scenario["canonical_same_id_count"] = 1
scenario["canonical_project_resource_count_before"] = scenario["canonical_observations"]["before"]["project_resource_count"]
scenario["canonical_project_resource_count_after_mutation"] = scenario["canonical_observations"]["after_mutation"]["project_resource_count"]
scenario["canonical_project_resource_count_after_reapply"] = scenario["canonical_observations"]["after_reapply"]["project_resource_count"]
scenario["canonical_project_resource_count_after_cleanup"] = scenario["canonical_observations"]["after_cleanup"]["project_resource_count"]
document["baseline"]["evidence_sha256"] = json.loads(open(baseline_manifest).read())["evidence_sha256"]
scenario.pop("canonical_duplicate_count", None)
open(path, "w").write(json.dumps(document, indent=2, sort_keys=True) + "\n")
PY
python3 "$root_dir/scripts/validate_p13_5c_evidence.py" --canonical-evidence "$output"
echo "P13.5C canonical_out_of_band Network drift evidence: $output"
