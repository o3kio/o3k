#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-guards.XXXXXX")"
trap 'rm -rf -- "${WORK_DIR}"' EXIT
EVIDENCE="${WORK_DIR}/evidence.json"
PYTHONPATH="${ROOT_DIR}/scripts${PYTHONPATH:+:${PYTHONPATH}}" python3 - <<'PY'
from p15_7_scale_semantics import validate_bootstrap_scale_membership

bootstrap = "bootstrap-block"
initial = {"blocks": [
    {"block_id": bootstrap, "placement_eligible": True},
    {"block_id": "a", "placement_eligible": True},
]}

# Placement may drain the bootstrap block. After removal and replacement, the
# canonical eligible set is still five, and bootstrap is correctly absent.
bootstrap_drained = {
    "blocks": [{"block_id": "a", "placement_eligible": True}],
    "bootstrap_expect": "absent",
}
validate_bootstrap_scale_membership(
    initial, bootstrap_drained, bootstrap, "compute-agent", "compute-agent")

# When a child is drained, the bootstrap identity remains eligible.
child_drained = {
    "blocks": [{"block_id": bootstrap, "placement_eligible": True}],
    "bootstrap_expect": "present",
}
validate_bootstrap_scale_membership(
    initial, child_drained, bootstrap, "block-a", "compute-agent")

for final, drain_agent in (
    ({"blocks": [], "bootstrap_expect": "absent"}, "block-a"),
    ({"blocks": [{"block_id": bootstrap, "placement_eligible": True}],
      "bootstrap_expect": "present"}, "compute-agent"),
):
    try:
        validate_bootstrap_scale_membership(
            initial, final, bootstrap, drain_agent, "compute-agent")
    except ValueError:
        pass
    else:
        raise AssertionError("inconsistent bootstrap checkpoint was accepted")
PY
# The mandatory P15.7 path must remain valid when no Araf endpoint is
# configured at all.  Keep this explicit so a future environment-level
# prerequisite cannot accidentally turn the optional consumer into a gate.
unset O3K_P15_7_ARAF_URL
FIXTURE_ENV="${WORK_DIR}/foreign-project.env"
FIXTURE_MASK="${WORK_DIR}/foreign-project-mask.txt"
: >"${FIXTURE_ENV}"
GITHUB_ENV="${FIXTURE_ENV}" bash "${ROOT_DIR}/scripts/prepare-p15-7-foreign-project-fixture.sh" >"${FIXTURE_MASK}"
python3 - "${FIXTURE_ENV}" "${FIXTURE_MASK}" <<'PY'
from pathlib import Path
import re, sys
values = dict(line.split("=", 1) for line in Path(sys.argv[1]).read_text().splitlines())
password = values["O3K_EXTRA_TENANT_PASSWORD"]
assert re.fullmatch(r"[0-9a-f]{64}", password)
assert values["O3K_P15_7_FOREIGN_PASSWORD"] == password
assert values["O3K_EXTRA_TENANT_PROJECT_ID"] == values["O3K_P15_7_FOREIGN_PROJECT_ID"]
assert values["O3K_EXTRA_TENANT_PROJECT_NAME"] == "tenant-b"
assert values["O3K_EXTRA_TENANT_USER_NAME"] == values["O3K_P15_7_FOREIGN_USER_NAME"] == "tenant-b-user"
assert Path(sys.argv[2]).read_text() == f"::add-mask::{password}\n"
PY
PLACEMENT_BLOCKS="${WORK_DIR}/placement-blocks.json"
cat >"${PLACEMENT_BLOCKS}" <<'JSON'
[
  {"block":{"id":"block-bootstrap","state":"ready","execution_identity":"compute-agent","resource_provider_ids":["compute-agent"]}},
  {"block":{"id":"block-a-id","state":"ready","execution_identity":"block-a","resource_provider_ids":["block-a"]}},
  {"block":{"id":"block-unavailable","state":"draining","execution_identity":"unavailable-agent","resource_provider_ids":["unavailable-agent"]}},
  {"block":{"id":"block-unlinked","state":"ready","execution_identity":"unlinked-agent","resource_provider_ids":[]}}
]
JSON
[[ "$(python3 "${ROOT_DIR}/scripts/resolve-p15-7-placement-block.py" "${PLACEMENT_BLOCKS}" compute-agent)" == block-bootstrap ]]
[[ "$(python3 "${ROOT_DIR}/scripts/resolve-p15-7-placement-block.py" "${PLACEMENT_BLOCKS}" block-a)" == block-a-id ]]
for invalid_identity in unavailable-agent unlinked-agent absent-agent; do
  if python3 "${ROOT_DIR}/scripts/resolve-p15-7-placement-block.py" "${PLACEMENT_BLOCKS}" \
    "${invalid_identity}" >/dev/null 2>&1; then
    echo "non-ready or unlinked placement host accepted: ${invalid_identity}" >&2
    exit 1
  fi
done
python3 - "${PLACEMENT_BLOCKS}" "${WORK_DIR}/placement-blocks-ambiguous.json" <<'PY'
import json, pathlib, sys
items = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
items.append({"block": {"id": "duplicate-bootstrap", "state": "ready",
               "execution_identity": "compute-agent",
               "resource_provider_ids": ["compute-agent"]}})
pathlib.Path(sys.argv[2]).write_text(json.dumps(items), encoding="utf-8")
PY
if python3 "${ROOT_DIR}/scripts/resolve-p15-7-placement-block.py" \
  "${WORK_DIR}/placement-blocks-ambiguous.json" compute-agent >/dev/null 2>&1; then
  echo "ambiguous placement host mapping accepted" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, sys
sha = "0123456789abcdef0123456789abcdef01234567"
bootstrap_block_id = "99999999-9999-4999-8999-999999999999"
child_ids = {
    "block-a": "11111111-1111-4111-8111-111111111111",
    "block-b": "22222222-2222-4222-8222-222222222222",
    "block-c": "33333333-3333-4333-8333-333333333333",
    "block-d": "44444444-4444-4444-8444-444444444444",
    "block-e": "55555555-5555-4555-8555-555555555555",
}
ELIGIBILITY = ("placement_eligible = state=='ready' AND >=1 resource_provider_id in "
               "/operator/diagnostics/providers with state 'Enabled' AND no drain_blockers; "
               "all BuildingBlocks enumerated (bootstrap included by TLS agent identity)")

def block_entry(agent, block_id, state="ready", enabled=True, eligible=True, bootstrap=False, blockers=()):
    providers = [agent]
    return {
        "block_id": block_id,
        "execution_identity": agent,
        "resource_provider_ids": providers,
        "provider_states": ["Enabled"] if enabled and state == "ready" else (
            ["Draining"] if state == "draining" else ["Unavailable"]),
        "state": state,
        "drain_blockers": list(blockers),
        "agent_available": True,
        "is_bootstrap": bootstrap,
        "compute_capable": True,
        "placement_eligible": bool(eligible and state == "ready" and enabled),
    }

def checkpoint(phase, entries):
    return {
        "phase": phase,
        "eligibility_basis": ELIGIBILITY,
        "blocks": entries,
        "total_blocks": len(entries),
        "eligible_ready_count": sum(1 for entry in entries if entry["placement_eligible"]),
    }

bootstrap_ready = lambda: block_entry("compute-agent", bootstrap_block_id, bootstrap=True)
initial_entries = [bootstrap_ready()] + [
    block_entry(agent, child_ids[agent]) for agent in ("block-a", "block-b", "block-c", "block-d")]
post_drain_entries = [bootstrap_ready()] + [
    block_entry(agent, child_ids[agent], state=("draining" if agent == "block-a" else "ready"),
                enabled=(agent != "block-a"), eligible=(agent != "block-a"),
                blockers=({"kind": "workload", "count": 1},) if agent == "block-a" else ())
    for agent in ("block-a", "block-b", "block-c", "block-d")]
post_remove_entries = [bootstrap_ready()] + [
    block_entry(agent, child_ids[agent]) for agent in ("block-b", "block-c", "block-d")]
final_entries = [bootstrap_ready()] + [
    block_entry(agent, child_ids[agent]) for agent in ("block-b", "block-c", "block-d", "block-e")]

checkpoints = [
    checkpoint("initial-scale-checkpoint", initial_entries),
    checkpoint("pre-drain", [dict(entry) for entry in initial_entries]),
    checkpoint("post-drain", post_drain_entries),
    checkpoint("post-remove", post_remove_entries),
    checkpoint("post-replacement", final_entries),
    checkpoint("post-reboot", [dict(entry) for entry in final_entries]),
    checkpoint("post-crash-repair", [dict(entry) for entry in final_entries]),
    checkpoint("post-maintenance", [dict(entry) for entry in final_entries]),
]

def eligible_projection(entries):
    eligible = [entry for entry in entries if entry["placement_eligible"]]
    return ([entry["execution_identity"] for entry in eligible],
            [entry["block_id"] for entry in eligible])

initial_agents, initial_blocks = eligible_projection(initial_entries)
final_agents, final_blocks = eligible_projection(final_entries)

doc = {
  "artifact_type":"o3k-p15-7-scale-composition-evidence", "schema_version":1,
  "phase":"P15.7", "status":"passed", "evidence_tier":"protected-real-host",
  "profile":"small-edge-cloud",
  "tested_source_sha":sha,
  "checkout_head":sha,"git_tree_clean":True,"harness_inputs_sha256":"0" * 64,
  "execution":{"provider":"agent","hypervisor":"libvirt","database_backend":"postgres",
    "real_o3kd":True,"real_auth":True,"real_execution_boundary":True,
    "multiple_real_hosts":True,"block_count":5,"provisioned_vms":5,"sqlite_parity":True},
  "scale_composition":{
    "counting_rule":"eligible_ready",
    "eligibility_rule":ELIGIBILITY,
    "bootstrap":{"agent_id":"compute-agent","block_id":bootstrap_block_id},
    "enrolled_identities":{"count":6,"distinct":True,
      "agents":["compute-agent","block-a","block-b","block-c","block-d","block-e"],
      "block_ids":[bootstrap_block_id]+[child_ids[a] for a in ("block-a","block-b","block-c","block-d","block-e")]},
    "initial_concurrent_ready":{"count":5,"agents":initial_agents,"block_ids":initial_blocks},
    "peak_concurrent_ready":{"count":5,"minimum":5,"met":True},
    "final_concurrent_ready":{"count":5,"agents":final_agents,"block_ids":final_blocks},
    "checkpoints":checkpoints,
    "drained_agent":"block-a","replacement_agent":"block-e","duplicate_identities":False},
  "journey":{"fresh_deployment":True,"init":True,"topology":True,"capacity":True,
    "constrained_placement":True,"add_block_capacity_growth":True,
    "multiple_authenticated_joins":{"status":"passed","count":5,"each_authenticated":True},
    "drain":{"status":"passed","no_new_placement":True,"blockers_observed":True,"evacuation_claimed":False,
      "blocker_requery":{"phase":"post-delete-pre-remove","drain_block_id":child_ids["block-a"],
        "state":"draining","workload_id":"66666666-6666-4666-8666-666666666666",
        "blockers_at_drain":[{"kind":"workload","count":1}],
        "blockers_at_requery":[],"blockers_empty":True,
        "attachment_blockers":[],"local_storage_blockers":[],
        "deleted_workload_absent_from_blockers":True}},
    "remove_rejoin_replace":True,"restart_recovery":True,
    "crash_injection_repair":{"status":"passed",
      "fault_hook":{"env":"O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS","pause_ms":45000,
        "semantics":"positive-ms sleep on the delete path after durable terminalization commits and before endpoint release"},
      "server_c":{"resource_id":"66666666-6666-4666-8666-666666666666",
        "owned_endpoint_id":"77777777-7777-4777-8777-777777777777","fixed_ip":"198.18.0.4"},
      "endpoint_before_crash":{"port_id":"77777777-7777-4777-8777-777777777777","existed":True,
        "binding_state_exposed":False,"presence_asserted_while_pause_held":True},
      "operation_terminal_observed_ms":4200,
      "kill":{"signal":"SIGKILL","pid":4242,"identity_verified":True,"orderly_restart":False},
      "delete_request_observed_http_code":"000",
      "restart":{"path":"normal boot path via start_o3kd_verified","readyz":"passed"},
      "sweep":{"passes_observed":2,"time_to_repair_ms":9400,"bounded_wait_ms":180000,"endpoint_absent_after":True},
      "fixed_ip_reuse":{"attempted":True,"succeeded":True},
      "quota":{"dimension":"network:ports","before":3,"after":3,"restored":True},
      "placement_allocation":{"vcpu_allocated_before":2,"vcpu_allocated_after":2,"leak":False},
      "responsiveness_during_backlog":{"orphan_present_at_create":True,
        "unrelated_db_backed_probe":{"path":"/operator/diagnostics/providers?limit=1","succeeded":True,"latency_ms":43,"curl_exit":0,"status_code":200},
        "create_call_latency_ms":2100,
        "activation_latency_ms":41000,"server_active":True},
      "caller_supplied_endpoint_preserved":True,
      "foreign_project_endpoint_preserved":True},
    "host_maintenance":{"status":"passed","block_id":child_ids["block-e"],
      "execution_identity":"block-e","resource_provider_ids":["block-e"],
      "drain":{"succeeded":True,"blockers_empty":True,"blockers":"no residents existed"},
      "placement_rejected_on_draining_block":True,
      "host_reboot":{"issued_from":"outer host via virsh reboot on the recorded domain UUID","guest_returned_ssh":True},
      "agent_restart":{"modeled":"operator restarts the host service","reconnected":True},
      "identity_preserved":{"same_building_block_id":True,"same_execution_identity":True,
        "same_resource_provider_ids":True,"no_duplicate_block_or_provider":True},
      "returned_to_ready":{"operator_transition":"POST /operator/building-blocks/{id}/actions/ready","succeeded":True,
        "provider_reopened":True},
      "final_eligible_ready_count":5},
    "transient_failures":[{"type":"bounded_retry","api":"keystone token issue","at_unix_ms":1750000000000,
      "fault_injection_active":False,"detail":"attempts=2 outcome=acquired"}],
    "projections_convergent":{"native":True,"openstack":True,
      "araf":{"required":False,"status":"not_configured",
        "reason":"external_consumer_not_provisioned"}}},
  "network_observation":{"child_vms":[
    {"domain":"o3k-p15-7-example-block-a","uuid":"88888888-8888-4888-8888-888888888888",
     "expected_mac":"52:54:00:aa:bb:cc","selected_ip":"192.0.2.20","gateway":"192.0.2.1",
     "candidates":[{"ip":"192.0.2.20","mac":"52:54:00:aa:bb:cc","expiry":"1727700000","source":"net-dhcp-leases"}],
     "freshness":{"available":True,"freshest_ip":"192.0.2.20","source":"/var/lib/libvirt/dnsmasq/virbr0.status"},
     "selection_reason":"freshest_valid_owned_lease_for_mac","ssh_proof":True,
     "assertions":{"no_cross_mac":True,"not_gateway":True,"no_stale_over_fresh":True}}],
    "all_ssh_proven":True,
    "resolver_contract":"freshest valid owned DHCP lease for the expected MAC"},
  "restart_recovery":{"status":"passed","canonical_state_survived":True,"postgres":True,"sqlite_parity":True},
  "database_ownership":{"mode":"disposable","effective_backend":"postgres",
    "backend_proof":{"status":"passed","method":"o3kd_env_backend_configuration"},
    "server_version":"16.4","redacted_endpoint":"postgres://REDACTED@127.0.0.1:5432/o3k_test",
    "schema_prepared":True,"fault_injection":"docker_restart","managed":True},
  "security_negatives":{"unauthenticated_join_rejected":True,"replay_join_rejected":True,
    "cross_tenant_concealment":True,"foreign_state_preserved":True},
  "bootstrap_timing":{"measured":True,"sample_count":3,"boundary":"fresh o3kd through five authenticated block joins",
    "excludes_preprovisioned_external_work":True,"claim_scope":"profile-specific-measurement-only"},
  "leak_check":{"status":"passed","owned_leaks":0,"owned_inconsistencies":0,"foreign_state_changes":0},
  "defect_ledger":{"status":"passed","blockers":0,"high":0,"medium":0},
  "claim_validation":{"status":"passed","sources":["README.md","docs/ROADMAP.md",
    "docs/status/current-state.yaml","compatibility/product-profiles.yaml",
    "docs/compatibility/matrix.yaml","docs/architecture/p15-e2d-gap-register.md"],
    "unsupported_claims_preserved":True,"claims":["bounded small-edge profile convergence"]}
}
json.dump(doc, open(sys.argv[1], "w", encoding="utf-8"), indent=2)
PY

env -u O3K_P15_7_ARAF_URL python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}" \
  --expected-source-sha 0123456789abcdef0123456789abcdef01234567 \
  --expected-profile small-edge-cloud
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
del d["journey"]["crash_injection_repair"]["responsiveness_during_backlog"]["unrelated_db_backed_probe"]
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "crash-pause responsiveness probe missing from evidence accepted" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
d["journey"]["crash_injection_repair"]["responsiveness_during_backlog"]["unrelated_db_backed_probe"] = {
    "path":"/operator/diagnostics/providers?limit=1", "succeeded":True, "latency_ms":43,"curl_exit":0,"status_code":200}
p.write_text(json.dumps(d))
PY
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
probe=d["journey"]["crash_injection_repair"]["responsiveness_during_backlog"]["unrelated_db_backed_probe"]
probe["status_code"]=403; p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "crash-pause probe with non-2xx status accepted" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
probe=d["journey"]["crash_injection_repair"]["responsiveness_during_backlog"]["unrelated_db_backed_probe"]
probe["status_code"]=200; probe["curl_exit"]=28; p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "crash-pause probe with curl failure accepted" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
probe=d["journey"]["crash_injection_repair"]["responsiveness_during_backlog"]["unrelated_db_backed_probe"]
probe["curl_exit"]=0; p.write_text(json.dumps(d))
PY
DIAGNOSTIC_EVIDENCE="${WORK_DIR}/diagnostic-only.json"
python3 - "${DIAGNOSTIC_EVIDENCE}" <<'PY'
import json, sys
json.dump({"artifact_type":"o3k-p15-7-diagnostic-fast-lane-journey",
           "schema_version":1,"phase":"P15.7","status":"passed",
           "evidence_tier":"diagnostic-only","diagnostic_lane":True,
           "final_completion_evidence":False}, open(sys.argv[1],"w",encoding="utf-8"))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${DIAGNOSTIC_EVIDENCE}"; then
  echo "diagnostic-only artifact accepted as final P15.7 evidence" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib
p = pathlib.Path(__import__('sys').argv[1]); d=json.loads(p.read_text())
d["execution"]["provider"] = "fake"; p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "fake provider accepted by P15.7 validator" >&2; exit 1
fi
# A below-S5 peak concurrency or a duplicate identity must fail closed.
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
d["execution"]["provider"] = "agent"
d["scale_composition"]["peak_concurrent_ready"]["count"] = 4
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "below-S5 peak concurrency accepted by P15.7 validator" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
d["scale_composition"]["peak_concurrent_ready"]["count"] = 5
d["scale_composition"]["duplicate_identities"] = True
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "duplicate canonical identities accepted by P15.7 validator" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
d["scale_composition"]["duplicate_identities"] = False
d["scale_composition"]["initial_concurrent_ready"]["count"] = 4
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "four-identity initial topology accepted by P15.7 validator" >&2; exit 1
fi
# An evidence artifact that does not prove the postgres backend must fail
# closed: a sqlite effective backend (or a missing proof) is not composable
# with the production database claim.
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
d["scale_composition"]["initial_concurrent_ready"]["count"] = 5
d["database_ownership"]["effective_backend"] = "sqlite"
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "sqlite effective backend accepted by P15.7 validator" >&2; exit 1
fi

# Araf is an optional external consumer. An artifact produced with no
# O3K_P15_7_ARAF_URL must remain valid, while a required Araf projection must
# fail closed.
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
d["execution"]["provider"] = "agent"
d["scale_composition"]["initial_concurrent_ready"]["count"] = 5
d["database_ownership"]["effective_backend"] = "postgres"
d["journey"]["projections_convergent"]["araf"] = {
    "required": False, "status": "not_applicable",
    "reason": "external_consumer_not_provisioned"
}
p.write_text(json.dumps(d))
PY
env -u O3K_P15_7_ARAF_URL python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}" \
  --expected-source-sha 0123456789abcdef0123456789abcdef01234567 \
  --expected-profile small-edge-cloud
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
d["journey"]["projections_convergent"]["araf"]["required"] = True
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "required Araf projection accepted by P15.7 validator" >&2; exit 1
fi

# Eligibility-based counting guards (issues #974/#1037 decision): the
# bootstrap block must be inside the eligible set and the checkpoints must
# carry per-block eligibility derivations.
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
# Restore the Araf mutation above so each eligibility guard fails on its own reason.
d["journey"]["projections_convergent"]["araf"]["required"] = False
d["scale_composition"]["enrolled_identities"]["agents"] = [a for a in d["scale_composition"]["enrolled_identities"]["agents"] if a != "compute-agent"]
d["scale_composition"]["enrolled_identities"]["count"] = 5
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "bootstrap-excluding enrolled identity set accepted by P15.7 validator" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
enrolled = d["scale_composition"]["enrolled_identities"]
enrolled["agents"] = ["compute-agent"] + [a for a in ("block-a","block-b","block-c","block-d","block-e")]
enrolled["count"] = 6
initial = d["scale_composition"]["initial_concurrent_ready"]
initial["block_ids"] = [b for b in initial["block_ids"] if b != d["scale_composition"]["bootstrap"]["block_id"]]
initial["agents"] = [a for a in initial["agents"] if a != "compute-agent"]
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "bootstrap-excluding initial eligible set accepted by P15.7 validator" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
# Restore the initial eligible set, then corrupt the #1042 requery: the
# deleted workload must never read as a resident blocker.
bootstrap_block = d["scale_composition"]["bootstrap"]["block_id"]
initial = d["scale_composition"]["initial_concurrent_ready"]
initial["block_ids"] = [bootstrap_block] + initial["block_ids"]
initial["agents"] = ["compute-agent"] + initial["agents"]
requery = d["journey"]["drain"]["blocker_requery"]
requery["blockers_at_requery"] = [{"kind": "workload", "count": 1}]
requery["deleted_workload_absent_from_blockers"] = False
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "stale-workload blocker requery accepted by P15.7 validator" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
requery = d["journey"]["drain"]["blocker_requery"]
requery["blockers_at_requery"] = []
requery["deleted_workload_absent_from_blockers"] = True
del d["journey"]["crash_injection_repair"]
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "crash-injection leg missing from P15.7 evidence accepted" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
maintenance = d["journey"]["host_maintenance"]
maintenance["identity_preserved"]["same_resource_provider_ids"] = False
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "broken maintenance identity preservation accepted by P15.7 validator" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
maintenance = d["journey"]["host_maintenance"]
maintenance["identity_preserved"]["same_resource_provider_ids"] = True
d["network_observation"]["child_vms"][0]["ssh_proof"] = False
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "SSH-less lease evidence accepted by P15.7 validator" >&2; exit 1
fi
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
d["network_observation"]["child_vms"][0]["ssh_proof"] = True
d["scale_composition"]["checkpoints"] = []
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "checkpoint-free evidence accepted by P15.7 validator" >&2; exit 1
fi

GATE_ARTIFACT_DIR="${WORK_DIR}/gate-artifacts"
if O3K_P15_7_REAL_HOST=1 O3K_PROVIDER=fake \
   O3K_P15_7_SOURCE_SHA=0123456789abcdef0123456789abcdef01234567 \
   O3K_REAL_HOST_ARTIFACT_DIR="${GATE_ARTIFACT_DIR}" \
   bash "${ROOT_DIR}/tests/p15_7_scale_composition.sh"; then
  echo "fake provider accepted by P15.7 gate" >&2; exit 1
fi
python3 - "${GATE_ARTIFACT_DIR}/p15-7-gate-result.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["status"] == "blocked" and doc["reason"] == "provider_mode_not_agent"
assert doc["redacted"] is True
PY
python3 - "${ROOT_DIR}/scripts/p15-7-real-host-journey.sh" \
  "${ROOT_DIR}/.github/workflows/real-host-validation.yml" \
  "${ROOT_DIR}/scripts/p15-7-libvirt-storage-pool.sh" \
  "${ROOT_DIR}/.github/workflows/p15-7-diagnostic-fast-lane.yml" \
  "${ROOT_DIR}/scripts/bootstrap-disposable-testlab.sh" \
  "${ROOT_DIR}/scripts/p15-7-vm-address.sh" <<'PY'
from pathlib import Path
import sys
journey = Path(sys.argv[1]).read_text(encoding="utf-8")
workflow = Path(sys.argv[2]).read_text(encoding="utf-8")
pool = Path(sys.argv[3]).read_text(encoding="utf-8")
diagnostic = Path(sys.argv[4]).read_text(encoding="utf-8")
bootstrap = Path(sys.argv[5]).read_text(encoding="utf-8")
vm_address = Path(sys.argv[6]).read_text(encoding="utf-8")
upload = workflow.split("- name: Upload redacted real-host artifacts", 1)[1].split("if-no-files-found:", 1)[0]
assert "target/real-host-workflow-artifacts/p15-7-provisioning-diagnostics.json" in upload
for required in ("virt-install", "qemu-img create", "block-a", "block-b", "block-c", "block-d", "block-e", "o3k init",
                 "bootstrap/join", "actions/drain", "actions/remove", "actions/ready", "docker restart",
                 "capacity_total", "CAPACITY_AFTER_ADD", "CAPACITY_AFTER_D",
                 "CAPACITY_AFTER_REMOVE", "CAPACITY_AFTER_E", "drain_blockers", "cargo test --locked -p o3kd",
                 "o3k-p15-7-journey-owned=", "o3k-p15-7-journey-owned-v1",
                 "rm -rf -- \"$WORK_ROOT\"", "second_real_host_required", "assert_owned_domains_absent",
                 "agent-id", "agent identity transfer failed", "/var/lib/o3k-compute/agent-id",
                 "actual_uuid", "DOMAINS+=(\"$d\")", "OVERLAYS+=(\"$overlay\")",
                 "UUIDS[$((${#IPS[@]} - 1))]=\"$(<\"$WORK_ROOT/block-c-uuid\")\"", "provision_vms_bounded",
                 "UUIDS[$((${#IPS[@]} - 1))]=\"$(<\"$WORK_ROOT/block-d-uuid\")\"",
                 "UUIDS[$((${#IPS[@]} - 1))]=\"$(<\"$WORK_ROOT/block-e-uuid\")\"",
                 "capture-p15-7-provision-diagnostics.py", "p15-7-provisioning-diagnostics.json", "REPLAY_JOIN_FILE",
                 "REPLAY_JOIN_BY_AGENT[$DRAIN_AGENT]", "compute-agent-replay-join.json",
                 "for agent in block-a block-b block-c block-d block-e; do",
                 "for required_agent in block-a block-b block-c block-d block-e; do",
                 "initial eligible Ready count is not exactly five",
                 "post-replacement eligible Ready count is not exactly five",
                 "peak concurrent Ready count is below five",
                 "removed block {absent_id} is still present in the canonical topology",
                 "record_scale_checkpoint", "p15-7-scale-checkpoint-",
                 "O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS",
                 "kill9_o3kd_verified", "start_o3kd_verified", "read_o3kd_ledger",
                 "server-owned endpoint orphan repair sweep",
                 "p15-7-drain-blocker-requery.json",
                 "p15-7-crash-injection-evidence.json",
                 "p15-7-host-maintenance-evidence.json",
                 "p15-7-vm-lease-", "p15-7-transient-failures.jsonl",
                 "record_lease_evidence", "record_transient",
                 "actions/ready",
                 'virsh -c qemu:///system reboot "$MAINT_UUID"',
                 "restart_o3kd_verified",
                 "wait_o3kd_readyz",
                 "pg_proxy_dsn",
                 "rewrite_o3kd_env_for_proxy",
                 "rejoin_bootstrap_agent",
                 "bootstrap_store_probe",
                 "PROXY_DSN",
                 "pg_stat_activity WHERE datname = current_database()",
                 "effective_backend",
                 "backend_proof",
                 "O3K_DATABASE_BACKEND=postgres",
                 "install -m 0644 \"$STATE_ROOT/tls/agent.pem\"",
                 "capture-p15-7-workload-diagnostics.py", "p15-7-workload-failure-diagnostics.json",
                 "capture_workload_failure_diagnostics", "${workload_label}-operation.raw.json", "/operations/$operation_id",
                 "install -d -o root -g libvirt-qemu -m 02750 /var/lib/o3k-compute",
                 "capture_failure_diagnostics",
                 "join-request.json", "remote_agent_cleanup", "sudo mkdir -- '$remote_stage'", "sudo rm -rf -- '$remote_stage'",
                 "canonical agent identity does not match agent id", "cross_tenant_test_prerequisite_missing",
                 "FOREIGN_PROJECT_ID", "FOREIGN_TOKEN_PROJECT_ID", "foreign token scope mismatch",
                 "O3K_P15_7_FOREIGN_USER_NAME", "O3K_P15_7_FOREIGN_PASSWORD",
                 'OS_USERNAME="$FOREIGN_USER_NAME" OS_PASSWORD="$FOREIGN_PASSWORD"',
                 "FOREIGN_MISSING_ID", "foreign-resource response differs from missing-resource response",
                 'problem.pop("resource_id", None)', "CROSS_TENANT_CONCEALMENT=true",
                 "record_optional_araf", "external_consumer_not_provisioned", "araf-projection.json",
                 "system_operator_token_required", "O3K_P15_7_OPERATOR_TOKEN_FILE", "O3K_P15_7_OPERATOR_TOKEN", "PROJECT_TOKEN",
                 "xml.etree.ElementTree", "net-dumpxml", "libvirt gateway unavailable",
                 "LIBVIRT_STORAGE_ROOT", "libvirt-storage-owned-v1", "LIBVIRT_QEMU_GROUP",
                 "sudo -n qemu-img create", "cannot stage pinned VM image for libvirt",
                 "qemu-img resize", "VM_DISK_SIZE_GB",
                 "cannot create run-owned libvirt storage workspace", "staged VM image digest mismatch",
                 "cannot stage cloud-init seed for libvirt", "network-config=$WORK_ROOT/network-config-$1",
                 "dhcp4: true", "dhcp6: false", "renderer: networkd", "set-name: eth0",
                 "macaddress: \"$mac\"", "mac=$mac", "net-dhcp-leases", "serial console tail",
                 "--serial \"file,path=$serial\"",
                 "awk '/MemTotal:/ {print int(\\$2/1024); exit}' /proc/meminfo"):
    assert required in journey, required
# The stale-DHCP-lease regression (run 990923002 attempt 4): the journey must
# resolve the VM address through the MAC-bound UUID-only resolver and must
# never freeze a lease-derived address across the SSH window.
for required in ("wait_vm_ssh() {", "vm_network_diagnostics() {",
                 "p15-7-vm-address.sh\" resolve \"$uuid\" \"$mac\" \"$NETWORK\" \"$GATEWAY\"",
                 "seq 1 300",
                 "domifaddr \"$uuid\" --source lease", "domifaddr \"$uuid\" --source arp",
                 "domiflist \"$uuid\""):
    assert required in journey, required
assert 'ip="$(find_ip' not in journey and "find_ip()" not in journey
# Ownership-safe cleanup must prefer the recorded UUID as the locator.
for required in ('if [[ "$u" =~ ^[0-9a-fA-F-]{36}$ ]]; then',
                 'virsh -c qemu:///system domstate "$u" >/dev/null 2>&1 || continue',
                 'virsh -c qemu:///system dumpxml "$u" 2>/dev/null | grep -Fq "o3k-p15-7-journey-owned=$RUN_ID"',
                 'virsh -c qemu:///system destroy "$u"'):
    assert required in journey, required
assert journey.index('printf \'%s\\n\' "$uuid" >"$WORK_ROOT/$id-uuid"') \
    < journey.index('wait_vm_ssh "$d" "$uuid" "$mac" "$serial" "$id"')
# The resolver helper itself: UUID-only lookups, exact-MAC lease binding,
# network lease-table fallback, and gateway rejection.
for required in ("domifaddr \"$uuid\" --source lease", "net-dhcp-leases \"$network\"",
                 "net-dumpxml \"$network\"", "for (i = 1; i <= NF; i++)",
                 "tolower($i) == tolower(m)", "grep -Fxiq", "!= gw",
                 "expiry-time", "DNSMASQ_STATUS_DIR",
                 "printf '%s\\n' \"${candidates[@]}\""):
    assert required in vm_address, required
assert 'domifaddr "$d"' not in vm_address
# The journey liveness-probes every emitted candidate instead of assuming a
# single-address resolver result.
for required in ("while IFS= read -r candidate", "ssh_vm \"$candidate\" true"):
    assert required in journey, required
# The project-token acquisition must survive transient control-plane
# failures loudly (with the CLI's own error text) instead of exiting
# silently under `set -e` (observed on run 990923002 as a silent journey
# death concurrent with control-plane DB errors).
assert 'PROJECT_TOKEN="$(openstack token issue -f value -c id 2>"$PROJECT_TOKEN_ERR" | tr -d '"'"'[:space:]'"'"' || true)"' in journey
assert '[[ "$PROJECT_TOKEN" ]] && break' in journey
assert 'for _ in $(seq 1 15); do' in journey
assert 'P15.7 project token acquisition diagnostics:' in journey
# External-mode outage injection must observe the CONTROL PLANE's outage (the
# run-owned proxy it consumes), never the operator-owned server's endpoint
# (severing our proxy cannot affect that, so polling it can never observe the
# outage and always dies) and must prove the operator server itself stays up.
assert 'OUTAGE_OBSERVED=true' in journey
assert 'operator-owned PostgreSQL became unreachable during the outage proof' in journey
assert 'RECOVERY_OBSERVED=true' in journey
assert 'for _ in $(seq 1 60); do pg_external_ready && sleep 1 || break; done' not in journey
# The OpenStack host projection is case-sensitive and Nova-compatible:
# `OS-EXT-SRV-ATTR:host` (lower case), as the product's own serialization and
# evidence artifacts declare. The upper-case spelling silently yields an empty
# host and strands the drain/placement resolution.
assert '-c OS-EXT-SRV-ATTR:host 2>/dev/null' in journey
assert 'OS-EXT-SRV-ATTR:HOST' not in journey
assert "--os-password" not in journey
assert '! grep -Fq "$WORKLOAD_A" "$FOREIGN_SHOW"' not in journey
# The protected workflows must authorize exactly the five journey child
# identities (the bootstrap compute-agent is enrolled by the canonical
# bootstrap itself, not by this list).
for workflow_text in (workflow, diagnostic):
    assert "O3K_TESTLAB_ADDITIONAL_AGENT_IDS: block-a,block-b,block-c,block-d,block-e" in workflow_text
    assert "block-f" not in workflow_text
for tenant_variable in ("O3K_EXTRA_TENANT_PROJECT_ID", "O3K_EXTRA_TENANT_PROJECT_NAME",
                        "O3K_EXTRA_TENANT_USER_ID", "O3K_EXTRA_TENANT_USER_NAME",
                        "O3K_EXTRA_TENANT_PASSWORD"):
    assert tenant_variable in bootstrap
assert workflow.index("Prepare P15.7 foreign-project fixture credentials") < workflow.index("Bootstrap fresh generic TestLab")
assert diagnostic.index("Prepare P15.7 foreign-project fixture credentials") < diagnostic.index("Bootstrap minimal PostgreSQL TestLab")
diagnostic_fixture_step = diagnostic.split("- name: Prepare P15.7 foreign-project fixture credentials", 1)[1].split("- name: Bootstrap minimal PostgreSQL TestLab", 1)[0]
assert "working-directory: ${{ env.DIAGNOSTIC_REPO }}" in diagnostic_fixture_step
assert journey.index('[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]]') < journey.index('mkdir -p "$ARTIFACT_DIR" "$WORK_ROOT"')
assert "O3K_P15_7_JOURNEY_COMMAND" not in journey
assert journey.index('capture_workload_failure_diagnostics workload-b') < journey.index('die "workload B did not become ACTIVE before cleanup"')
assert journey.index('die "workload B did not become ACTIVE before cleanup"') < journey.index('Idempotency-Key: p15-7-$RUN_ID-delete-b')
assert 'p15-7-libvirt-storage-pool.sh" assert-absent "$RUN_ID" "$LIBVIRT_STORAGE_ROOT"' in journey
assert 'p15-7-libvirt-storage-pool.sh" define "$RUN_ID" "$LIBVIRT_STORAGE_ROOT"' in journey
assert 'p15-7-libvirt-storage-pool.sh" cleanup "$RUN_ID" "$LIBVIRT_STORAGE_ROOT"' in journey
assert journey.index('p15-7-libvirt-storage-pool.sh" define') < journey.index('provision_vms_bounded block-a block-b')
# S5 lifecycle ordering: the eligibility-based initial checkpoint must run
# after block-a..block-d join and before any drain; the #1042 blocker requery
# sits between the workload deletion and the remove; drain and removal
# precede the block-e replacement join; the replacement is measured against
# the post-removal settled baseline, never against the pre-drain total; the
# #1035 crash leg and the #1033 maintenance leg run after the post-replacement
# checkpoint and before the historical late restart gate.
assert journey.index('record_scale_checkpoint initial-scale-checkpoint') < journey.index('DRAIN_AGENT="$HOST_A"')
assert journey.index('install_agent block-d "${IPS[3]}"') < journey.index('DRAIN_AGENT="$HOST_A"')
assert journey.index('actions/drain') < journey.index('drain-blocker-requery.json')
assert journey.index('drain-blocker-requery.json') < journey.index('actions/remove')
assert journey.index('actions/remove') < journey.index('join_block block-e "${IPS[4]}"')
assert journey.index('capacity-after-remove.json') < journey.index('capacity-after-e.json')
assert journey.index('record_scale_checkpoint post-replacement') < journey.index('# ── #1035 crash-injection leg')
assert journey.index('# ── #1035 crash-injection leg') < journey.index('# ── #1033 host-maintenance leg')
assert journey.index('restart_o3kd_verified\nwait_o3kd_readyz "readyz did not reconstruct after restart"') < journey.index('# ── #1035 crash-injection leg')
assert journey.index('record_scale_checkpoint post-crash-repair') < journey.index('record_scale_checkpoint post-maintenance')
# External-mode PostgreSQL wiring: the restart helper is defined before the
# wiring, the env rewrite immediately precedes the restart, the canonical
# bootstrap identity is re-established before readiness is required, and the
# late restart pairs the helper with the historical readyz wait unchanged.
assert journey.index('restart_o3kd_verified() {') < journey.index('PROXY_DSN="$(pg_proxy_dsn)"')
assert "  rewrite_o3kd_env_for_proxy\n  restart_o3kd_verified" in journey
assert journey.index('  restart_o3kd_verified\n  # The previous backend') \
    < journey.index('  rejoin_bootstrap_agent\n  wait_o3kd_readyz "readyz did not reconstruct after the PostgreSQL backend switch"')
assert 'restart_o3kd_verified\nwait_o3kd_readyz "readyz did not reconstruct after restart"' in journey
for required in ("pool-list --all --name", "pool-dumpxml", "pool-define", "pool-start",
                 "pool-destroy", "pool-undefine", "target/path",
                 "pool identity does not match its exact run-owned name and path",
                 "cleanup-stale-diagnostic-images"):
    assert required in pool, required
assert 'cleanup-stale-diagnostic-images "${RUNNER_TEMP}"' in diagnostic
assert 'cirros-0.6.3-x86_64-disk.img.p15-7-diagnostic-${GITHUB_RUN_ID}.XXXXXX' in diagnostic
assert 'operator_curl() {' in journey
assert 'operator_curl "$API/operator/diagnostics/providers?limit=1" --max-time 10' in journey
assert 'Authorization: Bearer $PROJECT_TOKEN" \\\n  "$API/operator/diagnostics/providers?limit=1"' not in journey
assert 'refresh_operator_authority' in journey
assert 'scripts/p15-7-refresh-operator-authority.sh' in journey
assert 'secure_remove_credentials() {' in journey
assert 'secure_remove_credentials "$OPERATOR_CURL_CONFIG" "$SSH_KEY"' in journey
assert 'secure_remove_credentials "$OPERATOR_TOKEN_FILE" "$WORK_ROOT/operator.token"' in journey
assert 'shred --remove --zero --force -- "$secret_file"' in journey
assert 'Authorization: Bearer $PROJECT_TOKEN' in journey
assert 'openstack token issue -f value -c id' in journey
# Prevent recurrence of the bootstrap/identity and cleanup regressions that
# previously made a protected run appear healthier than it was.
assert 'sudo -n test -f "$TLS_ROOT/agents/$required_agent/agent.pem"' in journey
assert '-graft-points "user-data=$WORK_ROOT/user-data-$1" "meta-data=$WORK_ROOT/meta-data-$1"' in journey
assert 'ssh_vm "$ip" "sudo cloud-init status --wait"' in journey
assert 'ssh_vm "$ip" "sudo virsh -c qemu:///system uri"' in journey
assert 'if [[ "$cleanup_failed" == false ]]; then' in journey
assert 'delete_owned_openstack()' in journey
# Cleanup absence proofs must survive a transient control-plane failure with a
# bounded retry (observed as a 500 "compute service is unavailable" during the
# final cleanup) while remaining fail-closed on a genuinely unprovable result.
assert 'must not strand the cleanup' in journey
assert 'if openstack_absent_code "$kind" "$id"; then' in journey
assert 'policy failures are deliberately not treated as absence' in journey
assert 'DRAIN_AGENT="$HOST_A"' in journey
assert 'scripts/resolve-p15-7-placement-block.py' in journey
assert 'workload A placement host has no unique ready canonical block/provider mapping' in journey
assert '^(block-a|block-b|block-c)$' not in journey
assert '"$HOST_B" != "$HOST_A"' in journey
assert 'JOIN_REGION="${O3K_P15_7_REGION:-}"' in journey
assert '--region RegionOne' not in journey
assert 'resource_class") != "VCPU"' in journey
assert 'OS_WORKLOAD_A="$WORKLOAD_A"' in journey and 'OS_WORKLOAD_B="$WORKLOAD_B"' in journey
assert 'OS_PORT_A_ID="" OS_PORT_B_ID=""' in journey
native_create_requests = [line for line in journey.splitlines() if 'network_ids' in line]
assert len(native_create_requests) == 2, native_create_requests
assert '$OS_PORT_A_ID' in native_create_requests[0]
assert '$OS_PORT_B_ID' in native_create_requests[1]
assert all('$OS_NETWORK_ID' not in line for line in native_create_requests)
assert 'SSH_PUBLIC_KEY="$(<"$SSH_KEY.pub")"' in journey
assert all(r'\"key_name\":\"$OS_KEYPAIR_NAME\"' in line for line in native_create_requests)
assert all(r'\"ssh_public_key\":\"$SSH_PUBLIC_KEY\"' in line for line in native_create_requests)
assert '"o3k-p15-7-$RUN_ID-port-a"' in journey
assert '"o3k-p15-7-$RUN_ID-port-b"' in journey
assert '"$OS_PORT_B_ID" != "$OS_PORT_A_ID"' in journey
assert 'delete_owned_openstack port "$OS_PORT_B_ID"' in journey
assert 'delete_owned_openstack port "$OS_PORT_A_ID"' in journey
assert 'WORKLOAD_IMAGE="${O3K_TESTLAB_IMAGE_PATH:-}"' in journey
assert 'WORKLOAD_IMAGE_MARKER="${WORKLOAD_IMAGE}.o3k-owned"' in journey
assert "o3k-disposable-image-v1" in journey
assert "phase=generic" in journey
assert "araf_projection_prerequisite_missing" not in journey
assert 'DIAGNOSTIC_ONLY="${O3K_P15_7_DIAGNOSTIC_ONLY:-false}"' in journey
assert 'diagnostic mode requires a separate non-completion artifact path' in journey
assert 'o3k-p15-7-diagnostic-fast-lane-journey' in journey
assert 'final_completion_evidence' in journey
PY

python3 - "${ROOT_DIR}/.github/workflows/p15-7-diagnostic-fast-lane.yml" <<'PY'
from pathlib import Path
import sys
workflow = Path(sys.argv[1]).read_text(encoding="utf-8")
preflight = Path(sys.argv[1]).parents[2] / "scripts/p15-7-diagnostic-preflight.sh"
preflight = preflight.read_text(encoding="utf-8")
postgres_step = workflow.split("      - name: Start run-scoped PostgreSQL\n", 1)[1].split("      - name:", 1)[0]
ordered_steps = (
    "Check out the canonical repository at the exact SHA",
    "Ownership-safe sanitation of prior TestLab state",
    "Protected P15.7 authority and capacity preflight",
    "Start run-scoped PostgreSQL",
    "Allocate run-scoped TestLab ports",
    "Bootstrap minimal PostgreSQL TestLab",
    "Run P15.7 journey (diagnostic only)",
    "Capture redacted P15.7 diagnostics",
    "Stop and remove diagnostic TestLab",
)
positions = [workflow.index(step) for step in ordered_steps]
assert positions == sorted(positions), positions
bootstrap_step = workflow.split("      - name: Bootstrap minimal PostgreSQL TestLab\n", 1)[1].split("      - name:", 1)[0]
assert 'GITHUB_SHA: ${{ inputs.target_sha || github.sha }}' in bootstrap_step
assert 'O3K_P15_7_DIAGNOSTIC_ONLY: "true"' in workflow
assert 'p15-7-diagnostic-fast-lane-journey.json' in workflow
assert 'p15-7-workload-failure-diagnostics.json' in workflow
assert 'diagnostic-only' in workflow
assert 'P13.4' not in workflow and 'p13-4' not in workflow and 'p13_4' not in workflow
assert 'p15-7-scale-composition-evidence.json' not in workflow
assert 'p15-7-gate-result.json' not in workflow
assert 'final_completion_evidence' in workflow
assert postgres_step.index('p15-7-postgres-ownership.json') < postgres_step.index('pg_isready')
assert 'scripts/p15-7-protected-preflight.sh' in preflight
assert 'o3k-p15-7-diagnostic-fast-lane-preflight' in preflight
assert '"final_completion_evidence": False' in preflight
assert 'authority_preflight_failed' in preflight
assert 'minimum_cpu_count": 4' in preflight
assert 'minimum_available_memory_kib": 6144000' in preflight
assert 'minimum_free_disk_kib": 20971520' in preflight
PY

# Failed bounded provisioning must retain a useful, run-scoped artifact without
# retaining credentials or depending on the workspace surviving cleanup.
PROVISION_ROOT="${WORK_DIR}/provision"
PROVISION_ARTIFACT="${WORK_DIR}/provision-diagnostics.json"
mkdir -m 0700 "${PROVISION_ROOT}"
printf 'o3k-p15-7-journey-owned-v1\nrun=test-run\n' >"${PROVISION_ROOT}/.o3k-owned"
cat >"${PROVISION_ROOT}/block-a-provision.log" <<'LOG'
VM did not receive a DHCP lease: o3k-p15-7-example-block-a
Authorization: Bearer sentinel-native-token
operator_password=redacted-by-this-pattern
eyJhbGciOiJSUzI1NiJ9eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZW50aW5lbCJ9eyJzdWIiOiJzZW50aW5lbCJ9.c2lnbmF0dXJlLXNlbnRpbmVsLXNpZ25hdHVyZQ
-----BEGIN PRIVATE KEY-----
sentinel-private-key-material
-----END PRIVATE KEY-----
LOG
printf '1\n' >"${PROVISION_ROOT}/block-a-exit"
printf '0\n' >"${PROVISION_ROOT}/block-b-exit"
for number in $(seq 1 200); do
  printf 'provision diagnostic line %s\n' "$number" >>"${PROVISION_ROOT}/block-b-provision.log"
done
python3 "${ROOT_DIR}/scripts/capture-p15-7-provision-diagnostics.py" \
  "${PROVISION_ARTIFACT}" "${PROVISION_ROOT}" \
  0123456789abcdef0123456789abcdef01234567 test-run
python3 - "${PROVISION_ARTIFACT}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text(encoding="utf-8"))
assert doc["status"] == "failed" and doc["redacted"] is True
assert doc["native_system_operator_token_acquired_before_provisioning"] is False
assert doc["signed_provider_token_refreshed_before_exchange"] is True
assert doc["vms"][0]["exit_status"] == "1"
assert any("DHCP lease" in line for line in doc["vms"][0]["tail"])
assert any("provision diagnostic line 200" in line for line in doc["vms"][1]["tail"])
assert "provision diagnostic line 1" not in doc["vms"][1]["tail"]
serialized = path.read_text(encoding="utf-8")
for secret in (
    "sentinel-native-token", "sentinel-password", "redacted-by-this-pattern", "sentinel",
    "sentinel-private-key-material",
    "eyJhbGciOiJSUzI1NiJ9eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZW50aW5lbCJ9eyJzdWIiOiJzZW50aW5lbCJ9.c2lnbmF0dXJlLXNlbnRpbmVsLXNpZ25hdHVyZQ",
):
    assert secret not in serialized, secret
assert path.stat().st_mode & 0o777 == 0o600
PY
WORKLOAD_DIAGNOSTIC_ROOT="${WORK_DIR}/workload-diagnostic-input"
mkdir -m 0700 "${WORKLOAD_DIAGNOSTIC_ROOT}"
printf 'o3k-p15-7-journey-owned-v1\nrun=test-run\n' >"${WORKLOAD_DIAGNOSTIC_ROOT}/.o3k-owned"
chmod 0600 "${WORKLOAD_DIAGNOSTIC_ROOT}/.o3k-owned"
cat >"${WORKLOAD_DIAGNOSTIC_ROOT}/workload-b-state.raw.json" <<'JSON'
{"status":{"state":"BUILDING"},"authorization":"sentinel-native-token","provider_payload":"must-not-escape"}
JSON
cat >"${WORKLOAD_DIAGNOSTIC_ROOT}/workload-b-operation.raw.json" <<'JSON'
{"state":"running","error":"sentinel-operation-error","provider_resource_id":"must-not-escape"}
JSON
cat >"${WORKLOAD_DIAGNOSTIC_ROOT}/agent-block-a-events.raw.jsonl" <<'JSONL'
{"timestamp":"2026-09-16T00:00:00Z","level":"INFO","fields":{"message":"command accepted","operation_id":"22222222-2222-4222-8222-222222222222","action":"create","authorization":"sentinel-agent-token"}}
{"timestamp":"2026-09-16T00:00:01Z","level":"INFO","fields":{"message":"command execution completed","operation_id":"22222222-2222-4222-8222-222222222222","action":"create","state":3,"console_bytes":0,"secret":"sentinel-agent-secret"}}
{"timestamp":"2026-09-16T00:00:02Z","level":"INFO","fields":{"message":"unapproved event","operation_id":"22222222-2222-4222-8222-222222222222","secret":"sentinel-unapproved-secret"}}
{"timestamp":"2026-09-16T00:00:03Z","level":"INFO","fields":{"message":"command execution failed","operation_id":"33333333-3333-4333-8333-333333333333","action":"create","error":"unrelated"}}
{"timestamp":"2026-09-16T00:00:04Z","level":"WARN","fields":{"message":"create failed definitively; reporting terminal failure","operation_id":"22222222-2222-4222-8222-222222222222","error":"sentinel-definitive-error"}}
JSONL
WORKLOAD_DIAGNOSTIC_ARTIFACT="${WORK_DIR}/workload-failure-diagnostics.json"
python3 "${ROOT_DIR}/scripts/capture-p15-7-workload-diagnostics.py" \
  "${WORKLOAD_DIAGNOSTIC_ARTIFACT}" "${WORKLOAD_DIAGNOSTIC_ROOT}" \
  0123456789abcdef0123456789abcdef01234567 test-run \
  11111111-1111-4111-8111-111111111111 22222222-2222-4222-8222-222222222222 \
  compute-agent block-a 44444444-4444-4444-8444-444444444444 200 200
python3 - "${WORKLOAD_DIAGNOSTIC_ARTIFACT}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text(encoding="utf-8"))
assert doc["artifact_type"] == "o3k-p15-7-workload-failure-diagnostics"
assert doc["reason"] == "workload-b_activation_failure" and doc["redacted"] is True
assert doc["observations"]["native_server_state"] == "BUILDING"
assert doc["observations"]["operation_state"] == "running"
assert doc["observations"]["operation_error_category"] == "unknown"
events = doc["observations"]["agent_events"]
assert [event["message"] for event in events] == ["command accepted", "command execution completed", "create failed definitively; reporting terminal failure"]
assert events[1]["state"] == 3 and events[1]["console_bytes"] == 0
serialized = path.read_text(encoding="utf-8")
for secret in ("sentinel-native-token", "sentinel-operation-error", "sentinel-agent-token",
               "sentinel-agent-secret", "sentinel-unapproved-secret", "must-not-escape"):
    assert secret not in serialized, secret
assert "provider_resource_id" not in serialized and "authorization" not in serialized
assert path.stat().st_mode & 0o777 == 0o600
PY
# The bootstrap agent can fail before a drain block has been selected. Keep
# its failure evidence and distinguish an absent drain from a fabricated ID.
python3 - "${ROOT_DIR}" "${WORKLOAD_DIAGNOSTIC_ROOT}" "${WORKLOAD_DIAGNOSTIC_ARTIFACT}" <<'PY'
import json, pathlib, subprocess, sys
root, work, output = map(pathlib.Path, sys.argv[1:])
operation_id = "22222222-2222-4222-8222-222222222222"
(work / "workload-a-state.raw.json").write_text(json.dumps({"status": {"state": "ERROR"}, "token": "sentinel-a-secret"}))
(work / "workload-a-operation.raw.json").write_text(json.dumps({"state": "failed", "error": "terminal"}))
(work / "agent-compute-agent-events.raw.jsonl").write_text(json.dumps({
    "fields": {"message": "command execution failed", "operation_id": operation_id,
               "error_kind": "libvirt_operation_failed", "token": "sentinel-a-secret"}
}) + "\n")
command = [sys.executable, str(root / "scripts/capture-p15-7-workload-diagnostics.py"),
           str(output), str(work), "0123456789abcdef0123456789abcdef01234567", "test-run",
           "11111111-1111-4111-8111-111111111111", operation_id,
           "unknown", "unknown", "none", "200", "200", "workload-a"]
subprocess.run(command, check=True)
doc = json.loads(output.read_text())
assert doc["reason"] == "workload-a_activation_failure"
assert doc["placement_observation"]["drained_block_id"] is None
assert doc["observations"]["native_server_state"] == "ERROR"
assert doc["observations"]["operation_state"] == "failed"
assert doc["observations"]["operation_error_category"] == "terminal"
assert any(e["agent"] == "compute-agent" and e["error_kind"] == "libvirt_operation_failed"
           for e in doc["observations"]["agent_events"])
assert "sentinel-a-secret" not in output.read_text()
command[-1] = "workload-b"
assert subprocess.run(command, capture_output=True).returncode != 0
PY
JOURNEY_ARTIFACT="${WORK_DIR}/journey-diagnostics.json"
python3 "${ROOT_DIR}/scripts/capture-p15-7-provision-diagnostics.py" \
  "${JOURNEY_ARTIFACT}" "${PROVISION_ROOT}" \
  0123456789abcdef0123456789abcdef01234567 test-run journey_failed
python3 - "${JOURNEY_ARTIFACT}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text(encoding="utf-8"))
assert doc["status"] == "failed" and doc["redacted"] is True
assert doc["reason"] == "journey_failed"
serialized = path.read_text(encoding="utf-8")
assert "sentinel-native-token" not in serialized
assert "sentinel-private-key-material" not in serialized
assert path.stat().st_mode & 0o777 == 0o600
PY

# libvirt emits both quote styles across supported versions. Keep gateway
# discovery independent of that XML serialization detail.
python3 - <<'PY'
import xml.etree.ElementTree as ET

for xml in (
    "<network><ip address='192.0.2.1' netmask='255.255.255.0'/></network>",
    '<network><ip address="192.0.2.2" netmask="255.255.255.0"/></network>',
):
    root = ET.fromstring(xml)
    gateway = next(
        e.get("address") for e in root.iter()
        if e.tag.rsplit("}", 1)[-1] == "ip" and e.get("address")
    )
    assert gateway.startswith("192.0.2."), gateway
PY
echo "P15.7 validator guards passed"
