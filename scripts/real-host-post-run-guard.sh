#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${O3K_REAL_HOST_ARTIFACT_DIR:-${ROOT_DIR}/target/real-host-workflow-artifacts}"
RESULT_PATH="${ARTIFACT_DIR}/real-host-workflow-result.json"
LEAK_RESULT_PATH="${ARTIFACT_DIR}/resource-leak-result.json"
LIFECYCLE_RESULT="${ARTIFACT_DIR}/libvirt-result.json"
AGENT_PROCESS_RESULT="${ARTIFACT_DIR}/compute-agent-process-mtls-result.json"
P15_7_RESULT="${ARTIFACT_DIR}/p15-7-gate-result.json"
STEP_STATUS="${O3K_REAL_HOST_WORKFLOW_STEP_STATUS:-skipped}"
P15_7_STEP_STATUS="${O3K_REAL_HOST_P15_7_STEP_STATUS:-skipped}"
CURRENT_INVENTORY="${ARTIFACT_DIR}/real-host-owned-inventory-after.json"
mkdir -p "${ARTIFACT_DIR}"

inventory_status=not_checked
if python3 - "${RESULT_PATH}" <<'PY'
import json, sys
try:
    ready = json.load(open(sys.argv[1], encoding="utf-8")).get("status") == "ready"
except (OSError, json.JSONDecodeError):
    ready = False
raise SystemExit(0 if ready else 1)
PY
then
    inventory_status=available
    if ! bash "${ROOT_DIR}/scripts/real-host-owned-inventory.sh" "${CURRENT_INVENTORY}"; then
        inventory_status=unavailable
    fi
fi

python3 - "${RESULT_PATH}" "${LIFECYCLE_RESULT}" "${AGENT_PROCESS_RESULT}" "${P15_7_RESULT}" "${STEP_STATUS}" "${P15_7_STEP_STATUS}" "${CURRENT_INVENTORY}" "${inventory_status}" "${LEAK_RESULT_PATH}" <<'PY'
import json, os, sys, tempfile, time
result_path, lifecycle_path, agent_process_path, p15_7_path, step_status, p15_7_step_status, current_inventory_path, inventory_status, leak_result_path = sys.argv[1:]

def write_atomic(path, document):
    directory = os.path.dirname(path) or "."
    descriptor, temporary = tempfile.mkstemp(prefix=".resource-result.", dir=directory, text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, indent=2)
            output.write("\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise

try:
    with open(result_path, encoding="utf-8") as stream:
        preflight = json.load(stream)
except (OSError, json.JSONDecodeError):
    preflight = {"status": "blocked", "reason": "guard_result_unavailable"}
status = preflight.get("status")
reason = preflight.get("reason", "unknown")
try:
    with open(lifecycle_path, encoding="utf-8") as stream:
        lifecycle_status = json.load(stream).get("status")
except (OSError, json.JSONDecodeError):
    lifecycle_status = None
try:
    with open(agent_process_path, encoding="utf-8") as stream:
        agent_process_status = json.load(stream).get("status")
except (OSError, json.JSONDecodeError):
    agent_process_status = None
try:
    with open(p15_7_path, encoding="utf-8") as stream:
        p15_7_status = json.load(stream).get("status")
except (OSError, json.JSONDecodeError):
    p15_7_status = None
p15_7_observed = p15_7_step_status != "skipped" or p15_7_status is not None

baseline = preflight.get("inventory_baseline", {})
after = None
result_leaks = None
foreign_state_changed = None
if status == "ready" and inventory_status == "available":
    try:
        with open(current_inventory_path, encoding="utf-8") as stream:
            after = json.load(stream)
    except (OSError, json.JSONDecodeError):
        after = {"status": "unavailable", "redacted": True}
    if (baseline.get("schema_version") in (2, 3) and after.get("schema_version") in (2, 3)
            and baseline.get("status") == "available" and after.get("status") == "available"):
        baseline_resources = baseline.get("openstack", {}).get("resources", {})
        after_resources = after.get("openstack", {}).get("resources", {})
        result_leaks = {
            "domains": sorted(set(after.get("domains", [])) - set(baseline.get("domains", []))),
            "network_links": sorted(
                set(after.get("network_links", [])) - set(baseline.get("network_links", []))
            ),
            "openstack": {
                name: sorted(set(after_resources.get(name, [])) - set(baseline_resources.get(name, [])))
                for name in sorted(set(baseline_resources) | set(after_resources))
            },
        }
        result_leaks["openstack"] = {
            name: values for name, values in result_leaks["openstack"].items() if values
        }
        foreign_state_changed = baseline.get("foreign_state") != after.get("foreign_state")

if status == "blocked":
    final_status = "blocked"
elif status != "ready":
    final_status = "skipped"
    reason = "prerequisites_skipped"
elif inventory_status != "available" or after is None or after.get("status") != "available" or result_leaks is None:
    final_status = "failed"
    reason = "owned_inventory_unavailable_after_workflow"
elif result_leaks["domains"] or result_leaks["network_links"] or result_leaks["openstack"]:
    final_status = "failed"
    reason = "resource_leak_detected"
elif foreign_state_changed:
    final_status = "failed"
    reason = "foreign_state_changed"
elif step_status != "success":
    final_status = "failed" if step_status == "failure" else "skipped"
    reason = "workflow_step_failed" if step_status == "failure" else "workflow_step_skipped"
elif lifecycle_status != "passed":
    final_status = lifecycle_status if lifecycle_status in {"failed", "skipped"} else "failed"
    reason = "lifecycle_workflow_failed" if final_status == "failed" else "lifecycle_workflow_skipped"
elif agent_process_status != "passed":
    final_status = "failed"
    reason = "compute_agent_process_probe_failed"
elif p15_7_observed and p15_7_status == "blocked":
    final_status = "blocked"
    reason = "p15_7_gate_blocked"
elif p15_7_observed and p15_7_step_status == "failure":
    final_status = "failed"
    reason = "p15_7_gate_failed"
elif p15_7_observed and p15_7_step_status == "success" and p15_7_status != "passed":
    final_status = "failed"
    reason = "p15_7_evidence_unavailable" if p15_7_status is None else "p15_7_gate_failed"
elif p15_7_observed and p15_7_step_status != "success":
    final_status = "skipped"
    reason = "p15_7_gate_skipped"
else:
    final_status = "passed"
    reason = "workflow_and_prerequisites_passed"

result = {"artifact_type": "real-host-workflow-result", "status": final_status,
          "reason": reason, "redacted": True, "finished_at": int(time.time()),
          "preflight_status": status, "lifecycle_status": lifecycle_status}
result["agent_process_status"] = agent_process_status
if p15_7_observed:
    result["p15_7_step_status"] = p15_7_step_status
    result["p15_7_status"] = p15_7_status
if result_leaks is not None:
    result["leaks"] = result_leaks
if foreign_state_changed is not None:
    result["foreign_state_changed"] = foreign_state_changed
if after is not None:
    result["inventory_after"] = after
if isinstance(preflight.get("environment"), dict):
    result["environment"] = preflight["environment"]
write_atomic(result_path, result)
if status == "blocked":
    leak_status = "blocked"
    leak_reason = reason
elif status != "ready":
    leak_status = "skipped"
    leak_reason = "prerequisites_skipped"
elif inventory_status != "available" or after is None or after.get("status") != "available" or result_leaks is None:
    leak_status = "failed"
    leak_reason = "owned_inventory_unavailable_after_workflow"
elif result_leaks["domains"] or result_leaks["network_links"] or result_leaks["openstack"]:
    leak_status = "failed"
    leak_reason = "resource_leak_detected"
elif foreign_state_changed:
    leak_status = "failed"
    leak_reason = "foreign_state_changed"
else:
    leak_status = "passed"
    leak_reason = "no_resource_leak_detected"

leak_result = {"artifact_type": "resource-leak-result", "schema_version": 1,
               "status": leak_status, "redacted": True,
               "finished_at": result["finished_at"], "reason": leak_reason}
if result_leaks is not None:
    leak_result["leaks"] = result_leaks
if foreign_state_changed is not None:
    leak_result["foreign_state_changed"] = foreign_state_changed
write_atomic(leak_result_path, leak_result)
if final_status != "passed":
    raise SystemExit(f"real-host workflow did not pass: {final_status} ({reason})")
PY

echo "real-host workflow passed"
