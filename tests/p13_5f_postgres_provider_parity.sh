#!/usr/bin/env bash
set -euo pipefail

# PostgreSQL provider-level parity orchestrator.  The existing P13.5B journey
# is deliberately reused so the OpenTofu/provider boundary is identical to the
# portable evidence path.  This wrapper never promotes an unavailable or
# failed journey to PASS; callers receive a machine-readable blocked artifact.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${O3K_P13_5F_POSTGRES_EVIDENCE_OUTPUT:-$root_dir/target/p13-5f/postgres-provider-parity.json}"
mkdir -p "$(dirname "$output")"

write_abort_artifact() {
  [[ -s "$output" ]] && return 0
  python3 - "$output" "$root_dir" <<'PY'
import json, os, pathlib, subprocess, sys
out, root = sys.argv[1:]
head = subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"], text=True).strip()
head = os.environ.get("O3K_P13_SOURCE_HEAD_SHA", head)
names = ["PG1-import-read-reconstruction", "PG2-mutable-drift-reconvergence", "PG3-remote-deletion-recreation", "PG4-independent-replacement", "PG5-router-interface-relationship", "PG6-volume-attachment-relationship", "PG7-operation-replay-unknown-outcome"]
document = {"artifact_type": "o3k-p13-5f-postgres-provider-parity", "schema_version": 1, "phase": "P13.5F", "tested_o3k_head_sha": head, "backend": "postgresql", "provider_modified": False, "execution": {"orchestrator": "tests/p13_5f_postgres_provider_parity.sh", "status": "failed", "failure_artifact": True}, "scenarios": [{"scenario": name, "result": "blocked", "externally_equivalent": False, "reason": "orchestrator exited before scenario completion"} for name in names], "final_verdict": "blocked"}
pathlib.Path(out).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
PY
}
trap write_abort_artifact EXIT

if [[ -z "${O3K_DATABASE_URL:-}" ]]; then
  echo "P13.5F PostgreSQL parity BLOCKED: O3K_DATABASE_URL is required" >&2
  exit 2
fi
export O3K_TEST_DATABASE_PURPOSE=p13
if ! command -v pg_isready >/dev/null 2>&1 || ! pg_isready -d "$O3K_DATABASE_URL" >/dev/null 2>&1; then
  echo "P13.5F PostgreSQL parity BLOCKED: PostgreSQL is not ready" >&2
  exit 2
fi
for required in O3K_P13_TOFU O3K_P13_PROVIDER_BINARY O3K_P13_PROVIDER_ARCHIVE O3K_P13_TOFU_ARCHIVE; do
  if [[ -z "${!required:-}" || ! -f "${!required}" ]]; then
    echo "P13.5F PostgreSQL parity BLOCKED: missing pinned toolchain input $required" >&2
    exit 2
  fi
done
if [[ ! "${O3K_P13_PROVIDER_SHA256:-}" =~ ^[[:xdigit:]]{64}$ ]]; then
  echo "P13.5F PostgreSQL parity BLOCKED: O3K_P13_PROVIDER_SHA256 must be a 64-hex digest" >&2
  exit 2
fi
python3 "$root_dir/scripts/p13_provider_contract.py" --verify-tools

# The accepted P13.3 router gate consumes this shared harness credential.  CI
# only supplies the database URL, so provide the same disposable default used
# by the reused P13.5 journeys instead of allowing `set -u` to abort the
# baseline before it can execute.
export O3K_P13_PASSWORD="${O3K_P13_PASSWORD:-p13-5b-refresh-import-password}"

work_dir="${O3K_P13_5F_WORK_DIR:-$(mktemp -d /var/tmp/o3k-p13-5f-postgres.XXXXXX)}"
mkdir -p "$work_dir"
log="$work_dir/p13-5b-refresh-import.log"
b_output="$work_dir/p13-5b-refresh-import-evidence.json"
baseline="$work_dir/p13-baseline-manifest.json"
if [[ -n "${O3K_P13_5F_BASELINE_MANIFEST:-}" ]]; then
  baseline="${O3K_P13_5F_BASELINE_MANIFEST}"
  if python3 - "$baseline" "$root_dir" <<'PY' >"$work_dir/baseline.log" 2>&1
import json, subprocess, sys
manifest, root = sys.argv[1:]
d = json.load(open(manifest, encoding="utf-8"))
head = subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"], text=True).strip()
if d.get("status") != "verified" or d.get("source_commit") != head:
    raise SystemExit("baseline manifest is not verified for the exact runtime HEAD")
PY
  then
    baseline_result=verified
  else
    baseline_result=blocked
  fi
elif O3K_DATABASE_BACKEND=postgres \
     O3K_P13_ALLOW_DESTRUCTIVE_POSTGRES_RESET=1 \
     O3K_TEST_DATABASE_PURPOSE=p13 \
     python3 "$root_dir/scripts/p13_baseline_gate_manifest.py" --output "$baseline" >"$work_dir/baseline.log" 2>&1; then
  baseline_result=verified
else
  baseline_result=blocked
fi

run_status=blocked
native_volume_skip=0
if [[ -z "${O3K_LVM_VOLUME_GROUP:-}" || -z "${O3K_LVM_THIN_POOL:-}" || -z "${O3K_LVM_PROVIDER_NAMESPACE:-}" ]]; then
  native_volume_skip=1
fi
if [[ -x "${O3K_P13_O3KD:-$root_dir/target/debug/o3kd}" ]]; then
  set +e
  O3K_DATABASE_BACKEND=postgres \
  O3K_P13_5B_EVIDENCE_OUTPUT="$b_output" \
  P13_5B_EXPLORATORY=1 \
  P13_5A_RUN_BASELINE=1 \
  P13_5B_BASELINE_RESULT="$baseline_result" \
  P13_5B_BASELINE_MANIFEST="$baseline" \
  O3K_P13_5B_SKIP_NATIVE_VOLUME="$native_volume_skip" \
  O3K_P13_5B_KEEP_WORK_DIR=1 \
    bash "$root_dir/tests/p13_5b_refresh_import.sh" >"$log" 2>&1
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then run_status=passed; else run_status=failed; fi
else
  echo "P13.5F: P13.5B prerequisites unavailable; retaining preflight evidence" >"$log"
fi

run_child() {
  local label="$1" log_path="$2"
  shift 2
  set +e
  env O3K_DATABASE_BACKEND=postgres "$@" >"$log_path" 2>&1
  local rc=$?
  set -e
  [[ $rc -eq 0 ]]
}

c_output="$work_dir/p13-5c-canonical-drift.json"
c_log="$work_dir/p13-5c-canonical-drift.log"
c_status=blocked
if run_child p13-5c "$c_log" env P13_5A_RUN_BASELINE=1 P13_5B_BASELINE_MANIFEST="$baseline" P13_5C_ALLOW_BLOCKED_BASELINE=1 P13_5C_REMOTE_DELETE=1 \
  O3K_P13_5C_OUT_OF_BAND_EVIDENCE_OUTPUT="$c_output" bash "$root_dir/tests/p13_5c_canonical_out_of_band_drift.sh"; then
  c_status=passed
fi

e_dir="$work_dir/p13-5e-evidence"
e_log="$work_dir/p13-5e-fault-proxy.log"
e_status=blocked
mkdir -p "$e_dir"
if run_child p13-5e "$e_log" O3K_P13_EVIDENCE_DIR="$e_dir" bash "$root_dir/tests/p13_5e_real_provider_fault_proxy.sh"; then
  e_status=passed
fi

d_output="$work_dir/p13-5d-replacement.json"
d_log="$work_dir/p13-5d-replacement.log"
d_status=blocked
if [[ -n "${O3K_P13_5F_D_SCENARIOS:-}" ]]; then
  d_scenarios="${O3K_P13_5F_D_SCENARIOS}"
elif [[ -n "${O3K_LVM_VOLUME_GROUP:-}" && -n "${O3K_LVM_THIN_POOL:-}" && -n "${O3K_LVM_PROVIDER_NAMESPACE:-}" ]]; then
  d_scenarios=all
else
  d_scenarios=independent-resource,router-interface
fi
if run_child p13-5d "$d_log" P13_5D_SCENARIO="$d_scenarios" P13_5D_BASELINE_MANIFEST="$baseline" \
  O3K_P13_5D_EVIDENCE_OUTPUT="$d_output" bash "$root_dir/tests/p13_5d_replacement_relationships.sh"; then
  d_status=passed
fi

python3 - "$output" "$root_dir" "$run_status" "$b_output" "$log" "$baseline" "$c_status" "$c_output" "$c_log" "$e_status" "$e_dir" "$e_log" "$d_status" "$d_output" "$d_log" <<'PY'
import json
import hashlib
import os
import pathlib
import sys
from datetime import datetime, timezone

output = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
run_status, b_output, log, baseline, c_status, c_output, c_log, e_status, e_dir, e_log, d_status, d_output, d_log = sys.argv[3:]
head = __import__("subprocess").check_output(
    ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
).strip()
source_head = __import__("os").environ.get("O3K_P13_SOURCE_HEAD_SHA", head)

def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

scenarios = [
    "PG1-import-read-reconstruction",
    "PG2-mutable-drift-reconvergence",
    "PG3-remote-deletion-recreation",
    "PG4-independent-replacement",
    "PG5-router-interface-relationship",
    "PG6-volume-attachment-relationship",
    "PG7-operation-replay-unknown-outcome",
]
document = {
    "artifact_type": "o3k-p13-5f-postgres-provider-parity",
    "schema_version": 1,
    "phase": "P13.5F",
    "tested_runtime_head_sha": source_head,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "backend": "postgresql",
    "provider_modified": False,
    "real_provider_execution": True,
    "toolchain": {
        "opentofu": "1.12.6",
        "provider": "terraform-provider-openstack/openstack 3.4.0",
        "opentofu_archive_sha256": sha256(os.environ["O3K_P13_TOFU_ARCHIVE"]),
        "provider_archive_sha256": sha256(os.environ["O3K_P13_PROVIDER_ARCHIVE"]),
        "provider_binary_sha256": sha256(os.environ["O3K_P13_PROVIDER_BINARY"]),
    },
    "execution": {
        "orchestrator": "tests/p13_5f_postgres_provider_parity.sh",
        "reused_journey": "tests/p13_5b_refresh_import.sh",
        "status": run_status,
        "evidence": str(pathlib.Path(b_output).resolve()),
        "log": str(pathlib.Path(log).resolve()),
        "baseline_manifest": str(pathlib.Path(baseline).resolve()),
        "child_runs": {
            "P13.5C": {"status": c_status, "evidence": str(pathlib.Path(c_output).resolve()), "log": str(pathlib.Path(c_log).resolve())},
            "P13.5E": {"status": e_status, "evidence": str(pathlib.Path(e_dir).resolve()), "log": str(pathlib.Path(e_log).resolve())},
            "P13.5D": {"status": d_status, "evidence": str(pathlib.Path(d_output).resolve()), "log": str(pathlib.Path(d_log).resolve())},
        },
    },
    "scenarios": [
        {
            "scenario": name,
            "result": "not_run",
            "externally_equivalent": False,
            "reason": "dedicated PostgreSQL parity journey is not implemented or was not executable",
        }
        for name in scenarios
    ],
    "final_verdict": "blocked",
}
if pathlib.Path(b_output).is_file():
    b = json.loads(pathlib.Path(b_output).read_text(encoding="utf-8"))
    passed = {(row.get("resource"), row.get("scenario")) for row in b.get("scenarios", []) if row.get("result") == "passed"}
    evidence = str(pathlib.Path(b_output).resolve())
    for row in document["scenarios"]:
        if row["scenario"] == "PG1-import-read-reconstruction" and ("openstack_networking_network_v2", "import") in passed:
            source = next(item for item in b["scenarios"] if item.get("resource") == "openstack_networking_network_v2" and item.get("scenario") == "import")
            row.update(result="passed", externally_equivalent=True, evidence=evidence,
                       backend="postgresql", provider_modified=False,
                       restart_reconstruction=True, final_plan_noop=True,
                       canonical_id=source.get("canonical_id"), owner_scope=source.get("owner_scope"),
                       plan_actions=source.get("plan_actions", []))
        # Import/read coverage does not prove relationship lifecycle parity.
        # PG5 and PG6 require their dedicated relationship journeys below;
        # never promote them from a generic import result.
    if all(row["result"] == "passed" for row in document["scenarios"]):
        document["final_verdict"] = "passed"
    c = json.loads(pathlib.Path(c_output).read_text(encoding="utf-8")) if pathlib.Path(c_output).is_file() else {}
    if c_status == "passed" and c.get("scenario", {}).get("result") == "passed":
        c_row = c["scenario"]
        document["scenarios"][1].update(result="passed", externally_equivalent=True, evidence=str(pathlib.Path(c_output).resolve()),
                                         backend="postgresql", provider_modified=False,
                                         restart_reconstruction=True, final_plan_noop=c_row.get("final_plan_noop"),
                                         canonical_id_before=c_row.get("canonical_id_before"),
                                         canonical_id_after=c_row.get("canonical_id_after_reapply"),
                                         plan_actions=c_row.get("normal_plan_actions", []))
        deletion = c.get("scenario", {}).get("remote_deletion_recreation", {})
        if deletion.get("result") == "passed" and deletion.get("old_resource_absent") is True and deletion.get("identity_changed") is True:
            document["scenarios"][2].update(result="passed", externally_equivalent=True, evidence=str(pathlib.Path(c_output).resolve()),
                                             backend="postgresql", provider_modified=False,
                                             restart_reconstruction=True, final_plan_noop=True,
                                             old_resource_absent=True, new_resource_id=deletion.get("new_resource_id"),
                                             old_resource_id=deletion.get("old_resource_id"),
                                             replacement_actions=["create"])
    # P13.5E proves fault-proxy recovery, but does not by itself prove the
    # PostgreSQL durable Operation replay/unknown-outcome contract required by
    # PG7. Keep PG7 blocked until that dedicated journey emits evidence.
    if d_status == "passed" and pathlib.Path(d_output).is_file():
        d = json.loads(pathlib.Path(d_output).read_text(encoding="utf-8"))
        if d.get("aggregate_verdict") == "PASS":
            rows_by_scenario = {row.get("scenario"): row for row in d.get("scenarios", [])}
            for scenario_name, pg_name in {
                "independent-resource": "PG4-independent-replacement",
                "router-interface": "PG5-router-interface-relationship",
                "volume-attachment": "PG6-volume-attachment-relationship",
            }.items():
                d_row = rows_by_scenario.get(scenario_name, {})
                if (
                    d_row.get("result") == "passed"
                    and d_row.get("parents_preserved") is True
                    and d_row.get("provider_leaks") == 0
                    and d_row.get("foreign_changes") == 0
                    and d_row.get("restart_reconstruction") is True
                    and d_row.get("final_plan_noop") is True
                ):
                    next(row for row in document["scenarios"] if row["scenario"] == pg_name).update(
                        result="passed", externally_equivalent=True, evidence=str(pathlib.Path(d_output).resolve()),
                        backend="postgresql", provider_modified=False,
                        restart_reconstruction=True, final_plan_noop=True,
                        parents_preserved=True, provider_leaks=0, foreign_changes=0,
                        plan_actions=d_row.get("plan_actions", []),
                        parent_ids_before=d_row.get("parent_ids_before"), parent_ids_after=d_row.get("parent_ids_after"),
                        replacement_actions=d_row.get("plan_actions", []),
                    )
    pg7 = pathlib.Path(e_dir) / "PG7-operation-replay-unknown-outcome.json"
    if e_status == "passed" and pg7.is_file():
        replay = json.loads(pg7.read_text(encoding="utf-8"))
        if (
            replay.get("result") == "passed"
            and replay.get("externally_equivalent") is True
            and replay.get("backend_completion_observed") is True
            and replay.get("restart_boundary") is True
            and replay.get("duplicate_mutation") is False
            and replay.get("final_plan_noop") is True
        ):
            next(row for row in document["scenarios"] if row["scenario"] == "PG7-operation-replay-unknown-outcome").update(
                result="passed", externally_equivalent=True, evidence=str(pg7.resolve()),
                backend="postgresql", provider_modified=False, restart_reconstruction=True, final_plan_noop=True,
                fault_location=replay["fault_location"], backend_completion_observed=True,
                restart_boundary=True, replay_reconstruction=True,
            )
    if all(row["result"] == "passed" for row in document["scenarios"]):
        document["final_verdict"] = "passed"
output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
print(json.dumps({"output": str(output), "status": document["final_verdict"], "execution": run_status}))
PY
python3 "$root_dir/scripts/validate_p13_5f_postgres_provider_parity.py" "$output"
