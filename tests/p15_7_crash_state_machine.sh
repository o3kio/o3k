#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-crash-state.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
EVIDENCE="$WORK_DIR/crash.json"
SHA=0123456789abcdef0123456789abcdef01234567
RUN=state-machine-run
SERVER=11111111-1111-1111-1111-111111111111
ENDPOINT=22222222-2222-2222-2222-222222222222
TOOL=(python3 "$ROOT_DIR/scripts/p15-7-crash-evidence.py" "$EVIDENCE")
PHASES=(fault_armed terminal_state_observed endpoint_present_pre_crash process_identity_armed \
  process_killed process_restarted repair_lock_acquired contending_create_waiting \
  contending_create_started orphan_discovered repair_completed contending_create_accepted \
  accounting_verified completed)

step() {
  "${TOOL[@]}" "$1" "$2" source_sha "$SHA" run_id "$RUN" \
    server_id "$SERVER" endpoint_id "$ENDPOINT" target_resource_id "$SERVER" \
    >/dev/null
}

step fault_armed running
if "${TOOL[@]}" orphan_discovered running source_sha "$SHA" run_id "$RUN" \
    server_id "$SERVER" endpoint_id "$ENDPOINT" target_resource_id "$SERVER" >/dev/null 2>&1; then
  echo "out-of-order crash phase was accepted" >&2
  exit 1
fi
for phase in "${PHASES[@]:1:${#PHASES[@]}-2}"; do
  step "$phase" running
done
step completed passed

python3 - "$EVIDENCE" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["status"] == "passed"
assert [item["phase"] for item in doc["checkpoints"]] == [
    "fault_armed", "terminal_state_observed", "endpoint_present_pre_crash",
    "process_identity_armed", "process_killed", "process_restarted",
    "repair_lock_acquired", "contending_create_waiting", "contending_create_started",
    "orphan_discovered", "repair_completed", "contending_create_accepted",
    "accounting_verified", "completed"
]
PY

MISSING="$WORK_DIR/missing-phase.json"
cp "$EVIDENCE" "$MISSING"
python3 - "$MISSING" <<'PY'
import json, sys
path = sys.argv[1]
doc = json.load(open(path, encoding="utf-8"))
doc["checkpoints"].pop()
doc["status"] = "running"
doc["phase"] = "accounting_verified"
doc.pop("failure_phase", None)
doc["checkpoints"].pop(5)
json.dump(doc, open(path, "w", encoding="utf-8"))
PY
MISSING_TOOL=(python3 "$ROOT_DIR/scripts/p15-7-crash-evidence.py" "$MISSING")
if "${MISSING_TOOL[@]}" completed passed >/dev/null 2>&1; then
  echo "missing crash phase history was accepted" >&2
  exit 1
fi

FAILED="$WORK_DIR/failed.json"
TOOL_FAILED=(python3 "$ROOT_DIR/scripts/p15-7-crash-evidence.py" "$FAILED")
"${TOOL_FAILED[@]}" fault_armed running source_sha "$SHA" run_id "$RUN" \
  server_id "$SERVER" endpoint_id "$ENDPOINT" target_resource_id "$SERVER" >/dev/null
"${TOOL_FAILED[@]}" fault_armed failed failure_phase fault_armed source_sha "$SHA" run_id "$RUN" \
  server_id "$SERVER" endpoint_id "$ENDPOINT" target_resource_id "$SERVER" >/dev/null
if "${TOOL_FAILED[@]}" terminal_state_observed running source_sha "$SHA" run_id "$RUN" \
    server_id "$SERVER" endpoint_id "$ENDPOINT" target_resource_id "$SERVER" >/dev/null 2>&1; then
  echo "failed evidence was advanced to a passing path" >&2
  exit 1
fi
python3 - "$FAILED" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["status"] == "failed"
assert doc["failure_phase"] == "fault_armed"
assert len(doc["checkpoints"]) == 2
PY

for mutation in wrong-run wrong-sha wrong-target stale-schema; do
  mutated="$WORK_DIR/$mutation.json"
  cp "$EVIDENCE" "$mutated"
  case "$mutation" in
    wrong-run) args=(run_id other-run) ;;
    wrong-sha) args=(source_sha ffffffffffffffffffffffffffffffffffffffff) ;;
    wrong-target) args=(target_resource_id 33333333-3333-3333-3333-333333333333) ;;
    stale-schema) python3 - "$mutated" <<'PY'
import json, sys
path = sys.argv[1]
doc = json.load(open(path, encoding="utf-8")); doc["schema_version"] = 2
json.dump(doc, open(path, "w", encoding="utf-8"))
PY
      args=() ;;
  esac
  MUTATION_TOOL=(python3 "$ROOT_DIR/scripts/p15-7-crash-evidence.py" "$mutated")
  if [[ "$mutation" != stale-schema ]] && "${MUTATION_TOOL[@]}" completed passed "${args[@]}" >/dev/null 2>&1; then
    echo "context mutation was accepted: $mutation" >&2
    exit 1
  fi
  if [[ "$mutation" == stale-schema ]] && "${MUTATION_TOOL[@]}" completed passed >/dev/null 2>&1; then
    echo "stale schema was accepted" >&2
    exit 1
  fi
done

echo "P15.7 crash evidence state-machine guards PASS"
