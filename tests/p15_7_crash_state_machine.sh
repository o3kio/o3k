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
CONTENDER_ENDPOINT=33333333-3333-3333-3333-333333333333
OTHER_ENDPOINT=44444444-4444-4444-4444-444444444444
TOOL=(python3 "$ROOT_DIR/scripts/p15-7-crash-evidence.py" "$EVIDENCE")
PHASES=(fault_armed terminal_state_observed endpoint_present_pre_crash process_identity_armed \
  process_killed process_restarted repair_lock_acquired contending_create_waiting \
  contending_create_started orphan_discovered repair_completed contending_create_accepted \
  accounting_verified completed)

step() {
  local phase="$1" status="$2"
  shift 2
  "${TOOL[@]}" "$phase" "$status" source_sha "$SHA" run_id "$RUN" \
    server_id "$SERVER" endpoint_id "$ENDPOINT" target_resource_id "$SERVER" \
    "$@" >/dev/null
}

step fault_armed running
if "${TOOL[@]}" orphan_discovered running source_sha "$SHA" run_id "$RUN" \
    server_id "$SERVER" endpoint_id "$ENDPOINT" target_resource_id "$SERVER" >/dev/null 2>&1; then
  echo "out-of-order crash phase was accepted" >&2
  exit 1
fi
for phase in "${PHASES[@]:1:${#PHASES[@]}-2}"; do
  if [[ "$phase" == contending_create_started ]]; then
    MUTATION="$WORK_DIR/target-mutation.json"
    cp "$EVIDENCE" "$MUTATION"
    MUTATION_TOOL=(python3 "$ROOT_DIR/scripts/p15-7-crash-evidence.py" "$MUTATION")
    if "${MUTATION_TOOL[@]}" "$phase" running source_sha "$SHA" run_id "$RUN" \
        server_id "$SERVER" endpoint_id "$OTHER_ENDPOINT" target_resource_id "$SERVER" \
        contending_endpoint_id "$CONTENDER_ENDPOINT" >/dev/null 2>&1; then
      echo "target endpoint mutation was accepted" >&2
      exit 1
    fi
    step "$phase" running contending_endpoint_id "$CONTENDER_ENDPOINT"
  else
    step "$phase" running
  fi
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
contender = next(item for item in doc["checkpoints"]
                 if item["phase"] == "contending_create_started")
assert contender["endpoint_id"] == "22222222-2222-2222-2222-222222222222"
assert contender["contending_endpoint_id"] == "33333333-3333-3333-3333-333333333333"
PY

# An atomic publication failure must not advance the persisted phase. The
# failure classification records the attempted phase separately for cleanup.
WRITE_FAILURE="$WORK_DIR/write-failure.json"
FAILURE_TOOL=(python3 "$ROOT_DIR/scripts/p15-7-crash-evidence.py" "$WRITE_FAILURE")
"${FAILURE_TOOL[@]}" fault_armed running source_sha "$SHA" run_id "$RUN" \
  server_id "$SERVER" endpoint_id "$ENDPOINT" target_resource_id "$SERVER" >/dev/null
BLOCKER="$WORK_DIR/not-a-directory"
printf '%s\n' blocker >"$BLOCKER"
if python3 "$ROOT_DIR/scripts/p15-7-crash-evidence.py" "$BLOCKER/evidence.json" \
    terminal_state_observed running source_sha "$SHA" run_id "$RUN" \
    server_id "$SERVER" endpoint_id "$ENDPOINT" target_resource_id "$SERVER" >/dev/null 2>&1; then
  echo "publication through a non-directory parent unexpectedly succeeded" >&2
  exit 1
fi
python3 - "$WRITE_FAILURE" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["phase"] == "fault_armed"
assert [item["phase"] for item in doc["checkpoints"]] == ["fault_armed"]
PY
python3 "$ROOT_DIR/scripts/write_p15_7-failure-artifact.py" \
  "$WORK_DIR/write-failure-classification.json" "$SHA" "$RUN" fault_armed \
  evidence_validation fault_armed "expected next phase" "publication failed" \
  "$SERVER" "$ENDPOINT" pending unknown "checkpoint publication failed" \
  terminal_state_observed
python3 - "$WORK_DIR/write-failure-classification.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["phase"] == "fault_armed"
assert doc["last_successful_checkpoint"] == "fault_armed"
assert doc["attempted_phase"] == "terminal_state_observed"
PY

# Cleanup is reported independently and must not replace the first API
# failure with the synthetic cleanup classification.
PRIMARY_FAILURE="$WORK_DIR/primary-failure.json"
python3 "$ROOT_DIR/scripts/write_p15_7-failure-artifact.py" \
  "$PRIMARY_FAILURE" "$SHA" "$RUN" initial-capacity-diagnostics \
  product_correctness journey_start "capacity diagnostics must return 200" \
  "API read failed: HTTP 500" "$SERVER" "$ENDPOINT" pending unknown \
  "API read failed: HTTP 500" initial-capacity-diagnostics
python3 "$ROOT_DIR/scripts/write_p15_7-failure-artifact.py" \
  "$PRIMARY_FAILURE" "$SHA" "$RUN" journey cleanup journey_start \
  "journey cleanup" "journey failed; cleanup completed" "$SERVER" "$ENDPOINT" \
  passed unchanged "journey failed; cleanup completed"
python3 - "$PRIMARY_FAILURE" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["phase"] == "initial-capacity-diagnostics"
assert doc["failure_class"] == "product_correctness"
assert doc["message"] == "API read failed: HTTP 500"
assert doc["cleanup_result"] == "passed"
assert doc["cleanup_message"] == "cleanup completed"
PY

# Exercise the actual journey persistence helper: a failed write records the
# attempted phase without advancing the last successful phase used by cleanup.
STATE_TEST="$WORK_DIR/state-helper-test.sh"
cat >"$STATE_TEST" <<'SH'
set -Eeuo pipefail
ROOT_DIR="$1"
WORK_DIR="$2"
CRASH_EVIDENCE_FILE="$WORK_DIR/helper.json"
SOURCE_SHA=0123456789abcdef0123456789abcdef01234567
RUN_ID=state-helper-run
CRASH_PHASE=""
CRASH_ATTEMPTED_PHASE=""
LAST_SUCCESSFUL_CHECKPOINT=journey_start
DIE_MESSAGE=""
die() { DIE_MESSAGE="$*"; return 1; }
source "$ROOT_DIR/scripts/p15-7-crash-evidence-state.sh"
persist_crash_checkpoint fault_armed running \
  server_id 11111111-1111-1111-1111-111111111111 \
  endpoint_id 22222222-2222-2222-2222-222222222222 \
  target_resource_id 11111111-1111-1111-1111-111111111111
[[ "$CRASH_PHASE" == fault_armed && "$CRASH_ATTEMPTED_PHASE" == fault_armed ]] || exit 1
[[ "$LAST_SUCCESSFUL_CHECKPOINT" == fault_armed ]] || exit 1
BLOCKER="$WORK_DIR/not-a-directory"
printf '%s\n' blocker >"$BLOCKER"
CRASH_EVIDENCE_FILE="$BLOCKER/evidence.json"
if persist_crash_checkpoint terminal_state_observed running 2>/dev/null; then
  echo "failed publication unexpectedly advanced helper state" >&2
  exit 1
fi
[[ "$CRASH_PHASE" == fault_armed ]] || exit 1
[[ "$LAST_SUCCESSFUL_CHECKPOINT" == fault_armed ]] || exit 1
[[ "$CRASH_ATTEMPTED_PHASE" == terminal_state_observed ]] || exit 1
[[ "$DIE_MESSAGE" == *terminal_state_observed* ]] || exit 1
SH
bash "$STATE_TEST" "$ROOT_DIR" "$WORK_DIR"

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
