#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-contender.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
mkdir -p "$WORK_DIR/work" "$WORK_DIR/artifacts"
printf 'server-id\n' >"$WORK_DIR/work/workload-d-create.txt"
printf 'ERROR request_id=req-123 password=secret-value provider failed\n' >"$WORK_DIR/work/workload-d-create.err"
printf '%s\n' '{"items":[{"id":"33333333-3333-4333-8333-333333333333","resource_id":"11111111-1111-4111-8111-111111111111","action":"server.create","state":"failed","request_id":"req-456"}]}' >"$WORK_DIR/work/operations-d.json"
printf '%s\n' '{"status":{"state":"ERROR"},"request_id":"req-789"}' >"$WORK_DIR/work/workload-d-show.json"
printf 'ERROR agent provider operation failed request_id=req-agent\n' >"$WORK_DIR/work/contender-agent.log"
printf 'ERROR daemon timeout\n' >"$WORK_DIR/work/contender-daemon.log"
printf 'ERROR provider failed\n' >"$WORK_DIR/work/contender-provider.log"
printf 'Bad Request password=reuse-secret\n' >"$WORK_DIR/work/reuse-port.err"
python3 "$ROOT_DIR/scripts/capture-p15-7-contender-evidence.py" \
  --artifact "$WORK_DIR/artifacts/evidence.json" --work-root "$WORK_DIR/work" \
  --source-sha 0123456789abcdef0123456789abcdef01234567 --run-id contender-guard \
  --phase repair_completed --wrapper-exit-status 137 --pid 42 --pgid 42 --starttime 99 \
  --request-start-ms 1000 --request-end-ms 2500 \
  --endpoint-id 22222222-2222-7222-8222-222222222222 \
  --server-id 11111111-1111-4111-8111-111111111111
python3 - "$WORK_DIR/artifacts/evidence.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["wrapper"]["exit_status"] == 137
assert doc["wrapper"]["signal"] == "SIGKILL"
assert doc["wrapper"]["timeout_detected"] is True
assert doc["wrapper"]["timeout_seconds"] == 67
assert doc["request"]["elapsed_ms"] == 1500
assert doc["server"]["state"] == "ERROR"
assert doc["operation"]["id"] == "33333333-3333-4333-8333-333333333333"
assert doc["operation"]["state"] == "failed"
assert doc["request"]["endpoint_id"] == "22222222-2222-7222-8222-222222222222"
assert "Bad Request" in doc["fixed_ip_reuse"]["stderr"]
assert "reuse-secret" not in doc["fixed_ip_reuse"]["stderr"]
assert "req-123" in doc["request"]["request_ids"]
assert "req-456" in doc["request"]["request_ids"]
assert "secret-value" not in doc["wrapper"]["stderr"]
assert doc["correlated_errors"]["daemon"]
assert doc["correlated_errors"]["agent"]
assert doc["correlated_errors"]["provider"]
PY
echo "P15.7 contender evidence guards PASS"
