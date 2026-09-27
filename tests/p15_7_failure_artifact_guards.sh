#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-failure.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
SHA=0123456789abcdef0123456789abcdef01234567
python3 "$ROOT_DIR/scripts/write_p15_7-failure-artifact.py" \
  "$WORK_DIR/failure.json" "$SHA" run-a crash_recovery orphan_repair \
  terminal_state_observed "terminal delete observed" "endpoint remained present" \
  server-a endpoint-a pending unknown "redacted failure"
python3 - "$WORK_DIR/failure.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["status"] == "failed"
assert doc["failure_class"] == "orphan_repair"
assert doc["source_sha"] == "0123456789abcdef0123456789abcdef01234567"
assert doc["target_resource_ids"] == {"server_id": "server-a", "endpoint_id": "endpoint-a"}
assert "password" not in json.dumps(doc).lower()
PY
if python3 "$ROOT_DIR/scripts/write_p15_7-failure-artifact.py" \
    "$WORK_DIR/bad.json" not-a-sha run-a crash unknown "" x y s e pending unknown msg >/dev/null 2>&1; then
  echo "invalid failure artifact SHA was accepted" >&2
  exit 1
fi
echo "P15.7 failure artifact guards PASS"
