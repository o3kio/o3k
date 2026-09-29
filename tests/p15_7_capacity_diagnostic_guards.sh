#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-capacity-diag.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
cat >"$WORK_DIR/o3kd.log" <<'LOG'
INFO operator diagnostics capacity request_id=req-123
ERROR capacity diagnostics store operation failed operation=capacity_summary error_kind=corrupt
ERROR capacity diagnostics postgres://user:password@127.0.0.1/db token=super-secret
LOG
python3 "$ROOT_DIR/scripts/capture-p15-7-capacity-diagnostics.py" \
  "$WORK_DIR/o3kd.log" "$WORK_DIR/diagnostics.json"
python3 - "$WORK_DIR/diagnostics.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text(encoding="utf-8"))
assert doc["status"] == "captured"
assert doc["line_count"] == 3
text = path.read_text(encoding="utf-8")
assert "password@" not in text
assert "super-secret" not in text
assert "capacity_summary" in text
PY
python3 "$ROOT_DIR/scripts/capture-p15-7-capacity-diagnostics.py" \
  "$WORK_DIR/missing.log" "$WORK_DIR/missing.json"
python3 - "$WORK_DIR/missing.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1], encoding="utf-8"))["status"] == "unavailable"
PY
echo "P15.7 capacity diagnostic guards PASS"
