#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-checkpoint-diagnostic-test.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
ARTIFACT_DIR="$WORK_DIR/artifacts"
BUILD_DIR="${O3K_P15_7_CHECKPOINT_TEST_TARGET:-$ROOT_DIR/target/p15-7-checkpoint-diagnostic-test}"
mkdir -p "$ARTIFACT_DIR" "$BUILD_DIR"

command -v sudo >/dev/null 2>&1
id o3k >/dev/null 2>&1
sudo -n -u o3k id >/dev/null

# The fixture is built by this account, never by sudo/root. Subsequent
# invocations reuse only the resulting executable and exercise the actual
# root-launched/o3k-child boundary.
CARGO_TARGET_DIR="$BUILD_DIR" cargo test --locked -p o3k-compute --lib \
  targeted_checkpoint_unprivileged_boundary_publishes_and_releases --no-run --message-format=json \
  >"$WORK_DIR/build.log" 2>&1
EXECUTABLE="$(python3 - "$WORK_DIR/build.log" <<'PY'
import json, pathlib, sys
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    if item.get("reason") == "compiler-artifact" and item.get("executable"):
        print(item["executable"])
        break
PY
)"
[[ -x "$EXECUTABLE" ]]

run_case() {
  local name="$1" expected_status="$2" expected_step="$3" expected_kind="$4"
  local artifact="$ARTIFACT_DIR/$name" work="$WORK_DIR/$name-work"
  mkdir -p "$artifact" "$work"
  if O3K_P15_7_DIAGNOSTIC_EXECUTABLE="$EXECUTABLE" \
      O3K_P15_7_DIAGNOSTIC_INJECT_FAILURE="$name" \
      "$ROOT_DIR/scripts/p15-7-checkpoint-path-diagnostic.sh" \
      "$ROOT_DIR" "$artifact" "$work" "guard-$name" >"$artifact/launcher.log" 2>&1; then
    status=0
  else
    status=$?
  fi
  [[ "$status" -eq "$expected_status" ]]
  python3 - "$artifact/p15-7-checkpoint-path-diagnostic.json" "$expected_status" "$expected_step" "$expected_kind" "$name" <<'PY'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
status, step, kind, name = sys.argv[2:6]
assert doc["status"] == int(status)
if name == "":
    assert doc["diagnostic"]["diagnostic_result"] == "published_and_released"
    assert doc["original_layout"] == "permission_denied"
    assert doc["corrected_layout"] == "published_and_released"
else:
    assert doc["failure_step"] == step
    assert doc["failure_kind"] == kind
assert doc["cleanup"] == {"completed": True, "idempotent": True}
PY
  ! grep -Eiq '(password|token|secret)=[^R]' "$artifact/p15-7-checkpoint-path-diagnostic.log"
  grep -Fq 'daemon identity:' "$artifact/p15-7-checkpoint-path-diagnostic.log"
  if [[ "$name" != early_exit ]]; then
    grep -Fq 'verified path=' "$artifact/p15-7-checkpoint-path-diagnostic.log"
  fi
}

run_case "" 0 "" ""
run_case child_launch 127 child_execution test_executable_failed
run_case publication 1 publication evidence_missing
run_case early_exit 99 bootstrap early_exit
# A second injected failure proves cleanup is idempotent and preserves the
# same primary transition rather than retaining a stale marker.
run_case child_launch 127 child_execution test_executable_failed

! grep -Eq 'virsh|virt-install|provision_vms_bounded' "$ROOT_DIR/scripts/p15-7-checkpoint-path-diagnostic.sh"
echo "P15.7 checkpoint diagnostic boundary/cleanup tests: PASS"
