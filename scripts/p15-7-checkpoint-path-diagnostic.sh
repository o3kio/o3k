#!/usr/bin/env bash
set -Eeuo pipefail

# Pre-VM publisher boundary diagnostic. Cargo is deliberately run as the
# normal runner account; only the already-built test executable crosses the
# root/o3k boundary.
ROOT_DIR="$1"
ARTIFACT_DIR="$2"
WORK_ROOT="$3"
RUN_ID="$4"
RUNNER_UID="$(id -u)"
RUNNER_GID="$(id -g)"
DIAGNOSTIC_LOG="$ARTIFACT_DIR/p15-7-checkpoint-path-diagnostic.log"
DIAGNOSTIC_JSON="$ARTIFACT_DIR/p15-7-checkpoint-path-diagnostic.json"
DIAGNOSTIC_WORKSPACE="$(mktemp -d "/tmp/o3k-p15-7-checkpoint-diagnostic-${RUN_ID}.XXXXXX")"
DIAGNOSTIC_ROOT="$DIAGNOSTIC_WORKSPACE/root"
DIAGNOSTIC_STAGE="$DIAGNOSTIC_WORKSPACE/stage"
DIAGNOSTIC_TARGET="$WORK_ROOT/checkpoint-diagnostic-target"
BUILD_LOG="$WORK_ROOT/checkpoint-diagnostic-build.log"
RUN_LOG="$WORK_ROOT/checkpoint-diagnostic-run.log"
EVIDENCE_STAGE="$DIAGNOSTIC_STAGE/checkpoint-path-evidence.json"
STAGED_EXECUTABLE="$DIAGNOSTIC_STAGE/checkpoint-boundary-test"
CLEANUP_FAILED=false
INJECT_FAILURE="${O3K_P15_7_DIAGNOSTIC_INJECT_FAILURE:-}"
PREBUILT_EXECUTABLE="${O3K_P15_7_DIAGNOSTIC_EXECUTABLE:-}"

mkdir -p "$ARTIFACT_DIR" "$DIAGNOSTIC_STAGE"
chmod 0755 "$DIAGNOSTIC_WORKSPACE" "$DIAGNOSTIC_STAGE"
: >"$DIAGNOSTIC_LOG"
chmod 0600 "$DIAGNOSTIC_LOG"

write_result() {
  local status="$1" step="$2" kind="$3" errno="${4:-}"
  python3 - "$DIAGNOSTIC_JSON" "$status" "$step" "$kind" "$errno" "$RUN_ID" "$RUNNER_UID" <<'PY'
import json, pathlib, sys
out, status, step, kind, errno, run_id, runner_uid = sys.argv[1:8]
pathlib.Path(out).write_text(json.dumps({
    "run_id": run_id,
    "runner_uid": int(runner_uid),
    "status": int(status),
    "failure_step": None if kind == "published_and_released" else step,
    "failure_kind": None if kind == "published_and_released" else kind,
    "failure_errno": int(errno) if errno.isdigit() else None,
    "diagnostic_result": "published_and_released" if kind == "published_and_released" else "failed_closed",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

append_log() {
  local source="$1" label="$2"
  {
    printf '\n== %s ==\n' "$label"
    tail -n 200 "$source" 2>/dev/null | head -c 32768 \
      | sed -E 's/(Authorization: Bearer |password=|token=|secret=)[^[:space:]]+/\1REDACTED/Ig'
  } >>"$DIAGNOSTIC_LOG" || true
}

cleanup_workspace() {
  sudo -n rm -rf -- "$DIAGNOSTIC_ROOT" >/dev/null 2>&1 || CLEANUP_FAILED=true
  rm -rf -- "$DIAGNOSTIC_TARGET" "$DIAGNOSTIC_WORKSPACE" >/dev/null 2>&1 || CLEANUP_FAILED=true
}

record_cleanup() {
  local completed="$1"
  python3 - "$DIAGNOSTIC_JSON" "$completed" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text(encoding="utf-8"))
doc["cleanup"] = {"completed": sys.argv[2] == "true", "idempotent": True}
path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}


fail() {
  local status="$1" step="$2" kind="$3" errno="${4:-}"
  write_result "$status" "$step" "$kind" "$errno"
  cleanup_workspace
  record_cleanup "$([[ "$CLEANUP_FAILED" == false ]] && echo true || echo false)"
  if [[ "$CLEANUP_FAILED" == true ]]; then
    printf 'diagnostic cleanup residue: workspace=%s target=%s root=%s\n' \
      "$(basename "$DIAGNOSTIC_WORKSPACE")" "$(basename "$DIAGNOSTIC_TARGET")" \
      "$(basename "$DIAGNOSTIC_ROOT")" >>"$DIAGNOSTIC_LOG"
  fi
  printf 'checkpoint diagnostic failed at %s (%s); inspect %s\n' "$step" "$kind" "$DIAGNOSTIC_LOG" >&2
  # Preserve the first failing operation's status for the caller while the
  # bounded JSON/log artifacts retain the structured stage and kind.
  exit "$status"
}

{
  printf 'runner uid=%s gid=%s\n' "$RUNNER_UID" "$RUNNER_GID"
  printf 'daemon identity: '
  sudo -n -u o3k id
  printf 'workspace=%s mode=%s\n' "$(basename "$DIAGNOSTIC_WORKSPACE")" "$(stat -c '%a' "$DIAGNOSTIC_WORKSPACE")"
} >>"$DIAGNOSTIC_LOG" 2>&1 || fail 1 toolchain_lookup launcher_identity
command -v cargo >/dev/null 2>&1 || fail 127 toolchain_lookup cargo_unavailable
[[ "$INJECT_FAILURE" == early_exit ]] && fail 99 bootstrap early_exit

if [[ -n "$PREBUILT_EXECUTABLE" ]]; then
  BUILT_EXECUTABLE="$PREBUILT_EXECUTABLE"
  printf 'prebuilt executable supplied by no-VM fixture\n' >>"$DIAGNOSTIC_LOG"
elif (cd "$ROOT_DIR" && CARGO_TARGET_DIR="$DIAGNOSTIC_TARGET" cargo test --locked -p o3k-compute --lib \
    targeted_checkpoint_unprivileged_boundary_publishes_and_releases --no-run --message-format=json \
    >"$BUILD_LOG" 2>&1); then
  :
else
  status=$?
  append_log "$BUILD_LOG" build
  fail "$status" build cargo_failed
fi
if [[ -z "$PREBUILT_EXECUTABLE" ]]; then
  append_log "$BUILD_LOG" build
  BUILT_EXECUTABLE="$(python3 - "$BUILD_LOG" <<'PY'
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
fi
[[ -n "$BUILT_EXECUTABLE" && -x "$BUILT_EXECUTABLE" ]] || fail 1 build executable_not_found
install -m 0755 "$BUILT_EXECUTABLE" "$STAGED_EXECUTABLE" || fail 1 build stage_failed

sudo -n install -d -o root -g root -m 0755 "$DIAGNOSTIC_ROOT" \
  || fail 1 child_execution diagnostic_root_create
for path in /tmp "$DIAGNOSTIC_WORKSPACE" "$DIAGNOSTIC_STAGE" "$DIAGNOSTIC_ROOT" "$STAGED_EXECUTABLE"; do
  sudo -n -u o3k test -x "$path" || fail 1 child_execution daemon_cannot_traverse
done
printf 'staged executable mode=%s owner=%s\n' "$(stat -c '%a' "$STAGED_EXECUTABLE")" \
  "$(stat -c '%U:%G' "$STAGED_EXECUTABLE")" >>"$DIAGNOSTIC_LOG"
for path in /tmp "$DIAGNOSTIC_WORKSPACE" "$DIAGNOSTIC_STAGE" "$DIAGNOSTIC_ROOT" "$STAGED_EXECUTABLE"; do
  printf 'verified path=%s mode=%s owner=%s\n' "$path" "$(stat -c '%a' "$path")" \
    "$(stat -c '%U:%G' "$path")" >>"$DIAGNOSTIC_LOG"
done

if [[ "$INJECT_FAILURE" == child_launch ]]; then
  STAGED_EXECUTABLE="$DIAGNOSTIC_STAGE/missing-child"
fi

if sudo -n env \
    O3K_CHECKPOINT_BOUNDARY_ROOT="$DIAGNOSTIC_ROOT" \
    O3K_CHECKPOINT_BOUNDARY_EVIDENCE="$EVIDENCE_STAGE" \
    "$STAGED_EXECUTABLE" --exact \
      checkpoint_tests::targeted_checkpoint_unprivileged_boundary_publishes_and_releases --nocapture \
    >"$RUN_LOG" 2>&1; then
  :
else
  status=$?
  append_log "$RUN_LOG" child_execution
  fail "$status" child_execution test_executable_failed
fi
append_log "$RUN_LOG" child_execution
if [[ "$INJECT_FAILURE" == publication ]]; then
  rm -f -- "$EVIDENCE_STAGE"
fi
[[ -s "$EVIDENCE_STAGE" ]] || fail 1 publication evidence_missing
install -m 0600 "$EVIDENCE_STAGE" "$DIAGNOSTIC_JSON" || fail 1 publication evidence_copy_failed
python3 - "$DIAGNOSTIC_JSON" <<'PY'
import json, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text(encoding="utf-8"))
doc["status"] = 0
doc["runner_uid"] = os.getuid()
doc["diagnostic"] = {
    "diagnostic_result": "published_and_released",
    "failure_step": None,
    "failure_kind": None,
    "failure_errno": None,
}
path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
cleanup_workspace
record_cleanup "$([[ "$CLEANUP_FAILED" == false ]] && echo true || echo false)"
[[ "$CLEANUP_FAILED" == false ]] || fail 1 cleanup workspace_cleanup_failed
