#!/usr/bin/env bash
set -Eeuo pipefail

# No-VM regression for the pre-checkout repair boundary. The workflow steps
# are extracted and executed without a repository checkout.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-checkout-recovery.XXXXXX")"
cleanup() { sudo -n rm -rf -- "$WORK" 2>/dev/null || rm -rf -- "$WORK"; }
trap cleanup EXIT

command -v sudo >/dev/null 2>&1 || { echo "sudo is required" >&2; exit 2; }
sudo -n true || { echo "passwordless sudo is required" >&2; exit 2; }

extract_step() {
  local workflow="$1" marker="$2" output="$3"
  python3 - "$workflow" "$marker" "$output" <<'PY'
import pathlib, sys
workflow, marker, output = map(pathlib.Path, sys.argv[1:])
lines = workflow.read_text(encoding="utf-8").splitlines()
needle = f"      - name: {marker}"
try:
    start = lines.index(needle)
except ValueError:
    raise SystemExit(f"missing workflow step: {marker}")
try:
    run = next(i for i in range(start + 1, len(lines)) if lines[i] == "        run: |")
except StopIteration:
    raise SystemExit(f"step has no inline run block: {marker}")
body = []
for line in lines[run + 1:]:
    if line.startswith("      - name: "):
        break
    if line.startswith("          "):
        body.append(line[10:])
    elif line == "":
        body.append("")
    else:
        raise SystemExit(f"unexpected indentation in {marker}: {line!r}")
output.write_text("\n".join(body) + "\n", encoding="utf-8")
PY
  chmod 0755 "$output"
}

REPAIR="$WORK/repair.sh"
FAILURE="$WORK/failure.sh"
extract_step "$ROOT_DIR/.github/workflows/p15-7-protected-preflight.yml" \
  "Repair prior protected workspace access before checkout" "$REPAIR"
extract_step "$ROOT_DIR/.github/workflows/p15-7-protected-preflight.yml" \
  "Preserve checkout failure evidence" "$FAILURE"
grep -Fq 'o3k-p15-7-checkout-failure-${{ github.run_id }}.json' \
  "$ROOT_DIR/.github/workflows/p15-7-protected-preflight.yml"
grep -Fq 'o3k-p15-7-checkout-failure-${{ github.run_id }}.log' \
  "$ROOT_DIR/.github/workflows/p15-7-protected-preflight.yml"

if grep -Fq 'chmod -R 0600' "$ROOT_DIR/scripts/p15-7-real-host-journey.sh"; then
  echo "recursive 0600 still targets a directory" >&2
  exit 1
fi
grep -Fq 'find -P "$ARTIFACT_DIR/o3kd-hang" -type d -exec chmod 0700' \
  "$ROOT_DIR/scripts/p15-7-real-host-journey.sh"
grep -Fq 'find -P "$ARTIFACT_DIR/o3kd-hang" -type f -exec chmod 0600' \
  "$ROOT_DIR/scripts/p15-7-real-host-journey.sh"

runner_uid="$(id -u)"
runner_gid="$(id -g)"
if id -u o3k >/dev/null 2>&1; then
  boundary_uid="$(id -u o3k)"
  boundary_gid="$(id -g o3k)"
elif id -u nobody >/dev/null 2>&1; then
  # Keep the regression meaningful on a generic runner image without the
  # daemon account; nobody is only a substitute for the unprivileged boundary.
  boundary_uid="$(id -u nobody)"
  boundary_gid="$(id -g nobody)"
else
  boundary_uid="$runner_uid"
  boundary_gid="$runner_gid"
fi
chmod 0755 "$WORK"

make_legacy_tree() {
  local root="$1"
  mkdir -p "$root/target/real-host-workflow-artifacts/o3kd-hang"
  printf 'bounded thread evidence\n' >"$root/target/real-host-workflow-artifacts/o3kd-hang/thread-stacks.txt"
  printf 'bounded debugger evidence\n' >"$root/target/real-host-workflow-artifacts/o3kd-hang/gdb-backtrace.txt"
  sudo -n chown -R root:root "$root/target"
  sudo -n chmod 0600 "$root/target/real-host-workflow-artifacts/o3kd-hang"
  sudo -n chmod 0600 "$root/target/real-host-workflow-artifacts/o3kd-hang"/*
}

workspace="$WORK/workspace"
mkdir -p "$workspace"
make_legacy_tree "$workspace"
if sudo -n -u "#$boundary_uid" find -P \
  "$workspace/target/real-host-workflow-artifacts/o3kd-hang" -xdev -print \
  >/dev/null 2>&1; then
  echo "legacy 0600 directory was unexpectedly traversable" >&2
  exit 1
fi
env \
  GITHUB_WORKSPACE="$workspace" \
  O3K_PREFLIGHT_RUNNER_UID="$boundary_uid" \
  O3K_PREFLIGHT_RUNNER_GID="$boundary_gid" \
  bash "$REPAIR"

hang="$workspace/target/real-host-workflow-artifacts/o3kd-hang"
test "$(stat -c '%a' "$hang")" = 700
test "$(stat -c '%a' "$hang/thread-stacks.txt")" = 600
test "$(stat -c '%u:%g' "$hang")" = "$boundary_uid:$boundary_gid"
sudo -n -u "#$boundary_uid" find -P "$hang" -xdev -type f -readable -print >/dev/null

# Prove the actual checkout cleaner can traverse and remove the repaired tree.
sudo -n chown "$boundary_uid:$boundary_gid" "$workspace"
sudo -n chmod 0700 "$workspace"
sudo -n -u "#$boundary_uid" env HOME="$WORK/home" git -C "$workspace" init -q
sudo -n -u "#$boundary_uid" git -C "$workspace" clean -ffdx -q
test ! -e "$workspace/target"

# A nested symlink is rejected before any ownership or mode repair.
symlink_workspace="$WORK/symlink-workspace"
mkdir -p "$symlink_workspace/target/real-host-workflow-artifacts"
ln -s "$WORK" "$symlink_workspace/target/real-host-workflow-artifacts/o3kd-hang"
if env GITHUB_WORKSPACE="$symlink_workspace" \
  O3K_PREFLIGHT_RUNNER_UID="$boundary_uid" O3K_PREFLIGHT_RUNNER_GID="$boundary_gid" \
  bash "$REPAIR"; then
  echo "nested symlink was accepted" >&2
  exit 1
fi

# The failure collector is independent of .git and repository scripts.
failure_workspace="$WORK/failure-workspace"
mkdir -p "$failure_workspace/target/real-host-workflow-artifacts/o3kd-hang"
chmod 0600 "$failure_workspace/target/real-host-workflow-artifacts/o3kd-hang"
failure_temp="$WORK/failure-temp"
mkdir -p "$failure_temp"
env \
  RUNNER_TEMP="$failure_temp" \
  GITHUB_WORKSPACE="$failure_workspace" \
  GITHUB_RUN_ID=checkout-regression \
  TARGET_SHA=07a9124697e58eb0c3750147e0d05bb826f7ba6b \
  WORKFLOW_REVISION_SHA=07a9124697e58eb0c3750147e0d05bb826f7ba6b \
  bash "$FAILURE"
failure_json="$failure_temp/o3k-p15-7-checkout-failure-checkout-regression.json"
failure_log="$failure_temp/o3k-p15-7-checkout-failure-checkout-regression.log"
test -f "$failure_json" && test -f "$failure_log"
test "$(stat -c '%a' "$failure_json")" = 600
test "$(stat -c '%a' "$failure_log")" = 600
python3 - "$failure_json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["redacted"] is True
assert value["failure_step"] == "checkout"
assert value["failure_kind"] == "actions_checkout_failed"
assert value["target_sha"] == value["workflow_revision_sha"]
assert len(value["bounded_workspace_diagnostics"]) <= 32768
PY

echo "P15.7 checkout recovery tests passed"
