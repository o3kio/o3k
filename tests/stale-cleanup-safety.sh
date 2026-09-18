#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-stale-cleanup.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT

mkdir -p "$WORK_DIR/bin" "$WORK_DIR/runner/o3k-testlab"
cat >"$WORK_DIR/bin/virsh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-}" in
  -c)
    if [[ "${3:-}" == list ]]; then
      printf 'o3k-foreign-canary\n'
    else
      printf 'foreign domain was targeted\n' >&2
      exit 1
    fi
    ;;
  *) printf 'foreign domain was targeted\n' >&2; exit 1 ;;
esac
EOF
cat >"$WORK_DIR/bin/ip" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == -o && "${2:-}" == link && "${3:-}" == show ]]; then
  printf '9: o3k-foreign-canary: <BROADCAST>\n'
else
  printf 'foreign link was targeted\n' >&2
  exit 1
fi
EOF
# Privileged passthrough that makes an "owned" daemon unkillable: `sudo kill`
# is a no-op while `sudo kill -0` keeps reporting the process alive, so
# cleanup-disposable-testlab.sh cannot confirm shutdown and must preserve the
# run ledger. Every other sudo command passes through unchanged.
cat >"$WORK_DIR/bin/sudo" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${1:-}" == -n ]] && shift
if [[ "${1:-}" == kill ]]; then
  for a in "$@"; do
    [[ "$a" == -0 ]] && exit 0
  done
  exit 0
fi
exec "$@"
EOF
# The cleanup proves the daemon identity partly through `ps -o user`; report
# the owned account so process_record_matches can succeed.
cat >"$WORK_DIR/bin/ps" <<'EOF'
#!/usr/bin/env bash
printf 'o3k\n'
EOF
# Collapse the cleanup's 1-second shutdown polling loop so the regression is
# fast (the owned process stays alive regardless).
cat >"$WORK_DIR/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$WORK_DIR/bin/virsh" "$WORK_DIR/bin/ip" "$WORK_DIR/bin/sudo" \
    "$WORK_DIR/bin/ps" "$WORK_DIR/bin/sleep"

PATH="$WORK_DIR/bin:/usr/bin:/bin" RUNNER_TEMP="$WORK_DIR/runner" \
  GITHUB_RUN_ID=991991 O3K_TESTLAB_STATE_BASE="$WORK_DIR/runner/o3k-testlab" \
  bash "$ROOT_DIR/scripts/cleanup-stale-testlab-processes.sh"

echo "stale cleanup foreign-name safety test passed"

# A prior O3K run can leave a verified-owned daemon alive (matching run marker
# + PID record + start_ticks + exe proof chain in cleanup-disposable-testlab.sh
# `stop_owned_process` / `process_record_matches`).  The per-run cleanup must
# confirm the owned daemon is stopped before it may discard the run ledger,
# so an alive verified-owned process must preserve STATE_ROOT and PID_ROOT
# rather than delete them.  Pin that behavior.
PROC_RUN="local-42"
PROC_RUNNER_TEMP="$WORK_DIR/proc-runner"
PROC_STATE_ROOT="$PROC_RUNNER_TEMP/o3k-testlab/$PROC_RUN"
PROC_PID_ROOT="$PROC_RUNNER_TEMP/o3k-testlab-pids/$PROC_RUN"
mkdir -p "$PROC_STATE_ROOT/bin" "$PROC_PID_ROOT" \
  "$PROC_RUNNER_TEMP/o3k-testlab-inventory" \
  "$PROC_RUNNER_TEMP/o3k-testlab-pids" "$PROC_RUNNER_TEMP/o3k-testlab-inventory"
printf 'o3k-disposable-testlab-v1\nrun=%s\n' "$PROC_RUN" >"$PROC_STATE_ROOT/.o3k-run-owned"
printf 'o3k-owned-v1 path=%s\n' "$PROC_STATE_ROOT" >"$PROC_STATE_ROOT/.o3k-owned"
chmod 0755 "$PROC_STATE_ROOT"
cp /usr/bin/sleep "$PROC_STATE_ROOT/bin/o3kd"
chmod 0755 "$PROC_STATE_ROOT/bin/o3kd"
"$PROC_STATE_ROOT/bin/o3kd" 300 & proc_pid=$!
proc_ticks="$(awk '{print $22}' "/proc/$proc_pid/stat")"
printf '%s|%s|o3k|o3kd\n' "$proc_pid" "$proc_ticks" >"$PROC_PID_ROOT/o3kd.pid"

set +e
proc_out="$(PATH="$WORK_DIR/bin:/usr/bin:/bin" \
  RUNNER_TEMP="$PROC_RUNNER_TEMP" GITHUB_RUN_ID="$PROC_RUN" \
  O3K_TESTLAB_STATE_ROOT="$PROC_STATE_ROOT" \
  O3K_OPENSTACK_VENV="" O3K_TESTLAB_IMAGE_PATH="" \
  bash "$ROOT_DIR/scripts/cleanup-disposable-testlab.sh" 2>&1)"
proc_rc=$?
set -e
[[ "$proc_rc" != 0 ]] \
  || { echo "cleanup deleted state while an owned daemon was alive" >&2; exit 1; }
grep -Fq "service did not stop" <<<"$proc_out" \
  || { echo "cleanup did not refuse shutdown on a live owned daemon" >&2; exit 1; }
[[ -d "$PROC_STATE_ROOT" ]] \
  || { echo "STATE_ROOT deleted while an owned daemon was alive" >&2; exit 1; }
[[ -d "$PROC_PID_ROOT" ]] \
  || { echo "PID_ROOT deleted while an owned daemon was alive" >&2; exit 1; }
kill "$proc_pid" 2>/dev/null || true
wait "$proc_pid" 2>/dev/null || true

echo "stale cleanup owned-process preservation test passed"
