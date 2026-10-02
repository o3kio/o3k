#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/p15-7-real-host-journey.sh"
[[ -f "$SCRIPT" ]] || { echo "missing P15.7 journey" >&2; exit 1; }

# The waiter observation must be derived from the repair pause contract. A
# fixed ten-second poll is unsafe because the real repair lease may legally
# take longer to transfer.
grep -Fq 'CONTENDING_CREATE_WAITER_BOUND_MS=$((CONTENDING_CREATE_REPAIR_PAUSE_MS - 5000))' "$SCRIPT"
grep -Fq 'CONTENDING_CREATE_WAITER_WAIT_START_MS=' "$SCRIPT"
grep -Fq 'CONTENDING_CREATE_WAITER_WAIT_MS=' "$SCRIPT"
if grep -Fq 'for _ in $(seq 1 100)' "$SCRIPT"; then
  echo "fixed ten-second contention waiter window remains" >&2
  exit 1
fi
grep -Fq 'waiter_wait_bound_ms "$CONTENDING_CREATE_WAITER_BOUND_MS"' "$SCRIPT"
grep -Fq 'waiter_observation_wait_ms' "$SCRIPT"

# The launched operation is bounded and its exact PID is reaped on every
# failure path. Broad process-name cleanup is forbidden.
grep -Fq 'setsid --wait timeout --foreground --kill-after=5s --signal=TERM 67s' "$SCRIPT"
grep -Fq 'stop_contending_create()' "$SCRIPT"
grep -Fq 'wait "$pid" 2>/dev/null || wait_status=$?' "$SCRIPT"
grep -Fq 'CONTENDING_CREATE_PID=""' "$SCRIPT"
grep -Fq 'kill -TERM -- "-$pgid"' "$SCRIPT"
grep -Fq 'process group remains after reap' "$SCRIPT"
if grep -Eq 'pkill|killall|pgrep .*openstack|kill .*o3kd' <(sed -n '/stop_contending_create()/,/^}/p' "$SCRIPT"); then
  echo "contention cleanup uses broad process matching" >&2
  exit 1
fi

# The release seam is touched only after the waiter marker has been observed.
python3 - "$SCRIPT" <<'PY'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
launch = next(i for i, line in enumerate(lines) if 'setsid --wait timeout --foreground --kill-after=5s --signal=TERM 67s openstack server create' in line)
waiter = next(i for i in range(launch, len(lines)) if 'CONTENDING_CREATE_LOCK_WAIT_OBSERVED=true' in lines[i])
release = next(i for i in range(waiter, len(lines)) if 'sudo -n touch -- "$CRASH_REPAIR_RELEASE_FILE"' in lines[i])
assert waiter < release, "repair release occurs before waiter observation"
stream_ready = next(i for i, line in enumerate(lines) if 'wait_for_agent_streams post-crash-restart' in line)
released_check = next(i for i in range(release, len(lines)) if '[[ "$CRASH_REPAIR_PAUSE_RELEASED_AFTER_CREATE" == true ]]' in lines[i])
assert stream_ready < launch, "contender must wait for surviving placement streams after restart"
source = '\n'.join(lines)
terminal = source.index('persist_crash_checkpoint terminal_state_observed running')
canary = source.index('openstack port create --network "$OS_NETWORK_ID" "o3k-p15-7-$RUN_ID-port-d"')
kill = source.index('CRASH_KILLED_PID="$(kill9_o3kd_verified)"')
assert terminal < canary < kill, "canary setup must occur during the orphan backlog, outside the post-restart repair window"
assert any('stop_contending_create' in line for line in lines[:launch]), "exact-PID cleanup helper not defined before launch"
source = '\n'.join(lines)
cleanup = source.split('cleanup() {', 2)[2].split('\n}', 1)[0]
assert cleanup.index('write_orphan_repair_diagnostics') < cleanup.index('stop_contending_create'), "checkpoint/timeline evidence must survive marker removal"
assert source.index('cp -- "$WORK_ROOT/orphan-repair-checkpoint.json"') < source.index('CONTENDING_CREATE_REQUEST_START_MS="$(date +%s%3N)"'), "published checkpoint must be retained before contention"
diagnostics = source.split('write_orphan_repair_diagnostics() {', 1)[1]
assert 'head -c 8192 -- "$CRASH_REPAIR_CHECKPOINT_FILE"' in diagnostics, "failure checkpoint capture must remain bounded"
PY

# Exercise the exact-PID cleanup contract with a run-owned dummy child. The
# helper is extracted without running the expensive journey.
helper="$(awk '/^stop_contending_create\(\) \{/{on=1} on{print} on && /^}/{exit}' "$SCRIPT")"
[[ -n "$helper" ]] || { echo "could not extract cleanup helper" >&2; exit 1; }
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-contention.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
mkdir -p "$WORK_DIR/state"
if ! env WORK_DIR="$WORK_DIR" bash -c '
  set -Eeuo pipefail
  CRASH_REPAIR_WAITER_FILE="$WORK_DIR/state/waiter"
  CRASH_REPAIR_RELEASE_FILE="$WORK_DIR/state/release"
  : >"$CRASH_REPAIR_WAITER_FILE"
  : >"$CRASH_REPAIR_RELEASE_FILE"
  setsid --wait sleep 60 & CONTENDING_CREATE_PID=$!
  child_pid="$CONTENDING_CREATE_PID"
  CONTENDING_CREATE_PGID="$CONTENDING_CREATE_PID"
  CONTENDING_CREATE_STARTTIME="$(cut -d " " -f22 "/proc/$child_pid/stat")"
  '"$helper"'
  stop_contending_create
  [[ -z "$CONTENDING_CREATE_PID" ]]
  [[ "$CONTENDING_CREATE_OBSERVED_PID" == "$child_pid" && "$CONTENDING_CREATE_OBSERVED_PGID" == "$child_pid" ]]
  ! kill -0 "$child_pid" 2>/dev/null
  [[ ! -e "$CRASH_REPAIR_WAITER_FILE" && ! -e "$CRASH_REPAIR_RELEASE_FILE" ]]
'; then
  echo "exact-PID contention cleanup regression failed" >&2
  exit 1
fi

# A create that exits before the waiter marker appears is still reaped and
# cannot strand synchronization state.
if ! env WORK_DIR="$WORK_DIR" bash -c '
  set -Eeuo pipefail
  CRASH_REPAIR_WAITER_FILE="$WORK_DIR/state/early-waiter"
  CRASH_REPAIR_RELEASE_FILE="$WORK_DIR/state/early-release"
  : >"$CRASH_REPAIR_WAITER_FILE"
  : >"$CRASH_REPAIR_RELEASE_FILE"
  setsid --wait false & CONTENDING_CREATE_PID=$!
  child_pid="$CONTENDING_CREATE_PID"
  CONTENDING_CREATE_PGID="$CONTENDING_CREATE_PID"
  sleep 0.1
  CONTENDING_CREATE_STARTTIME=""
  '"$helper"'
  stop_contending_create
  [[ -z "$CONTENDING_CREATE_PID" && "$CONTENDING_CREATE_REAPED" == true ]]
  ! kill -0 "$child_pid" 2>/dev/null
  [[ ! -e "$CRASH_REPAIR_WAITER_FILE" && ! -e "$CRASH_REPAIR_RELEASE_FILE" ]]
'; then
  echo "early-exit contention cleanup regression failed" >&2
  exit 1
fi

# A child ignoring TERM must hit the bounded KILL fallback and be reaped.
IGNORE_TERM_SCRIPT="$WORK_DIR/ignore-term.sh"
printf '#!/bin/sh\ntrap "" TERM\nsleep 60\n' >"$IGNORE_TERM_SCRIPT"
chmod 0700 "$IGNORE_TERM_SCRIPT"
if ! env WORK_DIR="$WORK_DIR" bash -c '
  set -Eeuo pipefail
  CRASH_REPAIR_WAITER_FILE="$WORK_DIR/state/kill-waiter"
  CRASH_REPAIR_RELEASE_FILE="$WORK_DIR/state/kill-release"
  : >"$CRASH_REPAIR_WAITER_FILE"
  : >"$CRASH_REPAIR_RELEASE_FILE"
  setsid --wait "$WORK_DIR/ignore-term.sh" & CONTENDING_CREATE_PID=$!
  child_pid="$CONTENDING_CREATE_PID"
  CONTENDING_CREATE_PGID="$CONTENDING_CREATE_PID"
  CONTENDING_CREATE_STARTTIME="$(cut -d " " -f22 "/proc/$child_pid/stat")"
  '"$helper"'
  stop_contending_create
  [[ -z "$CONTENDING_CREATE_PID" && "$CONTENDING_CREATE_REAPED" == true ]]
  ! kill -0 "$child_pid" 2>/dev/null
  [[ ! -e "$CRASH_REPAIR_WAITER_FILE" && ! -e "$CRASH_REPAIR_RELEASE_FILE" ]]
'; then
  echo "TERM-to-KILL contention cleanup regression failed" >&2
  exit 1
fi

echo "P15.7 contention waiter/cleanup guards: PASS"
