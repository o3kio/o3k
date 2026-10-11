#!/usr/bin/env bash
set -Eeuo pipefail

# Remove only prior disposable TestLab runs that carry the O3K ownership
# marker. The per-run cleanup script remains the authority for process
# identity, state ownership, and bounded shutdown.
RUN_ID="${O3K_TESTLAB_RUN_ID:-${GITHUB_RUN_ID:-${O3K_RUN_ID:-local-$$}}}"
RUNNER_TEMP="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
STATE_BASE="${O3K_TESTLAB_STATE_BASE:-/var/lib/o3k-testlab}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLEANUP_SCRIPT="${ROOT_DIR}/scripts/cleanup-disposable-testlab.sh"
PROTECTED_OBSERVER="${ROOT_DIR}/scripts/pp5-protected-state-observer.py"

if [[ ! "$RUN_ID" =~ ^[0-9]+(-generic|-pp5)?$|^local-[0-9]+(-generic|-pp5)?$ ]]; then
  RUN_ID="local-$$"
fi
[[ "$RUNNER_TEMP" == /* && "$RUNNER_TEMP" != *..* && -d "$RUNNER_TEMP" && ! -L "$RUNNER_TEMP" ]] || {
  echo "stale cleanup: runner temp path is unsafe" >&2
  exit 1
}
[[ "$STATE_BASE" == /* && "$STATE_BASE" != *..* && ! -L "$STATE_BASE" ]] || {
  echo "stale cleanup: state base path is unsafe" >&2
  exit 1
}
[[ -x "$CLEANUP_SCRIPT" ]] || {
  echo "stale cleanup: per-run cleanup script is unavailable" >&2
  exit 1
}

STATE_BASES=("$STATE_BASE")
if [[ -d "${RUNNER_TEMP%/}/o3k-testlab" && "${RUNNER_TEMP%/}/o3k-testlab" != "$STATE_BASE" ]]; then
  STATE_BASES+=("${RUNNER_TEMP%/}/o3k-testlab")
fi

for base_dir in "${STATE_BASES[@]}"; do
  [[ -d "$base_dir" && ! -L "$base_dir" ]] || continue
  for state_root in "$base_dir"/*; do
    [[ -d "$state_root" && ! -L "$state_root" ]] || continue
    stale_run_id="${state_root##*/}"
    [[ "$stale_run_id" =~ ^[0-9]+(-generic|-pp5)?$|^local-[0-9]+(-generic|-pp5)?$ ]] || continue
    [[ "$stale_run_id" != "$RUN_ID" ]] || continue
    if ! stale_source_sha="$(python3 "$PROTECTED_OBSERVER" read-marker-source-sha \
      --state-root "$state_root" --run-id "$stale_run_id" 2>/dev/null)"; then
      continue
    fi
    [[ "$stale_source_sha" =~ ^[0-9a-f]{40}$ ]] || continue

    echo "stale cleanup: removing prior owned run ${stale_run_id}"
    RUNNER_TEMP="$RUNNER_TEMP" O3K_TESTLAB_RUN_ID="$stale_run_id" \
      O3K_P15_7_SOURCE_SHA="$stale_source_sha" \
      O3K_TESTLAB_STATE_ROOT="$state_root" \
      O3K_REAL_HOST_INVENTORY_ROOT="${RUNNER_TEMP%/}/o3k-testlab-inventory/${stale_run_id}" \
      O3K_TESTLAB_PID_ROOT="${RUNNER_TEMP%/}/o3k-testlab-pids/${stale_run_id}" \
      O3K_OPENSTACK_VENV="" \
      O3K_TESTLAB_IMAGE_PATH="" \
      bash "$CLEANUP_SCRIPT"
  done
done

# Do not sweep host resources by name.  A prefix is not an ownership proof:
# a foreign operator may legitimately have a domain or link named `o3k-*`.
# Per-run cleanup is the only destructive path and requires the run marker,
# process identity, and resource-specific ownership records.  An orphaned
# host resource without those records is intentionally preserved for bounded
# operator reconciliation rather than guessed at here.

echo "stale cleanup: complete"
