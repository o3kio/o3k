#!/usr/bin/env bash

# Shared state transition for the protected #1035 crash-evidence writer.
# The caller supplies ROOT_DIR, CRASH_EVIDENCE_FILE, SOURCE_SHA, RUN_ID,
# CRASH_PHASE, CRASH_ATTEMPTED_PHASE, LAST_SUCCESSFUL_CHECKPOINT, and die().

persist_crash_checkpoint() {
  local phase="$1" status="$2"
  shift 2
  CRASH_ATTEMPTED_PHASE="$phase"
  if ! python3 "$ROOT_DIR/scripts/p15-7-crash-evidence.py" "$CRASH_EVIDENCE_FILE" \
    "$phase" "$status" source_sha "$SOURCE_SHA" run_id "$RUN_ID" \
    "$@"; then
    die "could not persist #1035 crash evidence phase $phase"
    return 1
  fi
  CRASH_PHASE="$phase"
  if [[ "$status" != failed ]]; then
    LAST_SUCCESSFUL_CHECKPOINT="$phase"
  fi
}
