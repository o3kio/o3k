#!/usr/bin/env bash
set -Eeuo pipefail

# Cheap qualification of the certification machinery itself.  This script
# does not provision TestLab, mutate PostgreSQL, or claim product evidence.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_SHA="${O3K_P15_7_SOURCE_SHA:-${GITHUB_SHA:-}}"
[[ "$EXPECTED_SHA" =~ ^[0-9a-fA-F]{40}$ ]] || {
  echo "harness qualification requires an exact source SHA" >&2
  exit 1
}
actual_sha="$(git -C "$ROOT_DIR" rev-parse HEAD)"
[[ "$actual_sha" == "$EXPECTED_SHA" ]] || {
  echo "harness qualification source SHA mismatch" >&2
  exit 1
}
[[ -z "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=no)" ]] || {
  echo "harness qualification requires a clean tracked tree" >&2
  exit 1
}

bash -n "$ROOT_DIR/scripts/p15-7-real-host-journey.sh"
python3 -m py_compile \
  "$ROOT_DIR/scripts/p15-7-crash-evidence.py" \
  "$ROOT_DIR/scripts/p15-7-campaign-lock.py" \
  "$ROOT_DIR/scripts/capture-p15-7-maintenance-diagnostics.py" \
  "$ROOT_DIR/scripts/write_p15_7-failure-artifact.py" \
  "$ROOT_DIR/scripts/validate_p15_7_evidence.py"
bash "$ROOT_DIR/tests/p15_7_crash_state_machine.sh"
bash "$ROOT_DIR/tests/p15_7_campaign_lock_guards.sh"
bash "$ROOT_DIR/tests/p15_7_failure_artifact_guards.sh"
bash "$ROOT_DIR/tests/p15_7_restart_environment_guards.sh"
bash "$ROOT_DIR/tests/p15_7_contention_cleanup_guards.sh"
bash "$ROOT_DIR/tests/p15_7_api_read_retry_guards.sh"
bash "$ROOT_DIR/tests/p15_7_capacity_diagnostic_guards.sh"
bash "$ROOT_DIR/tests/p15_7_scale_composition_guards.sh"
python3 "$ROOT_DIR/tests/test_p15_7_maintenance_diagnostics.py"
bash "$ROOT_DIR/tests/pp5_focused_lane_guards.sh"
bash "$ROOT_DIR/tests/p15_7_protected_preflight.sh"

echo "PP5_FAST_HARNESS_QUALIFICATION=PASS (machinery only; no product or real-host claim)"
