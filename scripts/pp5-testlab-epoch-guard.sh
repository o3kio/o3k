#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHASE_RUN_ID="${O3K_TESTLAB_RUN_ID:-}"
STATE_ROOT="${O3K_TESTLAB_STATE_ROOT:-}"
ARTIFACT_DIR="${O3K_REAL_HOST_ARTIFACT_DIR:-${ROOT_DIR}/target/real-host-workflow-artifacts}"
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] || {
  echo "PP.5 TestLab epoch guard: workflow run ID is invalid" >&2
  exit 1
}
exec python3 "${ROOT_DIR}/scripts/pp5-testlab-epoch-guard.py" lane-preconditions \
  --run-id "${GITHUB_RUN_ID}" --testlab-run-id "${PHASE_RUN_ID}" \
  --state-root "${STATE_ROOT}" --artifact "${ARTIFACT_DIR}/pp5-lane-preconditions.json"
