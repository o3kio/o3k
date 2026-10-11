#!/usr/bin/env bash
set -Eeuo pipefail

# One-host lower-bound smoke: the canonical bootstrap compute block only.
export O3K_P15_7_PHASE=s1-boundary
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${O3K_REAL_HOST_ARTIFACT_DIR:-${ROOT_DIR}/target/real-host-workflow-artifacts}"
python3 "${ROOT_DIR}/scripts/pp5-protected-harness-microgate.py" validate-artifact \
  --run-id "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}" \
  --source-sha "${O3K_P15_7_SOURCE_SHA:?O3K_P15_7_SOURCE_SHA is required}" \
  --artifact "${ARTIFACT_DIR}/pp5-lane-initial-state.json" \
  --microgate-artifact "${ARTIFACT_DIR}/pp5-protected-harness-microgate.json" \
  || { echo "S1 blocked: protected PP.5 microgate artifact is missing or failed" >&2; exit 1; }
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/p15_7_scale_composition.sh"
