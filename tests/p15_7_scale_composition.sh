#!/usr/bin/env bash
set -Eeuo pipefail

# The protected runner supplies O3K_P15_7_JOURNEY_COMMAND.  It is deliberately
# not implemented as a fake/local fallback: a green P15.7 result requires the
# real o3kd, authenticated multi-block joins, and the real execution boundary.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${O3K_REAL_HOST_ARTIFACT_DIR:-target/real-host-workflow-artifacts}"
EVIDENCE_FILE="${O3K_P15_7_EVIDENCE_FILE:-${ARTIFACT_DIR}/p15-7-scale-composition-evidence.json}"
GATE_RESULT="${ARTIFACT_DIR}/p15-7-gate-result.json"
SOURCE_SHA="${O3K_P15_7_SOURCE_SHA:-${GITHUB_SHA:-}}"
PROFILE="${O3K_P15_7_PROFILE:-small-edge-cloud}"
mkdir -p "${ARTIFACT_DIR}"

write_result() {
    local status="$1" reason="$2"
    python3 - "${GATE_RESULT}" "${status}" "${reason}" "${SOURCE_SHA}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "artifact_type": "o3k-p15-7-gate-result",
    "schema_version": 1,
    "status": sys.argv[2],
    "reason": sys.argv[3],
    "tested_source_sha": sys.argv[4] if len(sys.argv[4]) == 40 else None,
    "redacted": True,
}, sort_keys=True) + "\n", encoding="utf-8")
PY
}
trap 'write_result failed "unexpected_gate_error"' ERR

[[ "${O3K_P15_7_REAL_HOST:-}" == 1 ]] || { write_result blocked real_host_explicit_opt_in_required; exit 2; }
[[ "${O3K_PROVIDER:-}" == agent ]] || { write_result blocked provider_mode_not_agent; exit 2; }
[[ "${SOURCE_SHA}" =~ ^[0-9a-fA-F]{40}$ ]] || { write_result blocked exact_source_sha_required; exit 2; }

if [[ ! -f "${EVIDENCE_FILE}" ]]; then
    [[ -n "${O3K_P15_7_JOURNEY_COMMAND:-}" ]] || { write_result blocked journey_driver_not_configured; exit 2; }
    export O3K_P15_7_EVIDENCE_FILE="${EVIDENCE_FILE}"
    bash -lc "${O3K_P15_7_JOURNEY_COMMAND}"
fi
[[ -f "${EVIDENCE_FILE}" ]] || { write_result failed evidence_artifact_missing; exit 1; }

if ! python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE_FILE}" \
    --expected-source-sha "${SOURCE_SHA,,}" --expected-profile "${PROFILE}"; then
    write_result failed evidence_validation_failed
    exit 1
fi
write_result passed evidence_validated
