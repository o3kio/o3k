#!/usr/bin/env bash
set -Eeuo pipefail

# Protected #1035 lane. The runner supplies a real-host command for the
# minimum PostgreSQL/o3kd/compute/network topology; there is deliberately no
# SQLite or fake-provider fallback here.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${O3K_REAL_HOST_ARTIFACT_DIR:-target/real-host-workflow-artifacts}"
SOURCE_SHA="${O3K_P15_7_SOURCE_SHA:-${GITHUB_SHA:-}}"
COMMAND="${O3K_P15_7_1035_JOURNEY_COMMAND:-}"
mkdir -p "${ARTIFACT_DIR}"
[[ "${O3K_P15_7_REAL_HOST:-}" == 1 ]] || { echo "real-host opt-in required" >&2; exit 2; }
[[ "${SOURCE_SHA}" =~ ^[0-9a-fA-F]{40}$ ]] || { echo "exact source SHA required" >&2; exit 2; }
[[ -n "${COMMAND}" ]] || { echo "O3K_P15_7_1035_JOURNEY_COMMAND is required" >&2; exit 2; }

status=0
export O3K_P15_7_PHASE=1035-crash-recovery
bash -lc "${COMMAND}" || status=$?
python3 "${ROOT_DIR}/scripts/write_pp5_phase_results.py" "${ARTIFACT_DIR}" --source-sha "${SOURCE_SHA}" >/dev/null
python3 - "${ARTIFACT_DIR}/pp5-1035-crash-recovery-result.json" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("status") != "passed":
    raise SystemExit(1)
PY
exit "${status}"
