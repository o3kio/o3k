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

PROJECT_AUTH_EVIDENCE="${ARTIFACT_DIR}/p15-7-project-auth.json"
PROJECT_AUTH_ALLOWLIST=(
    OS_AUTH_URL OS_USERNAME OS_PASSWORD OS_PROJECT_NAME OS_REGION_NAME
    OS_USER_DOMAIN_NAME OS_PROJECT_DOMAIN_NAME OS_INTERFACE
    OS_IDENTITY_API_VERSION OS_CLOUD OS_CLIENT_CONFIG_FILE
    O3K_TESTLAB_STATE_ROOT O3K_REAL_HOST_SERVICE_ACCOUNT
    O3K_REAL_HOST_COMPUTE_BINARY O3K_REAL_HOST_NETWORK_CAPABILITY
    O3K_REAL_HOST_DAEMON_ACCOUNT O3K_REAL_HOST_COMPUTE_ACCOUNT
    O3K_COMPUTE_BRIDGE_NAME O3K_TESTLAB_PID_ROOT
    O3K_REAL_HOST_PROTECTED_PATHS O3K_REAL_HOST_INVENTORY_ROOT
    O3K_OPENSTACK_VENV O3K_BOOTSTRAP_SECRET O3K_TESTLAB_ENV_FILE
    O3K_AGENT_INSPECT_PROBE_OUTPUT
)

write_project_auth_result() {
    local status="$1" reason="$2" project_id="${3:-}"
    python3 - "${PROJECT_AUTH_EVIDENCE}" "${status}" "${reason}" "${SOURCE_SHA}" "${project_id}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "artifact_type": "o3k-p15-7-project-auth",
    "schema_version": 1,
    "status": sys.argv[2],
    "reason": sys.argv[3],
    "tested_source_sha": sys.argv[4],
    "project_id": sys.argv[5] or None,
    "redacted": True,
}, sort_keys=True) + "\n", encoding="utf-8")
PY
}

import_bootstrap_environment() {
    local env_file="${O3K_TESTLAB_ENV_FILE:-}"
    [[ -n "$env_file" ]] || {
        [[ -n "${O3K_TESTLAB_STATE_ROOT:-}" ]] || return 1
        env_file="$O3K_TESTLAB_STATE_ROOT/bootstrap.env"
    }
    [[ -f "$env_file" && ! -L "$env_file" ]] || return 1
    [[ "$(stat -c '%a' -- "$env_file" 2>/dev/null || true)" == 600 ]] || return 1
    [[ "$(stat -c '%u' -- "$env_file" 2>/dev/null || true)" == "$(id -u)" ]] || return 1

    declare -A allowed=() seen=()
    local key
    for key in "${PROJECT_AUTH_ALLOWLIST[@]}"; do allowed["$key"]=1; done

    local line name value
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=([^$'\n\r']*)$ ]] || return 1
        name="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        [[ -n "${allowed[$name]:-}" && -z "${seen[$name]:-}" ]] || return 1
        seen["$name"]=1
        printf -v "$name" '%s' "$value"
        export "$name"
    done <"$env_file"
    O3K_TESTLAB_ENV_FILE="$env_file"
    export O3K_TESTLAB_ENV_FILE
    for key in OS_AUTH_URL OS_USERNAME OS_PASSWORD OS_PROJECT_NAME OS_REGION_NAME \
        OS_USER_DOMAIN_NAME OS_PROJECT_DOMAIN_NAME OS_INTERFACE \
        OS_IDENTITY_API_VERSION OS_CLOUD OS_CLIENT_CONFIG_FILE; do
        [[ -n "${!key:-}" ]] || return 1
    done
    [[ -f "$OS_CLIENT_CONFIG_FILE" && ! -L "$OS_CLIENT_CONFIG_FILE" ]] || return 1
    [[ "$(stat -c '%a' -- "$OS_CLIENT_CONFIG_FILE" 2>/dev/null || true)" == 600 ]] || return 1
    [[ "$(stat -c '%u' -- "$OS_CLIENT_CONFIG_FILE" 2>/dev/null || true)" == "$(id -u)" ]] || return 1
}

project_auth_smoke() {
    local expected_project_id project_id project_listing
    expected_project_id="$(python3 - "${ARTIFACT_DIR}/disposable-testlab-bootstrap.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.is_file():
    raise SystemExit(1)
data = json.loads(path.read_text(encoding="utf-8"))
print(data.get("project_id", ""), end="")
PY
)" || return 1
    [[ "$expected_project_id" =~ ^[0-9a-fA-F-]{36}$ ]] || return 1
    project_id="$(openstack token issue -f value -c project_id 2>/dev/null | tr -d '[:space:]')" || return 1
    [[ "$project_id" == "$expected_project_id" ]] || return 1
    project_listing="$(openstack server list -f json 2>/dev/null)" || return 1
    python3 - "$project_listing" <<'PY' || return 1
import json
import sys

value = json.loads(sys.argv[1])
if not isinstance(value, list):
    raise SystemExit(1)
PY
    write_project_auth_result passed authenticated "$project_id"
}

[[ "${O3K_P15_7_REAL_HOST:-}" == 1 ]] || { write_result blocked real_host_explicit_opt_in_required; exit 2; }
[[ "${O3K_PROVIDER:-}" == agent ]] || { write_result blocked provider_mode_not_agent; exit 2; }
[[ "${SOURCE_SHA}" =~ ^[0-9a-fA-F]{40}$ ]] || { write_result blocked exact_source_sha_required; exit 2; }

if [[ ! -f "${EVIDENCE_FILE}" ]]; then
    [[ -n "${O3K_P15_7_JOURNEY_COMMAND:-}" ]] || { write_result blocked journey_driver_not_configured; exit 2; }
    if ! import_bootstrap_environment; then
        write_project_auth_result blocked canonical_bootstrap_environment_missing
        write_result blocked project_auth_environment_missing
        exit 2
    fi
    if ! project_auth_smoke; then
        write_project_auth_result blocked project_auth_smoke_failed
        write_result blocked project_auth_smoke_failed
        exit 2
    fi
    if [[ "${O3K_P15_7_AUTH_SMOKE_ONLY:-}" == 1 ]]; then
        write_result passed project_auth_smoke_only
        exit 0
    fi
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
