#!/usr/bin/env bash
set -Eeuo pipefail

# Re-exchange a near-expiry TestLab operator token through the canonical
# Keycloak-to-O3K authority driver. This helper owns no IAM/token semantics.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${O3K_P15_7_AUTHORITY_MODE:-external-oidc}"
[[ "$MODE" == testlab-keycloak || "$MODE" == external-oidc ]] \
  || { echo "P15.7 authority refresh: invalid authority mode" >&2; exit 2; }
[[ "$MODE" == testlab-keycloak ]] || exit 0

TOKEN_FILE="${O3K_P15_7_OPERATOR_TOKEN_FILE:-}"
CURL_CONFIG="${O3K_P15_7_OPERATOR_CURL_CONFIG:-}"
AUTHORITY_SCRIPT="${O3K_P15_7_KEYCLOAK_AUTHORITY_SCRIPT:-$ROOT_DIR/scripts/p15-7-keycloak-authority.sh}"
[[ -n "$TOKEN_FILE" && -f "$TOKEN_FILE" && ! -L "$TOKEN_FILE" \
  && -n "$CURL_CONFIG" && "$CURL_CONFIG" != *..* && ! -L "$CURL_CONFIG" \
  && -x "$AUTHORITY_SCRIPT" && ! -L "$AUTHORITY_SCRIPT" ]] \
  || { echo "P15.7 authority refresh: owned token/config/driver unavailable" >&2; exit 2; }

remaining="$(python3 - "$TOKEN_FILE" <<'PY' 2>/dev/null || true
import base64, json, pathlib, sys, time
parts = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8').strip().split('.')
if len(parts) != 3:
    raise SystemExit(0)
claims = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
print(int(claims.get('exp', 0)) - int(time.time()))
PY
)"
if [[ "$remaining" =~ ^[0-9]+$ ]] && (( remaining > 300 )); then
  exit 0
fi

O3K_P15_7_AUTHORITY_MODE=testlab-keycloak \
  O3K_P15_7_KEYCLOAK_STATE_ROOT="${O3K_P15_7_KEYCLOAK_STATE_ROOT:-${RUNNER_TEMP:-/tmp}/o3k-p15-7-keycloak-${GITHUB_RUN_ID:-local-$$}}" \
  O3K_P15_7_NATIVE_API_URL="${O3K_P15_7_NATIVE_API_URL:?}" \
  O3K_P15_7_AUTHORITY_OUTPUT_FILE="$TOKEN_FILE" \
  GITHUB_RUN_ID="${GITHUB_RUN_ID:-local-$$}" \
  O3K_P15_7_SOURCE_SHA="${O3K_P15_7_SOURCE_SHA:-${GITHUB_SHA:-}}" \
  bash "$AUTHORITY_SCRIPT" exchange \
  || { echo "P15.7 authority refresh: canonical federation exchange failed" >&2; exit 1; }

token="$(<"$TOKEN_FILE")"
[[ -n "$token" && "$token" != *$'\n'* ]] \
  || { echo "P15.7 authority refresh: renewed token is empty" >&2; exit 1; }
umask 077
config_tmp="$(mktemp "${CURL_CONFIG}.XXXXXX")"
cleanup() {
  if [[ -n "${config_tmp:-}" && -f "$config_tmp" && ! -L "$config_tmp" ]]; then
    if command -v shred >/dev/null 2>&1; then
      shred --remove --zero --force -- "$config_tmp" >/dev/null 2>&1 || rm -f -- "$config_tmp"
    else
      rm -f -- "$config_tmp"
    fi
  fi
}
trap cleanup EXIT
printf 'header = "Authorization: Bearer %s"\n' "$token" >"$config_tmp"
chmod 0600 "$config_tmp"
mv -f -- "$config_tmp" "$CURL_CONFIG"
config_tmp=""
