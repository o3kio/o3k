#!/usr/bin/env bash
# PP.4 campaign — shared in-VM helpers (sourced by the phase scripts).
set -Eeuo pipefail

log() { echo "[$(date -u +%H:%M:%SZ)] $*"; }

# Append one acceptance case to the durable evidence ledger.
case_ok()  { printf '{"id":%s,"name":%s,"status":"PASS","ts":%s}\n' \
  "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$1")" \
  "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$2")" \
  "$(date +%s)" >> "$EVID/cases.jsonl"; }
case_fail() { printf '{"id":%s,"name":%s,"status":"FAIL","ts":%s}\n' \
  "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$1")" \
  "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$2")" \
  "$(date +%s)" >> "$EVID/cases.jsonl"; }

# die records a FAIL case first, so a crash never loses the failing check.
die() {
  log "ERROR: $*"
  [ -n "${CURRENT_CASE:-}" ] && case_fail "$CURRENT_CASE" "$CURRENT_NAME: $*" || true
  echo "PP4-ERROR: $*" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

STATE_DIR=/var/lib/o3k/araf-demo
DEMO_CA="$STATE_DIR/tls/ca.crt"

# curl against the demo surfaces (demo-CA verified).
pcurl() { curl -sf --cacert "$DEMO_CA" "$@"; }

# Real OIDC login against an Araf surface (tenant|operator) via the BFF.
# Mirrors packaging/o3k-araf-demo.sh browser_login: authorization-code+PKCE,
# session cookie + CSRF double submit, no token material in the jar.
# Sets BFF_COOKIE / BFF_CSRF / BFF_HOST.
araf_login() {
  local surface="$1" host
  case "$surface" in
    tenant) host="tenant.o3k.demo" ;;
    operator) host="operator.o3k.demo" ;;
    *) die "bad surface" ;;
  esac
  local pw
  pw="$(awk -F': ' '/^password:/{print $2}' "$STATE_DIR/credentials.txt" 2>/dev/null || true)"
  [ -n "$pw" ] || die "credentials file unreadable"
  local work jar headers html kc_headers cb_headers
  work="$(mktemp -d)"; jar="$work/jar"; headers="$work/h"; html="$work/a.html"
  kc_headers="$work/k.h"; cb_headers="$work/c.h"
  pcurl -D "$headers" -o /dev/null "https://${host}/api/v1/auth/login"
  local auth_url form callback status
  auth_url="$(sed -n 's/^Location: //Ip' "$headers" | tr -d '\r' | head -1)"
  [ -n "$auth_url" ] || { rm -rf "$work"; die "${surface}: no OIDC redirect"; }
  pcurl -c "$jar" -b "$jar" "$auth_url" -o "$html"
  form="$(python3 - "$html" "$auth_url" <<'PY'
import re, sys
from urllib.parse import urljoin
html = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'<form[^>]+action=["\x27]([^"\x27]+)', html, re.IGNORECASE)
print(urljoin(sys.argv[2], m.group(1).replace("&amp;", "&")) if m else "")
PY
)"
  [ -n "$form" ] || { rm -rf "$work"; die "${surface}: keycloak form missing"; }
  pcurl -D "$kc_headers" -o /dev/null -c "$jar" -b "$jar" -X POST "$form" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode username=alice --data-urlencode "password=${pw}" \
    --data-urlencode credentialId=
  callback="$(sed -n 's/^Location: //Ip' "$kc_headers" | tr -d '\r' | head -1)"
  [ -n "$callback" ] || { rm -rf "$work"; die "${surface}: no callback redirect"; }
  status="$(curl -s --cacert "$DEMO_CA" -o /dev/null -w '%{http_code}' -D "$cb_headers" \
    -c "$jar" -b "$jar" "$callback")"
  case "$status" in 302|303) ;; *) rm -rf "$work"; die "${surface}: callback rejected ($status)" ;; esac
  local cookie_name="araf_${surface}_session"
  BFF_COOKIE="${cookie_name}=$(sed -n "s/^Set-Cookie: ${cookie_name}=\([^;]*\).*/\1/Ip" "$cb_headers" | head -1)"
  BFF_CSRF="araf_csrf=$(sed -n 's/^Set-Cookie: araf_csrf=\([^;]*\).*/\1/Ip' "$cb_headers" | head -1)"
  BFF_HOST="$host"
  rm -rf "$work"
  [ "${BFF_COOKIE}" != "${cookie_name}=" ] || die "${surface}: session cookie missing"
}

# Authenticated BFF GET.
bff_get() { pcurl -H "cookie: ${BFF_COOKIE}; ${BFF_CSRF}" "https://${BFF_HOST}$1"; }

# Authenticated BFF POST (JSON body, CSRF header).
bff_post() { pcurl -H "cookie: ${BFF_COOKIE}; ${BFF_CSRF}" \
  -H "x-csrf-token: ${BFF_CSRF#araf_csrf=}" -H 'content-type: application/json' \
  -X POST "https://${BFF_HOST}$1" ${2:+-d "$2"}; }

bff_delete() { pcurl -H "cookie: ${BFF_COOKIE}; ${BFF_CSRF}" \
  -H "x-csrf-token: ${BFF_CSRF#araf_csrf=}" -X DELETE "https://${BFF_HOST}$1"; }

# Secret-pattern scan of a file: returns 1 (fail) when a pattern matches.
# Patterns cover O3K/OIDC token shapes, client secrets, session keys,
# passwords, private keys, enrollment/bootstrap secrets.
secret_scan_file() {
  local f="$1"
  grep -Ein 'BEGIN (RSA|EC|OPENSSH|PGP)? ?PRIVATE KEY' "$f" && return 1
  grep -Ein '(access_token|refresh_token|id_token|client_secret|session_store_key|bootstrap_secret|enrollment_token)["=: ]+[A-Za-z0-9._~+/-]{16,}' "$f" && return 1
  grep -Ein '(O3K_BOOTSTRAP_SECRET|O3K_ENROLLMENT_TOKEN|ARAF_SESSION_STORE_KEY|TENANT_CLIENT_SECRET|OPERATOR_CLIENT_SECRET|KEYCLOAK_ADMIN_PASSWORD|ALICE_PASSWORD)=["'"'"']?[A-Za-z0-9]{12,}' "$f" && return 1
  return 0
}
