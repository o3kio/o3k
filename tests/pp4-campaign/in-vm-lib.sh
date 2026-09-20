#!/usr/bin/env bash
# PP.4 campaign — shared in-VM helpers (sourced by the phase scripts).
set -Eeuo pipefail

log() { echo "[$(date -u +%H:%M:%SZ)] $*"; }

# Every acceptance case records the phase it came from: scenario C (phase1b)
# and the cleanup matrix (phase2) both use C1..C6, and the durable manifest
# must be able to require each phase's own set rather than a union that one
# phase could accidentally satisfy.
_pp4_phase() { printf '%s' "${PP4_PHASE:-unknown}"; }

_pp4_json() { python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$1"; }

case_ok()  { printf '{"id":%s,"phase":%s,"name":%s,"status":"PASS","ts":%s}\n' \
  "$(_pp4_json "$1")" "$(_pp4_json "$(_pp4_phase)")" "$(_pp4_json "$2")" "$(date +%s)" >> "$EVID/cases.jsonl"; }
case_fail() { printf '{"id":%s,"phase":%s,"name":%s,"status":"FAIL","ts":%s}\n' \
  "$(_pp4_json "$1")" "$(_pp4_json "$(_pp4_phase)")" "$(_pp4_json "$2")" "$(date +%s)" >> "$EVID/cases.jsonl"; }

# die records a FAIL case first, so a crash never loses the failing check.
die() {
  log "ERROR: $*"
  [ -n "${CURRENT_CASE:-}" ] && case_fail "$CURRENT_CASE" "$CURRENT_NAME: $*" || true
  echo "PP4-ERROR: $*" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

# Fail-closed phase trap. A crashed phase must never leave the host polling
# for its full budget: record a FAIL case and write the phase-done marker with
# status=failed so host-run sees the real marker immediately.
# Usage: pp4_install_phase_trap phase1a "$EVID/phase1a-done" PHASE1A
pp4_install_phase_trap() { # PHASE_ID DONE_MARKER COMPLETE_PREFIX
  PP4_TRAP_PHASE="$1"
  PP4_TRAP_MARKER="$2"
  PP4_TRAP_PREFIX="$3"
  PP4_PHASE_OK=0
  trap 'pp4_phase_on_exit $?' EXIT
}

pp4_phase_on_exit() {
  local rc="$1"
  [ "${PP4_PHASE_OK:-0}" = 1 ] && return 0
  trap - EXIT
  set +e
  case_fail "${PP4_TRAP_PHASE}-ABORT" "${PP4_TRAP_PHASE} aborted before completion (exit=$rc)"
  printf '%s\n' "${PP4_TRAP_PREFIX}-COMPLETE status=failed exit=$rc" > "$PP4_TRAP_MARKER"
  log "${PP4_TRAP_PREFIX} aborted (exit=$rc); wrote $(basename "$PP4_TRAP_MARKER") status=failed"
}

# Mark the phase as intentionally complete (the EXIT trap then stays silent).
pp4_phase_complete() { PP4_PHASE_OK=1; }

STATE_DIR=/var/lib/o3k/araf-demo
DEMO_CA="$STATE_DIR/tls/ca.crt"

# curl against the demo surfaces (demo-CA verified).
pcurl() { curl -sf --cacert "$DEMO_CA" "$@"; }

# Exact HTTP status of a demo-surface request (never fails closed on the
# request itself; the caller asserts the status it expects).
pcurl_status() { curl -s --cacert "$DEMO_CA" -o /dev/null -w '%{http_code}' "$@"; }

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
  printf '%s\n' "$pw" > "$work/password"
  python3 - "$work/password" "$work/login.form" <<'PY'
import sys
from urllib.parse import urlencode
password = open(sys.argv[1], encoding="utf-8").readline().rstrip("\n")
path = sys.argv[2]
with open(path, "wb") as handle:
    handle.write(urlencode({"username": "alice", "password": password,
                            "credentialId": ""}).encode())
PY
  rm -f "$work/password"
  pcurl -D "$kc_headers" -o /dev/null -c "$jar" -b "$jar" -X POST "$form" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary "@$work/login.form"
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

# Authenticated BFF GET. Non-zero when the request itself fails.
bff_get() { pcurl -H "cookie: ${BFF_COOKIE}; ${BFF_CSRF}" "https://${BFF_HOST}$1"; }

# Authenticated BFF POST (JSON body, CSRF header).
bff_post() { pcurl -H "cookie: ${BFF_COOKIE}; ${BFF_CSRF}" \
  -H "x-csrf-token: ${BFF_CSRF#araf_csrf=}" -H 'content-type: application/json' \
  -X POST "https://${BFF_HOST}$1" ${2:+-d "$2"}; }

bff_delete() { pcurl -H "cookie: ${BFF_COOKIE}; ${BFF_CSRF}" \
  -H "x-csrf-token: ${BFF_CSRF#araf_csrf=}" -X DELETE "https://${BFF_HOST}$1"; }

# Authenticated BFF POST whose EXPECTED outcome is a failure: prints the exact
# HTTP status and writes the response body to $3 (never fails closed on the
# response itself — the caller asserts the status it expects).
bff_post_status() { # PATH JSON_BODY OUT_FILE -> status
  curl -s --cacert "$DEMO_CA" -o "$3" -w '%{http_code}' \
    -H "cookie: ${BFF_COOKIE}; ${BFF_CSRF}" \
    -H "x-csrf-token: ${BFF_CSRF#araf_csrf=}" -H 'content-type: application/json' \
    -X POST "https://${BFF_HOST}$1" -d "$2"
}

# Read-only canonical-store query (one value per line).
sqlite_ro() { # SQL -> lines
  python3 -c '
import sqlite3, sys
c = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
for row in c.execute(sys.argv[1]):
    print("\t".join(str(value) for value in row))
' "$1"
}

# ---------------------------------------------------------------------------
# Classified-gap ledger (`GAP <id> <detail>` lines, consumed by make-manifest.py)
#
# A classified gap records an OBSERVED, verified limitation of this product
# profile. It is evidence — never a PASS for behaviour that did not happen.
# ---------------------------------------------------------------------------
pp4_gaps_reset() { : > "${EVID:?}/35-classified-gaps.txt"; }

record_gap() { # ID DETAIL
  local id="$1" detail="${2:-}"
  printf 'GAP %s %s\n' "$id" "$detail" >> "${EVID:?}/35-classified-gaps.txt"
  log "classified gap: ${id} ${detail}"
}

# libvirt boot proof. O3K domains are named o3k-<sha256(server_id)[0:20]> and
# carry no <uuid>, so `virsh domstate <server-uuid>` can never match. The
# authoritative lookup (tests/p13_7_real_host_iac_acceptance.sh) enumerates
# every domain and matches the run ownership marker in its XML instead.
# Returns 0 only when a domain with server_id="<id>" + managed_by="o3k-compute"
# exists AND its state is running; any failure is "not proven" (fail closed).
libvirt_domain_running_for() { # SERVER_ID
  local server_id="${1:-}" candidate xml state
  [ -n "$server_id" ] || return 1
  command -v virsh >/dev/null 2>&1 || return 1
  for candidate in $(virsh -c qemu:///system list --all --name 2>/dev/null); do
    [ -n "$candidate" ] || continue
    xml="$(virsh -c qemu:///system dumpxml "$candidate" 2>/dev/null)" || continue
    if grep -Fq "server_id=\"${server_id}\"" <<<"$xml" \
        && grep -Fq 'managed_by="o3k-compute"' <<<"$xml"; then
      state="$(virsh -c qemu:///system domstate "$candidate" 2>/dev/null)" || return 1
      [ "$state" = running ] && return 0
      return 1
    fi
  done
  return 1
}

# Resolve the run-owned libvirt domain name for a server (empty when absent).
libvirt_domain_name_for() { # SERVER_ID
  local server_id="${1:-}" candidate xml
  [ -n "$server_id" ] || return 1
  for candidate in $(virsh -c qemu:///system list --all --name 2>/dev/null); do
    [ -n "$candidate" ] || continue
    xml="$(virsh -c qemu:///system dumpxml "$candidate" 2>/dev/null)" || continue
    if grep -Fq "server_id=\"${server_id}\"" <<<"$xml" \
        && grep -Fq 'managed_by="o3k-compute"' <<<"$xml"; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

# Secret-pattern scan of a file: returns 1 (fail) when a pattern matches.
# Patterns cover O3K/OIDC token shapes, JWTs, bearer credentials, URL-embedded
# credentials, client secrets, session keys, passwords, private keys,
# enrollment/bootstrap secrets.
secret_scan_file() {
  local f="$1"
  grep -Ein 'BEGIN (RSA|EC|OPENSSH|PGP)? ?PRIVATE KEY' "$f" && return 1
  grep -Ein '(access_token|refresh_token|id_token|client_secret|session_store_key|bootstrap_secret|enrollment_token)["=: ]+[A-Za-z0-9._~+/-]{16,}' "$f" && return 1
  # JWT compact serialization and bearer headers.
  grep -Ein 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}' "$f" && return 1
  grep -Ein '(^|[^A-Za-z])(authorization|bearer)[":= ]+["'"'"']?bearer [A-Za-z0-9._~+/-]{16,}' "$f" && return 1
  grep -Ein 'bearer [A-Za-z0-9._~+/-]{20,}' "$f" && return 1
  # Credentials embedded in a URL (scheme://user:password@host).
  grep -Ein '://[A-Za-z0-9._%-]+:[^@/[:space:]"'"'"']{6,}@' "$f" && return 1
  grep -Ein '(O3K_BOOTSTRAP_SECRET|O3K_ENROLLMENT_TOKEN|ARAF_SESSION_STORE_KEY|TENANT_CLIENT_SECRET|OPERATOR_CLIENT_SECRET|KEYCLOAK_ADMIN_PASSWORD|ALICE_PASSWORD)=["'"'"']?[A-Za-z0-9]{12,}' "$f" && return 1
  return 0
}
