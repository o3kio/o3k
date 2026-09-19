#!/usr/bin/env bash
# PP.3 (#972) Araf demo deployment contract tests.
#
# Static + functional checks that the pinned compatibility tuple and the
# demo deployment mechanism cannot drift into unsupported shapes:
#   - tuple schema completeness and digest pinning
#   - script constants == tuple digests (single source of truth)
#   - no floating tags, no fixture mode, no target compilation
#   - preflight-before-mutation, lifecycle fencing, secret-safe output
#   - release-only artifacts (no source build on target)
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

pass=0 fail=0
ok()   { pass=$((pass + 1)); }
bad()  { printf 'PP3 CONTRACT FAIL: %s\n' "$*" >&2; fail=$((fail + 1)); }
check() { # check DESCRIPTION CONDITION...
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok; else bad "${desc}"; fi
}
check_grep()     { check "expected present: $2"        grep -qF "$2" "$1"; }
check_no_grep()  { check "must be absent: $1 <= $2"    sh -c "! grep -qF '$2' '$1'"; }

SCRIPT="packaging/o3k-araf-demo.sh"
COMPOSE="packaging/araf-demo/compose.yaml"
REALM="packaging/araf-demo/realm.json"
NGINX="packaging/araf-demo/nginx.conf"
TUPLE="contracts/araf-compatibility-v1.yaml"
PROFILE="compatibility/product-profiles.yaml"

# --- tuple schema ----------------------------------------------------------
check_grep "${TUPLE}" "pp3_tuple:"
check_grep "${TUPLE}" "status: pinned-evidence-backed"
check_grep "${TUPLE}" "tracking_issue: 972"
for field in version source_sha release_asset_identity; do
  check_grep "${TUPLE}" "    ${field}:"
done
for artifact in bff_digest tenant_console_digest operator_console_digest keycloak_digest nginx_unprivileged_digest; do
  check_grep "${TUPLE}" "${artifact}: sha256:"
done
for artifact in bff tenant_console operator_console; do
  check_grep "${TUPLE}" "${artifact}_platform_digest: sha256:"
  check_grep "${TUPLE}" "${artifact}_config_digest: sha256:"
  check_grep "${TUPLE}" "${artifact}_oci_tarball_sha256: "
done
check_grep "${TUPLE}" "artifact_distribution:"
check_grep "${TUPLE}" "local_verification_tag: o3k-demo-v1.0.0-rc.12"
check_grep "${TUPLE}" "missing_record_fails_closed: true"
check_grep "${TUPLE}" "floating_tag_rejected: true"
check_grep "${TUPLE}" "o3k_readiness_independent_of_araf: true"
check_grep "${TUPLE}" "fixture_mode_rejected_in_production_profile: true"
check_grep "${TUPLE}" "mechanism: docker-compose-v2"
check "no floating tag as compatibility authority" \
  sh -c "! grep -E '^\s+(bff|tenant_console|operator_console)_digest:.*(latest|main|stable|edge)\b' '${TUPLE}'"

# script constants must equal tuple digests (drift guard)
for pair in \
  "ARAF_BFF_DIGEST" "ARAF_TENANT_CONSOLE_DIGEST" "ARAF_OPERATOR_CONSOLE_DIGEST" \
  "KEYCLOAK_DIGEST" "NGINX_DIGEST"; do
  script_val="$(sed -n "s/^${pair}=\"\(sha256:[a-f0-9]*\)\"/\1/p" "${SCRIPT}")"
  check "script ${pair} matches tuple digest" \
    sh -c "[ -n '${script_val}' ] && grep -qF '${script_val}' '${TUPLE}'"
done
for pair in \
  "ARAF_BFF_CONFIG_DIGEST" "ARAF_TENANT_CONSOLE_CONFIG_DIGEST" "ARAF_OPERATOR_CONSOLE_CONFIG_DIGEST"; do
  script_val="$(sed -n "s/^${pair}=\"\(sha256:[a-f0-9]*\)\"/\1/p" "${SCRIPT}")"
  check "script ${pair} matches tuple" \
    sh -c "[ -n '${script_val}' ] && grep -qF '${script_val}' '${TUPLE}'"
done
for pair in \
  "ARAF_BFF_TAR_SHA256" "ARAF_TENANT_CONSOLE_TAR_SHA256" "ARAF_OPERATOR_CONSOLE_TAR_SHA256"; do
  script_val="$(sed -n "s/^${pair}=\"\([a-f0-9]*\)\"/\1/p" "${SCRIPT}")"
  check "script ${pair} matches tuple" \
    sh -c "[ -n '${script_val}' ] && grep -qF '${script_val}' '${TUPLE}'"
done

# --- deployment mechanism --------------------------------------------------
check_grep "${COMPOSE}" "ARAF_RUNTIME_PROFILE: production"
check_grep "${COMPOSE}" 'ARAF_UPSTREAM_ADAPTER: ${ARAF_UPSTREAM_ADAPTER'
check_grep "${COMPOSE}" "name: o3k-araf-demo"
check "compose: infra images pinned by digest" \
  sh -c "! grep -E 'image:.*\$\{(KEYCLOAK|NGINX)_[A-Z_]+IMAGE\}[^@]' '${COMPOSE}'"
check "compose: Araf services never pull, use verified local tag" \
  python3 -c "
import re, sys
text = open('${COMPOSE}').read()
n_never = len(re.findall(r'^\s*pull_policy: never', text, re.M))
n_tag = len(re.findall(r'image: \\\${ARAF_[A-Z_]+(?::\?set [^}]*)?}:\\\${LOCAL_IMAGE_TAG(?::\?set [^}]*)?}', text))
sys.exit(0 if n_never == 4 and n_tag == 4 else 1)"
check_grep "${COMPOSE}" "o3k.io/pp-owner: o3k-araf-demo"
check_grep "${COMPOSE}" "127.0.0.1:443:8080"
check "no console/BFF port published on all interfaces" \
  sh -c "! grep -E 'ports: \[[\"'\"'\"']?(8080|8081|5173|5174):' '${COMPOSE}'"
check_grep "${COMPOSE}" "combined-ca.crt:/etc/ssl/certs/ca-certificates.crt:ro"
check_grep "${COMPOSE}" "read_only: true"

# fixture mode / shortcuts forbidden in the demo profile
check_no_grep "${COMPOSE}" "fixture"
check_no_grep "${COMPOSE}" "ARAF_RUNTIME_PROFILE: development"
check_no_grep "${COMPOSE}" "ARAF_RUNTIME_PROFILE: test"
check_no_grep "${SCRIPT}" "cargo "
check_no_grep "${SCRIPT}" "pnpm"
check_no_grep "${SCRIPT}" "npm "
check_no_grep "${SCRIPT}" "docker build"
check_no_grep "${SCRIPT}" "docker prune"
check_no_grep "${SCRIPT}" "compose pull"
check_grep "${SCRIPT}" "digest mismatch after load"
check_grep "${SCRIPT}" "release asset replaced"

# o3k authority boundary: script never fabricates canonical O3K state
for forbidden in "o3k init" "o3k join" "INSERT INTO" "sqlite3 "; do
  check_no_grep "${SCRIPT}" "${forbidden}"
done

# --- lifecycle + fencing ---------------------------------------------------
for sub in install verify status start stop uninstall purge; do
  check_grep "${SCRIPT}" "${sub})"
done
check_grep "${SCRIPT}" "preflight()" # checks before any mutation
check_grep "${SCRIPT}" 'unsupported target'
check_grep "${SCRIPT}" "HOSTS_MARKER"
check_grep "${SCRIPT}" "ENV_BEGIN"
check_grep "${SCRIPT}" "compose down -v"
check_grep "${SCRIPT}" "refusing to purge unexpected state dir"
check_grep "${SCRIPT}" "ownership fencing failure"
check_grep "${SCRIPT}" "ensure_o3kd_federation" # canonical machinery, not fabricated state
check_no_grep "${SCRIPT}" "docker volume prune"
check_no_grep "${SCRIPT}" "docker system prune"
check_no_grep "${SCRIPT}" "rmi"

# --- secrets safety --------------------------------------------------------
# Secrets may only enter compose as ${VAR:?set ...} env interpolations,
# never as literal values (values come from the 0600 --env-file).
check "compose has no literal secret values" \
  sh -c "! grep -E '(PASSWORD|SECRET|_KEY): [^\"\$]' '${COMPOSE}'"
check "realm template secrets are env-substitution placeholders only" \
  sh -c "! grep -E '\"secret\": \"' '${REALM}' | grep -vE '\\\$\\{[A-Z_]+\\}'"
check_grep "${REALM}" '"${TENANT_CLIENT_SECRET}"'
check_grep "${REALM}" "o3k-demo"
check_grep "${NGINX}" "ssl_certificate_key"
check "script never logs secret values" \
  sh -c "! grep -E '^\s*(log|echo) .*(SECRET|PASSWORD|STORE_KEY)' '${SCRIPT}'"
check_grep "${SCRIPT}" "umask 077"

# --- readiness independence ------------------------------------------------
check_grep "${SCRIPT}" "o3kd readiness (independent of Araf)"
check_grep "${SCRIPT}" "BFF->O3K dependency"
check_grep "${TUPLE}" "araf_is_not:"

# --- profile record --------------------------------------------------------
check_grep "${PROFILE}" "araf-client-optional"
check_grep "${PROFILE}" "araf_integration:"
check_grep "${PROFILE}" "araf_demo_tuple:"

# --- functional: realm template is valid JSON --------------------------------
check "realm template valid JSON" python3 -c "import json;json.load(open('${REALM}'))"

# --- functional: script parses and constants resolve ------------------------
check "script has valid bash syntax" bash -n "${SCRIPT}"

echo "PP.3 contract tests: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
