#!/usr/bin/env bash
# PP.4 (#973) Araf demo one-line-installer contract tests.
#
# Static + functional checks that the pinned compatibility tuple and the
# demo deployment mechanism cannot drift into unsupported shapes:
#   - pp3_tuple/pp4_tuple schema completeness and digest pinning (the frozen
#     pp3_tuple drift gates are all retained)
#   - script constants == tuple digests (single source of truth)
#   - no floating tags, no fixture mode, no target compilation
#   - preflight-before-mutation, lifecycle fencing, secret-safe output
#   - release-only artifacts (no source build on target)
#   - PP.4 integration: installer version pin, Debian 12 static docker pins,
#     T3 timing stamp, tuple subcommand, credentials file (written, never
#     printed), installer success block, one-line installer integration
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

pass=0 fail=0
ok()   { pass=$((pass + 1)); }
bad()  { printf 'PP4 CONTRACT FAIL: %s\n' "$*" >&2; fail=$((fail + 1)); }
check() { # check DESCRIPTION CONDITION...
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok; else bad "${desc}"; fi
}
check_grep()     { check "expected present: $2"        grep -qF "$2" "$1"; }
check_no_grep()  { check "must be absent: $1 <= $2"    sh -c "! grep -qF '$2' '$1'"; }

SCRIPT="packaging/o3k-araf-demo.sh"
WRAPPER="packaging/get-o3k.sh"
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

# --- pp4_tuple section (PP.4 #973 one-line installer integration) -------------
check_grep "${TUPLE}" "pp4_tuple:"
check_grep "${TUPLE}" "tracking_issue: 973"
check_grep "${TUPLE}" "one_line_installer_integration: candidate-successor-release-pending-publication"
check_grep "${TUPLE}" "supported_targets: [ubuntu-24.04-x86_64, debian-12-x86_64]"
check_grep "${TUPLE}" "browser_trust: operator-imported demo CA"
# pp4_tuple.araf digests == script constants (same drift gate as pp3)
for pair in \
  "ARAF_BFF_DIGEST" "ARAF_TENANT_CONSOLE_DIGEST" "ARAF_OPERATOR_CONSOLE_DIGEST" \
  "KEYCLOAK_DIGEST" "NGINX_DIGEST"; do
  script_val="$(sed -n "s/^${pair}=\"\(sha256:[a-f0-9]*\)\"/\1/p" "${SCRIPT}")"
  check "pp4_tuple ${pair} matches script constant" \
    sh -c "[ -n '${script_val}' ] && sed -n '/^pp4_tuple:/,\$p' '${TUPLE}' | grep -qF '${script_val}'"
done
check_grep "${TUPLE}" "status: candidate-pending-fresh-host-evidence"
check "pp4_tuple does not retain the historical O3K rc.8 pin" \
  sh -c "! sed -n '/^pp4_tuple:/,\$p' '${TUPLE}' | grep -qF 'version: v0.4.0-rc.8'"
check_grep "${TUPLE}" "version: v0.4.0-rc.15"
check_grep "${TUPLE}" "source_sha: null"
check_grep "${TUPLE}" "source_identity_authority: signed-release-manifest"
check_grep "${TUPLE}" "release_asset_identity: github.com/o3kio/o3k/releases/tag/v0.4.0-rc.15"
check "pp4_tuple requires the native IAM API contract" \
  sh -c "sed -n '/^pp4_tuple:/,\$p' '${TUPLE}' | grep -qF 'o3k-native-iam-v1'"

# Araf tuple constants cited by the installer/demo scripts must equal
# pp4_tuple.araf (the values are printed to the operator as demo provenance).
for pair in ARAF_VERSION ARAF_SOURCE_SHA; do
  script_val="$(sed -n "s/^${pair}=\"\([^\"]*\)\"/\1/p" "${SCRIPT}")"
  check "script ${pair} matches pp4_tuple.araf" \
    sh -c "[ -n '${script_val}' ] && sed -n '/^pp4_tuple:/,\$p' '${TUPLE}' | grep -qF '${script_val}'"
done
araf_version_pin="$(sed -n 's/^ARAF_VERSION="\([^"]*\)"/\1/p' "${SCRIPT}")"
check "script LOCAL_IMAGE_TAG derives from ARAF_VERSION" \
  sh -c "grep -q '^LOCAL_IMAGE_TAG=\"o3k-demo-\\\${ARAF_VERSION}\"' '${SCRIPT}'"
check "script LOCAL_IMAGE_TAG resolves to pp4_tuple.local_verification_tag" \
  sh -c "[ -n '${araf_version_pin}' ] && sed -n '/^pp4_tuple:/,\$p' '${TUPLE}' | grep -qF 'o3k-demo-${araf_version_pin}'"
# Docker-engine pins (Debian static path) must be recorded in the contract,
# not only in the script, so a silent swap is a reviewable contract change.
docker_static_version="$(sed -n 's/^DOCKER_STATIC_VERSION="\([^"]*\)"/\1/p' "${SCRIPT}")"
docker_static_sha="$(sed -n 's/^DOCKER_STATIC_SHA256="\([^"]*\)"/\1/p' "${SCRIPT}")"
compose_sha="$(sed -n 's/^COMPOSE_PLUGIN_SHA256="\([^"]*\)"/\1/p' "${SCRIPT}")"
for pin in "${docker_static_version}" "${docker_static_sha}" "${compose_sha}"; do
  check "pp4_tuple records pinned engine value ${pin}" \
    sh -c "[ -n '${pin}' ] && sed -n '/^pp4_tuple:/,\$p' '${TUPLE}' | grep -qF '${pin}'"
done

# --- PP.4 regression guard: the demo must never mutate O3K-owned config ------
# O3K's installer keeps an install-time content ledger for /etc/o3k/o3kd.env and
# refuses to re-run when it changed; a demo-managed block in that file breaks
# one-line-installer convergence (found in PP.4 adversarial review). The demo
# wires federation through a systemd drop-in + its own env file instead.
check "demo script never writes to o3kd.env" \
  sh -c "! grep -Eq '(>>|>) *\\\"?\\\$\{?O3KD_ENV' '${SCRIPT}'"
check "demo script uses the managed drop-in" \
  sh -c "grep -q 'O3KD_DROPIN=' '${SCRIPT}' && grep -q 'EnvironmentFile=-' '${SCRIPT}'"
check "demo uninstall never removes compose orphans" \
  sh -c "! grep -q 'compose down .*--remove-orphans' '${SCRIPT}'"
check "demo fences compose resources by owner label" \
  sh -c "grep -q 'assert_compose_ownership' '${SCRIPT}' && grep -q 'o3k.io/pp-owner' '${SCRIPT}'"
check "demo start and stop fence compose resources" \
  sh -c "grep -A3 '^cmd_start' '${SCRIPT}' | grep -q assert_compose_ownership && grep -A3 '^cmd_stop' '${SCRIPT}' | grep -q assert_compose_ownership"
check "demo refuses to overwrite a colliding local image tag" \
  sh -c "grep -q 'refusing to overwrite foreign state' '${SCRIPT}'"
check "demo verifies the OCI config before loading" \
  sh -c "grep -q 'oci_archive_config_matches' '${SCRIPT}' && grep -q 'OCI archive config digest' '${SCRIPT}'"
check "campaign accepts only a verified source-revision identity on rematerializing engines" \
  sh -c "grep -q 'org.opencontainers.image.revision' 'tests/pp4-campaign/in-vm-phase1a.sh' && grep -q 'source-revision' 'tests/pp4-campaign/in-vm-phase1a.sh'"
check "browser native create submits network_ids as an array" \
  sh -c "grep -q 'JSON.stringify(\[env.networkId\])' 'tests/pp4-browser-e2e/specs/tenant.spec.ts'"
check "demo script keeps a legacy-block migration path" \
  sh -c "grep -q 'legacy_strip_o3kd_env_block' '${SCRIPT}'"
check "federation enable is wrapped in snapshot/rollback" \
  sh -c "grep -q 'snapshot_federation_state' '${SCRIPT}' && grep -q 'restore_federation_state' '${SCRIPT}'"
# Regression guard (rc.7 defect): the federated-subject lookup ran sed against
# the demo env file before ensure_o3kd_federation creates it; with set -e +
# pipefail the missing-file status aborted the whole demo stage silently.
check "subject lookup is guarded against a missing demo env file" \
  sh -c "grep -q 'if \[ -f \"\${O3KD_DEMO_ENV}\" \]' '${SCRIPT}'"
check "keycloak helpers retry with visible status (no silent set -e abort)" \
  sh -c "grep -q 'demo IdP admin API call did not succeed' '${SCRIPT}' && grep -q 'kc_user_id()' '${SCRIPT}'"

# --- PP.4 one-line installer integration (get-o3k.sh) -------------------------
check_grep "${WRAPPER}" 'O3K_INSTALLER_VERSION="v0.4.0-rc.15"'
check_grep "${WRAPPER}" 'pp4_stamp()'
check_grep "${WRAPPER}" 'pp4_stamp T0'
check_grep "${WRAPPER}" 'pp4_stamp T1'
check_grep "${WRAPPER}" 'pp4_stamp T2'
check_grep "${WRAPPER}" 'pp4_stamp T5'
check_grep "${WRAPPER}" 'PP4-TIMESTAMP'
check_grep "${WRAPPER}" 'install-timestamps.env'
check_grep "${WRAPPER}" 'PP4_TIMESTAMPS_FILE='
check_grep "${WRAPPER}" '/usr/local/share/o3k/araf-demo'
check_grep "${WRAPPER}" 'cmp -s'
check "wrapper invokes the demo stage from the verified bundle" \
  sh -c "grep -qF 'bash \"\$BUNDLE_DIR/packaging/o3k-araf-demo.sh\" install' '${WRAPPER}'"
check "wrapper reads the demo tuple via the tuple subcommand" \
  sh -c "grep -qF 'o3k-araf-demo.sh\" tuple' '${WRAPPER}'"
check "wrapper fails closed on demo-stage failure with a retry hint" \
  sh -c "grep -qF 'Araf demo deployment failed' '${WRAPPER}' && grep -qF 'retry the demo stage with' '${WRAPPER}'"
check "wrapper states the readiness it observed, both ways" \
  sh -c "grep -qF 'its control plane is ready' '${WRAPPER}' && grep -qF 'o3kd is NOT ready' '${WRAPPER}'"
# PP.4 success block (what the operator sees)
for token in \
  'O3K demo ready' 'Tenant Console:' 'Operator Console:' 'O3K API:' \
  'CLI configuration:' 'OpenStack compatibility:' 'Uninstall:' \
  'credentials.txt'; do
  check_grep "${WRAPPER}" "${token}"
done
check "wrapper parses under dash (piped to sudo sh -)" dash -n "${WRAPPER}"
# dash -n only catches parse errors; it accepts ${v:1}, $'...' and printf %q
# which then fail at runtime. shellcheck at error severity catches that class.
check "wrapper has no shellcheck error-level findings under POSIX sh" \
  sh -c "command -v shellcheck >/dev/null 2>&1 || exit 0; shellcheck -s sh -S error '${WRAPPER}' >/dev/null 2>&1"
check_no_grep "${WRAPPER}" "cargo "
check_no_grep "${WRAPPER}" "docker build"

# --- PP.4 demo script additions ------------------------------------------------
check_grep "${SCRIPT}" 'O3K_TUPLE_VERSION="v0.4.0-rc.15"'
check_no_grep "${SCRIPT}" 'O3K_TUPLE_SOURCE_SHA'
check_grep "${SCRIPT}" 'ubuntu:24.04|debian:12' # OS preflight accepts both targets
check_grep "${SCRIPT}" 'unsupported target'
check_grep "${SCRIPT}" 'DOCKER_STATIC_VERSION='
check_grep "${SCRIPT}" 'DOCKER_STATIC_SHA256='
check_grep "${SCRIPT}" 'COMPOSE_PLUGIN_VERSION='
check_grep "${SCRIPT}" 'COMPOSE_PLUGIN_SHA256='
check "DOCKER_STATIC_SHA256 is a 64-hex pin" \
  sh -c "grep -Eq '^DOCKER_STATIC_SHA256=\"[0-9a-f]{64}\"' '${SCRIPT}'"
check "COMPOSE_PLUGIN_SHA256 is a 64-hex pin" \
  sh -c "grep -Eq '^COMPOSE_PLUGIN_SHA256=\"[0-9a-f]{64}\"' '${SCRIPT}'"
check_grep "${SCRIPT}" 'download.docker.com/linux/static/stable/x86_64'
check_grep "${SCRIPT}" 'sha256sum -c -'
check_grep "${SCRIPT}" 'docker.service'
check_grep "${SCRIPT}" 'Restart=always'
check_grep "${SCRIPT}" 'libexec/docker/cli-plugins'
check_grep "${SCRIPT}" 'systemctl daemon-reload'
check_grep "${SCRIPT}" 'PP4_TIMESTAMPS_FILE'
check_grep "${SCRIPT}" 'T3_ISO='
check_grep "${SCRIPT}" 'timestamps.env'
check_grep "${SCRIPT}" 'cmd_tuple'
check_grep "${SCRIPT}" 'tuple)'
check_grep "${SCRIPT}" 'ARAF_BFF_DIGEST'
check_grep "${SCRIPT}" 'release-manifest.json'
check "tuple reads O3K side from the installed manifest" \
  sh -c "grep -qF 'O3K_VERSION=' '${SCRIPT}' && grep -qF 'O3K_SOURCE_SHA=' '${SCRIPT}'"
check_grep "${SCRIPT}" 'write_credentials_file'
check_grep "${SCRIPT}" 'credentials.txt'
check "credentials file is written 0600" \
  sh -c "grep -qF 'chmod 600 \"\${f}\"' '${SCRIPT}'"
check "credentials file contents are never printed" \
  sh -c "! grep -Eq '(cat|tail|head|less) .*credentials\\.txt' '${SCRIPT}'"

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
check "every service restarts after host reboot" \
  python3 -c "
import yaml, sys
d = yaml.safe_load(open('${COMPOSE}'))
missing = [n for n, s in d['services'].items() if s.get('restart') != 'unless-stopped']
sys.exit(1 if missing else 0)"
check_grep "${COMPOSE}" "127.0.0.1:443:443"
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
for sub in install verify tuple status start stop uninstall purge; do
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
check_grep "${PROFILE}" "state: not-proven"
check "profile preserves historical v0.4.0-rc.8 integration wording" \
  sh -c "grep -qF 'historically exercised with v0.4.0-rc.8' '${PROFILE}'"

# --- functional: realm template is valid JSON --------------------------------
check "realm template valid JSON" python3 -c "import json;json.load(open('${REALM}'))"

# --- functional: tuple YAML parses and both tuples coexist --------------------
check "tuple contract is valid YAML with pp3+pp4 tuples" \
  python3 -c "
import yaml
d = yaml.safe_load(open('${TUPLE}'))
assert 'pp3_tuple' in d and 'pp4_tuple' in d
assert d['pp3_tuple']['o3k']['version'] == 'v0.4.0-rc.5'
assert d['pp3_tuple']['araf']['version'] == 'v1.0.0-rc.12'
assert d['pp4_tuple']['o3k']['version'] == 'v0.4.0-rc.15'
assert d['pp4_tuple']['o3k']['source_sha'] is None
assert d['pp4_tuple']['o3k']['source_identity_authority'] == 'signed-release-manifest'
assert d['pp4_tuple']['araf']['version'] == 'v1.0.0-rc.15'
assert d['pp4_tuple']['araf']['source_sha'] == 'f0c2a04a671d5edf7711cab63c4f83c49a9170d2'
assert d['pp4_tuple']['araf']['version'] != d['pp3_tuple']['araf']['version']
assert d['pp4_tuple']['contracts']['native_api_version'] == 'o3k-native-iam-v1'"

# --- functional: script parses and constants resolve ------------------------
check "script has valid bash syntax" bash -n "${SCRIPT}"

echo "PP.4 contract tests: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
