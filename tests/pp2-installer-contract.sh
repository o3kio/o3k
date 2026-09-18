#!/usr/bin/env bash
# pp2-installer-contract.sh — PP.2 (#971) canonical-bootstrap installer
# contract validation.
#
# Static contract checks plus one functional test, all against the exact
# shipped text of the installer scripts (no execution of the installer
# itself, no system mutation, no root required):
#   - packaging/get-o3k.sh orchestrates the canonical P15.6 bootstrap: it
#     invokes `o3k init` AND `o3k join --token`, defers the compute start to
#     install.sh, contains NO direct durable-store mutation (no sqlite / no
#     INSERT INTO), parses /etc/o3k/o3kd.env, and never prints the bootstrap
#     secret or the enrollment token;
#   - scripts/generate-passwords.sh emits O3K_BOOTSTRAP_SECRET and preserves
#     it byte-identically across regenerations (functional, temp dir);
#   - packaging/bootstrap-testlab.sh fails closed via
#     require_canonical_bootstrap on the create path BEFORE any image
#     creation (teardown unaffected), and its temporary clouds.yaml pins the
#     image/network endpoint overrides;
#   - packaging/install.sh accepts --defer-compute-start and then enables
#     o3k-compute.service without --now (the wrapper starts it after the
#     canonical join).
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$ROOT_DIR/packaging/get-o3k.sh"
PASSWORDGEN="$ROOT_DIR/scripts/generate-passwords.sh"
BOOTSTRAP="$ROOT_DIR/packaging/bootstrap-testlab.sh"
INSTALL_SH="$ROOT_DIR/packaging/install.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-pp2-contract.XXXXXX")"
PASS=0
FAIL=0

cleanup() { rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT

record_pass() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
record_fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

check_grep() { # check_grep DESC PATTERN FILE [-F|-E]
  local desc="$1" pattern="$2" file="$3" mode="${4:--F}"
  if grep "$mode" -q -- "$pattern" "$file" 2>/dev/null; then
    record_pass "$desc"
  else
    record_fail "$desc (missing in $file: $pattern)"
  fi
}

check_no_grep() { # check_no_grep DESC PATTERN FILE [-F|-E]
  local desc="$1" pattern="$2" file="$3" mode="${4:--F}"
  if grep "$mode" -q -- "$pattern" "$file" 2>/dev/null; then
    record_fail "$desc (forbidden text present in $file: $pattern)"
  else
    record_pass "$desc"
  fi
}

# ----------------------------------------------------------- get-o3k.sh -----

# Canonical orchestration: the installer is the invoker of the canonical
# init/join workflows (contracts/installer-v1.yaml invoke_canonical_init_join).
check_grep "get-o3k.sh invokes \`o3k init --agent-id\`" \
  'init --agent-id "$AGENT_ID"' "$WRAPPER"
check_grep "get-o3k.sh invokes \`o3k join\`" \
  '"$O3K_BIN" join' "$WRAPPER"
check_grep "get-o3k.sh join is authenticated with --token" \
  '--token "$ENROLLMENT_TOKEN"' "$WRAPPER"
check_grep "get-o3k.sh defers the compute start to install.sh" \
  '--defer-compute-start' "$WRAPPER"
check_grep "get-o3k.sh parses the daemon env file" \
  'ENV_FILE=/etc/o3k/o3kd.env' "$WRAPPER"
check_grep "get-o3k.sh reads scalars from o3kd.env (read_env_scalar)" \
  'read_env_scalar()' "$WRAPPER"

# Authority boundary: orchestration only, never a direct durable-store write.
check_no_grep "get-o3k.sh contains no sqlite access" \
  'sqlite' "$WRAPPER" -i
check_no_grep "get-o3k.sh contains no INSERT INTO" \
  'INSERT[[:space:]]+INTO' "$WRAPPER" -E
check_no_grep "get-o3k.sh contains no o3k.sqlite reference" \
  'o3k\.sqlite' "$WRAPPER" -E

# Secret hygiene: no printf/echo/step/die statement may reference the
# bootstrap secret or the enrollment token (passing them via env to `o3k
# init` is the canonical mechanism and is not a print).
if grep -nE '(printf|echo|step|die)[^#]*(\$|\$\{)(BOOTSTRAP_SECRET|ENROLLMENT_TOKEN)' \
    "$WRAPPER" >"$WORK_DIR/secret-print.txt" 2>/dev/null; then
  record_fail "get-o3k.sh prints a secret ($(head -n1 "$WORK_DIR/secret-print.txt"))"
else
  record_pass "get-o3k.sh never prints the bootstrap secret or enrollment token"
fi

# ---------------------------------------------- generate-passwords.sh -------

PW_FILE="$WORK_DIR/o3kd.env"
gen_out_1="$(O3K_PASSWORD_FILE="$PW_FILE" bash "$PASSWORDGEN")" \
  || { record_fail "generate-passwords.sh first run exited non-zero"; }
if [[ -f "$PW_FILE" && ! -L "$PW_FILE" ]]; then
  record_pass "generate-passwords.sh creates the env file"
else
  record_fail "generate-passwords.sh did not create the env file"
fi
[[ "$(stat -c %a "$PW_FILE" 2>/dev/null || echo absent)" = 600 ]] \
  && record_pass "env file is 0600" \
  || record_fail "env file mode is not 0600"
SECRET_1="$(awk -F= '$1 == "O3K_BOOTSTRAP_SECRET" {print $2; exit}' "$PW_FILE" 2>/dev/null || true)"
if [[ "$SECRET_1" =~ ^[0-9a-f]{64}$ ]]; then
  record_pass "O3K_BOOTSTRAP_SECRET generated as 64 lowercase hex"
else
  record_fail "O3K_BOOTSTRAP_SECRET missing or not 64 lowercase hex"
fi
grep -q '^O3K_BOOTSTRAP_PASSWORD=' "$PW_FILE" \
  && record_pass "O3K_BOOTSTRAP_PASSWORD generated" \
  || record_fail "O3K_BOOTSTRAP_PASSWORD missing"
grep -q '^O3K_TOKEN_SIGNING_KEY=' "$PW_FILE" \
  && record_pass "O3K_TOKEN_SIGNING_KEY generated" \
  || record_fail "O3K_TOKEN_SIGNING_KEY missing"
if [[ -n "$SECRET_1" && "$gen_out_1" != *"$SECRET_1"* ]]; then
  record_pass "generate-passwords.sh never prints the secret"
else
  record_fail "generate-passwords.sh printed the secret (or secret empty)"
fi
O3K_PASSWORD_FILE="$PW_FILE" bash "$PASSWORDGEN" >/dev/null \
  || { record_fail "generate-passwords.sh second run exited non-zero"; }
SECRET_2="$(awk -F= '$1 == "O3K_BOOTSTRAP_SECRET" {print $2; exit}' "$PW_FILE" 2>/dev/null || true)"
[[ -n "$SECRET_1" && "$SECRET_2" = "$SECRET_1" ]] \
  && record_pass "second run preserves the bootstrap secret byte-identically" \
  || record_fail "second run rotated the bootstrap secret"
[[ "$(stat -c %a "$PW_FILE" 2>/dev/null || echo absent)" = 600 ]] \
  && record_pass "env file still 0600 after regeneration" \
  || record_fail "env file mode changed after regeneration"

# ---------------------------------------------- bootstrap-testlab.sh --------

check_grep "bootstrap-testlab.sh defines require_canonical_bootstrap" \
  'require_canonical_bootstrap()' "$BOOTSTRAP"
check_grep "bootstrap-testlab.sh create path enforces the canonical precondition" \
  'require_canonical_bootstrap \' "$BOOTSTRAP"
check_grep "bootstrap-testlab.sh fails closed with a canonical precondition message" \
  'canonical P15.6 bootstrap (o3k init + authenticated o3k join) is not durably ready' "$BOOTSTRAP"
check_grep "bootstrap-testlab.sh temp clouds.yaml pins image_endpoint_override" \
  'image_endpoint_override' "$BOOTSTRAP"
check_grep "bootstrap-testlab.sh temp clouds.yaml pins network_endpoint_override" \
  'network_endpoint_override' "$BOOTSTRAP"
check_grep "bootstrap-testlab.sh temp clouds.yaml pins image_api_version 2" \
  '"image_api_version": "2"' "$BOOTSTRAP"

# Ordering: definition < invocation (create path) < first image creation, and
# the invocation sits AFTER the teardown branch (teardown stays unaffected).
def_line="$(grep -nF 'require_canonical_bootstrap()' "$BOOTSTRAP" | cut -d: -f1)"
call_line="$(grep -nF 'require_canonical_bootstrap \' "$BOOTSTRAP" | cut -d: -f1)"
image_line="$(grep -nF 'openstack image create' "$BOOTSTRAP" | head -n1 | cut -d: -f1)"
teardown_branch_line="$(grep -nF 'if [[ $TEARDOWN -eq 1 ]]; then' "$BOOTSTRAP" | cut -d: -f1)"
if [[ -n "$def_line" && -n "$call_line" && -n "$image_line" ]] \
  && (( def_line < call_line )) && (( call_line < image_line )); then
  record_pass "require_canonical_bootstrap defined before invoked before image creation (def=$def_line call=$call_line image=$image_line)"
else
  record_fail "require_canonical_bootstrap ordering wrong (def=$def_line call=$call_line image=$image_line)"
fi
if [[ -n "$teardown_branch_line" && -n "$call_line" ]] \
  && (( teardown_branch_line < call_line )); then
  record_pass "teardown branch precedes the canonical precondition (teardown unaffected)"
else
  record_fail "teardown branch does not precede the canonical precondition"
fi

# --------------------------------------------------------- install.sh -------

check_grep "install.sh accepts --defer-compute-start" \
  '--defer-compute-start) DEFER_COMPUTE_START=1; shift;;' "$INSTALL_SH"
check_grep "install.sh deferred mode enables o3k-compute.service WITHOUT --now" \
  'systemctl enable o3k-compute.service' "$INSTALL_SH"
check_grep "install.sh non-deferred mode keeps enable --now" \
  'systemctl enable --now o3k-compute.service' "$INSTALL_SH"
# The exact line shape: the deferred branch must call bare `enable` (no --now).
if grep -A2 'if \[\[ "$DEFER_COMPUTE_START" -eq 1 \]\]; then' "$INSTALL_SH" \
    | grep -Fqx '      systemctl enable o3k-compute.service'; then
  record_pass "deferred branch runs the exact bare-enable line"
else
  record_fail "deferred branch does not run the exact bare-enable line"
fi

printf 'pp2 installer contract: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
