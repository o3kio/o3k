#!/usr/bin/env bash
# pp6_c1_install_journey.sh — bounded, non-root evidence for the C1 installer
# journey wiring in packaging/install.sh (issue #1086 C1 phase 2).
#
# The full install requires root and a signed release bundle, so this matrix
# extracts the exact C1 block from the shipped installer text and drives it
# with stubbed `install`/binary functions — the same least-invasive mechanism
# tests/installer-negative.sh uses for the wrapper.  It proves:
#   - the o3k binary selection never treats the source-tree bins/o3k crate
#     directory as an executable;
#   - a C1 release without signed inputs fails closed with the explicit
#     prepare -> offline-sign -> install journey (exit 2);
#   - signed inputs provision through the INSTALLED binary path, and
#     --c1-migrate passes --mode legacy-migration through;
#   - a non-C1 release manifest skips the whole block.
# It fabricates no authenticated installed-release acceptance.

set -u
cd "$(dirname "$0")/.."
ROOT_DIR="$(pwd)"
INSTALL_SH="$ROOT_DIR/packaging/install.sh"
WORK_DIR="$(mktemp -d /tmp/o3k-c1-journey-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok - %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'not ok - %s\n' "$1" >&2; }

bash -n "$INSTALL_SH" && ok "install.sh parses" || { bad "install.sh syntax"; exit 1; }

# ---- extract the shipped C1 block (comment header through its closing fi) ----
BLOCK="$WORK_DIR/c1-block.sh"
sed -n '/^# C1 requires externally supplied signed documents/,/^fi$/p' "$INSTALL_SH" >"$BLOCK"
[[ -s "$BLOCK" ]] && ok "C1 block extracted" || bad "C1 block extraction"

# The /usr/local-only guard is environmental; assert the shipped text, then
# neutralize exactly that line so the behavioral cases can run unprivileged
# against the fixture prefix.
grep -qF '[[ "$PREFIX" == /usr/local ]] || { echo "C1 release requires /usr/local" >&2; exit 1; }' "$BLOCK" \
  && ok "C1 block requires the /usr/local prefix" || bad "prefix guard missing"
BLOCK_BEHAVIORAL="$WORK_DIR/c1-block-behavioral.sh"
sed 's|^  \[\[ "$PREFIX" == /usr/local \]\].*|  : # test neutered prefix guard|' "$BLOCK" >"$BLOCK_BEHAVIORAL"
if cmp -s "$BLOCK" "$BLOCK_BEHAVIORAL"; then
  bad "behavioral block did not neuter the prefix guard"
fi
BLOCK="$BLOCK_BEHAVIORAL"

# ---- fixture layout ----
FAKE_PREFIX="$WORK_DIR/prefix"
mkdir -p "$FAKE_PREFIX/share/o3k" "$FAKE_PREFIX/bin"
cat >"$FAKE_PREFIX/share/o3k/release-manifest.json" <<'JSON'
{"version":"v0.4.0-rc.5","profile_id":"o3k-demo-v1","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_artifact_sha256":"1111111111111111111111111111111111111111111111111111111111111111","schema_version":"1","installation_policy_authority":{"key_id":"policy-key-1","ed25519_public_key":"2222222222222222222222222222222222222222222222222222222222222222"}}
JSON

run_block() {
  # Stubbed environment: PREFIX pointed at the fixture prefix, install
  # operations and the installed binary recorded, never executed for real.
  local log="$1"
  PREFIX="$FAKE_PREFIX" \
  C1_POLICY_INPUT="${C1_POLICY_INPUT:-}" \
  C1_STATE_INPUT="${C1_STATE_INPUT:-}" \
  C1_TRUST_INPUT="${C1_TRUST_INPUT:-}" \
  C1_PREPARE_ONLY="${C1_PREPARE_ONLY:-0}" \
  C1_MIGRATE="${C1_MIGRATE:-0}" \
  O3K_TEST_C1_LOG="$log" \
  bash -c '
    install() { printf "install %s\n" "$*" >>"${O3K_TEST_C1_LOG}"; }
    : >"${O3K_TEST_C1_LOG}"
    source "$1"
  ' _ "$BLOCK" 2>"$log.stderr"
}

# ---- case 0: unneutered block refuses a non-/usr/local prefix ----
BLOCK_ORIG="$WORK_DIR/c1-block.sh"
PREFIX="$FAKE_PREFIX" bash -c 'install() { :; }; source "$1"' _ "$BLOCK_ORIG" 2>"$WORK_DIR/case0.stderr"
status=$?
[[ $status -eq 1 ]] && ok "non-/usr/local prefix refused" || bad "prefix guard exit=$status"
grep -q "C1 release requires /usr/local" "$WORK_DIR/case0.stderr" \
  && ok "prefix refusal message" || bad "prefix refusal message missing"

# ---- installed-binary stub (records invocations; never mutates) ----
cat >"$FAKE_PREFIX/bin/o3k" <<'SH'
#!/usr/bin/env bash
printf "o3k %s\n" "$*" >>"${O3K_TEST_C1_LOG:?}"
SH
chmod +x "$FAKE_PREFIX/bin/o3k"

# ---- case 1: C1 manifest without signed inputs fails closed with the journey ----
: >"$WORK_DIR/case1.log"
set +e
run_block "$WORK_DIR/case1.log"
status=$?
set -e
[[ $status -eq 2 ]] && ok "missing inputs exit 2" || bad "missing inputs exit=$status (want 2)"
grep -q "Two-step journey" "$WORK_DIR/case1.log.stderr" \
  && ok "journey message printed" || bad "journey message missing"
grep -q -- "--c1-prepare-only" "$WORK_DIR/case1.log.stderr" \
  && ok "journey names the prepare step" || bad "prepare step missing"
grep -q -- "--c1-migrate" "$WORK_DIR/case1.log.stderr" \
  && ok "journey names the migration step" || bad "migration step missing"
grep -q -- "--c1-backend" "$WORK_DIR/case1.log.stderr" \
  && ok "journey names the backend selector" || bad "backend selector missing"
if grep -qE "^install " "$WORK_DIR/case1.log"; then
  bad "installations ran without signed inputs"
else
  ok "no installation without signed inputs"
fi

# ---- case 2: signed inputs provision through the installed binary ----
mkdir -p "$WORK_DIR/inputs"
printf 'signed-policy' >"$WORK_DIR/inputs/policy.json"
printf 'signed-state' >"$WORK_DIR/inputs/state.json"
printf 'signed-trust' >"$WORK_DIR/inputs/trust.json"
C1_POLICY_INPUT="$WORK_DIR/inputs/policy.json" \
C1_STATE_INPUT="$WORK_DIR/inputs/state.json" \
C1_TRUST_INPUT="$WORK_DIR/inputs/trust.json" \
C1_MIGRATE=0 \
run_block "$WORK_DIR/case2.log"
status=$?
[[ $status -eq 0 ]] && ok "signed-input run succeeds" || bad "signed-input run exit=$status"
grep -q "install -o root -g o3k -m 0640 $WORK_DIR/inputs/policy.json /etc/o3k/installation-policy.json" "$WORK_DIR/case2.log" \
  && ok "policy installed to fixed path" || bad "policy install line missing"
grep -q "o3k installation-provision --policy $WORK_DIR/inputs/policy.json --state $WORK_DIR/inputs/state.json --trust $WORK_DIR/inputs/trust.json$" "$WORK_DIR/case2.log" \
  && ok "provision invoked with new-install default" || bad "provision invocation wrong"
if grep -q "legacy-migration" "$WORK_DIR/case2.log"; then
  bad "legacy migration mode without --c1-migrate"
else
  ok "no migration mode by default"
fi

# ---- case 3: --c1-migrate forwards legacy-migration mode ----
C1_POLICY_INPUT="$WORK_DIR/inputs/policy.json" \
C1_STATE_INPUT="$WORK_DIR/inputs/state.json" \
C1_TRUST_INPUT="$WORK_DIR/inputs/trust.json" \
C1_MIGRATE=1 \
run_block "$WORK_DIR/case3.log"
grep -q -- "--mode legacy-migration" "$WORK_DIR/case3.log" \
  && ok "--c1-migrate forwards --mode legacy-migration" || bad "migration flag not forwarded"
# The invoked binary must be the INSTALLED path, never the source tree.
first_o3k_line="$(grep -m1 '^o3k ' "$WORK_DIR/case3.log")"
[[ "$first_o3k_line" == o3k\ installation-provision* ]] \
  && ok "provision ran through the installed binary stub" || bad "unexpected binary line: $first_o3k_line"

# ---- case 4: non-C1 manifest skips the whole block ----
cat >"$FAKE_PREFIX/share/o3k/release-manifest.json" <<'JSON'
{"version":"v0.4.0-rc.5","profile_id":"o3k-demo-v1","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":"1"}
JSON
: >"$WORK_DIR/case4.log"
run_block "$WORK_DIR/case4.log"
status=$?
[[ $status -eq 0 ]] && ok "non-C1 manifest skips the block" || bad "non-C1 manifest exit=$status"
if grep -qE "^(install|o3k) " "$WORK_DIR/case4.log"; then
  bad "C1 actions ran for a non-C1 manifest"
else
  ok "no C1 actions for a non-C1 manifest"
fi

# ---- prepare-only hook: extract and exercise the shipped text ----
HOOK="$WORK_DIR/prepare-hook.sh"
sed -n '/^if \[\[ "$C1_PREPARE_ONLY" == 1 \]\]; then$/,/^fi$/p' "$INSTALL_SH" >"$HOOK"
[[ -s "$HOOK" ]] && ok "prepare-only hook extracted" || bad "prepare-only hook extraction"

run_hook() {
  local log="$1"
  PREFIX="$FAKE_PREFIX" \
  DATA_DIR="${DATA_DIR:-/var/lib/o3k}" \
  C1_BACKEND="${C1_BACKEND:-sqlite}" \
  C1_PREPARE_ONLY=1 \
  O3K_TEST_C1_LOG="$log" \
  bash -c '
    : >"${O3K_TEST_C1_LOG}"
    source "$1"
  ' _ "$HOOK" 2>"$log.stderr"
}

# C1 manifest: prepare runs through the installed binary with the backend.
cat >"$FAKE_PREFIX/share/o3k/release-manifest.json" <<'JSON'
{"version":"v0.4.0-rc.5","profile_id":"o3k-demo-v1","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_artifact_sha256":"1111111111111111111111111111111111111111111111111111111111111111","schema_version":"1","installation_policy_authority":{"key_id":"policy-key-1","ed25519_public_key":"2222222222222222222222222222222222222222222222222222222222222222"}}
JSON
set +e
C1_BACKEND=postgresql run_hook "$WORK_DIR/hook1.log"
status=$?
set -e
[[ $status -eq 0 ]] && ok "prepare-only runs for a C1 manifest" || bad "prepare-only exit=$status"
grep -q "o3k recovery-provision-prepare --data-root /var/lib/o3k --backend postgresql" "$WORK_DIR/hook1.log" \
  && ok "prepare invoked via installed binary with --backend" || bad "prepare invocation missing: $(cat "$WORK_DIR/hook1.log")"

# Non-C1 manifest: explicit failure instead of silent success.
cat >"$FAKE_PREFIX/share/o3k/release-manifest.json" <<'JSON'
{"version":"v0.4.0-rc.5","profile_id":"o3k-demo-v1","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":"1"}
JSON
set +e
run_hook "$WORK_DIR/hook2.log"
status=$?
set -e
[[ $status -eq 2 ]] && ok "prepare-only on non-C1 manifest exits 2" || bad "non-C1 prepare-only exit=$status"
grep -q "requires a C1 release" "$WORK_DIR/hook2.log.stderr" \
  && ok "non-C1 refusal message" || bad "non-C1 refusal message missing"

# Missing manifest: explicit failure.
rm -f "$FAKE_PREFIX/share/o3k/release-manifest.json"
set +e
run_hook "$WORK_DIR/hook3.log"
status=$?
set -e
[[ $status -eq 2 ]] && ok "prepare-only without manifest exits 2" || bad "missing-manifest exit=$status"
grep -q "requires an installed release manifest" "$WORK_DIR/hook3.log.stderr" \
  && ok "missing-manifest refusal message" || bad "missing-manifest message missing"

# ---- case 5: source-tree bins/o3k directory is not selected as the binary ----
# In a source tree, $ROOT_DIR/bin/o3k is a crate DIRECTORY; the installer
# must not treat it as the operator CLI binary.
if [[ -d "$ROOT_DIR/bins/o3k" && ! -f "$ROOT_DIR/bins/o3k" ]]; then
  if grep -q 'if \[\[ -f "\$ROOT_DIR/bin/o3k" && -x "\$ROOT_DIR/bin/o3k" \]\]; then' "$INSTALL_SH"; then
    ok "binary selection requires a regular executable file"
  else
    bad "binary selection no longer guards against the crate directory"
  fi
fi

echo "pp6_c1_install_journey: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
