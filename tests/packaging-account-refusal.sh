#!/usr/bin/env bash
# Executable regression tests for the account-reuse refusal logic in
# packaging/install.sh (pre-existing o3k / o3k-compute accounts).
#
# The installer evaluates account reuse only when it runs as root, and the
# checks are bound to the literal account names `o3k` / `o3k-compute`. To
# exercise the real code paths without touching any live `o3k` identities,
# each case builds a private copy of the installer in which every `o3k` token
# is rewritten to a per-case tag (for example `o3kta<PID>`), creates scratch
# accounts and groups under the rewritten names, runs the rewritten installer
# against isolated prefix/data/config/log directories, and verifies both the
# refusal (or acceptance) and the absence of mutated install state. Every
# scratch account, group, and directory is removed on exit, so the test is
# independent and idempotent. The real `o3k` accounts and the pre-existing
# host groups (kvm, libvirt) are never modified.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "skipping account-refusal tests: root is required to create scratch accounts"
  exit 0
fi
for tool in useradd userdel groupadd groupdel getent sed; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "skipping account-refusal tests: missing required tool: $tool"
    exit 0
  fi
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-account-refusal.XXXXXX")"
CREATED_USERS=()
CREATED_GROUPS=()
cleanup() {
  local name
  for name in ${CREATED_USERS[@]+"${CREATED_USERS[@]}"}; do
    if id "$name" >/dev/null 2>&1; then userdel "$name" 2>/dev/null || true; fi
  done
  for name in ${CREATED_GROUPS[@]+"${CREATED_GROUPS[@]}"}; do
    if getent group "$name" >/dev/null 2>&1; then groupdel "$name" 2>/dev/null || true; fi
  done
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

fail() { echo "account-refusal test failed: $*" >&2; exit 1; }

# ensure_group creates the group only when missing; pre-existing host groups
# (kvm, libvirt) are used but never recorded for deletion.
ensure_group() {
  if ! getent group "$1" >/dev/null 2>&1; then
    groupadd --system "$1"
    CREATED_GROUPS+=("$1")
  fi
}

make_user() { # name primary-group home shell [supplementary-group...]
  local name="$1" gid="$2" home="$3" shell="$4"
  shift 4
  local args=(--system --gid "$gid" --home-dir "$home" --shell "$shell" --no-create-home)
  if (($#)); then args+=(--groups "$(IFS=,; echo "$*")"); fi
  useradd "${args[@]}" "$name"
  CREATED_USERS+=("$name")
}

# build_bundle copies install.sh with every `o3k` token rewritten to the
# per-case tag and mirrors the renamed service/rules files the rewritten
# script references. preflight is stubbed: it runs before the account guard
# and is exercised separately in tests/packaging-safety.sh.
build_bundle() { # tag destination
  local tag="$1" dest="$2" helper
  mkdir -p "$dest/packaging" "$dest/scripts" "$dest/bin"
  sed "s/o3k/${tag}/g" "$ROOT_DIR/packaging/install.sh" >"$dest/packaging/install.sh"
  cp "$ROOT_DIR/packaging/o3kd.service" "$dest/packaging/${tag}d.service"
  cp "$ROOT_DIR/packaging/o3k-compute.service" "$dest/packaging/${tag}-compute.service"
  cp "$ROOT_DIR/packaging/50-o3k-libvirt.rules" "$dest/packaging/50-${tag}-libvirt.rules"
  cp "$ROOT_DIR/packaging/backup-trust.example.json" "$dest/packaging/backup-trust.example.json"
  for helper in reset.sh uninstall.sh diagnose.sh bootstrap-certs.sh bootstrap-testlab.sh; do
    cp "$ROOT_DIR/packaging/$helper" "$dest/packaging/$helper"
  done
  printf '#!/usr/bin/env bash\nset -Eeuo pipefail\n' >"$dest/packaging/preflight.sh"
  chmod 0755 "$dest/packaging/preflight.sh"
  cp "$ROOT_DIR/scripts/generate-passwords.sh" "$dest/scripts/generate-passwords.sh"
  # The rewritten installer resolves the o3k doctor binary at bundle
  # bin/<tag> (the rewrite maps bin/o3k); provide the shim so the completed
  # CASE G install never falls back to a cargo build outside the repo.
  printf '#!/usr/bin/env bash\nexit 0\n' >"$dest/bin/$tag"
  chmod 0755 "$dest/bin/$tag"
}

FAKE_BIN_DIR="$WORK_DIR/fake-binaries"
mkdir -p "$FAKE_BIN_DIR"
for name in o3kd o3k-compute; do
  printf '#!/usr/bin/env bash\nexit 0\n' >"$FAKE_BIN_DIR/$name"
  chmod 0755 "$FAKE_BIN_DIR/$name"
done

# setup_tls creates the minimal TLS bundle that passes the libvirt TLS gate,
# which runs before the account guard.
setup_tls() { # config-dir
  local tls="$1/tls" file
  mkdir -p "$tls"
  for file in ca.pem server.pem server-key.pem agent.pem agent-key.pem; do
    printf 'test credential\n' >"$tls/$file"
  done
  printf '%064d\n' 0 >"$tls/agent-fingerprint"
  printf 'compute-agent\n' >"$tls/agent-id"
}

RUN_STATUS=0
RUN_OUTPUT=
run_installer() { # tag case-dir
  local tag="$1" dir="$2"
  if RUN_OUTPUT="$(bash "$WORK_DIR/bundle-$tag/packaging/install.sh" \
      --profile libvirt --noninteractive \
      --binary "$FAKE_BIN_DIR/o3kd" --compute-binary "$FAKE_BIN_DIR/o3k-compute" \
      --prefix "$dir/prefix" --data-dir "$dir/data" \
      --config-dir "$dir/config" --log-dir "$dir/log" 2>&1)"; then
    RUN_STATUS=0
  else
    RUN_STATUS=$?
  fi
}

# A refusal at the account guard happens before any file installation, so no
# install state may exist afterwards: no prefix, no data/log directories, no
# systemd units, and no polkit rule.
assert_no_install_state() { # tag case-dir
  local tag="$1" dir="$2"
  [[ ! -e "$dir/prefix" ]] || fail "prefix was created despite refusal: $dir/prefix"
  [[ ! -e "$dir/data" ]] || fail "data directory was created despite refusal: $dir/data"
  [[ ! -e "$dir/log" ]] || fail "log directory was created despite refusal: $dir/log"
  [[ ! -e "/etc/systemd/system/${tag}d.service" ]] || fail "systemd unit installed for $tag"
  [[ ! -e "/etc/systemd/system/${tag}-compute.service" ]] || fail "compute systemd unit installed for $tag"
  [[ ! -e "/etc/polkit-1/rules.d/50-${tag}-libvirt.rules" ]] || fail "polkit rule installed for $tag"
}

assert_account_refusal() { # tag case-dir message-regex
  local tag="$1" dir="$2" pattern="$3"
  [[ "$RUN_STATUS" -ne 0 ]] || fail "installer accepted a contaminated account for $tag"
  grep -Eq "$pattern" <<<"$RUN_OUTPUT" \
    || fail "unexpected installer output for $tag (status $RUN_STATUS): $RUN_OUTPUT"
  assert_no_install_state "$tag" "$dir"
}

# Scratch identity names are pid-unique; refuse to run if any collides with an
# existing account so a leftover from a killed run is never reused blindly.
for tag in "o3kta$$" "o3ktb$$" "o3ktc$$" "o3ktd1$$" "o3ktd2$$" "o3kte$$" "o3ktf$$"; do
  if id "$tag" >/dev/null 2>&1 || id "${tag}-compute" >/dev/null 2>&1; then
    fail "scratch identity already exists: $tag"
  fi
done

# CASE A — contaminated control user with the kvm host-execution group.
tag="o3kta$$"
build_bundle "$tag" "$WORK_DIR/bundle-$tag"
ensure_group "$tag"
ensure_group kvm
make_user "$tag" "$tag" "/var/lib/$tag" /usr/sbin/nologin kvm
case_dir="$WORK_DIR/case-a"
setup_tls "$case_dir/config"
run_installer "$tag" "$case_dir"
assert_account_refusal "$tag" "$case_dir" \
  "refusing to reuse ${tag} account with (unexpected group|host-execution groups)"
echo "CASE A passed: control user with kvm group refused"

# CASE B — contaminated control user with the libvirt host-execution group.
tag="o3ktb$$"
build_bundle "$tag" "$WORK_DIR/bundle-$tag"
ensure_group "$tag"
ensure_group libvirt
make_user "$tag" "$tag" "/var/lib/$tag" /usr/sbin/nologin libvirt
case_dir="$WORK_DIR/case-b"
setup_tls "$case_dir/config"
run_installer "$tag" "$case_dir"
assert_account_refusal "$tag" "$case_dir" \
  "refusing to reuse ${tag} account with (unexpected group|host-execution groups)"
echo "CASE B passed: control user with libvirt group refused"

# CASE C — control user with an unrelated extra group.
tag="o3ktc$$"
build_bundle "$tag" "$WORK_DIR/bundle-$tag"
ensure_group "$tag"
ensure_group someothergroup
make_user "$tag" "$tag" "/var/lib/$tag" /usr/sbin/nologin someothergroup
case_dir="$WORK_DIR/case-c"
setup_tls "$case_dir/config"
run_installer "$tag" "$case_dir"
assert_account_refusal "$tag" "$case_dir" \
  "refusing to reuse ${tag} account with unexpected group: someothergroup"
echo "CASE C passed: control user with unrelated extra group refused"

# CASE D — wrong account identity: correct name but a foreign home directory
# or a login shell must be treated as an unrelated pre-existing account.
tag="o3ktd1$$"
build_bundle "$tag" "$WORK_DIR/bundle-$tag"
ensure_group "$tag"
make_user "$tag" "$tag" "/home/$tag" /usr/sbin/nologin
case_dir="$WORK_DIR/case-d1"
setup_tls "$case_dir/config"
run_installer "$tag" "$case_dir"
assert_account_refusal "$tag" "$case_dir" \
  "refusing to reuse an unrelated ${tag} account"
echo "CASE D1 passed: control user with wrong home directory refused"

tag="o3ktd2$$"
build_bundle "$tag" "$WORK_DIR/bundle-$tag"
ensure_group "$tag"
make_user "$tag" "$tag" "/var/lib/$tag" /bin/bash
case_dir="$WORK_DIR/case-d2"
setup_tls "$case_dir/config"
run_installer "$tag" "$case_dir"
assert_account_refusal "$tag" "$case_dir" \
  "refusing to reuse an unrelated ${tag} account"
echo "CASE D2 passed: control user with login shell refused"

# CASE E — contaminated compute identity: an otherwise valid compute account
# carrying an unexpected group beyond {compute, libvirt, kvm}.
tag="o3kte$$"
build_bundle "$tag" "$WORK_DIR/bundle-$tag"
ensure_group "$tag"
ensure_group "${tag}-compute"
ensure_group libvirt
ensure_group kvm
ensure_group someothergroup
make_user "$tag" "$tag" "/var/lib/$tag" /usr/sbin/nologin
make_user "${tag}-compute" "${tag}-compute" "/var/lib/$tag/compute" /usr/sbin/nologin \
  libvirt kvm someothergroup
case_dir="$WORK_DIR/case-e"
setup_tls "$case_dir/config"
run_installer "$tag" "$case_dir"
assert_account_refusal "$tag" "$case_dir" \
  "refusing to reuse ${tag}-compute account with unexpected group: someothergroup"
echo "CASE E passed: compute user with unexpected group refused"

# CASE F — legitimate existing identities: correct home/shell and only the
# allowed groups. The installer must NOT refuse at account validation. To
# prove the run passed the account guard without mutating the host further,
# the data directory is pre-populated with foreign state: the next guard
# (ownership marker check) must be the one that stops the install.
tag="o3ktf$$"
build_bundle "$tag" "$WORK_DIR/bundle-$tag"
ensure_group "$tag"
ensure_group "${tag}-compute"
ensure_group libvirt
ensure_group kvm
make_user "$tag" "$tag" "/var/lib/$tag" /usr/sbin/nologin
make_user "${tag}-compute" "${tag}-compute" "/var/lib/$tag/compute" /usr/sbin/nologin \
  libvirt kvm
case_dir="$WORK_DIR/case-f"
setup_tls "$case_dir/config"
mkdir -p "$case_dir/data"
printf 'foreign state\n' >"$case_dir/data/foreign"
run_installer "$tag" "$case_dir"
[[ "$RUN_STATUS" -ne 0 ]] || fail "installer unexpectedly succeeded with foreign data state"
if grep -q 'refusing to reuse' <<<"$RUN_OUTPUT"; then
  fail "legitimate existing identities were refused: $RUN_OUTPUT"
fi
grep -q 'populated unowned directory' <<<"$RUN_OUTPUT" \
  || fail "installer did not reach the post-account-validation stage: $RUN_OUTPUT"
id "$tag" >/dev/null 2>&1 || fail "installer removed the legitimate control account $tag"
id "${tag}-compute" >/dev/null 2>&1 || fail "installer removed the legitimate compute account ${tag}-compute"
[[ ! -e "/etc/systemd/system/${tag}d.service" && ! -e "/etc/systemd/system/${tag}-compute.service" ]] \
  || fail "systemd units installed for $tag"
[[ ! -e "/etc/polkit-1/rules.d/50-${tag}-libvirt.rules" ]] || fail "polkit rule installed for $tag"
echo "CASE F passed: legitimate existing identities accepted past account validation"

# CASE G — a COMPLETED libvirt install must place the compute identity file
# where the agent actually reads it: <compute-data-dir>/agent-id, owned by
# the compute account. Regression: the installer historically wrote it into
# the control data dir only, so the installed agent started without its
# identity and the mTLS registration was always rejected (PermissionDenied),
# leaving the installed profile permanently not-ready.
tag="o3kg$$"
build_bundle "$tag" "$WORK_DIR/bundle-$tag"
ensure_group "$tag"
ensure_group "${tag}-compute"
ensure_group libvirt
ensure_group kvm
make_user "$tag" "$tag" "/var/lib/$tag" /usr/sbin/nologin
make_user "${tag}-compute" "${tag}-compute" "/var/lib/$tag/compute" /usr/sbin/nologin \
  libvirt kvm
case_dir="$WORK_DIR/case-g"
setup_tls "$case_dir/config"
# The real flow lets bootstrap-certs.sh claim the config parent; mirror its
# ownership marker (rewritten like the installer's own tokens, including the
# marker filename) so the installer's config-dir claim succeeds.
printf '%s-owned-v1 path=%s\n' "$tag" "$case_dir/config" >"$case_dir/config/.${tag}-owned"
run_installer "$tag" "$case_dir"
[[ "$RUN_STATUS" -eq 0 ]] || fail "clean libvirt install failed (status $RUN_STATUS): $RUN_OUTPUT"
agent_id_file="$case_dir/data/compute/agent-id"
[[ -f "$agent_id_file" ]] || fail "compute agent identity file is missing: $agent_id_file"
grep -Fxq 'compute-agent' "$agent_id_file" \
  || fail "compute agent identity content is wrong: $(cat "$agent_id_file")"
[[ "$(stat -c '%U:%G' "$agent_id_file")" == "${tag}-compute:${tag}-compute" ]] \
  || fail "compute agent identity ownership is wrong: $(stat -c '%U:%G' "$agent_id_file")"
# Runtime access model: the compute data directory must be group-kvm setgid
# and the control data directory other-executable, so the QEMU process can
# traverse to and read the agent-created overlays (fail-before: the
# installed profile failed at domain start with "Cannot access storage
# file ... Permission denied").
[[ "$(stat -c '%U:%G' "$case_dir/data/compute")" == "${tag}-compute:kvm" ]] \
  || fail "compute data dir ownership is wrong: $(stat -c '%U:%G' "$case_dir/data/compute")"
[[ "$(stat -c '%a' "$case_dir/data/compute")" == "2710" ]] \
  || fail "compute data dir mode is wrong: $(stat -c '%a' "$case_dir/data/compute")"
[[ "$(stat -c '%a' "$case_dir/data")" == "711" ]] \
  || fail "control data dir mode is wrong: $(stat -c '%a' "$case_dir/data")"
[[ -d "$case_dir/data/compute/image-cache/overlays" ]] \
  || fail "image-cache overlay chain was not pre-created"
[[ "$(stat -c '%U:%G %a' "$case_dir/data/compute/image-cache/overlays")" == "${tag}-compute:kvm 2770" ]] \
  || fail "overlay dir ownership/mode is wrong: $(stat -c '%U:%G %a' "$case_dir/data/compute/image-cache/overlays")"
# The compute unit must run with group read/write so agent-created files
# stay QEMU-readable (the fail-before defect was domain start failing with
# "Cannot access storage file ... Permission denied").
grep -q '^UMask=0027$' "$ROOT_DIR/packaging/o3k-compute.service" \
  || fail "compute unit must use UMask=0027"
# A reinstall must preserve the QEMU access model on pre-existing runtime
# files: simulate an agent-created file and prove its group survives the
# reinstall as kvm (the fail-before defect chowned the subtree back to the
# compute account and broke every create after reset+reinstall).
printf 'sentinel\n' >"$case_dir/data/compute/sentinel"
chown "${tag}-compute:${tag}-compute" "$case_dir/data/compute/sentinel"
chmod 0640 "$case_dir/data/compute/sentinel"
run_installer "$tag" "$case_dir"
[[ "$RUN_STATUS" -eq 0 ]] || fail "reinstall failed (status $RUN_STATUS): $RUN_OUTPUT"
[[ "$(stat -c '%U:%G %a' "$case_dir/data/compute/sentinel")" == "${tag}-compute:kvm 640" ]] \
  || fail "reinstall reset the QEMU group on runtime files: $(stat -c '%U:%G %a' "$case_dir/data/compute/sentinel")"
rm -f "/etc/systemd/system/${tag}d.service" "/etc/systemd/system/${tag}-compute.service" \
  "/etc/polkit-1/rules.d/50-${tag}-libvirt.rules" 2>/dev/null || true
echo "CASE G passed: installed compute identity is placed for the agent"

echo "packaging account-refusal tests passed"
