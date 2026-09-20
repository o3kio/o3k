#!/usr/bin/env bash
# installer-negative.sh — portable negative matrix for the one-line installer
# path (issue #613, goal §16). No KVM required.
#
# Coverage — every destructive/foreign-state case must FAIL CLOSED:
#   - platform guard (kernel/arch/distro) and the ADR-0130 version fence,
#     exercised against the wrapper's OWN function definitions (sed-extracted,
#     run in subshells with faked inputs — packaging/get-o3k.sh hardcodes
#     /etc/os-release and has no self-test flag, so extraction is the least
#     invasive mechanism and tests the exact shipped text);
#   - full-wrapper aborts driven through a local python3 http endpoint and a
#     shim bundle: release endpoint unreachable, O3K_VERSION override wins over
#     the baked pin, missing release asset (404), corrupted archive, wrong
#     SHA-256 (abort BEFORE extraction), malformed bundle, unsafe extraction
#     ("../" and absolute entries, plus symlink and device/fifo entries
#     rejected from the `tar -tvzf` listing), preflight failure, foreign
#     install path pass-through, interrupted installer (trap cleanup),
#     interrupted bootstrap, TLS partial-set fail-closed, TLS complete-set
#     skip-and-preserve, converged second run, and a first-run success
#     control that proves the BAKED default version (no O3K_VERSION, no pin
#     line) resolves to the pinned v0.4.0-rc.9 release asset path;
#   - upgrade fence (issue #626): installed version newer than the resolved
#     target -> implicit-downgrade refusal (exit 1, nothing mutated,
#     nothing downloaded); installed version older -> verified delegation
#     download (tarball + .sha256 + install.sh) into the upgrade-download
#     directory, the exact `sudo .../bin/o3k upgrade` notice, exit 0, and no
#     service/binary mutation; delegation re-run reuses the verified tarball;
#     a tampered delegated tarball fails closed. The fence runs before apt
#     and before any bundled script, so curl|sh never auto-upgrades an
#     existing install.
#
# Version model under test: packaging/get-o3k.sh never consults a channel
# service — it resolves O3K_VERSION env > O3K_PINNED_VERSION (optional
# endpoint first line) > the baked O3K_INSTALLER_VERSION pin. This matrix
# drives the wrapper directly through the O3K_RELEASE_BASE override; the
# channel/version endpoint machinery belongs to the optional Worker
# (packaging/get-o3k-worker/) and is tested by its own node test suite.
#
# Not duplicated here (owned by existing tests): the /dev/kvm, libvirt, and
# disk-space checks live in packaging/preflight.sh and are exercised by
# tests/packaging-safety.sh plus the real-VM campaigns — this test proves the
# wrapper aborts when preflight fails; foreign o3k/o3k-compute accounts,
# systemd units, and polkit rules are fenced by packaging/install.sh and
# proven by tests/packaging-safety.sh and tests/packaging-account-refusal.sh;
# the installer's foreign-populated-path fence is proven by
# tests/packaging-safety.sh.
#
# Fixture note: every script in the shim bundle and every executable in the
# shim bin dir is a labeled TEST FIXTURE that only records its invocation —
# nothing real is installed, enabled, or started. All fixtures live under a
# private mktemp tree and are deleted by the exit trap. Root-only sections
# (full wrapper runs, /etc/o3k TLS fixtures) are guarded and SKIP with an
# explicit message otherwise, like tests/packaging-safety.sh.
#
# Canonical bootstrap emulation (PP.2 #971): the success/converge paths run
# the wrapper's REAL canonical P15.6 sequence (healthz -> `o3k init` as the
# o3k account -> authenticated `o3k join` -> compute start -> readyz ->
# `o3k doctor` -> bootstrap-testlab.sh). The fixture install.sh emulates the
# state the real install.sh leaves behind (fake 0600 /etc/o3k/o3kd.env with a
# generated O3K_BOOTSTRAP_SECRET preserved on re-runs, fake o3k-compute.env,
# the TLS agent-id only when the layout lacks it, and the o3k CLI shim copied
# to /usr/local/bin), a runuser shim executes the privilege-drop invocations
# without switching users, the bin/o3k fixture answers init/join/doctor, and
# the background HTTP fixtures keep 18080/9100 answering 200 for the matrix
# lifetime. Every fixture-created system path (/etc/o3k, /usr/local/bin/o3k)
# is removed by the exit trap; the matrix still refuses to start when those
# paths already exist.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$ROOT_DIR/packaging/get-o3k.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-installer-negative.XXXXXX")"
HTTP_PID=""
HEALTH_PID_18080=""
HEALTH_PID_9100=""
ETC_O3K_CREATED=0
USR_LOCAL_O3K_CREATED=0
PASS=0
FAIL=0
SKIP=0

cleanup() {
  [[ -n "$HTTP_PID" ]] && kill "$HTTP_PID" 2>/dev/null || true
  [[ -n "$HEALTH_PID_18080" ]] && kill "$HEALTH_PID_18080" 2>/dev/null || true
  [[ -n "$HEALTH_PID_9100" ]] && kill "$HEALTH_PID_9100" 2>/dev/null || true
  [[ "$ETC_O3K_CREATED" -eq 1 ]] && rm -rf -- /etc/o3k || true
  # USR_LOCAL_O3K_CREATED covers every /usr/local path the matrix (or its
  # fixtures) created: the fake release manifest, the Araf demo material the
  # wrapper copies into the share dir (PP.4), and the o3k CLI shim the fixture
  # install.sh copies to /usr/local/bin for the canonical bootstrap.
  [[ "$USR_LOCAL_O3K_CREATED" -eq 1 ]] && rm -f -- /usr/local/bin/o3k || true
  [[ "$USR_LOCAL_O3K_CREATED" -eq 1 ]] && rm -rf -- /usr/local/share/o3k/araf-demo || true
  [[ "$USR_LOCAL_O3K_CREATED" -eq 1 ]] && rm -f -- /usr/local/share/o3k/release-manifest.json || true
  [[ "$USR_LOCAL_O3K_CREATED" -eq 1 ]] && rmdir /usr/local/share/o3k 2>/dev/null || true
  # O3K_NEGATIVE_KEEP_WORKDIR=1 preserves the matrix for local debugging.
  if [[ "${O3K_NEGATIVE_KEEP_WORKDIR:-0}" != 1 ]]; then
    rm -rf -- "$WORK_DIR"
  else
    printf 'matrix preserved at %s\n' "$WORK_DIR" >&2
  fi
}
trap cleanup EXIT

record_pass() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
record_fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
record_skip() { SKIP=$((SKIP + 1)); printf 'skip %s\n' "$1"; }

# ---------------------------------------------------------------- helpers ---

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

start_http_server() { # start_http_server DIR PORT PID_VAR
  local dir="$1" port="$2" var="$3" pid="" attempt
  python3 -m http.server "$port" --bind 127.0.0.1 --directory "$dir" \
    >"$MATRIX/endpoint-http.log" 2>&1 &
  pid=$!
  for attempt in $(seq 1 100); do
    if curl -sf -o /dev/null "http://127.0.0.1:$port/ready"; then
      eval "$var=$pid"
      return 0
    fi
    sleep 0.1
  done
  kill "$pid" 2>/dev/null || true
  echo "http server on port $port did not come up; log:" >&2
  cat "$MATRIX/endpoint-http.log" >&2
  return 1
}

# ---- full-wrapper negative matrix (root, supported host, clean /etc/o3k) ----

run_full_matrix() {
  local MATRIX SHIM_BIN SRC_BUNDLE TMP_ROOT WWW RELEASE_PORT DEAD_PORT
  local HEALTH_UP=1
  MATRIX="$WORK_DIR/matrix"
  SHIM_BIN="$MATRIX/bin"
  SRC_BUNDLE="$MATRIX/src-bundle/o3k-0.4.0-rc.9"
  TMP_ROOT="$MATRIX/tmp"
  WWW="$MATRIX/www"
  mkdir -p "$SHIM_BIN" "$SRC_BUNDLE/packaging" "$SRC_BUNDLE/bin" "$TMP_ROOT" \
    "$WWW/releases/v0.4.0-rc.9"
  printf 'ok\n' >"$WWW/ready"

  if [[ $EUID -ne 0 ]]; then
    record_skip "full-wrapper negative matrix requires root (run: sudo bash tests/installer-negative.sh)"
    return
  fi
  if [[ -e /etc/o3k || -L /etc/o3k ]]; then
    record_skip "full-wrapper negative matrix requires an absent /etc/o3k (found one; refusing to touch it)"
    return
  fi
  # shellcheck disable=SC1091
  . /etc/os-release 2>/dev/null || true
  case "${ID:-}:${VERSION_CODENAME:-}" in
    ubuntu:noble|debian:bookworm) ;;
    *) record_skip "full-wrapper matrix needs Ubuntu 24.04/Debian 12 (host is ${ID:-unknown}:${VERSION_CODENAME:-unknown})"; return ;;
  esac
  for tool in curl python3 tar sha256sum awk sed grep mktemp cat; do
    command -v "$tool" >/dev/null 2>&1 || { record_skip "full-wrapper matrix needs $tool"; return; }
  done

  # ---- TEST FIXTURE: apt/systemd shims (record only, never touch the host) ----
  cat >"$SHIM_BIN/apt-get" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — records the invocation; performs no package operations.
printf '%s\n' "$*" >>"${O3K_TEST_APT_LOG:?}"
exit 0
EOF
  cat >"$SHIM_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — records the invocation; performs no service operations.
printf '%s\n' "$*" >>"${O3K_TEST_SYSTEMCTL_LOG:?}"
exit 0
EOF
  cat >"$SHIM_BIN/runuser" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — records the invocation (bootstrap secret redacted) and
# executes the command WITHOUT the privilege drop: the o3k fixture account
# intentionally does not exist in this matrix.
redacted="$(printf '%s' "$*" | sed -e 's/O3K_BOOTSTRAP_SECRET=[^ ]*/O3K_BOOTSTRAP_SECRET=<redacted>/g')"
printf 'runuser %s\n' "$redacted" >>"${O3K_TEST_RUNUSER_LOG:?}"
while [ $# -gt 0 ] && [ "$1" != "--" ]; do
  shift
done
if [ "${1:-}" = "--" ]; then
  shift
fi
exec "$@"
EOF
  cat >"$SHIM_BIN/install" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — delegates to /usr/bin/install. Sandboxed (user-namespace)
# runs cannot chown to the unmapped o3k uid; retry without ownership args in
# that case. On real hosts the o3k user exists and the first attempt wins.
if /usr/bin/install "$@"; then
  exit 0
fi
args=()
skip_next=0
for arg in "$@"; do
  case "$arg" in
    -o|-g|--owner|--group) skip_next=1 ;;
    *)
      if [ "$skip_next" -eq 1 ]; then
        skip_next=0
      else
        args+=("$arg")
      fi
      ;;
  esac
done
exec /usr/bin/install "${args[@]}"
EOF
  chmod +x "$SHIM_BIN/apt-get" "$SHIM_BIN/systemctl" "$SHIM_BIN/runuser" "$SHIM_BIN/install"

  # ---- TEST FIXTURE: shim release bundle (record only, delete with WORK_DIR) ----
  cat >"$SRC_BUNDLE/packaging/verify-release-bundle.sh" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — records the invocation and exits with O3K_TEST_VERIFY_EXIT.
printf 'verify-release-bundle %s\n' "$1" >>"${O3K_TEST_SCRIPT_LOG:?}"
exit "${O3K_TEST_VERIFY_EXIT:-0}"
EOF
  cat >"$SRC_BUNDLE/packaging/preflight.sh" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — records the invocation and exits with O3K_TEST_PREFLIGHT_EXIT.
# The real preflight checks (/dev/kvm, libvirt, disk) are exercised by
# tests/packaging-safety.sh; here the wrapper's abort-on-failure is proven.
printf 'preflight %s\n' "$*" >>"${O3K_TEST_SCRIPT_LOG:?}"
exit "${O3K_TEST_PREFLIGHT_EXIT:-0}"
EOF
  cat >"$SRC_BUNDLE/packaging/bootstrap-certs.sh" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — records the invocation; creates no TLS material.
printf 'bootstrap-certs %s\n' "$*" >>"${O3K_TEST_CERT_LOG:?}"
exit 0
EOF
  cat >"$SRC_BUNDLE/packaging/install.sh" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — records the invocation; modes: ok | foreign | interrupted | converge.
# Emulates the state the real install.sh leaves behind for the wrapper's
# canonical P15.6 bootstrap (PP.2): the o3k CLI shim at /usr/local/bin, a fake
# 0600 /etc/o3k/o3kd.env carrying a generated O3K_BOOTSTRAP_SECRET
# (preserved byte-for-byte on re-runs, like scripts/generate-passwords.sh), a
# fake /etc/o3k/o3k-compute.env, and the TLS agent-id ONLY when the
# surrounding layout lacks it (the real bootstrap-certs.sh owns TLS identity
# creation; the converge case ships a complete fixture set it must not
# clobber). Foreign/interrupted modes fail before writing anything, like the
# real fenced install path.
printf 'install %s\n' "$*" >>"${O3K_TEST_SCRIPT_LOG:?}"
case "${O3K_TEST_INSTALL_MODE:-ok}" in
  foreign)
    printf 'foreign populated install path\n' >&2
    exit 1
    ;;
  interrupted)
    bundle_dir="$(cd "$(dirname "$0")/.." && pwd)"
    tmp_root="$(dirname "$bundle_dir")"
    printf '%s\n' "$tmp_root" >"${O3K_TEST_INSTALL_TMP_LOG:?}"
    : >"$tmp_root/interrupted-installer-canary"
    exit 1
    ;;
esac
bundle_dir="$(cd "$(dirname "$0")/.." && pwd)"
umask 077
# The wrapper's canonical bootstrap writes o3k-owned 0600 secret fragments
# under the o3k-owned data directory (O3K_*_FILE intake); emulate the real
# install.sh prerequisites for that layout.
getent group o3k >/dev/null 2>&1 || groupadd --system o3k 2>/dev/null || true
if ! getent passwd o3k >/dev/null 2>&1; then
  useradd --system --gid o3k --home-dir /var/lib/o3k --shell /usr/sbin/nologin o3k 2>/dev/null || true
fi
if [ $EUID -eq 0 ] && getent passwd o3k >/dev/null 2>&1; then
  if [ ! -d /var/lib/o3k ]; then
    install -d -o o3k -g o3k -m 0700 /var/lib/o3k
  else
    chown o3k:o3k /var/lib/o3k 2>/dev/null || true
    chmod 0700 /var/lib/o3k 2>/dev/null || true
  fi
else
  mkdir -p /var/lib/o3k
fi
mkdir -p /etc/o3k/tls
if [ ! -e /etc/o3k/o3kd.env ] && [ ! -L /etc/o3k/o3kd.env ]; then
  secret="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  printf 'O3K_BOOTSTRAP_SECRET=%s\n' "$secret" >/etc/o3k/o3kd.env
  chmod 0600 /etc/o3k/o3kd.env
fi
if [ ! -e /etc/o3k/o3k-compute.env ] && [ ! -L /etc/o3k/o3k-compute.env ]; then
  printf 'O3K_COMPUTE_DATA_DIR=/var/lib/o3k-compute\nO3K_COMPUTE_PROFILE=libvirt\nO3K_COMPUTE_MAX_DISK_GB=30\n' \
    >/etc/o3k/o3k-compute.env
  chmod 0600 /etc/o3k/o3k-compute.env
fi
if [ ! -e /etc/o3k/tls/agent-id ] && [ ! -L /etc/o3k/tls/agent-id ]; then
  printf 'compute-agent\n' >/etc/o3k/tls/agent-id
  chmod 0600 /etc/o3k/tls/agent-id
fi
install -m 0755 "$bundle_dir/bin/o3k" /usr/local/bin/o3k
# PP.4: the real install.sh installs the bundle manifest as
# /usr/local/share/o3k/release-manifest.json (the demo `tuple` reads it
# fail-closed); the fixture mirrors that with a marked fixture manifest.
if [ ! -e /usr/local/share/o3k/release-manifest.json ]; then
  mkdir -p /usr/local/share/o3k
  printf '{"version":"0.4.0-rc.9","profile":"libvirt","source_commit":"fixture-source-sha-0000000000000000000000000000000000000000"}\n' \
    > /usr/local/share/o3k/release-manifest.json
  chmod 0644 /usr/local/share/o3k/release-manifest.json
fi
case "${O3K_TEST_INSTALL_MODE:-ok}" in
  converge)
    printf 'configuration preserved\n'
    printf 'credentials preserved\n'
    ;;
esac
exit 0
EOF
  cat >"$SRC_BUNDLE/packaging/bootstrap-testlab.sh" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — records the invocation; modes: ok | fail | converge.
printf 'bootstrap-testlab %s\n' "$*" >>"${O3K_TEST_SCRIPT_LOG:?}"
if [ "${O3K_TEST_BOOTSTRAP_MODE:-ok}" = fail ]; then
  printf 'bootstrap interrupted\n' >&2
  exit 1
fi
if [ "${O3K_TEST_BOOTSTRAP_MODE:-ok}" = converge ]; then
  printf 'TestLab resources already present\n'
fi
exit 0
EOF
  cat >"$SRC_BUNDLE/packaging/o3k-araf-demo.sh" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — records the invocation; answers install + tuple like the real
# PP.4 orchestrator (no containers, no state, no docker). The real script
# appends T3/T3_ISO to $PP4_TIMESTAMPS_FILE during install.
printf 'o3k-araf-demo %s\n' "$*" >>"${O3K_TEST_SCRIPT_LOG:?}"
cmd="${1:-}"
case "$cmd" in
  install)
    if [ -n "${PP4_TIMESTAMPS_FILE:-}" ] && [ -w "${PP4_TIMESTAMPS_FILE}" ]; then
      printf 'T3=1730000000\nT3_ISO=2026-01-01T00:00:00Z\n' >>"${PP4_TIMESTAMPS_FILE}"
    fi
    printf '[o3k-araf-demo] install OK (fixture)\n'
    ;;
  tuple)
    printf 'ARAF_VERSION=v1.0.0-rc.15\n'
    printf 'ARAF_SOURCE_SHA=f0c2a04a671d5edf7711cab63c4f83c49a9170d20\n'
    printf 'ARAF_BFF_DIGEST=sha256:bc717ecdbbbf3ea673efe168c90419936677d644aa0ae25af4eb84906cd744ba\n'
    printf 'O3K_VERSION=v0.4.0-rc.9\n'
    printf 'O3K_SOURCE_SHA=fixture-source-sha-0000000000000000000000000000000000000000\n'
    ;;
  *)
    printf 'o3k-araf-demo fixture: unsupported subcommand: %s\n' "$cmd" >&2
    exit 97
    ;;
esac
exit 0
EOF
  for file in verify-release-bundle.sh preflight.sh bootstrap-certs.sh install.sh bootstrap-testlab.sh o3k-araf-demo.sh; do
    chmod +x "$SRC_BUNDLE/packaging/$file"
  done
  # PP.4 fixture: demo deployment material the wrapper copies into
  # /usr/local/share/o3k/araf-demo/ (content-compared, so these stand in for
  # the real compose material).
  mkdir -p "$SRC_BUNDLE/packaging/araf-demo"
  for file in compose.yaml nginx.conf api-relay.conf realm.json README.md; do
    printf '# TEST FIXTURE araf-demo material: %s\n' "$file" >"$SRC_BUNDLE/packaging/araf-demo/$file"
  done
  # PP.4 fixture: the bundle manifest the wrapper reads source_commit from for
  # the success block (get-o3k.sh never trusts its own baked-in SHA).
  printf '{"version":"0.4.0-rc.9","profile":"libvirt","source_commit":"fixture-source-sha-0000000000000000000000000000000000000000"}\n' \
    >"$SRC_BUNDLE/manifest.json"
  cat >"$SRC_BUNDLE/bin/o3kd" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — must never be executed by the wrapper.
printf 'shim binary must not be executed\n' >&2
exit 97
EOF
  cat >"$SRC_BUNDLE/bin/o3k-compute" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — must never be executed by the wrapper.
printf 'shim binary must not be executed\n' >&2
exit 97
EOF
  cat >"$SRC_BUNDLE/bin/o3k" <<'EOF'
#!/usr/bin/env bash
# TEST FIXTURE — canonical CLI shim. The fixture install.sh copies this to
# /usr/local/bin/o3k so the wrapper's REAL canonical P15.6 bootstrap (init as
# the o3k account, authenticated join, doctor) executes against this shim; it
# records every invocation and answers the canonical contract. Nothing real
# is enrolled, joined, or diagnosed.
printf 'o3k %s\n' "$*" >>"${O3K_TEST_O3K_LOG:?}"
cmd="${1:-}"
if [ $# -gt 0 ]; then
  shift
fi
case "$cmd" in
  init)
    printf '{"enrollment_token": "fixture-enrollment-token-0123456789abcdef"}\n'
    ;;
  join)
    printf '{"building_block_id": "11111111-2222-3333-4444-555555555555"}\n'
    ;;
  doctor)
    # The installer's diagnostics gate parses `o3k doctor --json` and accepts
    # overall healthy|warning with zero FAIL checks.
    printf '{"overall_status": "healthy", "checks": []}\n'
    exit 0
    ;;
  *)
    printf 'o3k fixture: unsupported subcommand: %s\n' "$cmd" >&2
    exit 97
    ;;
esac
EOF
  chmod +x "$SRC_BUNDLE/bin/o3kd" "$SRC_BUNDLE/bin/o3k-compute" "$SRC_BUNDLE/bin/o3k"

  build_good_tarball() { # build_good_tarball TARBALL
    tar -C "$MATRIX/src-bundle" -czf "$1" ./o3k-0.4.0-rc.9
  }
  publish_tarball() { # publish_tarball TARBALL — copies into WWW + writes .sha256
    local digest
    cp "$1" "$WWW/releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz"
    digest="$(sha256sum "$1" | awk '{print $1}')"
    printf '%s  %s\n' "$digest" "o3k-0.4.0-rc.9-linux-x86_64.tar.gz" \
      >"$WWW/releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz.sha256"
  }
  publish_sha_digest() { # publish_sha_digest HEX64 — publishes a specific digest
    printf '%s  %s\n' "$1" "o3k-0.4.0-rc.9-linux-x86_64.tar.gz" \
      >"$WWW/releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz.sha256"
  }

  RELEASE_PORT="$(free_port)"
  DEAD_PORT="$(free_port)" # a port with nothing listening: connection refused
  start_http_server "$WWW" "$RELEASE_PORT" HTTP_PID

  export O3K_RELEASE_BASE="http://127.0.0.1:$RELEASE_PORT/releases"
  export TMPDIR="$TMP_ROOT"
  export O3K_TEST_SCRIPT_LOG="$MATRIX/scripts.log"
  export O3K_TEST_APT_LOG="$MATRIX/apt.log"
  export O3K_TEST_SYSTEMCTL_LOG="$MATRIX/systemctl.log"
  export O3K_TEST_CERT_LOG="$MATRIX/cert.log"
  export O3K_TEST_RUNUSER_LOG="$MATRIX/runuser.log"
  export O3K_TEST_O3K_LOG="$MATRIX/o3k-cli.log"

  run_wrapper() { # run_wrapper OUT ERR — runs the real wrapper with the matrix env
    local status
    PATH="$SHIM_BIN:$PATH" bash "$WRAPPER" >"$1" 2>"$2"
    status=$?
    # Debug aid: keep the most recent wrapper stderr for local failure triage.
    cp "$2" "$MATRIX/wrapper-last.err" 2>/dev/null || true
    return "$status"
  }

  expect_abort() { # expect_abort DESC MESSAGE [OUT ERR] — non-zero exit + message
    local desc="$1" message="$2" out="$3" err="$4" status=0
    if ! run_wrapper "$out" "$err"; then
      status=1
    fi
    [[ $status -ne 0 ]] || { record_fail "$desc (expected non-zero exit)"; return; }
    if grep -Fq -- "$message" "$err"; then
      record_pass "$desc"
    else
      record_fail "$desc (missing message: $message; stderr was: $(grep -aE "O3K installer|TestLab bootstrap|error" "$err" | tail -n2 | tr "\n" " "))"
    fi
  }

  assert_no_script_run() { # assert_no_script_run DESC — nothing at all was executed
    if [[ -s "$O3K_TEST_SCRIPT_LOG" ]]; then
      record_fail "$1 (a bundled script ran: $(head -n1 "$O3K_TEST_SCRIPT_LOG"))"
    else
      record_pass "$1"
    fi
  }
  assert_no_install_run() { # assert_no_install_run DESC — install.sh never ran
    if grep -q '^install ' "$O3K_TEST_SCRIPT_LOG" 2>/dev/null; then
      record_fail "$1 (install ran: $(grep '^install ' "$O3K_TEST_SCRIPT_LOG" | head -n1))"
    else
      record_pass "$1"
    fi
  }
  assert_tmp_clean() { # assert_tmp_clean DESC — the trap removed its temp dir
    if [[ -z "$(find "$TMP_ROOT" -mindepth 1 -print -quit)" ]]; then
      record_pass "$1"
    else
      record_fail "$1 (files remain under $TMP_ROOT)"
    fi
  }

  # ---- health endpoints on the ports the wrapper probes (success paths) -----
  start_health_servers() {
    if curl -sf -o /dev/null --max-time 2 http://127.0.0.1:18080/healthz 2>/dev/null \
      || curl -sf -o /dev/null --max-time 2 http://127.0.0.1:9100/readyz 2>/dev/null; then
      return 1 # ports already occupied by something foreign
    fi
    python3 - 18080 "$MATRIX/health-18080.log" <<'PY' &
import http.server
import sys


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(sys.argv[2], "a", encoding="utf-8") as stream:
            stream.write(self.path + "\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
    HEALTH_PID_18080=$!
    python3 - 9100 "$MATRIX/health-9100.log" <<'PY' &
import http.server
import sys


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(sys.argv[2], "a", encoding="utf-8") as stream:
            stream.write(self.path + "\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
    HEALTH_PID_9100=$!
    local attempt
    for attempt in $(seq 1 50); do
      if curl -sf -o /dev/null http://127.0.0.1:18080/healthz \
        && curl -sf -o /dev/null http://127.0.0.1:9100/readyz; then
        return 0
      fi
      sleep 0.1
    done
    kill "$HEALTH_PID_18080" "$HEALTH_PID_9100" 2>/dev/null || true
    HEALTH_PID_18080=""
    HEALTH_PID_9100=""
    return 1
  }
  if ! start_health_servers; then
    HEALTH_UP=0
    record_skip "success/health-path cases need ports 18080 and 9100 free (skipping those cases)"
  fi

  fresh_logs() { # fresh_logs CASE — new log files per case
    : >"$O3K_TEST_SCRIPT_LOG"
    : >"$O3K_TEST_APT_LOG"
    : >"$O3K_TEST_SYSTEMCTL_LOG"
    : >"$O3K_TEST_RUNUSER_LOG"
    : >"$O3K_TEST_O3K_LOG"
    # The health fixtures append per request; truncate so each case only sees
    # its own probe hits.
    : >"$MATRIX/health-18080.log" 2>/dev/null || true
    : >"$MATRIX/health-9100.log" 2>/dev/null || true
    rm -f -- "$O3K_TEST_CERT_LOG" "$MATRIX/install-tmp.log"
    # Deterministic version resolution per case: no explicit override and no
    # endpoint-injected pin line (the wrapper is run as a file, never piped),
    # so cases exercise the BAKED O3K_INSTALLER_VERSION unless a case sets
    # O3K_VERSION itself.
    unset O3K_VERSION O3K_PINNED_VERSION
    unset O3K_TEST_VERIFY_EXIT O3K_TEST_PREFLIGHT_EXIT O3K_TEST_INSTALL_MODE \
      O3K_TEST_BOOTSTRAP_MODE O3K_TEST_INSTALL_TMP_LOG
    O3K_TEST_INSTALL_TMP_LOG="$MATRIX/install-tmp.log"
    export O3K_TEST_INSTALL_TMP_LOG
  }

  local out="$MATRIX/out.log" err="$MATRIX/err.log"

  # 1. default-version resolution with no O3K_VERSION and no pin line: the
  #    BAKED O3K_INSTALLER_VERSION resolves to the pinned release asset path.
  #    An unreachable release endpoint makes the resolved path visible in the
  #    abort message, proving the wrapper never asked a channel service.
  fresh_logs default-version-release-down
  O3K_RELEASE_BASE="http://127.0.0.1:$DEAD_PORT/releases" \
    expect_abort "baked default version resolves to the pinned release asset" \
    "download failed: http://127.0.0.1:$DEAD_PORT/releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz" \
    "$out" "$err"
  assert_no_script_run "no bundled script ran after default-version download failure"

  # 2. O3K_VERSION override wins over the baked default: the abort names the
  #    OVERRIDE version's asset, not the baked v0.4.0-rc.9 one.
  fresh_logs override-version
  O3K_VERSION="0.2.0-overridetest" O3K_RELEASE_BASE="http://127.0.0.1:$DEAD_PORT/releases" \
    expect_abort "O3K_VERSION override wins over the baked default" \
    "download failed: http://127.0.0.1:$DEAD_PORT/releases/v0.2.0-overridetest/o3k-0.2.0-overridetest-linux-x86_64.tar.gz" \
    "$out" "$err"
  assert_no_script_run "no bundled script ran after override-version download failure"

  # 3. missing release asset (404) -> abort.
  fresh_logs missing-asset
  rm -f -- "$WWW/releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz" \
    "$WWW/releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz.sha256"
  expect_abort "missing release asset (404) aborts" \
    "download failed: http://127.0.0.1:$RELEASE_PORT/releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz" \
    "$out" "$err"
  assert_no_script_run "no bundled script ran after a 404 asset"

  # 4. corrupted archive (truncated tarball, matching hash) -> abort at listing.
  fresh_logs corrupted-archive
  build_good_tarball "$MATRIX/good.tar.gz"
  tarball_size="$(stat -c %s "$MATRIX/good.tar.gz")"
  head -c $((tarball_size / 2)) "$MATRIX/good.tar.gz" >"$MATRIX/corrupt.tar.gz"
  [[ -s "$MATRIX/corrupt.tar.gz" && "$(stat -c %s "$MATRIX/corrupt.tar.gz")" -lt "$tarball_size" ]]
  publish_tarball "$MATRIX/corrupt.tar.gz"
  expect_abort "corrupted archive aborts at listing" \
    "release archive is not a readable gzip tarball" "$out" "$err"
  assert_no_script_run "no bundled script ran from a corrupted archive"

  # 5. wrong SHA-256 -> abort BEFORE extraction.
  fresh_logs wrong-sha
  build_good_tarball "$MATRIX/good.tar.gz"
  publish_tarball "$MATRIX/good.tar.gz"
  publish_sha_digest "0000000000000000000000000000000000000000000000000000000000000000"
  expect_abort "wrong published SHA-256 aborts before extraction" \
    "published SHA-256 verification failed" "$out" "$err"
  assert_no_script_run "no bundled script ran on a hash mismatch"
  assert_tmp_clean "nothing extracted before hash verification"

  # 6. malformed bundle (verify-release-bundle.sh fails) -> abort.
  fresh_logs malformed-bundle
  publish_tarball "$MATRIX/good.tar.gz"
  O3K_TEST_VERIFY_EXIT=1 \
    expect_abort "malformed bundle aborts at verify-release-bundle.sh" \
    "release bundle verification failed" "$out" "$err"
  assert_no_install_run "install never ran for a malformed bundle"

  # 7+8. unsafe extraction: "../" and absolute entries, matching hash.
  fresh_logs unsafe-extraction
  python3 - "$MATRIX/evil.tar.gz" "$SRC_BUNDLE" "../evil-canary-$$" <<'PY'
import io
import os
import sys
import tarfile

tarball, bundle, evil = sys.argv[1], sys.argv[2], sys.argv[3]
base = os.path.dirname(bundle)
with tarfile.open(tarball, "w:gz") as tar:
    for root, dirs, files in os.walk(bundle):
        for name in files:
            path = os.path.join(root, name)
            tar.add(path, arcname="./" + os.path.relpath(path, base))
    info = tarfile.TarInfo(evil)
    data = b"evil escape payload\n"
    info.size = len(data)
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))
PY
  publish_tarball "$MATRIX/evil.tar.gz"
  expect_abort "unsafe extraction (../ entry) aborts" \
    "unsafe release archive entry (must start with ./): ../evil-canary-$$" "$out" "$err"
  [[ ! -e "$MATRIX/evil-canary-$$" ]] && record_pass "no ../ escape payload written outside the temp dir" \
    || record_fail "a ../ escape payload was written outside the temp dir"
  assert_no_script_run "no bundled script ran from a ../-entry archive"
  assert_tmp_clean "temp dir cleaned after ../ rejection"

  fresh_logs unsafe-absolute
  python3 - "$MATRIX/evil-abs.tar.gz" "$SRC_BUNDLE" "/evil-abs-canary-$$" <<'PY'
import io
import os
import sys
import tarfile

tarball, bundle, evil = sys.argv[1], sys.argv[2], sys.argv[3]
base = os.path.dirname(bundle)
with tarfile.open(tarball, "w:gz") as tar:
    for root, dirs, files in os.walk(bundle):
        for name in files:
            path = os.path.join(root, name)
            tar.add(path, arcname="./" + os.path.relpath(path, base))
    info = tarfile.TarInfo(evil)
    data = b"evil absolute payload\n"
    info.size = len(data)
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))
PY
  publish_tarball "$MATRIX/evil-abs.tar.gz"
  expect_abort "unsafe extraction (absolute entry) aborts" \
    "unsafe release archive entry (must start with ./): /evil-abs-canary-$$" "$out" "$err"
  [[ ! -e "/evil-abs-canary-$$" ]] && record_pass "no absolute-entry payload written to the host root" \
    || record_fail "an absolute-entry payload was written to the host root"
  assert_no_script_run "no bundled script ran from an absolute-entry archive"
  assert_tmp_clean "temp dir cleaned after absolute-entry rejection"

  # 9. unsafe extraction: a symlink entry inside ./ (name checks pass, the
  #    ` -> ` verbose-listing marker must reject it) -> abort before
  #    extraction and nothing is written.
  fresh_logs unsafe-symlink
  python3 - "$MATRIX/evil-symlink.tar.gz" "$SRC_BUNDLE" <<'PY'
import os
import sys
import tarfile

tarball, bundle = sys.argv[1], sys.argv[2]
base = os.path.dirname(bundle)
with tarfile.open(tarball, "w:gz") as tar:
    for root, dirs, files in os.walk(bundle):
        for name in files:
            path = os.path.join(root, name)
            tar.add(path, arcname="./" + os.path.relpath(path, base))
    info = tarfile.TarInfo("./evil-link")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    info.mode = 0o777
    tar.addfile(info)
PY
  publish_tarball "$MATRIX/evil-symlink.tar.gz"
  expect_abort "unsafe extraction (symlink entry) aborts" \
    "unsafe release archive entry (symlink)" "$out" "$err"
  [[ ! -e "$MATRIX/src-bundle/evil-link" && ! -L "$MATRIX/src-bundle/evil-link" ]] \
    && record_pass "no symlink payload written" \
    || record_fail "a symlink payload was written"
  assert_no_script_run "no bundled script ran from a symlink-entry archive"
  assert_tmp_clean "temp dir cleaned after symlink-entry rejection"

  # 10. unsafe extraction: a character-device entry inside ./ (leading type
  #     char `c` in the verbose listing) -> abort before extraction and
  #     nothing is written.
  fresh_logs unsafe-device
  python3 - "$MATRIX/evil-device.tar.gz" "$SRC_BUNDLE" <<'PY'
import os
import sys
import tarfile

tarball, bundle = sys.argv[1], sys.argv[2]
base = os.path.dirname(bundle)
with tarfile.open(tarball, "w:gz") as tar:
    for root, dirs, files in os.walk(bundle):
        for name in files:
            path = os.path.join(root, name)
            tar.add(path, arcname="./" + os.path.relpath(path, base))
    info = tarfile.TarInfo("./evil-dev")
    info.type = tarfile.CHRTYPE
    info.mode = 0o644
    info.devmajor = 1
    info.devminor = 3
    tar.addfile(info)
PY
  publish_tarball "$MATRIX/evil-device.tar.gz"
  expect_abort "unsafe extraction (device entry) aborts" \
    "unsafe release archive entry (device, fifo, or link)" "$out" "$err"
  [[ ! -e "$MATRIX/src-bundle/evil-dev" ]] \
    && record_pass "no device payload written" \
    || record_fail "a device payload was written"
  assert_no_script_run "no bundled script ran from a device-entry archive"
  assert_tmp_clean "temp dir cleaned after device-entry rejection"

  # 11. preflight failure -> abort. The real /dev/kvm/libvirt/disk checks are
  #    proven by tests/packaging-safety.sh and the real-VM campaigns; this
  #    proves the wrapper treats any preflight failure as fatal.
  fresh_logs preflight-fail
  publish_tarball "$MATRIX/good.tar.gz"
  O3K_TEST_PREFLIGHT_EXIT=1 \
    expect_abort "preflight failure aborts the wrapper" \
    "preflight failed (--profile libvirt --data-dir /var/lib/o3k)" "$out" "$err"
  assert_no_install_run "install never ran after preflight failure"

  # 12. foreign populated install path -> install.sh's failure exit passes
  #     through. The real fence is proven by tests/packaging-safety.sh.
  fresh_logs foreign-install-path
  publish_tarball "$MATRIX/good.tar.gz"
  O3K_TEST_INSTALL_MODE=foreign \
    expect_abort "foreign install path failure passes through the wrapper" \
    "installation failed; the host holds recoverable O3K-owned state and re-running the installer converges" \
    "$out" "$err"
  grep -Fq -- "--profile libvirt --noninteractive" "$O3K_TEST_SCRIPT_LOG" \
    && record_pass "install shim received the verified-bundle invocation" \
    || record_fail "install shim did not receive the expected arguments"

  # 13. interrupted installer -> wrapper aborts and the EXIT trap removes the
  #     private temp dir (no partial state claim). Install fails before the
  #     health probes, so this case needs no health endpoints.
  fresh_logs interrupted-installer
  publish_tarball "$MATRIX/good.tar.gz"
  O3K_TEST_INSTALL_MODE=interrupted \
    expect_abort "interrupted installer aborts" \
    "installation failed; the host holds recoverable O3K-owned state and re-running the installer converges" \
    "$out" "$err"
  if [[ -s "$MATRIX/install-tmp.log" ]]; then
    recorded_tmp="$(head -n1 "$MATRIX/install-tmp.log")"
    if [[ ! -e "$recorded_tmp" && ! -e "$recorded_tmp/interrupted-installer-canary" ]]; then
      record_pass "interrupted installer temp dir removed by the trap"
    else
      record_fail "interrupted installer left its temp dir or canary behind"
    fi
  else
    record_fail "interrupted installer shim did not record its temp dir"
  fi

  # 14. interrupted bootstrap -> wrapper aborts with a clear message. The
  #     canonical bootstrap (init/join/doctor) must already have run: the
  #     demo workload is created only AFTER canonical readiness.
  if [[ "$HEALTH_UP" -eq 0 ]]; then
    record_skip "interrupted bootstrap (needs health ports)"
  else
    fresh_logs interrupted-bootstrap
    publish_tarball "$MATRIX/good.tar.gz"
    O3K_TEST_BOOTSTRAP_MODE=fail \
      expect_abort "interrupted bootstrap aborts with a clear message" \
      "TestLab bootstrap failed" "$out" "$err"
    grep -Fq 'install ' "$O3K_TEST_SCRIPT_LOG" \
      && record_pass "install completed before bootstrap failure" \
      || record_fail "install did not run before bootstrap failure"
    if grep -Fq 'o3k init --agent-id compute-agent' "$O3K_TEST_O3K_LOG" \
      && grep -Fq 'o3k join --agent-id compute-agent' "$O3K_TEST_O3K_LOG" \
      && grep -Fq 'o3k doctor' "$O3K_TEST_O3K_LOG"; then
      record_pass "canonical init/join/doctor ran before the bootstrap step"
    else
      record_fail "canonical init/join/doctor did not all run before the bootstrap step"
    fi
  fi

  # 15. fresh first-run success control (TLS absent -> bootstrap-certs shim).
  #     The post-install cases above left fixture install state behind (fake
  #     o3kd.env/o3k-compute.env, tls/agent-id, the o3k CLI shim, the fixture
  #     release manifest + Araf demo material); this control emulates a FRESH
  #     host, so reset the fixture-created state first. Safe because the
  #     matrix owns these paths: the guard at the top proved /etc/o3k absent
  #     and /usr/local/bin/o3k absent before starting, and the share-dir
  #     entries are only dropped when they carry the fixture marker.
  [[ -e /etc/o3k ]] && ETC_O3K_CREATED=1
  [[ -e /usr/local/bin/o3k ]] && USR_LOCAL_O3K_CREATED=1
  rm -rf -- /etc/o3k
  rm -f -- /usr/local/bin/o3k
  if [[ -f /usr/local/share/o3k/release-manifest.json ]] \
    && grep -q 'fixture-source-sha' /usr/local/share/o3k/release-manifest.json 2>/dev/null; then
    USR_LOCAL_O3K_CREATED=1
    rm -f -- /usr/local/share/o3k/release-manifest.json
  fi
  if [[ -f /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh ]] \
    && grep -q 'TEST FIXTURE' /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh 2>/dev/null; then
    USR_LOCAL_O3K_CREATED=1
    rm -rf -- /usr/local/share/o3k/araf-demo
  fi
  rmdir /usr/local/share/o3k 2>/dev/null || true
  if [[ "$HEALTH_UP" -eq 0 ]]; then
    record_skip "first-run success control (needs health ports)"
  else
    fresh_logs success
    publish_tarball "$MATRIX/good.tar.gz"
    if run_wrapper "$out" "$err"; then
      record_pass "fresh first run exits 0 through the shim pipeline"
    else
      record_fail "fresh first run failed (stderr: $(grep -aE "O3K installer|TestLab bootstrap|error" "$err" | tail -n2 | tr "\n" " "))"
    fi
    # Default-version proof: with no O3K_VERSION and no pin line, the wrapper
    # resolved the BAKED O3K_INSTALLER_VERSION — visible both in the banner
    # and in the exact asset paths the release endpoint served.
    grep -Fq '✓ O3K v0.4.0-rc.9 verified' "$out" \
      && record_pass "baked default resolved to v0.4.0-rc.9 (verified banner)" \
      || record_fail "missing v0.4.0-rc.9 verified banner"
    if grep -Fq 'GET /releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz ' "$MATRIX/endpoint-http.log" \
      && grep -Fq 'GET /releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz.sha256 ' "$MATRIX/endpoint-http.log"; then
      record_pass "default resolution downloaded the pinned v0.4.0-rc.9 asset paths"
    else
      record_fail "release endpoint log does not show the pinned v0.4.0-rc.9 asset requests"
    fi
    grep -Fq 'release archive SHA-256 verified' "$out" \
      && record_pass "release archive verified" || record_fail "missing verification line"
    grep -Fq 'mTLS identities ready' "$out" \
      && record_pass "TLS bootstrap invoked when identities were absent" \
      || record_fail "missing mTLS-ready line"
    grep -Fq 'O3K demo ready' "$out" \
      && record_pass "PP.4 demo-ready banner printed" || record_fail "missing demo-ready banner"
    grep -Fq 'Tenant Console:   https://tenant.o3k.demo/' "$out" \
      && grep -Fq 'Operator Console: https://operator.o3k.demo/' "$out" \
      && grep -Fq 'Uninstall:' "$out" \
      && record_pass "PP.4 success block carries consoles + uninstall lines" \
      || record_fail "PP.4 success block incomplete"
    grep -Fq 'Araf:' "$out" && grep -Fq '  version: v1.0.0-rc.15' "$out" \
      && grep -Fq '  source: f0c2a04a671d5edf7711cab63c4f83c49a9170d20' "$out" \
      && record_pass "PP.4 success block carries the Araf tuple from the demo script" \
      || record_fail "PP.4 Araf tuple lines missing"
    grep -Fq 'o3k-araf-demo install' "$O3K_TEST_SCRIPT_LOG" \
      && grep -Fq 'o3k-araf-demo tuple' "$O3K_TEST_SCRIPT_LOG" \
      && record_pass "PP.4 demo stage ran install + tuple through the fixture" \
      || record_fail "PP.4 demo stage did not run through the fixture"
    grep -Fq 'Araf demo material installed (O3K share dir)' "$out" \
      && grep -Fq 'Araf demo deployed (pinned tuple)' "$out" \
      && record_pass "PP.4 demo stage markers printed" || record_fail "missing PP.4 demo stage markers"
    [[ -f /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh \
      && -f /usr/local/share/o3k/araf-demo/araf-demo/compose.yaml \
      && -x /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh ]] \
      && record_pass "PP.4 demo material installed into the O3K share dir" \
      || record_fail "PP.4 demo material missing from the O3K share dir"
    if [[ -f /var/lib/o3k/install-timestamps.env ]] \
      && grep -q '^T0=' /var/lib/o3k/install-timestamps.env \
      && grep -q '^T1=' /var/lib/o3k/install-timestamps.env \
      && grep -q '^T2=' /var/lib/o3k/install-timestamps.env \
      && grep -q '^T3=' /var/lib/o3k/install-timestamps.env \
      && grep -q '^T5=' /var/lib/o3k/install-timestamps.env \
      && grep -q '^PP4-TIMESTAMP T0=' "$out"; then
      record_pass "PP.4 timing ledger carries T0/T1/T2/T3/T5"
    else
      record_fail "PP.4 timing ledger incomplete"
    fi
    [[ -s "$O3K_TEST_CERT_LOG" ]] \
      && record_pass "bootstrap-certs shim ran" || record_fail "bootstrap-certs shim did not run"
    grep -Fq 'update' "$O3K_TEST_APT_LOG" && grep -Fq 'install' "$O3K_TEST_APT_LOG" \
      && record_pass "apt dependency stage ran" || record_fail "apt dependency stage did not run"
    grep -Fq 'enable --now libvirtd' "$O3K_TEST_SYSTEMCTL_LOG" \
      && record_pass "libvirtd enablement ran" || record_fail "libvirtd enablement did not run"
    # Canonical P15.6 bootstrap (PP.2): install must be told to defer the
    # compute start, the canonical markers must appear in order, and the
    # compute unit start must come from the wrapper after the join.
    grep -Fq -- '--defer-compute-start' "$O3K_TEST_SCRIPT_LOG" \
      && record_pass "install shim received --defer-compute-start" \
      || record_fail "install shim did not receive --defer-compute-start"
    grep -Fq '✓ canonical bootstrap initialized (CloudProfile + enrollment grant)' "$out" \
      && record_pass "canonical init marker printed" \
      || record_fail "missing canonical init marker"
    grep -Fq '✓ canonical authenticated join complete (BuildingBlock 11111111-2222-3333-4444-555555555555)' "$out" \
      && record_pass "canonical join marker printed" \
      || record_fail "missing canonical join marker"
    grep -Fq '✓ compute agent ready' "$out" \
      && record_pass "compute ready marker printed" || record_fail "missing compute ready marker"
    grep -Fq '✓ control plane ready (canonical readiness)' "$out" \
      && record_pass "canonical readiness marker printed" \
      || record_fail "missing canonical readiness marker"
    grep -Fq '✓ o3k doctor healthy' "$out" \
      && record_pass "doctor marker printed" || record_fail "missing doctor marker"
    grep -Fq 'BuildingBlock: 11111111-2222-3333-4444-555555555555' "$out" \
      && record_pass "summary carries the BuildingBlock id" \
      || record_fail "summary does not carry the BuildingBlock id"
    grep -Fq 'start o3k-compute.service' "$O3K_TEST_SYSTEMCTL_LOG" \
      && record_pass "wrapper started o3k-compute.service after canonical join" \
      || record_fail "wrapper did not start o3k-compute.service"
    if grep -Fq 'runuser -u o3k -- env O3K_API_URL=http://127.0.0.1:18080/o3k/v1 O3K_BOOTSTRAP_SECRET_FILE=/var/lib/o3k/.installer-bootstrap-secret /usr/local/bin/o3k init --agent-id compute-agent' "$O3K_TEST_RUNUSER_LOG" \
      && grep -Fq 'O3K_ENROLLMENT_TOKEN_FILE=/var/lib/o3k/.installer-enrollment-token' "$O3K_TEST_RUNUSER_LOG" \
      && grep -Fq 'o3k init --agent-id compute-agent' "$O3K_TEST_O3K_LOG" \
      && grep -Fq 'o3k join --agent-id compute-agent' "$O3K_TEST_O3K_LOG" \
      && grep -Fq 'o3k doctor' "$O3K_TEST_O3K_LOG"; then
      record_pass "canonical init/join/doctor executed through the fixtures (secrets via *_FILE, not argv)"
    else
      record_fail "canonical init/join/doctor did not execute through the fixtures"
    fi
    # Secret hygiene: the bootstrap secret and the enrollment token must never
    # reach the installer output (the runuser log above is redacted).
    fixture_secret="$(awk -F= '$1 == "O3K_BOOTSTRAP_SECRET" {print $2; exit}' /etc/o3k/o3kd.env 2>/dev/null || true)"
    if [[ -n "$fixture_secret" ]] \
      && ! grep -Fq -- "$fixture_secret" "$out" \
      && ! grep -Fq -- "$fixture_secret" "$err" \
      && ! grep -Fq 'O3K_BOOTSTRAP_SECRET=' "$out" \
      && ! grep -Fq -- "$fixture_secret" "$O3K_TEST_RUNUSER_LOG" \
      && ! grep -Fq 'fixture-enrollment-token-0123456789abcdef' "$out" \
      && ! grep -Fq 'fixture-enrollment-token-0123456789abcdef' "$err" \
      && ! grep -Eq 'BEGIN .*PRIVATE KEY' "$out"; then
      record_pass "bootstrap secret, enrollment token, and private keys absent from the output"
    else
      record_fail "secret material leaked into the installer output or logs"
    fi
    if grep -Fq '/healthz' "$MATRIX/health-18080.log" && grep -Fq '/readyz' "$MATRIX/health-18080.log" \
      && grep -Fq '/readyz' "$MATRIX/health-9100.log"; then
      record_pass "canonical health probes hit 18080 healthz+readyz and 9100 readyz"
    else
      record_fail "canonical health probes were not exercised"
    fi
    # The fixture install.sh created /etc/o3k and installed the o3k CLI shim
    # and the fixture release manifest; from here on the matrix owns those
    # paths exactly like its own fixtures.
    [[ -e /etc/o3k ]] && ETC_O3K_CREATED=1
    [[ -e /usr/local/bin/o3k ]] && USR_LOCAL_O3K_CREATED=1
    [[ -e /usr/local/share/o3k/release-manifest.json ]] && USR_LOCAL_O3K_CREATED=1
    [[ -e /usr/local/share/o3k/araf-demo ]] && USR_LOCAL_O3K_CREATED=1
  fi

  # 16. TLS partial set -> fail closed, nothing regenerated. Start from
  #     exactly one TLS file: drop the agent-id the fixture install.sh created
  #     during the success case so this case is deterministic whether or not
  #     that case ran (skipped when the health ports were unavailable).
  mkdir -p /etc/o3k/tls
  ETC_O3K_CREATED=1
  rm -f -- /etc/o3k/tls/agent-id
  printf 'test fixture\n' >/etc/o3k/tls/ca.pem
  chmod 0600 /etc/o3k/tls/ca.pem
  fresh_logs tls-partial
  publish_tarball "$MATRIX/good.tar.gz"
  expect_abort "partial TLS set fails closed" \
    "partial TLS identity set under /etc/o3k/tls (1 of 7 files)" "$out" "$err"
  assert_no_install_run "install never ran with a partial TLS set"
  [[ ! -e "$O3K_TEST_CERT_LOG" ]] \
    && record_pass "no TLS regeneration was attempted" \
    || record_fail "bootstrap-certs ran despite the partial TLS set"

  # 17. converged second run: complete TLS set is preserved, shims report the
  #     already-installed state, and the wrapper still exits 0.
  if [[ "$HEALTH_UP" -eq 0 ]]; then
    record_skip "converged second run (needs health ports)"
  else
    for file in ca.pem server.pem server-key.pem agent.pem agent-key.pem agent-fingerprint; do
      printf 'test fixture\n' >"/etc/o3k/tls/$file"
      chmod 0600 "/etc/o3k/tls/$file"
    done
    # The wrapper validates the agent-id charset ([A-Za-z0-9._-]); the fixture
    # content must satisfy it, unlike the opaque TLS material above.
    printf 'compute-agent\n' >"/etc/o3k/tls/agent-id"
    chmod 0600 "/etc/o3k/tls/agent-id"
    fresh_logs converge
    publish_tarball "$MATRIX/good.tar.gz"
    if O3K_TEST_INSTALL_MODE=converge O3K_TEST_BOOTSTRAP_MODE=converge \
        run_wrapper "$out" "$err"; then
      record_pass "converged second run exits 0"
    else
      record_fail "converged second run failed (stderr: $(grep -aE "O3K installer|TestLab bootstrap|error" "$err" | tail -n2 | tr "\n" " "))"
    fi
    grep -Fq 'TLS identities preserved' "$out" \
      && record_pass "complete TLS set preserved" || record_fail "missing TLS-preserved line"
    grep -Fq 'configuration preserved' "$out" && grep -Fq 'credentials preserved' "$out" \
      && record_pass "configuration and credentials preserved" \
      || record_fail "missing configuration/credentials preserved lines"
    grep -Fq 'TestLab resources already present' "$out" \
      && record_pass "TestLab resources already present" || record_fail "missing TestLab-converged line"
    [[ ! -e "$O3K_TEST_CERT_LOG" ]] \
      && record_pass "valid TLS identities were not regenerated" \
      || record_fail "bootstrap-certs regenerated valid identities"
    if [[ -f /usr/local/share/o3k/.o3k-installed ]]; then
      grep -Fq 'already installed' "$out" \
        && record_pass "installed-manifest notice printed" \
        || record_fail "missing installed-manifest notice"
    fi
  fi

  # The PP.4 fixture install.sh installs /usr/local/share/o3k/release-manifest.json
  # like the real one (and the wrapper copies the demo material into
  # /usr/local/share/o3k/araf-demo/). The upgrade-fence cases below need the
  # manifest path ABSENT (they install their own fixture manifest and refuse
  # to touch foreign state), so drop the fixture-marked copies first; anything
  # without the fixture marker is foreign and left alone.
  if [[ "$USR_LOCAL_O3K_CREATED" -eq 1 ]]; then
    if [[ -f /usr/local/share/o3k/release-manifest.json ]] \
      && grep -q 'fixture-source-sha' /usr/local/share/o3k/release-manifest.json 2>/dev/null; then
      rm -f -- /usr/local/share/o3k/release-manifest.json
    fi
    if [[ -f /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh ]] \
      && grep -q 'TEST FIXTURE' /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh 2>/dev/null; then
      rm -rf -- /usr/local/share/o3k/araf-demo
    fi
    rmdir /usr/local/share/o3k 2>/dev/null || true
  fi

  # 18-21. upgrade fence (issue #626): a resolved target must never be
  #     auto-installed over an existing release. These cases drive the REAL
  #     fence with a fake installed release manifest at
  #     /usr/local/share/o3k/release-manifest.json; they run only when that
  #     path is absent so a real install is never touched. The upgrade
  #     download directory is redirected to a sandbox via the documented
  #     O3K_UPGRADE_DOWNLOAD_DIR override.
  if [[ -e /usr/local/share/o3k/release-manifest.json || -L /usr/local/share/o3k ]]; then
    record_skip "upgrade fence cases need an absent /usr/local/share/o3k/release-manifest.json (found one; refusing to touch it)"
  else
    mkdir -p /usr/local/share/o3k
    USR_LOCAL_O3K_CREATED=1
    export O3K_UPGRADE_DOWNLOAD_DIR="$MATRIX/upgrade-download"
    endpoint_gets() { # endpoint_gets PATH — count of GET lines for a request path
      grep -c "GET $1" "$MATRIX/endpoint-http.log" 2>/dev/null || true
    }

    # 18. installed version NEWER than the resolved target -> implicit
    #     downgrade refused, exit 1, nothing mutated, nothing downloaded.
    fresh_logs fence-newer
    printf '{"version":"0.5.0-alpha.1","profile":"libvirt"}\n' >/usr/local/share/o3k/release-manifest.json
    release_gets_before="$(endpoint_gets '/releases/v0.4.0-rc.9/')"
    expect_abort "upgrade fence refuses an implicit downgrade" \
      "installed v0.5.0-alpha.1 is newer than requested v0.4.0-rc.9; refusing implicit downgrade" \
      "$out" "$err"
    assert_no_script_run "no bundled script ran on an implicit downgrade"
    [[ ! -s "$O3K_TEST_APT_LOG" && ! -s "$O3K_TEST_SYSTEMCTL_LOG" ]] \
      && record_pass "implicit downgrade mutated nothing (no apt/systemd calls)" \
      || record_fail "implicit downgrade mutated the host (apt/systemctl ran)"
    [[ ! -e "$MATRIX/upgrade-download" ]] \
      && record_pass "implicit downgrade created no upgrade-download directory" \
      || record_fail "implicit downgrade created an upgrade-download directory"
    [[ "$(endpoint_gets '/releases/v0.4.0-rc.9/')" -eq "$release_gets_before" ]] \
      && record_pass "implicit downgrade downloaded nothing from the release endpoint" \
      || record_fail "implicit downgrade fetched release assets"

    # 19. installed version OLDER than the resolved target -> verified
    #     delegation download into the upgrade-download directory + the exact
    #     next command, exit 0, no service/binary mutation.
    fresh_logs fence-older
    printf '{"version":"0.2.0-alpha.2","profile":"libvirt"}\n' >/usr/local/share/o3k/release-manifest.json
    publish_tarball "$MATRIX/good.tar.gz"
    printf '#!/usr/bin/env sh\n# TEST FIXTURE install.sh release asset\n' \
      >"$WWW/releases/v0.4.0-rc.9/install.sh"
    if run_wrapper "$out" "$err"; then
      record_pass "upgrade fence delegates an older install (exit 0)"
    else
      record_fail "upgrade fence delegation failed (stderr: $(grep -aE "O3K installer|TestLab bootstrap|error" "$err" | tail -n2 | tr "\n" " "))"
    fi
    grep -Fq "Run: sudo $MATRIX/upgrade-download/o3k-0.4.0-rc.9/bin/o3k upgrade" "$out" \
      && record_pass "delegation prints the exact sudo o3k upgrade command" \
      || record_fail "missing delegation command (stdout: $(head -c 300 "$out"))"
    grep -Fq 'the installer never upgrades an existing installation automatically' "$out" \
      && record_pass "delegation notice states curl|sh never auto-upgrades" \
      || record_fail "missing no-auto-upgrade notice"
    [[ -f "$MATRIX/upgrade-download/o3k-0.4.0-rc.9-linux-x86_64.tar.gz" \
      && -f "$MATRIX/upgrade-download/o3k-0.4.0-rc.9-linux-x86_64.tar.gz.sha256" \
      && -f "$MATRIX/upgrade-download/install.sh" ]] \
      && record_pass "delegation download holds tarball + .sha256 + install.sh" \
      || record_fail "delegation download files incomplete"
    # The staged entry point must exist so the printed command is runnable:
    # extraction targets the download dir itself (the tarball root is
    # already o3k-<version>/; the first implementation double-nested it).
    [[ -f "$MATRIX/upgrade-download/o3k-0.4.0-rc.9/bin/o3k" ]] \
      && record_pass "delegation staged the o3k entry point (no double nesting)" \
      || record_fail "staged entry point missing: $MATRIX/upgrade-download/o3k-0.4.0-rc.9/bin/o3k"
    [[ "$(stat -c %a "$MATRIX/upgrade-download")" = "700" ]] \
      && record_pass "delegation directory is private (0700)" \
      || record_fail "delegation directory mode is not 0700"
    (cd "$MATRIX/upgrade-download" && sha256sum -c --strict -- o3k-0.4.0-rc.9-linux-x86_64.tar.gz.sha256 >/dev/null) \
      && record_pass "delegated tarball matches the published SHA-256" \
      || record_fail "delegated tarball failed published SHA-256"
    cmp -s "$WWW/releases/v0.4.0-rc.9/install.sh" "$MATRIX/upgrade-download/install.sh" \
      && record_pass "install.sh copy is byte-identical to the published asset" \
      || record_fail "install.sh copy drifted from the published asset"
    assert_no_script_run "no bundled script ran during delegation"
    [[ ! -s "$O3K_TEST_APT_LOG" && ! -s "$O3K_TEST_SYSTEMCTL_LOG" ]] \
      && record_pass "delegation performed no apt/systemd mutation" \
      || record_fail "delegation mutated the host (apt/systemctl ran)"
    [[ -z "$(find /usr/local/share/o3k -mindepth 1 -maxdepth 1 ! -name release-manifest.json -print -quit)" ]] \
      && record_pass "delegation wrote nothing else under /usr/local/share/o3k" \
      || record_fail "delegation mutated /usr/local/share/o3k"
    [[ "$(endpoint_gets '/releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz ')" -ge 1 ]] \
      && record_pass "delegation fetched the tarball + .sha256 + install.sh from the release endpoint" \
      || record_fail "release endpoint did not serve the delegation assets"

    # 20. delegation re-run: the existing verified tarball is REUSED (no
    #     re-download); only the install.sh asset copy is refreshed.
    fresh_logs fence-reuse
    tarball_gets_before="$(endpoint_gets '/releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz ')"
    install_gets_before="$(endpoint_gets '/releases/v0.4.0-rc.9/install.sh ')"
    if run_wrapper "$out" "$err"; then
      record_pass "delegation re-run exits 0"
    else
      record_fail "delegation re-run failed (stderr: $(head -c 300 "$err"))"
    fi
    [[ "$(endpoint_gets '/releases/v0.4.0-rc.9/o3k-0.4.0-rc.9-linux-x86_64.tar.gz ')" -eq "$tarball_gets_before" ]] \
      && record_pass "delegation re-run reuses the verified tarball (no re-download)" \
      || record_fail "delegation re-run re-downloaded the tarball"
    [[ "$(endpoint_gets '/releases/v0.4.0-rc.9/install.sh ')" -gt "$install_gets_before" ]] \
      && record_pass "delegation re-run refreshes the install.sh asset copy" \
      || record_fail "delegation re-run did not refresh the install.sh copy"
    assert_no_script_run "no bundled script ran on the delegation re-run"
    [[ ! -s "$O3K_TEST_APT_LOG" && ! -s "$O3K_TEST_SYSTEMCTL_LOG" ]] \
      && record_pass "delegation re-run remains non-mutating" \
      || record_fail "delegation re-run mutated the host"

    # 21. tampered delegated tarball: the re-verification fails closed and
    #     nothing runs (the interrupted-delegation reuse rule).
    fresh_logs fence-tamper
    printf 'tampered\n' >>"$MATRIX/upgrade-download/o3k-0.4.0-rc.9-linux-x86_64.tar.gz"
    expect_abort "tampered delegated tarball fails closed on re-run" \
      "published SHA-256 verification failed" "$out" "$err"
    assert_no_script_run "no bundled script ran on a tampered delegated tarball"
    [[ ! -s "$O3K_TEST_APT_LOG" && ! -s "$O3K_TEST_SYSTEMCTL_LOG" ]] \
      && record_pass "tampered delegation mutated nothing" \
      || record_fail "tampered delegation mutated the host"

    rm -f -- /usr/local/share/o3k/release-manifest.json
    rmdir /usr/local/share/o3k 2>/dev/null || true
    # NOTE: USR_LOCAL_O3K_CREATED intentionally stays set — it also covers the
    # o3k CLI shim and the Araf demo material the fixtures installed during
    # the success/converge cases, which the EXIT cleanup must still remove.
    unset O3K_UPGRADE_DOWNLOAD_DIR
  fi
}

# ------------------------------------------------- platform / version fence --

FUNCS="$WORK_DIR/get-o3k-functions.sh"
# Least invasive mechanism: the wrapper hardcodes /etc/os-release and has no
# self-test flag, so the shipped function definitions are extracted verbatim
# and exercised in subshells with faked inputs. The extraction pattern matches
# the top-level function braces exactly; a refactor that changes the shape
# fails the sanity check below instead of silently testing nothing.
sed -n '/^check_platform() {/,/^}/p; /^check_version_format() {/,/^}/p' \
  "$WRAPPER" >"$FUNCS"
if grep -q 'check_platform()' "$FUNCS" && grep -q 'check_version_format()' "$FUNCS"; then
  record_pass "platform/version guard functions extracted from packaging/get-o3k.sh"
else
  record_fail "could not extract check_platform/check_version_format from packaging/get-o3k.sh"
fi

expect_platform_fail() { # expect_platform_fail DESC KERNEL MACHINE ID CODENAME MESSAGE
  local desc="$1" kernel="$2" machine="$3" distro="$4" codename="$5" message="$6" output=""
  if output="$(bash -c 'source "$1"; check_platform "$2" "$3" "$4" "$5"' \
      bash "$FUNCS" "$kernel" "$machine" "$distro" "$codename" 2>&1)"; then
    record_fail "$desc (expected non-zero exit)"
    return
  fi
  if printf '%s\n' "$output" | grep -Fq -- "$message"; then
    record_pass "$desc"
  else
    record_fail "$desc (missing message: $message; output: $output)"
  fi
}

expect_platform_fail "unsupported kernel fails closed" FreeBSD x86_64 ubuntu noble \
  "unsupported kernel: FreeBSD"
expect_platform_fail "unsupported architecture fails closed" Linux aarch64 ubuntu noble \
  "unsupported architecture: aarch64"
expect_platform_fail "unsupported distribution fails closed" Linux x86_64 fedora 40 \
  "unsupported distribution: fedora 40"
expect_platform_fail "unsupported distro codename fails closed" Linux x86_64 ubuntu jammy \
  "unsupported distribution: ubuntu jammy"
if bash -c 'source "$1"; check_platform Linux x86_64 ubuntu noble; check_platform Linux x86_64 debian bookworm' \
  bash "$FUNCS" >/dev/null 2>&1; then
  record_pass "supported platforms (Ubuntu 24.04, Debian 12) pass the guard"
else
  record_fail "supported platforms rejected by check_platform"
fi

expect_version_fail() { # expect_version_fail DESC VERSION
  if bash -c 'source "$1"; check_version_format "$2"' bash "$FUNCS" "$2" >/dev/null 2>&1; then
    record_fail "$1 (accepted $2)"
  else
    record_pass "$1"
  fi
}

expect_version_fail "version fence rejects 'main'" main
expect_version_fail "version fence rejects 'latest'" latest
expect_version_fail "version fence rejects three-dot versions" v1.2.3.4
expect_version_fail "version fence rejects control characters" 'v1.2.3;rm -rf /'
expect_version_fail "version fence rejects slashes" v0.2.0/alpha
if bash -c 'source "$1"; check_version_format v0.4.0-rc.9; check_version_format 0.4.0-alpha.1; check_version_format v0.2.0-alpha.1; check_version_format 1.2' \
  bash "$FUNCS" >/dev/null 2>&1; then
  record_pass "version fence accepts published release shapes"
else
  record_fail "version fence rejected a valid release version"
fi

# --------------------------------------------- upgrade fence unit tests ------

FENCE_FUNCS="$WORK_DIR/get-o3k-fence-functions.sh"
# Same extraction mechanism as the platform/version guards: the embedded
# python3 comparator and manifest reader are exercised with faked inputs in
# subshells, against the exact shipped text.
sed -n '/^compare_versions() {/,/^}/p; /^read_installed_version() {/,/^}/p' \
  "$WRAPPER" >"$FENCE_FUNCS"
if grep -q 'compare_versions()' "$FENCE_FUNCS" && grep -q 'read_installed_version()' "$FENCE_FUNCS"; then
  record_pass "upgrade fence functions extracted from packaging/get-o3k.sh"
else
  record_fail "could not extract compare_versions/read_installed_version from packaging/get-o3k.sh"
fi

expect_compare() { # expect_compare DESC LEFT RIGHT EXPECTED_EXIT
  local desc="$1" left="$2" right="$3" expected="$4" status=0
  set +e
  bash -c 'source "$1"; compare_versions "$2" "$3"' bash "$FENCE_FUNCS" "$left" "$right" >/dev/null 2>&1
  status=$?
  set -e
  [[ "$status" -eq "$expected" ]] \
    && record_pass "$desc" \
    || record_fail "$desc (exit $status, expected $expected)"
}

expect_compare "compare: older release sorts below newer (exit 0)" 0.2.0-alpha.2 0.4.0-alpha.1 0
expect_compare "compare: equal versions (exit 1)" v0.4.0-rc.9 0.4.0-rc.9 1
expect_compare "compare: newer release sorts above older (exit 2)" 0.4.0-alpha.1 0.2.0-alpha.2 2
expect_compare "compare: prerelease increments" 0.3.0-alpha.1 0.3.0-alpha.2 0
expect_compare "compare: prerelease is older than its release" 0.3.0-alpha.1 0.3.0 0
expect_compare "compare: release is newer than its prerelease" 0.3.0 0.3.0-alpha.1 2
expect_compare "compare: two-dot form equals padded three-dot" 1.2 1.2.0 1
expect_compare "compare: numeric prerelease identifiers order numerically" 0.3.0-alpha.2 0.3.0-alpha.10 0
expect_compare "compare: unparseable input fails closed (exit 3)" latest 0.4.0-alpha.1 3
expect_compare "compare: unparseable right side fails closed (exit 3)" 0.4.0-alpha.1 '0.3.0;rm' 3

fence_manifest="$WORK_DIR/fence-manifest.json"
printf '{"version":"0.4.0-alpha.1","profile":"libvirt"}\n' >"$fence_manifest"
if [[ "$(bash -c 'source "$1"; read_installed_version "$2"' bash "$FENCE_FUNCS" "$fence_manifest" 2>/dev/null)" = "0.4.0-alpha.1" ]]; then
  record_pass "read_installed_version parses the release manifest version"
else
  record_fail "read_installed_version did not parse the release manifest version"
fi
if [[ -z "$(bash -c 'source "$1"; read_installed_version "$2"' bash "$FENCE_FUNCS" "$WORK_DIR/absent-manifest.json" 2>/dev/null)" ]]; then
  record_pass "read_installed_version is empty for a fresh host (absent manifest)"
else
  record_fail "read_installed_version returned a version for an absent manifest"
fi
printf 'not json\n' >"$WORK_DIR/bad-fence-manifest.json"
set +e
bash -c 'source "$1"; read_installed_version "$2"' bash "$FENCE_FUNCS" "$WORK_DIR/bad-fence-manifest.json" >/dev/null 2>&1
bad_manifest_status=$?
set -e
[[ "$bad_manifest_status" -ne 0 ]] \
  && record_pass "read_installed_version fails closed on a malformed manifest" \
  || record_fail "read_installed_version accepted a malformed manifest"
printf '{"version":""}\n' >"$WORK_DIR/empty-fence-manifest.json"
set +e
bash -c 'source "$1"; read_installed_version "$2"' bash "$FENCE_FUNCS" "$WORK_DIR/empty-fence-manifest.json" >/dev/null 2>&1
empty_manifest_status=$?
set -e
[[ "$empty_manifest_status" -ne 0 ]] \
  && record_pass "read_installed_version fails closed on an empty version field" \
  || record_fail "read_installed_version accepted an empty version field"

# ------------------------------------------------------ full-wrapper matrix --

run_full_matrix

printf 'installer negative tests: %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[[ $FAIL -eq 0 ]]
