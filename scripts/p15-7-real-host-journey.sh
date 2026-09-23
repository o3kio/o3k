#!/usr/bin/env bash
set -Eeuo pipefail

# Protected P15.7 journey. The workflow variable is only a launcher; this
# repository-owned driver performs real joins and fails closed on missing
# evidence boundaries.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${O3K_REAL_HOST_ARTIFACT_DIR:-$ROOT_DIR/target/real-host-workflow-artifacts}"
EVIDENCE_FILE="${O3K_P15_7_EVIDENCE_FILE:-$ARTIFACT_DIR/p15-7-scale-composition-evidence.json}"
RUN_ID="${GITHUB_RUN_ID:-local-$$}"
SOURCE_SHA="${O3K_P15_7_SOURCE_SHA:-${GITHUB_SHA:-}}"
PROFILE="${O3K_P15_7_PROFILE:-small-edge-cloud}"
DIAGNOSTIC_ONLY="${O3K_P15_7_DIAGNOSTIC_ONLY:-false}"
AUTHORITY_MODE="${O3K_P15_7_AUTHORITY_MODE:-testlab-keycloak}"
KEYCLOAK_AUTHORITY_SCRIPT="${O3K_P15_7_KEYCLOAK_AUTHORITY_SCRIPT:-$ROOT_DIR/scripts/p15-7-keycloak-authority.sh}"
STATE_ROOT="${O3K_TESTLAB_STATE_ROOT:-/var/lib/o3k-testlab/$RUN_ID}"
TLS_ROOT="$STATE_ROOT/tls"
WORK_ROOT="${RUNNER_TEMP:-/tmp}/o3k-p15-7-journey-$RUN_ID"
HOST_IMAGE="${O3K_P15_7_HOST_IMAGE_PATH:-}"
HOST_IMAGE_SHA256="${O3K_P15_7_HOST_IMAGE_SHA256:-}"
# The pinned Ubuntu image boots the genuine compute hosts. Workloads use the
# separately verified, run-scoped generic TestLab image. Keeping these image
# roles distinct avoids uploading the much larger host image through the
# compatibility image API while preserving the host-image digest gate.
WORKLOAD_IMAGE="${O3K_TESTLAB_IMAGE_PATH:-}"
O3K_TESTLAB_IMAGE_PATH="$WORKLOAD_IMAGE"
WORKLOAD_IMAGE_MARKER="${WORKLOAD_IMAGE}.o3k-owned"
NETWORK="${O3K_P15_7_LIBVIRT_NETWORK:-default}"
LIBVIRT_IMAGE_ROOT="/var/lib/libvirt/images"
LIBVIRT_STORAGE_ROOT="$LIBVIRT_IMAGE_ROOT/o3k-p15-7-$RUN_ID"
AUTH_PORT="${O3K_TESTLAB_PORT:-28080}"
CONTROL_PORT="${O3K_TESTLAB_CONTROL_PORT:-28551}"
PG_CONTAINER="${O3K_P15_7_PG_CONTAINER:-o3k-p15-7-postgres-$RUN_ID}"
# PostgreSQL ownership. `disposable` (the default) consumes a harness-owned
# container and keeps the historical restart/failure gate. `external` consumes
# a required, operator-owned PostgreSQL endpoint through O3K_DATABASE_URL and
# must never start/stop/restart/drop that server. External mode exists because
# the PP.5 host cannot publish container ports, so a disposable container is
# unreachable from the control plane.
POSTGRES_MODE="${O3K_P15_7_POSTGRES_MODE:-disposable}"
# In external mode the run-owned proxy listens on this local port and forwards
# to the operator-owned target ($O3K_P15_7_EXTERNAL_PG_TARGET). The control
# plane consumes O3K_DATABASE_URL through the proxy, which is what makes an
# external fault injecting a sever/restore of the proxy safe and reversible.
POSTGRES_PROXY_PORT="${O3K_P15_7_POSTGRES_PROXY_PORT:-25432}"
POSTGRES_SERVER_VERSION=""
POSTGRES_SCHEMA_PREPARED=""
POSTGRES_REDACTED_ENDPOINT=""
# Effective-backend evidence. In external mode these are assigned only after
# the identity-verified restart and the fail-closed backend proofs below; in
# disposable mode they are derived from the bootstrap-written o3kd.env.
BACKEND_EFFECTIVE=""
BACKEND_PROOF_METHOD=""
BACKEND_PROOF_POOL_SESSIONS=""
BACKEND_PROOF_SEVER_OBSERVED=false
BACKEND_PROOF_RECOVERY_OBSERVED=false
API="http://127.0.0.1:$AUTH_PORT/o3k/v1"
ARAF_URL="${O3K_P15_7_ARAF_URL:-}"
ARAF_STATUS="not_configured"
ARAF_REASON="external_consumer_not_provisioned"
VM_USER="${O3K_P15_7_VM_USER:-o3k}"
VM_DISK_SIZE_GB="${O3K_P15_7_VM_DISK_SIZE_GB:-10}"
COMPUTE_LOG_FILTER="${O3K_COMPUTE_LOG_FILTER:-warn}"
# A region is an optional topology declaration, not an OpenStack display
# default.  The disposable daemon has no declared region unless the runner
# explicitly supplies one; sending the historical `RegionOne` string would
# therefore make the canonical join fail closed with a 400.
JOIN_REGION="${O3K_P15_7_REGION:-}"
P15_PROVISION_DIAGNOSTICS_CAPTURED=false
P15_WORKLOAD_DIAGNOSTICS_CAPTURED=false
# Transient-failure instrumentation: every bounded-retry event and every
# observed 5xx observed by the journey is appended to this JSONL fragment and
# merged into the final evidence under journey.transient_failures[].
TRANSIENT_EVENTS_FILE="$ARTIFACT_DIR/p15-7-transient-failures.jsonl"
# True only while the #1035 endpoint-release fault hook is present in the
# control-plane environment, so transient events can be correlated with the
# injected window.
FAULT_ACTIVE=false
O3K_FAULT_ENV_NAME="O3K_TEST_FAULT_PAUSE_BEFORE_ENDPOINT_RELEASE_MS"
# The pause must be long enough for the journey to observe the durable
# terminal delete and kill the control plane inside the window, and short
# enough to keep the bounded delete request and the protected-run budget
# honest. 45s covers terminalization observation (~seconds) plus assertions.
O3K_FAULT_ENV_VALUE="${O3K_P15_7_FAULT_PAUSE_MS:-45000}"
# The bootstrap compute-agent is genuine Small Edge compute capacity by
# product design (SPEC-0048 §4.1/§5): the canonical TestLab init/join enrolls
# it with real inventory, and no accepted document excludes it from capacity.
# Its identity is read from the durable TLS state, never hardcoded, and the
# bootstrap BuildingBlock counts toward every scale tier under the
# eligibility rule recorded in the evidence.
BOOTSTRAP_AGENT_ID=""
die() { echo "P15.7 journey blocked: $*" >&2; exit 1; }
[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] || die "run id is unsafe"
[[ "$DIAGNOSTIC_ONLY" == true || "$DIAGNOSTIC_ONLY" == false ]] || die "diagnostic mode is invalid"
if [[ "$DIAGNOSTIC_ONLY" == true ]]; then
  [[ "$EVIDENCE_FILE" != "$ARTIFACT_DIR/p15-7-scale-composition-evidence.json" ]] \
    || die "diagnostic mode requires a separate non-completion artifact path"
fi
[[ "$VM_USER" =~ ^[A-Za-z_][A-Za-z0-9._-]*$ ]] || die "VM user is unsafe"
[[ "$AUTH_PORT" =~ ^[0-9]+$ && "$CONTROL_PORT" =~ ^[0-9]+$ ]] || die "TestLab ports are invalid"
[[ "$VM_DISK_SIZE_GB" =~ ^[1-9][0-9]*$ ]] || die "VM disk size is invalid"
[[ "$COMPUTE_LOG_FILTER" =~ ^[A-Za-z0-9_=,:.-]+$ ]] || die "compute log filter is invalid"
for cmd in curl python3 realpath virsh virt-install qemu-img genisoimage ssh scp sha256sum ssh-keygen openssl openstack sudo id; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command unavailable: $cmd"
done
[[ "$POSTGRES_MODE" == external || "$POSTGRES_MODE" == disposable ]] \
  || die "postgres ownership mode is invalid: $POSTGRES_MODE"
[[ "$POSTGRES_PROXY_PORT" =~ ^[1-9][0-9]{3,4}$ ]] || die "postgres proxy port is invalid"
if [[ "$POSTGRES_MODE" == external ]]; then
  [[ -n "${O3K_DATABASE_URL:-}" ]] || die "external PostgreSQL mode requires O3K_DATABASE_URL"
  [[ -n "${O3K_P15_7_EXTERNAL_PG_TARGET:-}" ]] \
    || die "external PostgreSQL mode requires O3K_P15_7_EXTERNAL_PG_TARGET (real pg host:port for the run-owned proxy)"
  [[ "$O3K_P15_7_EXTERNAL_PG_TARGET" =~ ^[A-Za-z0-9_.:\-]+$ ]] || die "external PostgreSQL target is unsafe"
  command -v psql >/dev/null 2>&1 || die "external PostgreSQL mode requires psql"
fi
RUNNER_UID="$(id -u)"
RUNNER_GID="$(id -g)"
LIBVIRT_QEMU_GROUP="$(id -gn libvirt-qemu 2>/dev/null || true)"
[[ "$LIBVIRT_QEMU_GROUP" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || die "libvirt-qemu account unavailable"
SSH_KEY="$WORK_ROOT/vm.key"
KNOWN_HOSTS="$WORK_ROOT/known_hosts"
RUNNER_TEMP_ROOT="${RUNNER_TEMP:-/tmp}"
[[ "$RUNNER_TEMP_ROOT" == /* && "$RUNNER_TEMP_ROOT" != *..* && -d "$RUNNER_TEMP_ROOT" && ! -L "$RUNNER_TEMP_ROOT" ]] \
  || die "runner temp root is unsafe"
RUNNER_TEMP_ROOT="$(realpath -e -- "$RUNNER_TEMP_ROOT")"
WORK_ROOT="$RUNNER_TEMP_ROOT/o3k-p15-7-journey-$RUN_ID"
SSH_KEY="$WORK_ROOT/vm.key"
KNOWN_HOSTS="$WORK_ROOT/known_hosts"
[[ ! -e "$WORK_ROOT" ]] || die "run-owned journey workspace already exists"
mkdir -p "$ARTIFACT_DIR" "$WORK_ROOT"; chmod 0700 "$WORK_ROOT"
printf 'o3k-p15-7-journey-owned-v1\nrun=%s\n' "$RUN_ID" >"$WORK_ROOT/.o3k-owned"
chmod 0600 "$WORK_ROOT/.o3k-owned"
pg_redact_endpoint() {
  # Credentials must never leak into output or evidence. Mask everything between
  # the scheme and the '@' so the password is never echoed as part of a URL.
  python3 - "$1" <<'PY'
import sys
url = sys.argv[1]
sep = url.find('@')
if sep == -1:
    print(url, end=''); raise SystemExit(0)
head = url[:sep]
j = head.find('://')
print(head[:j+3] + 'REDACTED' + url[sep:], end='')
PY
}
pg_external_ready() {
  # Reachability and all version/schema probes run as read-only SELECT/SHOW
  # through O3K_DATABASE_URL; nothing is mutated, created, or dropped.
  psql "$O3K_DATABASE_URL" -v ON_ERROR_STOP=1 -tAc 'SELECT 1' >/dev/null 2>&1
}
write_postgres_proxy() {
  # Stage the run-owned forwarder inside WORK_ROOT so its path is unique to this
  # run and the process identity check in stop_postgres_proxy cannot match a
  # foreign process. A single-process asyncio forward is used (no forking) so
  # $! is the reliable listener PID.
  cat >"$WORK_ROOT/pg-proxy.py" <<'PY'
import asyncio, sys
LISTEN = ("127.0.0.1", int(sys.argv[1]))
TARGET_HOST, TARGET_PORT = sys.argv[2].rsplit(":", 1)
TARGET = (TARGET_HOST, int(TARGET_PORT))
async def forward(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass
async def client(reader, writer):
    try:
        upstream_read, upstream_write = await asyncio.open_connection(*TARGET)
    except Exception:
        writer.close()
        return
    await asyncio.gather(forward(reader, upstream_write), forward(upstream_read, writer))
async def main():
    server = await asyncio.start_server(client, *LISTEN)
    async with server:
        await server.serve_forever()
asyncio.run(main())
PY
  chmod 0600 "$WORK_ROOT/pg-proxy.py"
}
start_postgres_proxy() {
  # A run-owned localhost TCP forward in front of the operator-owned endpoint.
  # The forwarder never starts/stops/restarts the target PostgreSQL; it only
  # forwards bytes, so severing it injects an unavailability that is fully
  # reversible. The proxy is bounded (fixed local port) and its identity is
  # recorded in a run-owned ownership file that cleanup requires before signal.
  [[ -f "$WORK_ROOT/pg-proxy.pid" ]] && return 0
  write_postgres_proxy
  python3 "$WORK_ROOT/pg-proxy.py" "$POSTGRES_PROXY_PORT" \
    "$O3K_P15_7_EXTERNAL_PG_TARGET" >>"$WORK_ROOT/pg-proxy.log" 2>&1 &
  local spid=$!
  printf '%s:o3k-p15-7-postgres-proxy:run=%s\n' "$spid" "$RUN_ID" \
    >"$WORK_ROOT/pg-proxy.pid"
  chmod 0600 "$WORK_ROOT/pg-proxy.pid"
  for _ in $(seq 1 30); do pg_external_ready && return 0; sleep 1; done
  return 1
}
stop_postgres_proxy() {
  # Sever the run-owned proxy. Signal only when the ownership file and the live
  # process both identify this exact run's forwarder path; anything else fails
  # closed rather than killing an unrelated process.
  local spid=""
  [[ -f "$WORK_ROOT/pg-proxy.pid" && ! -L "$WORK_ROOT/pg-proxy.pid" ]] || return 0
  grep -Fq 'o3k-p15-7-postgres-proxy' "$WORK_ROOT/pg-proxy.pid" || return 0
  grep -Fq "run=$RUN_ID" "$WORK_ROOT/pg-proxy.pid" || return 1
  spid="$(cut -d: -f1 "$WORK_ROOT/pg-proxy.pid")"
  [[ "$spid" =~ ^[0-9]+$ ]] || return 1
  [[ "$(ps -o args= -p "$spid" 2>/dev/null || true)" == *"$WORK_ROOT/pg-proxy.py"* ]] || return 1
  kill "$spid" 2>/dev/null || true
  for _ in $(seq 1 30); do kill -0 "$spid" 2>/dev/null || break; sleep 1; done
  kill -0 "$spid" 2>/dev/null && return 1
  rm -f -- "$WORK_ROOT/pg-proxy.pid"
}
pg_proxy_dsn() {
  # Rewrite the operator-owned DSN so it reaches the same server through the
  # run-owned localhost proxy. Only the host:port changes; credentials,
  # database, and query parameters are preserved byte-for-byte. The source DSN
  # arrives through the process environment (never argv) and the rewritten DSN
  # is never echoed; output is captured by the caller into a 0600-scoped shell
  # variable and any diagnostic output uses pg_redact_endpoint.
  O3K_SOURCE_DSN="$O3K_DATABASE_URL" python3 - "$POSTGRES_PROXY_PORT" <<'PY'
import os, sys, urllib.parse
port = sys.argv[1]
parts = urllib.parse.urlsplit(os.environ["O3K_SOURCE_DSN"])
if parts.scheme not in ("postgres", "postgresql") or not parts.hostname:
    raise SystemExit("external PostgreSQL DSN is not a postgres URL")
netloc = parts.netloc
at = netloc.rfind("@")
userinfo = netloc[: at + 1] if at != -1 else ""
print(urllib.parse.urlunsplit(parts._replace(netloc=userinfo + "127.0.0.1:" + port)))
PY
}
rewrite_o3kd_env_for_proxy() {
  # Point the production o3kd environment at the run-owned proxy. The
  # bootstrap-written file is consumed by `set -a; . o3kd.env`, so both lines
  # are required: the URL alone does not select the postgres backend. Every
  # other line is preserved exactly. The rewrite is staged in a 0600 runner
  # temp and installed atomically with the daemon account ownership the
  # bootstrap established; the rewritten credential never reaches stdout.
  local env_tmp expected_backend_line expected_url_line
  sudo -n test -r "$STATE_ROOT/o3kd.env" || die "o3kd environment is unreadable"
  env_tmp="$(mktemp "$RUNNER_TEMP_ROOT/o3kd-env.XXXXXX")"
  chmod 0600 "$env_tmp"
  sudo -n cat "$STATE_ROOT/o3kd.env" | awk '!/^O3K_DATABASE_(BACKEND|URL)=/' >"$env_tmp" \
    || { rm -f -- "$env_tmp"; die "cannot stage rewritten o3kd environment"; }
  printf 'O3K_DATABASE_BACKEND=%s\n' "$(printf '%q' "postgres")" >>"$env_tmp"
  printf 'O3K_DATABASE_URL=%s\n' "$(printf '%q' "$PROXY_DSN")" >>"$env_tmp"
  expected_backend_line='O3K_DATABASE_BACKEND=postgres'
  expected_url_line="O3K_DATABASE_URL=$(printf '%q' "$PROXY_DSN")"
  grep -Fqx "$expected_backend_line" "$env_tmp" \
    && grep -Fqx "$expected_url_line" "$env_tmp" \
    || { rm -f -- "$env_tmp"; die "rewritten o3kd environment failed its content check"; }
  sudo -n install -o "${O3K_REAL_HOST_DAEMON_ACCOUNT:-o3k}" -g "${O3K_REAL_HOST_DAEMON_ACCOUNT:-o3k}" -m 0600 \
    "$env_tmp" "$STATE_ROOT/o3kd.env" \
    || { rm -f -- "$env_tmp"; die "cannot install rewritten o3kd environment"; }
  rm -f -- "$env_tmp"
  sudo -n grep -Fqx "$expected_backend_line" "$STATE_ROOT/o3kd.env" \
    && sudo -n grep -Fqx "$expected_url_line" "$STATE_ROOT/o3kd.env" \
    || die "installed o3kd environment does not carry the proxy database configuration"
}
bootstrap_store_probe() {
  # Minting an enrollment grant is the cheapest authenticated write that
  # exercises the durable store. While the proxy is severed this must fail;
  # after restore it must succeed. Grant JSON and the bootstrap secret never
  # reach stdout.
  O3K_API_URL="$API" O3K_BOOTSTRAP_SECRET="$(sudo -n cat "$STATE_ROOT/.bootstrap-secret")" \
    "$STATE_ROOT/bin/o3k" init --profile-id default --agent-id compute-agent >/dev/null 2>&1
}
rejoin_bootstrap_agent() {
  # Re-establish the canonical bootstrap identity on the current backend after
  # the backend switch: the enrollment the bootstrap performed lives in the
  # previous backend and does not exist on the operator-owned PostgreSQL.
  # Without it the bootstrap readiness gate keeps /readyz down and the
  # TestLab bootstrap block is missing from the canonical topology. This is
  # the same production authenticated init/join path
  # bootstrap-disposable-testlab.sh uses, reusing the durable TLS identity the
  # canonical bootstrap already recorded.
  local agent_id enrollment_token agent_epoch vcpus memory_mb join_attempt init_output
  agent_id="$(sudo -n cat "$STATE_ROOT/tls/agent-id")"
  [[ "$agent_id" =~ ^[A-Za-z0-9._-]+$ ]] || die "bootstrap agent identity is unavailable"
  init_output="$WORK_ROOT/bootstrap-rejoin-init.json"
  O3K_API_URL="$API" O3K_BOOTSTRAP_SECRET="$(sudo -n cat "$STATE_ROOT/.bootstrap-secret")" \
    "$STATE_ROOT/bin/o3k" init --profile-id default --agent-id "$agent_id" >"$init_output" \
    || die "bootstrap re-init failed after the PostgreSQL backend switch"
  enrollment_token="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("enrollment_token", ""))' "$init_output")"
  [[ -n "$enrollment_token" ]] || die "bootstrap re-init grant is missing"
  agent_epoch="$(openssl rand -hex 16)"
  vcpus="$(nproc --all 2>/dev/null || true)"
  memory_mb="$(awk '/^MemTotal:/ {print int($2 / 1024); exit}' /proc/meminfo)"
  [[ "$vcpus" =~ ^[1-9][0-9]*$ && "$memory_mb" =~ ^[1-9][0-9]*$ ]] \
    || die "host inventory is unavailable for the bootstrap re-join"
  for join_attempt in $(seq 1 5); do
    if O3K_API_URL="$API" "$STATE_ROOT/bin/o3k" join --token "$enrollment_token" \
      --agent-id "$agent_id" --agent-epoch "$agent_epoch" \
      --certificate "$STATE_ROOT/tls/agent.pem" \
      --vcpus "$vcpus" --memory-mb "$memory_mb" --disk-gb 10 >/dev/null; then
      return 0
    fi
    if ((join_attempt < 5)); then
      sleep 2
    fi
  done
  die "bootstrap re-join did not converge after the PostgreSQL backend switch"
}
wait_o3kd_readyz() {
  local message="$1"
  for _ in $(seq 1 60); do curl --fail --silent "http://127.0.0.1:$AUTH_PORT/readyz" >/dev/null 2>&1 && break; sleep 1; done
  curl --fail --silent "http://127.0.0.1:$AUTH_PORT/readyz" >/dev/null 2>&1 || die "$message"
}
read_o3kd_ledger() {
  # Read the run-owned o3kd ownership ledger and verify the recorded process
  # identity (owner uid, start ticks, executable path). No process-name lookup
  # is ever used. Prints "pid" on stdout; fails closed on identity drift.
  local PID_ROOT pid ticks uid binary extra
  PID_ROOT="${O3K_TESTLAB_PID_ROOT:-${RUNNER_TEMP:-/tmp}/o3k-testlab-pids/$RUN_ID}"
  IFS='|' read -r pid ticks uid binary extra <"$PID_ROOT/o3kd.pid"
  [[ -z "${extra:-}" && "$pid" =~ ^[0-9]+$ && "$ticks" =~ ^[0-9]+$ && "$uid" =~ ^[A-Za-z0-9._-]+$ && "$binary" == o3kd ]] || die "invalid o3kd ownership ledger"
  [[ "$(sudo -n stat -c '%U' "/proc/$pid" 2>/dev/null || true)" == "$uid" ]] || die "o3kd PID ownership changed"
  [[ "$(sudo -n awk '{print $22}' "/proc/$pid/stat" 2>/dev/null || true)" == "$ticks" ]] || die "o3kd PID was reused"
  [[ "$(sudo -n readlink -f "/proc/$pid/exe" 2>/dev/null || true)" == "$STATE_ROOT/bin/o3kd" ]] || die "o3kd executable identity changed"
  printf '%s\n' "$pid"
}
start_o3kd_verified() {
  # Start the exact owned daemon from its run-scoped environment through the
  # normal boot path, wait until the control plane accepts HTTP, and record
  # the new ownership ledger entry. The caller waits for readiness separately
  # so backend-specific canonical state can be re-established first.
  local new_pid new_ticks new_uid candidate
  sudo -n -u "${O3K_REAL_HOST_DAEMON_ACCOUNT:-o3k}" -- setsid nohup bash -c 'set -a; . "$1"; set +a; exec "$2" >>"$3" 2>&1' _ "$STATE_ROOT/o3kd.env" "$STATE_ROOT/bin/o3kd" "$STATE_ROOT/log/o3kd.log" >/dev/null 2>&1 &
  new_pid=""
  for _ in $(seq 1 120); do
    while IFS= read -r candidate; do
      [[ -n "$candidate" ]] || continue
      [[ "$(sudo -n readlink -f "/proc/$candidate/exe" 2>/dev/null || true)" == "$STATE_ROOT/bin/o3kd" ]] \
        || continue
      new_pid="$candidate"
      break
    done < <(sudo -n pgrep -u "${O3K_REAL_HOST_DAEMON_ACCOUNT:-o3k}" -x o3kd 2>/dev/null || true)
    [[ "$new_pid" ]] && break
    sleep .25
  done
  [[ "$new_pid" ]] || die "o3kd restart failed"
  new_ticks="$(sudo -n awk '{print $22}' "/proc/$new_pid/stat")"
  new_uid="$(sudo -n stat -c '%U' "/proc/$new_pid")"
  [[ "$new_uid" == "${O3K_REAL_HOST_DAEMON_ACCOUNT:-o3k}" && "$(sudo -n readlink -f "/proc/$new_pid/exe")" == "$STATE_ROOT/bin/o3kd" ]] || die "restarted o3kd identity is not owned"
  printf '%s|%s|%s|o3kd\n' "$new_pid" "$new_ticks" "$new_uid" >"${O3K_TESTLAB_PID_ROOT:-${RUNNER_TEMP:-/tmp}/o3k-testlab-pids/$RUN_ID}/o3kd.pid"
  # Process existence is not serving readiness: o3kd binds AUTH_PORT only
  # after pool init/seeding, measured at ~0.3s best case and ~1.5-2s on the
  # canonical run on a fast idle host. The backend-switch rejoin fires an
  # authenticated `o3k init` immediately after this function returns (only
  # `join` has retries; `init` has none), so returning at process-detection
  # deterministically raced the bind with ECONNREFUSED. Wait until the
  # control plane accepts HTTP on AUTH_PORT. /readyz deliberately stays
  # gated behind the rejoin, so any HTTP response (e.g. 404) is the signal.
  local http_up=""
  for _ in $(seq 1 120); do
    if curl --silent --output /dev/null "http://127.0.0.1:$AUTH_PORT/" 2>/dev/null; then
      http_up=1
      break
    fi
    sleep .25
  done
  [[ "$http_up" ]] || die "restarted o3kd did not accept control-plane HTTP"
}
stop_o3kd_orderly() {
  local pid="$1"
  sudo -n kill -0 "$pid" 2>/dev/null || die "owned o3kd is not running"
  sudo -n kill "$pid"; for _ in $(seq 1 30); do sudo -n kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  sudo -n kill -0 "$pid" 2>/dev/null && die "owned o3kd did not stop"
}
kill9_o3kd_verified() {
  # True process death for the #1035 crash-injection leg: identity-verified
  # SIGKILL of the run-owned o3kd (NOT the orderly restart). This is the only
  # place a SIGKILL of the control plane is permitted; the ownership ledger,
  # uid, start ticks, and executable path must all match this run's daemon.
  local pid
  pid="$(read_o3kd_ledger)"
  sudo -n kill -0 "$pid" 2>/dev/null || die "owned o3kd is not running"
  sudo -n kill -9 "$pid"
  for _ in $(seq 1 30); do sudo -n kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  sudo -n kill -0 "$pid" 2>/dev/null && die "owned o3kd survived SIGKILL"
  printf '%s\n' "$pid"
}
restart_o3kd_verified() {
  # Restart the exact owned daemon from its run-scoped environment. Process
  # identity is read from the ownership ledger; no process-name kill is
  # permitted. The daemon re-sources the same run-scoped o3kd.env, so the
  # effective backend selected above is retained across the restart.
  stop_o3kd_orderly "$(read_o3kd_ledger)"
  start_o3kd_verified
}
append_o3kd_fault_env() {
  # Append the #1035 endpoint-release fault hook to the run-scoped o3kd
  # environment (root-owned; edited with the same sudo install boundary as
  # the PostgreSQL proxy rewrite). The control plane must be restarted
  # through restart_o3kd_verified before the hook takes effect.
  [[ "$O3K_FAULT_ENV_VALUE" =~ ^[0-9]+$ && "$O3K_FAULT_ENV_VALUE" -ge 1000 && "$O3K_FAULT_ENV_VALUE" -le 300000 ]] \
    || die "fault pause value is unsafe"
  sudo -n test -r "$STATE_ROOT/o3kd.env" || die "o3kd environment is unreadable"
  sudo -n grep -Fqx "$O3K_FAULT_ENV_NAME=$O3K_FAULT_ENV_VALUE" "$STATE_ROOT/o3kd.env" && { FAULT_ACTIVE=true; return 0; }
  printf '%s=%s\n' "$O3K_FAULT_ENV_NAME" "$O3K_FAULT_ENV_VALUE" \
    | sudo -n tee -a "$STATE_ROOT/o3kd.env" >/dev/null \
    || die "cannot append fault hook to o3kd environment"
  sudo -n grep -Fqx "$O3K_FAULT_ENV_NAME=$O3K_FAULT_ENV_VALUE" "$STATE_ROOT/o3kd.env" \
    || die "fault hook missing from o3kd environment"
  FAULT_ACTIVE=true
}
clear_o3kd_fault_env() {
  # Remove the fault hook line, preserving every other environment line
  # byte-for-byte and the daemon-account ownership. Idempotent; used by the
  # crash leg and by both cleanup traps so a failed leg can never strand the
  # pause on the production delete path.
  local env_tmp
  [[ "$FAULT_ACTIVE" == true ]] || return 0
  sudo -n test -r "$STATE_ROOT/o3kd.env" || { FAULT_ACTIVE=false; return 0; }
  env_tmp="$(mktemp "$RUNNER_TEMP_ROOT/o3kd-env-clear.XXXXXX")"
  chmod 0600 "$env_tmp"
  sudo -n cat "$STATE_ROOT/o3kd.env" | grep -Fvx "$O3K_FAULT_ENV_NAME=$O3K_FAULT_ENV_VALUE" >"$env_tmp" \
    || { rm -f -- "$env_tmp"; FAULT_ACTIVE=false; return 0; }
  sudo -n install -o "${O3K_REAL_HOST_DAEMON_ACCOUNT:-o3k}" -g "${O3K_REAL_HOST_DAEMON_ACCOUNT:-o3k}" -m 0600 \
    "$env_tmp" "$STATE_ROOT/o3kd.env" || { rm -f -- "$env_tmp"; FAULT_ACTIVE=false; return 0; }
  rm -f -- "$env_tmp"
  sudo -n grep -Fq "$O3K_FAULT_ENV_NAME=" "$STATE_ROOT/o3kd.env" || FAULT_ACTIVE=false
}
record_transient() {
  # Append one transient-failure observation to the run-scoped JSONL fragment:
  # kind (bounded_retry|http_5xx), the API surface, an optional detail/status,
  # the timestamp, and whether fault injection was active at the time.
  python3 - "$TRANSIENT_EVENTS_FILE" "$FAULT_ACTIVE" "$1" "$2" "${3:-}" "${4:-}" <<'PY'
import json, pathlib, sys, time
path, fault, kind, api, detail, status = sys.argv[1:7]
event = {
    "type": kind,
    "api": api,
    "at_unix_ms": int(time.time() * 1000),
    "fault_injection_active": fault == "true",
}
if detail:
    event["detail"] = detail
if status:
    event["http_status"] = status
try:
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
except OSError:
    pass
PY
}
capture_failure_diagnostics() {
  local exit_status="$1"
  [[ "$exit_status" -ne 0 && "$P15_PROVISION_DIAGNOSTICS_CAPTURED" == false ]] || return 0
  python3 "$ROOT_DIR/scripts/capture-p15-7-provision-diagnostics.py" \
    "$ARTIFACT_DIR/p15-7-provisioning-diagnostics.json" "$WORK_ROOT" "$SOURCE_SHA" "$RUN_ID" journey_failed \
    || echo "P15.7 journey diagnostics could not be safely captured" >&2
}
capture_workload_failure_diagnostics() {
  local workload_label="${1:-workload-b}" workload_file workload_id
  [[ "$P15_WORKLOAD_DIAGNOSTICS_CAPTURED" == false ]] || return 0
  [[ "$workload_label" =~ ^workload-[ab]$ && -n "${PROJECT_TOKEN:-}" ]] || return 0
  workload_file="$WORK_ROOT/${workload_label}.json"
  [[ -f "$workload_file" ]] || return 0
  workload_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("resource_id", ""))' "$workload_file" 2>/dev/null || true)"
  [[ "$workload_id" =~ ^[0-9a-fA-F-]{36}$ ]] || return 0
  local operation_id server_http operation_http agent index ip drain_id workload_domain runner_domain
  drain_id="${DRAIN_ID:-none}"
  operation_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("operation_id", ""))' \
    "$workload_file" 2>/dev/null || true)"
  [[ "$operation_id" =~ ^[0-9a-fA-F-]{36}$ ]] || return 0
  server_http="$(curl --silent --show-error --max-time 10 --output "$WORK_ROOT/${workload_label}-state.raw.json" \
    --write-out '%{http_code}' -H "Authorization: Bearer $PROJECT_TOKEN" \
    "$API/compute/servers/$workload_id" 2>/dev/null || true)"
  operation_http="$(curl --silent --show-error --max-time 10 --output "$WORK_ROOT/${workload_label}-operation.raw.json" \
    --write-out '%{http_code}' -H "Authorization: Bearer $PROJECT_TOKEN" \
    "$API/operations/$operation_id" 2>/dev/null || true)"
  chmod 0600 "$WORK_ROOT/${workload_label}-state.raw.json" "$WORK_ROOT/${workload_label}-operation.raw.json" 2>/dev/null || true
  index=0
  for agent in block-a block-b block-c block-d block-e; do
    ip="${IPS[$index]:-}"
    if [[ "$ip" =~ ^[0-9.]+$ ]]; then
      ssh_vm "$ip" "sudo grep -F '$operation_id' /var/log/o3k-compute.log 2>/dev/null | tail -n 80" \
        >"$WORK_ROOT/agent-$agent-events.raw.jsonl" 2>/dev/null || true
      chmod 0600 "$WORK_ROOT/agent-$agent-events.raw.jsonl" 2>/dev/null || true
      ssh_vm "$ip" "sudo grep -E '\"message\":\"(agent command received|command accepted|command acceptance rejected|command execution completed|command execution failed|create failed definitively; reporting terminal failure|libvirt create request|libvirt create failed|libvirt command failed|libvirt provider operation failed)\"' /var/log/o3k-compute.log 2>/dev/null | tail -n 96" \
        >"$WORK_ROOT/agent-$agent-message-probe.raw.jsonl" 2>/dev/null || true
      chmod 0600 "$WORK_ROOT/agent-$agent-message-probe.raw.jsonl" 2>/dev/null || true
      if probe="$(ssh_vm "$ip" "log_state=missing; if sudo test -f /var/log/o3k-compute.log; then log_state=\$(sudo stat -c 'present %s' /var/log/o3k-compute.log); fi; alive=0; sudo pgrep -x o3k-compute >/dev/null 2>&1 && alive=1; ready=0; curl --silent --show-error --max-time 2 http://127.0.0.1:19101/readyz >/dev/null 2>&1 && ready=1; printf '%s alive %s ready %s' \"\$log_state\" \"\$alive\" \"\$ready\"" 2>/dev/null)"; then
        printf '%s\n' "$probe" >"$WORK_ROOT/agent-$agent-log-probe.raw"
      else
        printf 'unreachable\n' >"$WORK_ROOT/agent-$agent-log-probe.raw"
      fi
      chmod 0600 "$WORK_ROOT/agent-$agent-log-probe.raw" 2>/dev/null || true
    fi
    index=$((index + 1))
  done
  # The bootstrap compute-agent runs on the runner, so capture its exact
  # operation events alongside the VM-backed agents.
  sudo -n grep -F "$operation_id" "$STATE_ROOT/log/o3k-compute.log" 2>/dev/null | tail -n 80 \
    >"$WORK_ROOT/agent-compute-agent-events.raw.jsonl" || true
  sudo -n grep -E '"message":"(agent command received|command accepted|command acceptance rejected|command execution completed|command execution failed|create failed definitively; reporting terminal failure|libvirt create request|libvirt create failed|libvirt command failed|libvirt provider operation failed)"' "$STATE_ROOT/log/o3k-compute.log" 2>/dev/null | tail -n 96 \
    >"$WORK_ROOT/agent-compute-agent-message-probe.raw.jsonl" || true
  if sudo -n test -f "$STATE_ROOT/log/o3k-compute.log"; then
    printf 'present %s alive %s ready %s\n' "$(sudo -n stat -c '%s' "$STATE_ROOT/log/o3k-compute.log" 2>/dev/null || echo 0)" \
      "$(sudo -n kill -0 "$(awk -F'|' '$4=="o3k-compute" {print $1; exit}' "${O3K_TESTLAB_PID_ROOT:-/tmp/none}/o3k-compute.pid" 2>/dev/null)" 2>/dev/null && echo 1 || echo 0)" \
      "$(curl --silent --show-error --max-time 2 "http://127.0.0.1:${O3K_TESTLAB_COMPUTE_HEALTH_PORT:-19101}/readyz" >/dev/null 2>&1 && echo 1 || echo 0)" \
      >"$WORK_ROOT/agent-compute-agent-log-probe.raw"
  else
    printf 'missing\n' >"$WORK_ROOT/agent-compute-agent-log-probe.raw"
  fi
  chmod 0600 "$WORK_ROOT/agent-compute-agent-events.raw.jsonl" "$WORK_ROOT/agent-compute-agent-message-probe.raw.jsonl" "$WORK_ROOT/agent-compute-agent-log-probe.raw" 2>/dev/null || true
  workload_domain="$(domain_name_for_resource "$workload_id")"
  capture_host_state block-a "${IPS[0]:-}" "$workload_domain"
  if [[ "$workload_id" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    runner_domain="$workload_domain"
    capture_host_state compute-agent "" "$runner_domain"
  fi
  python3 "$ROOT_DIR/scripts/capture-p15-7-workload-diagnostics.py" \
    "$ARTIFACT_DIR/p15-7-workload-failure-diagnostics.json" "$WORK_ROOT" \
    "$SOURCE_SHA" "$RUN_ID" "$workload_id" "$operation_id" \
    "${HOST_A:-unknown}" "${HOST_B:-unknown}" "$drain_id" \
    "$server_http" "$operation_http" "$workload_label" || echo "P15.7 workload diagnostics could not be safely captured" >&2
  P15_WORKLOAD_DIAGNOSTICS_CAPTURED=true
}
early_cleanup() {
  local exit_status=$?
  set +e
  capture_failure_diagnostics "$exit_status"
  clear_o3kd_fault_env >/dev/null 2>&1 || true
  if [[ "$AUTHORITY_MODE" == testlab-keycloak && -x "$KEYCLOAK_AUTHORITY_SCRIPT" ]]; then
    O3K_P15_7_AUTHORITY_MODE=testlab-keycloak O3K_P15_7_KEYCLOAK_STATE_ROOT="${O3K_P15_7_KEYCLOAK_STATE_ROOT:-${RUNNER_TEMP:-/tmp}/o3k-p15-7-keycloak-${RUN_ID}}" \
      GITHUB_RUN_ID="$RUN_ID" O3K_P15_7_SOURCE_SHA="$SOURCE_SHA" \
      bash "$KEYCLOAK_AUTHORITY_SCRIPT" cleanup >/dev/null 2>&1 || true
  fi
  if [[ "${POSTGRES_MODE:-}" == external ]]; then
    stop_postgres_proxy >/dev/null 2>&1 || true
  fi
  if [[ -f "$WORK_ROOT/.o3k-owned" ]] \
    && grep -Fqx 'o3k-p15-7-journey-owned-v1' "$WORK_ROOT/.o3k-owned" \
    && grep -Fqx "run=$RUN_ID" "$WORK_ROOT/.o3k-owned"; then
    rm -rf -- "$WORK_ROOT"
  fi
  if [[ -n "${LIBVIRT_STORAGE_ROOT:-}" ]] \
    && sudo -n test -f "$LIBVIRT_STORAGE_ROOT/.o3k-owned" \
    && sudo -n grep -Fqx 'o3k-p15-7-libvirt-storage-owned-v1' "$LIBVIRT_STORAGE_ROOT/.o3k-owned" \
    && sudo -n grep -Fqx "run=$RUN_ID" "$LIBVIRT_STORAGE_ROOT/.o3k-owned"; then
    sudo -n rm -f -- "$LIBVIRT_STORAGE_ROOT/.o3k-owned" "$LIBVIRT_STORAGE_ROOT/base.img" || true
    sudo -n rmdir -- "$LIBVIRT_STORAGE_ROOT" >/dev/null 2>&1 || true
  fi
}
trap early_cleanup EXIT
JOURNEY_START_MS="$(date +%s%3N)"
[[ "$SOURCE_SHA" =~ ^[0-9a-fA-F]{40}$ ]] || die "exact source SHA required"
[[ "$HOST_IMAGE" && -f "$HOST_IMAGE" && ! -L "$HOST_IMAGE" ]] || die "second_real_host_required: pinned VM image unavailable"
[[ "$HOST_IMAGE_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || die "pinned VM image digest required"
printf '%s  %s\n' "$HOST_IMAGE_SHA256" "$HOST_IMAGE" | sha256sum --check --strict --status || die "VM image digest mismatch"
[[ -n "$WORKLOAD_IMAGE" && -f "$WORKLOAD_IMAGE" && ! -L "$WORKLOAD_IMAGE" ]] || die "owned workload image unavailable"
[[ -f "$WORKLOAD_IMAGE_MARKER" && ! -L "$WORKLOAD_IMAGE_MARKER" ]] \
  || die "owned workload image marker unavailable"
grep -Fqx 'o3k-disposable-image-v1' "$WORKLOAD_IMAGE_MARKER" \
  || die "owned workload image marker is invalid"
grep -Fqx 'phase=generic' "$WORKLOAD_IMAGE_MARKER" \
  || die "owned workload image phase marker is invalid"
grep -Fqx "run=$RUN_ID" "$WORKLOAD_IMAGE_MARKER" \
  || die "owned workload image marker run mismatch"
[[ -f "$STATE_ROOT/.o3k-run-owned" && -f "$TLS_ROOT/ca.pem" ]] || die "owned TestLab state/TLS unavailable"
sudo -n test -d "$LIBVIRT_IMAGE_ROOT" && sudo -n test ! -L "$LIBVIRT_IMAGE_ROOT" \
  || die "libvirt image root unavailable"
O3K_P15_7_LIBVIRT_IMAGE_ROOT="$LIBVIRT_IMAGE_ROOT" \
  bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" assert-absent "$RUN_ID" "$LIBVIRT_STORAGE_ROOT" \
  || die "run-owned libvirt storage pool already exists"
sudo -n test ! -e "$LIBVIRT_STORAGE_ROOT" || die "run-owned libvirt storage workspace already exists"
sudo -n install -d -o root -g "$LIBVIRT_QEMU_GROUP" -m 0711 "$LIBVIRT_STORAGE_ROOT" \
  || die "cannot create run-owned libvirt storage workspace"
printf 'o3k-p15-7-libvirt-storage-owned-v1\nrun=%s\n' "$RUN_ID" >"$WORK_ROOT/.libvirt-storage-owned"
sudo -n install -o root -g "$LIBVIRT_QEMU_GROUP" -m 0640 "$WORK_ROOT/.libvirt-storage-owned" \
  "$LIBVIRT_STORAGE_ROOT/.o3k-owned" || die "cannot write libvirt storage ownership marker"
rm -f -- "$WORK_ROOT/.libvirt-storage-owned"
BASE_IMAGE="$LIBVIRT_STORAGE_ROOT/base.img"
sudo -n install -o root -g "$LIBVIRT_QEMU_GROUP" -m 0640 "$HOST_IMAGE" "$BASE_IMAGE" \
  || die "cannot stage pinned VM image for libvirt"
printf '%s  %s\n' "$HOST_IMAGE_SHA256" "$BASE_IMAGE" |
  sudo -n sha256sum --check --strict --status || die "staged VM image digest mismatch"
for required_agent in block-a block-b block-c block-d block-e; do
  sudo -n test -f "$TLS_ROOT/agents/$required_agent/agent.pem" \
    || die "canonical capacity/replacement identities unavailable"
  sudo -n test ! -L "$TLS_ROOT/agents/$required_agent/agent.pem" \
    || die "canonical agent certificate is a symlink: $required_agent"
done
# The bootstrap compute-agent's canonical identity comes from the durable TLS
# state the canonical bootstrap recorded. It is matched by identity (never by
# display name or a hardcoded assumption) when the scale checkpoints decide
# which BuildingBlock is the bootstrap block.
BOOTSTRAP_AGENT_ID="$(sudo -n cat "$STATE_ROOT/tls/agent-id" 2>/dev/null || true)"
[[ "$BOOTSTRAP_AGENT_ID" =~ ^[A-Za-z0-9._-]+$ ]] || die "bootstrap agent identity is unavailable"
if [[ "$POSTGRES_MODE" == external ]]; then
  # Consume a required, operator-owned endpoint. Fail closed on a missing or
  # unreachable endpoint, verify and record the server version, and verify the
  # O3K schema is prepared. The run-owned proxy in front of the endpoint is the
  # same path the control plane uses, so reachability here is the real gate.
  start_postgres_proxy || die "run-owned PostgreSQL proxy did not start"
  POSTGRES_REDACTED_ENDPOINT="$(pg_redact_endpoint "$O3K_DATABASE_URL")"
  pg_external_ready || die "external PostgreSQL endpoint unreachable: $POSTGRES_REDACTED_ENDPOINT"
  POSTGRES_SERVER_VERSION="$(psql "$O3K_DATABASE_URL" -v ON_ERROR_STOP=1 -tAc 'SHOW server_version' 2>/dev/null || true)"
  [[ "$POSTGRES_SERVER_VERSION" =~ ^[0-9]+\.[0-9]+ ]] \
    || die "external PostgreSQL server version unavailable: $POSTGRES_REDACTED_ENDPOINT"
  if [[ "$(psql "$O3K_DATABASE_URL" -v ON_ERROR_STOP=1 -tAc "SELECT to_regclass('public._sqlx_migrations') IS NOT NULL" 2>/dev/null || true)" == t ]]; then
    POSTGRES_SCHEMA_PREPARED=true
  else
    die "external PostgreSQL schema is not prepared: $POSTGRES_REDACTED_ENDPOINT"
  fi
  # The bootstrap started o3kd without database configuration (SQLite). Re-point
  # the run-scoped environment at the proxy and restart the exact owned daemon
  # BEFORE any journey phase so every subsequent durable write lands on the
  # operator-owned PostgreSQL through the run-owned proxy.
  PROXY_DSN="$(pg_proxy_dsn)" || die "cannot derive the run-owned proxy database URL"
  [[ "$PROXY_DSN" == *127.0.0.1:"$POSTGRES_PROXY_PORT"* ]] \
    || die "run-owned proxy database URL did not rewrite to the proxy endpoint"
  rewrite_o3kd_env_for_proxy
  restart_o3kd_verified
  # The previous backend's enrollment does not exist on the operator-owned
  # PostgreSQL; re-establish the canonical bootstrap identity through the
  # production authenticated init/join path before readiness is required.
  rejoin_bootstrap_agent
  wait_o3kd_readyz "readyz did not reconstruct after the PostgreSQL backend switch"
  # Effective-backend proof, fail closed: the bootstrap re-join already forced
  # pool activity, so the server must now show at least two sessions on this
  # database — the o3kd pool plus this proof's own psql connection. Nothing
  # else uses this database.
  BACKEND_PROOF_POOL_SESSIONS="$(psql "$PROXY_DSN" -v ON_ERROR_STOP=1 -tAc \
    'SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()' 2>/dev/null || true)"
  [[ "$BACKEND_PROOF_POOL_SESSIONS" =~ ^[1-9][0-9]*$ ]] \
    || die "effective backend proof could not count server sessions"
  [[ "$BACKEND_PROOF_POOL_SESSIONS" -ge 2 ]] \
    || die "o3kd is not durably connected through the run-owned proxy (sessions=$BACKEND_PROOF_POOL_SESSIONS)"
  # Transient dependency proof: severing the proxy must make the control plane
  # unhealthy within a bounded window (an authenticated durable-store write
  # fails fast once the backend is unreachable), and restoring it must bring
  # the API back. This is the fast-fail wiring check; the formal outage
  # evidence remains the late restart/failure gate below.
  stop_postgres_proxy || die "run-owned PostgreSQL proxy failed to sever for the wiring proof"
  for _ in $(seq 1 60); do
    if ! curl --fail --silent --max-time 2 "http://127.0.0.1:$AUTH_PORT/readyz" >/dev/null 2>&1; then
      BACKEND_PROOF_SEVER_OBSERVED=true
      break
    fi
    if ! bootstrap_store_probe; then
      BACKEND_PROOF_SEVER_OBSERVED=true
      break
    fi
    sleep 1
  done
  [[ "$BACKEND_PROOF_SEVER_OBSERVED" == true ]] \
    || die "o3kd stayed healthy while the PostgreSQL proxy was severed"
  start_postgres_proxy || die "run-owned PostgreSQL proxy failed to restore for the wiring proof"
  for _ in $(seq 1 60); do
    if curl --fail --silent --max-time 2 "http://127.0.0.1:$AUTH_PORT/readyz" >/dev/null 2>&1 \
      && bootstrap_store_probe; then
      BACKEND_PROOF_RECOVERY_OBSERVED=true
      break
    fi
    sleep 1
  done
  [[ "$BACKEND_PROOF_RECOVERY_OBSERVED" == true ]] \
    || die "o3kd did not recover after the PostgreSQL proxy was restored"
  BACKEND_EFFECTIVE="postgres"
  BACKEND_PROOF_METHOD="pg_stat_activity_pool_count_and_proxy_sever_restore"
elif [[ "$POSTGRES_MODE" == disposable ]]; then
  [[ "$(sudo -n docker inspect -f '{{.State.Running}}' "$PG_CONTAINER" 2>/dev/null || true)" == true ]] || die "run-scoped PostgreSQL unavailable"
  # Derive the effective backend honestly from the bootstrap-written
  # environment; the disposable workflow sets both database lines there. An
  # absent line means the o3kd default (sqlite) is in effect.
  BACKEND_EFFECTIVE="$(sudo -n grep -E '^O3K_DATABASE_BACKEND=' "$STATE_ROOT/o3kd.env" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
  [[ -n "$BACKEND_EFFECTIVE" ]] || BACKEND_EFFECTIVE="sqlite"
  BACKEND_PROOF_METHOD="o3kd_env_backend_configuration"
fi
for agent_id in block-a block-b block-c block-d block-e; do
  sudo -n install -m 0644 "$TLS_ROOT/agents/$agent_id/agent.pem" "$WORK_ROOT/$agent_id.pem" || die "cannot read canonical certificate: $agent_id"
  sudo -n install -o "$RUNNER_UID" -g "$RUNNER_GID" -m 0600 "$TLS_ROOT/agents/$agent_id/agent-key.pem" "$WORK_ROOT/$agent_id-key.pem" || die "cannot read canonical private key: $agent_id"
done

declare -a DOMAINS=() UUIDS=() OVERLAYS=() SEEDS=() SERIALS=() IPS=()
declare -A BLOCK_IDS=()
OS_IMAGE_ID="" OS_KEYPAIR_NAME="" OS_NETWORK_ID="" OS_SUBNET_ID="" OS_PORT_A_ID="" OS_PORT_B_ID="" OS_FLAVOR_ID=""
OS_WORKLOAD_A="" OS_WORKLOAD_B="" OS_WORKLOAD_C="" OS_WORKLOAD_D="" OS_WORKLOAD_M=""
# Run-scoped objects the #1035 crash-injection and #1033 maintenance legs
# create; each is deleted by its own leg and also guarded here so an aborted
# leg cannot strand owned state.
REUSE_PORT_ID=""
FOREIGN_NET_ID="" FOREIGN_SUBNET_ID="" FOREIGN_PORT_ID=""
CLEANUP_DONE=false
# Initialized before the EXIT trap because provisioning can fail before the
# canonical operator exchange assigns the run-scoped token path.
OPERATOR_TOKEN_FILE="${O3K_P15_7_OPERATOR_TOKEN_FILE:-}"
declare -A REPLAY_JOIN_BY_AGENT=()
OPERATOR_CURL_CONFIG=""
FOREIGN_PROJECT_ID=""
FOREIGN_TOKEN=""
FOREIGN_TOKEN_PROJECT_ID=""
CROSS_TENANT_CONCEALMENT=false
FOREIGN_BEFORE="$(virsh -c qemu:///system list --all --uuid 2>/dev/null | sed '/^$/d' | sort)"
openstack_absent_code() {
  local kind="$1" id="$2" output status
  output="$(openstack "$kind" show "$id" 2>&1)"; status=$?
  if ((status == 0)); then
    return 1
  fi
  # A missing object is an idempotent terminal state. Authentication,
  # transport, and policy failures are deliberately not treated as absence.
  if grep -Eiq '(^|[[:space:]])(404|not[[:space:]-]*found)([[:space:]]|$)|no .* (with a name or id|found)' <<<"$output"; then
    return 0
  fi
  return 2
}
delete_owned_openstack() {
  local kind="$1" id="$2"; shift 2
  local attempt code=2
  # A transient control-plane failure (5xx/transport, observed on run
  # 990923002 as "compute service is unavailable" during the final cleanup
  # immediately after the PostgreSQL fault gate) must not strand the cleanup
  # and turn an otherwise complete journey into a failed one. Retry a bounded
  # number of times; a genuinely unprovable outcome still fails closed.
  for attempt in $(seq 1 5); do
    if openstack "$kind" show "$id" >/dev/null 2>&1; then
      openstack "$kind" delete "$@" "$id" >/dev/null 2>&1 || true
    fi
    if openstack_absent_code "$kind" "$id"; then
      if ((attempt > 1)); then
        record_transient bounded_retry "openstack $kind delete" "attempts=$attempt outcome=absent"
      fi
      return 0
    fi
    code=$?
    sleep 2
  done
  record_transient bounded_retry "openstack $kind delete" "attempts=$attempt outcome=unproven" "5xx-or-transport"
  return "$code"
}
secure_remove_credentials() {
  local secret_file
  for secret_file in "$@"; do
    [[ -n "$secret_file" && -f "$secret_file" && ! -L "$secret_file" ]] || continue
    if command -v shred >/dev/null 2>&1; then
      shred --remove --zero --force -- "$secret_file" >/dev/null 2>&1 \
        || rm -f -- "$secret_file"
    else
      rm -f -- "$secret_file"
    fi
  done
}
cleanup() {
  local exit_status=$?
  set +e
  capture_failure_diagnostics "$exit_status"
  clear_o3kd_fault_env >/dev/null 2>&1 || true
  [[ "$CLEANUP_DONE" == true ]] && { set -e; return; }
  if [[ "$AUTHORITY_MODE" == testlab-keycloak && -x "$KEYCLOAK_AUTHORITY_SCRIPT" ]]; then
    O3K_P15_7_AUTHORITY_MODE=testlab-keycloak O3K_P15_7_KEYCLOAK_STATE_ROOT="${O3K_P15_7_KEYCLOAK_STATE_ROOT:-${RUNNER_TEMP:-/tmp}/o3k-p15-7-keycloak-${RUN_ID}}" \
      GITHUB_RUN_ID="$RUN_ID" O3K_P15_7_SOURCE_SHA="$SOURCE_SHA" \
      bash "$KEYCLOAK_AUTHORITY_SCRIPT" cleanup >/dev/null 2>&1 || true
  fi
  local cleanup_failed=false
  if [[ "$POSTGRES_MODE" == external ]]; then
    stop_postgres_proxy || cleanup_failed=true
  fi
  # Credentials and enrollment material are never retained for recovery.
  # Remove only this run's exact files; VM diagnostics and ownership records
  # remain available when cleanup itself is blocked.
  secure_remove_credentials "$OPERATOR_CURL_CONFIG" "$SSH_KEY" \
    "$WORK_ROOT"/block-*-key.pem
  if [[ "$AUTHORITY_MODE" == testlab-keycloak ]]; then
    # The native operator bearer is short-lived but still privileged.  It is
    # owned by this journey and must not survive a failed resource cleanup.
    # Keep only non-secret diagnostics when later cleanup steps are blocked.
    secure_remove_credentials "$OPERATOR_TOKEN_FILE" "$WORK_ROOT/operator.token"
    rm -f -- "$WORK_ROOT/operator.token.o3k-owned"
  fi
  rm -f -- "$WORK_ROOT"/block-*-init.json \
    "$WORK_ROOT"/block-*-join-request.json \
    "$WORK_ROOT"/block-*.pem
  # OpenStack objects are deleted by their recorded IDs in dependency order.
  # No name or prefix scan is used, so a failed journey cannot touch foreign
  # tenant resources. Keep IDs and the work directory when verification fails.
  for workload_id in "$OS_WORKLOAD_M" "$OS_WORKLOAD_D" "$OS_WORKLOAD_C" "$OS_WORKLOAD_B" "$OS_WORKLOAD_A"; do
    [[ "$workload_id" =~ ^[0-9a-fA-F-]{36}$ ]] || continue
    delete_owned_openstack server "$workload_id" --wait || cleanup_failed=true
  done
  if [[ "$FOREIGN_PORT_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    curl --silent --output /dev/null -X DELETE -H "X-Auth-Token: $FOREIGN_TOKEN" \
      "http://127.0.0.1:$AUTH_PORT/v2.0/ports/$FOREIGN_PORT_ID" || cleanup_failed=true
  fi
  if [[ "$FOREIGN_SUBNET_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    curl --silent --output /dev/null -X DELETE -H "X-Auth-Token: $FOREIGN_TOKEN" \
      "http://127.0.0.1:$AUTH_PORT/v2.0/subnets/$FOREIGN_SUBNET_ID" || cleanup_failed=true
  fi
  if [[ "$FOREIGN_NET_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    curl --silent --output /dev/null -X DELETE -H "X-Auth-Token: $FOREIGN_TOKEN" \
      "http://127.0.0.1:$AUTH_PORT/v2.0/networks/$FOREIGN_NET_ID" || cleanup_failed=true
  fi
  if [[ "$REUSE_PORT_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    delete_owned_openstack port "$REUSE_PORT_ID" || cleanup_failed=true
  fi
  if [[ "$OS_PORT_B_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    delete_owned_openstack port "$OS_PORT_B_ID" || cleanup_failed=true
  fi
  if [[ "$OS_PORT_A_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    delete_owned_openstack port "$OS_PORT_A_ID" || cleanup_failed=true
  fi
  if [[ "$OS_KEYPAIR_NAME" =~ ^o3k-p15-7-[A-Za-z0-9._-]+$ ]]; then
    delete_owned_openstack keypair "$OS_KEYPAIR_NAME" || cleanup_failed=true
  fi
  if [[ "$OS_FLAVOR_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
    delete_owned_openstack flavor "$OS_FLAVOR_ID" || cleanup_failed=true
  fi
  if [[ "$OS_SUBNET_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    delete_owned_openstack subnet "$OS_SUBNET_ID" || cleanup_failed=true
  fi
  if [[ "$OS_NETWORK_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    delete_owned_openstack network "$OS_NETWORK_ID" || cleanup_failed=true
  fi
  if [[ "$OS_IMAGE_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    delete_owned_openstack image "$OS_IMAGE_ID" || cleanup_failed=true
  fi
  for i in "${!DOMAINS[@]}"; do
    d="${DOMAINS[$i]}"; u="${UUIDS[$i]}"
    # The recorded UUID is the authoritative locator once provisioning
    # captured it; the name is a validation/display attribute only. When no
    # UUID was recorded (the VM failed before domuuid resolved), fall back to
    # the name for diagnosis. Ownership must be proven from the domain XML
    # before anything is destroyed.
    if [[ "$u" =~ ^[0-9a-fA-F-]{36}$ ]]; then
      virsh -c qemu:///system domstate "$u" >/dev/null 2>&1 || continue
      virsh -c qemu:///system dumpxml "$u" 2>/dev/null | grep -Fq "o3k-p15-7-journey-owned=$RUN_ID" || continue
      virsh -c qemu:///system destroy "$u" >/dev/null 2>&1 || true
      virsh -c qemu:///system undefine "$u" --nvram >/dev/null 2>&1 || virsh -c qemu:///system undefine "$u" >/dev/null 2>&1 || true
      if virsh -c qemu:///system domstate "$u" >/dev/null 2>&1; then
        echo "P15.7 cleanup: owned domain remains after destroy/undefine: $d ($u)" >&2
        cleanup_failed=true
      fi
      continue
    fi
    actual_uuid="$(virsh -c qemu:///system domuuid "$d" 2>/dev/null || true)"
    [[ "$actual_uuid" =~ ^[0-9a-fA-F-]{36}$ ]] || continue
    [[ -z "$u" || "$actual_uuid" == "$u" ]] || continue
    virsh -c qemu:///system dumpxml "$actual_uuid" 2>/dev/null | grep -Fq "o3k-p15-7-journey-owned=$RUN_ID" || continue
    virsh -c qemu:///system destroy "$actual_uuid" >/dev/null 2>&1 || true
    virsh -c qemu:///system undefine "$actual_uuid" --nvram >/dev/null 2>&1 || virsh -c qemu:///system undefine "$actual_uuid" >/dev/null 2>&1 || true
    if virsh -c qemu:///system domuuid "$d" >/dev/null 2>&1; then
      echo "P15.7 cleanup: owned domain remains after destroy/undefine: $d ($u)" >&2
      cleanup_failed=true
    fi
  done
  if [[ "$cleanup_failed" == false ]]; then
    O3K_P15_7_LIBVIRT_IMAGE_ROOT="$LIBVIRT_IMAGE_ROOT" \
      bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" cleanup "$RUN_ID" "$LIBVIRT_STORAGE_ROOT" \
      || cleanup_failed=true
  fi
  # Backing disks and the ownership marker are retained when a domain cannot
  # be proven absent. This preserves recovery evidence and prevents deleting
  # files still referenced by a live or undefined VM.
  if [[ "$cleanup_failed" == false ]]; then
    # The libvirt image directory is root-owned.  Remove only the exact paths
    # recorded for this run, using the same ownership boundary as staging.
    for p in "${SEEDS[@]}" "${OVERLAYS[@]}"; do
      if [[ -f "$p" ]]; then
        sudo -n rm -f -- "$p" || cleanup_failed=true
      fi
    done
    rm -f -- "$SSH_KEY" "$SSH_KEY.pub" "$KNOWN_HOSTS" \
      "$WORK_ROOT"/block-*-agent-id
    if [[ -f "$LIBVIRT_STORAGE_ROOT/.o3k-owned" ]] \
      && sudo -n grep -Fqx 'o3k-p15-7-libvirt-storage-owned-v1' "$LIBVIRT_STORAGE_ROOT/.o3k-owned" \
      && sudo -n grep -Fqx "run=$RUN_ID" "$LIBVIRT_STORAGE_ROOT/.o3k-owned"; then
      for p in "$BASE_IMAGE" "${SEEDS[@]}" "${OVERLAYS[@]}" "${SERIALS[@]}"; do
        [[ -n "$p" ]] || continue
        sudo -n rm -f -- "$p" || cleanup_failed=true
      done
      sudo -n rm -f -- "$LIBVIRT_STORAGE_ROOT/.o3k-owned" || cleanup_failed=true
      sudo -n rmdir -- "$LIBVIRT_STORAGE_ROOT" || cleanup_failed=true
    else
      echo "P15.7 cleanup blocked; libvirt storage ownership marker is missing or invalid" >&2
      cleanup_failed=true
    fi
  fi
  if [[ "$cleanup_failed" == false && -f "$WORK_ROOT/.o3k-owned" ]] \
    && grep -Fqx 'o3k-p15-7-journey-owned-v1' "$WORK_ROOT/.o3k-owned" \
    && grep -Fqx "run=$RUN_ID" "$WORK_ROOT/.o3k-owned"; then
    rm -rf -- "$WORK_ROOT"
  fi
  if [[ "$cleanup_failed" == true ]]; then
    echo "P15.7 cleanup blocked; owned VM records and backing files were retained" >&2
  else
    CLEANUP_DONE=true
  fi
  set -e
}
trap cleanup EXIT
assert_owned_domains_absent() {
  local i d u
  for i in "${!DOMAINS[@]}"; do
    d="${DOMAINS[$i]}"; u="${UUIDS[$i]}"
    if [[ "$u" =~ ^[0-9a-fA-F-]{36}$ ]]; then
      virsh -c qemu:///system domstate "$u" >/dev/null 2>&1 \
        && die "owned VM remains after cleanup: $d ($u)"
    else
      virsh -c qemu:///system domuuid "$d" >/dev/null 2>&1 \
        && die "owned VM remains after cleanup: $d"
    fi
  done
  for p in "${SEEDS[@]}" "${OVERLAYS[@]}"; do
    [[ ! -e "$p" ]] || die "owned VM artifact remains after cleanup: $p"
  done
}
virsh -c qemu:///system net-info "$NETWORK" >/dev/null 2>&1 || die "libvirt network unavailable"
# libvirt's XML serializer may use either single- or double-quoted attribute
# values. Parse the network document structurally so the gateway check does
# not depend on a presentation detail of `virsh net-dumpxml`.
GATEWAY="$(virsh -c qemu:///system net-dumpxml "$NETWORK" |
  python3 -c 'import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.stdin).getroot()
for element in root.iter():
    if element.tag.rsplit("}", 1)[-1] == "ip" and element.get("address"):
        print(element.get("address"))
        break' || true)"
[[ "$GATEWAY" =~ ^[0-9.]+$ ]] || die "libvirt gateway unavailable"
ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY" -C "o3k-p15-7-$RUN_ID" || die "VM SSH key generation failed"
touch "$KNOWN_HOSTS"
ssh_vm() { ssh -F /dev/null -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS" "$VM_USER@$1" "${@:2}"; }
domain_name_for_resource() {
  python3 - "$1" <<'PY'
import hashlib, sys
print("o3k-" + hashlib.sha256(sys.argv[1].encode("utf-8")).hexdigest()[:20])
PY
}
capture_host_state() {
  local label="$1" ip="$2" domain="$3" output
  output="$WORK_ROOT/${label}-host-state.raw"
  if [[ "$label" == block-a ]]; then
    {
      ssh_vm "$ip" 'hostname; pgrep -af "[o]3k-compute" || true'
      ssh_vm "$ip" 'sudo virsh -c qemu:///system uri; sudo virsh -c qemu:///system version; systemctl is-active libvirtd libvirtd.socket virtqemud virtqemud.socket virtlogd virtlogd.socket'
      ssh_vm "$ip" 'sudo test -r /dev/kvm; printf "kvm_readable=%s\\n" "$?"; sudo virsh -c qemu:///system nodeinfo; sudo virsh -c qemu:///system nodememstats; free -h; df -h / /var/lib/o3k-compute'
      ssh_vm "$ip" "sudo virsh -c qemu:///system dominfo '$domain'; sudo virsh -c qemu:///system domstate '$domain' --reason; sudo virsh -c qemu:///system dumpxml '$domain'"
      ssh_vm "$ip" "sudo virsh -c qemu:///system list --all; ps -eo pid,ppid,user,stat,args --sort=pid | grep '[q]emu' || true"
      ssh_vm "$ip" 'sudo find /var/lib/o3k-compute -maxdepth 4 -printf "%M %u %g %s %p\\n" | sort'
      ssh_vm "$ip" "ip -details link; bridge link; sudo virsh -c qemu:///system domiflist '$domain'; sudo virsh -c qemu:///system net-info default; sudo virsh -c qemu:///system net-dhcp-leases default"
      ssh_vm "$ip" 'command -v aa-status >/dev/null && sudo aa-status || true; command -v getenforce >/dev/null && getenforce || true; sudo journalctl --since "-10 min" -u libvirtd -u virtqemud -u virtlogd --no-pager -n 200 || true; sudo journalctl --since "-10 min" -k --no-pager -n 120 || true'
    } >"$output" 2>/dev/null || true
  else
    {
      printf '%s\n' '== runner successful execution path =='
      hostname
      virsh -c qemu:///system uri 2>&1 || true
      virsh -c qemu:///system version 2>&1 || true
      virsh -c qemu:///system dominfo "$domain" 2>&1 || true
      virsh -c qemu:///system domstate "$domain" --reason 2>&1 || true
      virsh -c qemu:///system dumpxml "$domain" 2>&1 || true
      virsh -c qemu:///system domiflist "$domain" 2>&1 || true
      virsh -c qemu:///system nodeinfo 2>&1 || true
      test -r /dev/kvm; printf 'kvm_readable=%s\n' "$?"
      free -h 2>&1 || true
      df -h / /var/lib/libvirt/images 2>&1 || true
      systemctl is-active libvirtd libvirtd.socket virtqemud virtqemud.socket virtlogd virtlogd.socket 2>&1 || true
      ps -eo pid,ppid,user,stat,args --sort=pid | grep '[q]emu' 2>&1 || true
      ip -details link show 2>&1 || true
      bridge link show 2>&1 || true
    } >"$output" 2>/dev/null || true
  fi
  chmod 0600 "$output" 2>/dev/null || true
}
vm_network_diagnostics() {
  local d="$1" uuid="$2" serial="$3" id="$4"
  # Keep a bounded-provisioning failure actionable without guessing an address
  # or weakening the real DHCP/SSH boundary. These queries are read-only and
  # scoped to the run-owned domain/network; they intentionally contain no
  # credentials. The recorded UUID is the locator; the name is echoed only as
  # a human-readable cross-check.
  echo "P15.7 network diagnostics for owned VM $id ($d, uuid=$uuid)" >&2
  virsh -c qemu:///system domstate "$uuid" >&2 || true
  virsh -c qemu:///system domstate "$d" >&2 || true
  virsh -c qemu:///system domiflist "$uuid" >&2 || true
  virsh -c qemu:///system domifaddr "$uuid" --source lease >&2 || true
  virsh -c qemu:///system domifaddr "$uuid" --source arp >&2 || true
  virsh -c qemu:///system net-dhcp-leases "$NETWORK" >&2 || true
  virsh -c qemu:///system net-dumpxml "$NETWORK" >&2 || true
  if [[ -n "$serial" ]]; then
    echo "P15.7 serial console tail for owned VM $id" >&2
    sudo -n tail -n 120 -- "$serial" >&2 || true
  fi
}
record_lease_evidence() {
  # Stale-DHCP resolver evidence (run 990923002 attempt 4 regression): for
  # one child VM, record the domain display name, the libvirt UUID, the
  # expected MAC from the domain interface XML, every candidate DHCP lease
  # bound to that MAC, the freshness projection from libvirt's dnsmasq status
  # JSON, the selected address, the selection reason, and the SSH liveness
  # proof. Assertions: the selection never prefers a stale same-MAC lease over
  # a fresher valid one (when freshness data is available), never selects a
  # cross-MAC address, and never selects the gateway. Freshness-source absence
  # is recorded honestly (the resolver then emits every MAC-bound candidate
  # and the SSH probe is the only liveness proof), never fabricated.
  local id="$1" d="o3k-p15-7-$RUN_ID-$1" uuid mac ip ssh_proof=false
  uuid="$(<"$WORK_ROOT/$id-uuid")"
  mac="$(<"$WORK_ROOT/$id-mac")"
  ip="$(<"$WORK_ROOT/$id-ip")"
  ssh_vm "$ip" true >/dev/null 2>&1 && ssh_proof=true
  python3 - "$d" "$uuid" "$mac" "$ip" "$NETWORK" "$GATEWAY" "$ssh_proof" \
    "$ARTIFACT_DIR/p15-7-vm-lease-$id.json" <<'PY'
import json, pathlib, subprocess, sys, xml.etree.ElementTree as ET

domain, uuid, mac, selected, network, gateway, ssh_proof, out_path = sys.argv[1:9]
virsh = ["virsh", "-c", "qemu:///system"]

def run(*args):
    return subprocess.run(virsh + list(args), capture_output=True, text=True)

candidates = {}
for line in run("net-dhcp-leases", network).stdout.splitlines():
    fields = line.split()
    if len(fields) < 4:
        continue
    expiry, lease_mac, cidr = fields[0], fields[1], fields[2]
    if lease_mac.lower() != mac.lower():
        continue
    address = cidr.split("/", 1)[0]
    if address == gateway:
        continue
    candidates[address] = {"ip": address, "mac": lease_mac, "expiry": expiry,
                           "source": "net-dhcp-leases"}

freshness = {"available": False, "freshest_ip": None, "source": None}
bridge_xml = run("net-dumpxml", network).stdout
try:
    root = ET.fromstring(bridge_xml)
    bridge_name = next((e.get("name") for e in root.iter()
                        if e.tag.rsplit("}", 1)[-1] == "bridge" and e.get("name")), None)
except ET.ParseError:
    bridge_name = None
status_names = ([bridge_name + ".status"] if bridge_name else []) + [network + ".status"]
for status_name in status_names:
    status_path = pathlib.Path("/var/lib/libvirt/dnsmasq") / status_name
    if not status_path.is_file() or status_path.is_symlink():
        continue
    try:
        records = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        continue
    best = None
    for lease in records:
        if str(lease.get("mac-address", "")).lower() != mac.lower():
            continue
        expiry = lease.get("expiry-time")
        address = lease.get("ip-address", "")
        if not address or not isinstance(expiry, (int, float)):
            continue
        candidates.setdefault(address, {"ip": address, "mac": mac, "expiry": None,
                                        "source": "dnsmasq-status"})
        if best is None or expiry > best[0]:
            best = (expiry, address)
    if best:
        freshness = {"available": True, "freshest_ip": best[1],
                     "source": str(status_path), "max_expiry": best[0]}
        break

if selected not in candidates:
    raise SystemExit(f"selected address {selected} is not bound to the expected MAC {mac}")
no_stale_over_fresh = None
if freshness["available"]:
    no_stale_over_fresh = selected == freshness["freshest_ip"]
    if not no_stale_over_fresh:
        raise SystemExit(
            f"selected stale same-MAC lease {selected} over fresher {freshness['freshest_ip']}")
if ssh_proof != "true":
    raise SystemExit(f"SSH liveness proof failed for the selected address {selected}")
if len(candidates) == 1:
    reason = "single_mac_bound_candidate"
elif freshness["available"]:
    reason = "freshest_valid_owned_lease_for_mac"
else:
    reason = "liveness_probed_mac_bound_candidate"
fragment = {
    "domain": domain,
    "uuid": uuid,
    "expected_mac": mac,
    "selected_ip": selected,
    "gateway": gateway,
    "candidates": sorted(candidates.values(), key=lambda item: item["ip"]),
    "freshness": freshness,
    "selection_reason": reason,
    "ssh_proof": True,
    "assertions": {
        "no_cross_mac": True,
        "not_gateway": True,
        "no_stale_over_fresh": no_stale_over_fresh,
    },
}
pathlib.Path(out_path).write_text(
    json.dumps(fragment, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}
wait_vm_ssh() {
  # Combined DHCP + SSH readiness window. The address is re-resolved on
  # EVERY retry through scripts/p15-7-vm-address.sh: a libvirt DHCP lease is
  # not liveness proof — the journey derives its MACs deterministically from
  # the run id and dnsmasq retains a prior boot's lease for the same MAC for
  # up to an hour, so a rerun of the same run id can transiently observe the
  # previous boot's address. The single bounded window must both exceed this
  # shared host's worst-case guest boot profile (the PP.5 campaign harness
  # documents 10-20 minutes under multi-guest parallel boot) and keep the
  # five-VM journey inside the protected job's 120-minute budget: 300x2s
  # per VM bounds provisioning at ~50 minutes worst case (the first pair
  # boots in parallel), leaving the remaining phases their documented share.
  # SSH itself remains the hard reachability proof. Returns only the IP that
  # answered over SSH.
  local d="$1" uuid="$2" mac="$3" serial="$4" id="$5" candidate=""
  for _ in $(seq 1 300); do
    # The resolver normally prints exactly one freshest MAC-bound address;
    # when freshness data is unavailable it prints every MAC-bound candidate
    # and each one is liveness-probed here over SSH — the resolver never
    # guesses and SSH remains the only reachability proof.
    while IFS= read -r candidate; do
      [[ "$candidate" =~ ^[0-9.]+$ ]] || continue
      if ssh_vm "$candidate" true >/dev/null 2>&1; then
        echo "$candidate"
        return 0
      fi
    done < <(bash "$ROOT_DIR/scripts/p15-7-vm-address.sh" resolve "$uuid" "$mac" "$NETWORK" "$GATEWAY" 2>/dev/null || true)
    sleep 2
  done
  vm_network_diagnostics "$d" "$uuid" "$serial" "$id"
  die "VM did not become SSH-reachable with a MAC-bound DHCP address: $id"
}
provision_vm() {
  local id="$1" d="o3k-p15-7-$RUN_ID-$1" overlay="$LIBVIRT_STORAGE_ROOT/$1.qcow2" seed="$LIBVIRT_STORAGE_ROOT/$1-seed.iso" seed_tmp="$WORK_ROOT/$1-seed.iso" serial="$LIBVIRT_STORAGE_ROOT/$1-serial.log" ip uuid mac
  # Match the guest network by the exact MAC we give libvirt.  This avoids
  # relying on distribution-specific predictable interface names while still
  # exercising the real libvirt DHCP path.
  mac="$(python3 - "$RUN_ID-$id" <<'PY'
import hashlib, sys
suffix = hashlib.sha256(sys.argv[1].encode("utf-8")).hexdigest()[:6]
print("52:54:00:%s:%s:%s" % (suffix[0:2], suffix[2:4], suffix[4:6]))
PY
)"
  printf '%s\n' "$mac" >"$WORK_ROOT/$1-mac"
  sudo -n qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$overlay" || die "overlay creation failed: $id"
  # The pinned Ubuntu cloud image is intentionally small. The guest installs
  # the real libvirt/compute boundary packages during cloud-init; enlarge each
  # run-owned overlay before boot so package installation cannot exhaust the
  # root filesystem and leave cloud-init half-configured.
  sudo -n qemu-img resize "$overlay" "${VM_DISK_SIZE_GB}G" >/dev/null \
    || die "overlay resize failed: $id"
  cat >"$WORK_ROOT/user-data-$1" <<EOF
#cloud-config
users:
  - name: $VM_USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [libvirt, kvm]
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "$SSH_KEY.pub")
package_update: true
packages: [openssh-server, ca-certificates, curl, libvirt-daemon-system, libvirt-clients, qemu-system-x86]
runcmd:
  - [ sh, -c, 'printf "%s o3k-control-plane\\n" "$GATEWAY" >> /etc/hosts' ]
  - [ sh, -c, 'systemctl enable --now ssh || true' ]
  - [ sh, -c, 'systemctl enable --now libvirtd || systemctl enable --now libvirt-daemon || true' ]
EOF
  cat >"$WORK_ROOT/network-config-$1" <<EOF
version: 2
renderer: networkd
ethernets:
  primary:
    match:
      macaddress: "$mac"
    set-name: eth0
    dhcp4: true
    dhcp6: false
EOF
  printf 'instance-id: o3k-p15-7-%s-%s\nlocal-hostname: %s-host\n' "$RUN_ID" "$id" "$id" >"$WORK_ROOT/meta-data-$1"
  genisoimage -quiet -output "$seed_tmp" -volid cidata -joliet -rock \
    -graft-points "user-data=$WORK_ROOT/user-data-$1" "meta-data=$WORK_ROOT/meta-data-$1" \
      "network-config=$WORK_ROOT/network-config-$1" \
    || die "cloud-init seed failed: $id"
  sudo -n install -o root -g "$LIBVIRT_QEMU_GROUP" -m 0640 "$seed_tmp" "$seed" \
    || die "cannot stage cloud-init seed for libvirt: $id"
  rm -f -- "$seed_tmp"
  sudo -n install -o root -g "$LIBVIRT_QEMU_GROUP" -m 0660 /dev/null "$serial" \
    || die "cannot stage serial console for libvirt: $id"
  virt-install --connect qemu:///system --name "$d" --memory 2048 --vcpus 2 --import --disk "path=$overlay,format=qcow2" --disk "path=$seed,device=cdrom" --network "network=$NETWORK,model=virtio,mac=$mac" --os-variant ubuntu24.04 --serial "file,path=$serial" --metadata "description=o3k-p15-7-journey-owned=$RUN_ID" --noautoconsole --wait 0 >/dev/null || die "VM boot failed: $id"
  uuid="$(virsh -c qemu:///system domuuid "$d")"; [[ "$uuid" =~ ^[0-9a-fA-F-]{36}$ ]] || die "VM UUID unavailable: $id"
  printf '%s\n' "$uuid" >"$WORK_ROOT/$id-uuid"
  ip="$(wait_vm_ssh "$d" "$uuid" "$mac" "$serial" "$id")"
  ssh_vm "$ip" "sudo cloud-init status --wait" >/dev/null 2>&1 || die "cloud-init did not complete on real VM: $id"
  ssh_vm "$ip" "sudo virsh -c qemu:///system uri" >/dev/null 2>&1 || die "libvirt is not available on real VM: $id"
  printf '%s\n' "$ip" >"$WORK_ROOT/$id-ip"
  record_lease_evidence "$id"
}
join_block() {
  local id="$1" ip="$2" init="$WORK_ROOT/$1-init.json" token vcpus memory epoch
  local certificate="$WORK_ROOT/$id.pem"
  O3K_API_URL="$API" O3K_BOOTSTRAP_SECRET="$(sudo -n cat "$STATE_ROOT/.bootstrap-secret")" "$STATE_ROOT/bin/o3k" init --profile-id default --agent-id "$id" >"$init" || die "o3k init failed: $id"
  token="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("enrollment_token", ""))' "$init")"; [[ "$token" ]] || die "init grant missing: $id"
  vcpus="$(ssh_vm "$ip" nproc)"
  # Keep the awk program inside one remote command string.  Passing the
  # program as separate ssh arguments causes ssh to reconstruct it without
  # its shell quoting, so the VM shell interprets `int($2/1024)` itself.
  memory="$(ssh_vm "$ip" "awk '/MemTotal:/ {print int(\$2/1024); exit}' /proc/meminfo")"
  [[ "$vcpus" =~ ^[1-9][0-9]*$ && "$memory" =~ ^[1-9][0-9]*$ ]] || die "real inventory unavailable: $id"
  epoch="$(openssl rand -hex 16)"
  python3 - "$token" "$id" "$epoch" "$certificate" "$vcpus" "$memory" "$JOIN_REGION" >"$WORK_ROOT/$id-join-request.json" <<'PY'
import json, pathlib, sys
token, agent_id, epoch, certificate, vcpus, memory, region = sys.argv[1:]
request = {
    "enrollment_token": token,
    "agent_id": agent_id,
    "agent_epoch": epoch,
    "certificate": pathlib.Path(certificate).read_text(encoding="utf-8"),
    "capabilities": {"architecture": "unknown", "provider_name": "o3k-cli"},
    "inventories": {"VCPU": int(vcpus), "MEMORY_MB": int(memory), "DISK_GB": 10},
}
if region:
    request["region"] = region
json.dump(request, sys.stdout)
PY
  local join_args=(join --token "$token" --agent-id "$id" --agent-epoch "$epoch" --certificate "$certificate" --vcpus "$vcpus" --memory-mb "$memory" --disk-gb 10)
  if [[ -n "$JOIN_REGION" ]]; then
    [[ "$JOIN_REGION" =~ ^[A-Za-z0-9._-]+$ ]] || die "configured P15.7 region is unsafe"
    join_args+=(--region "$JOIN_REGION")
  fi
  O3K_API_URL="$API" "$STATE_ROOT/bin/o3k" "${join_args[@]}" >"$WORK_ROOT/$1-join.json" || die "authenticated join failed: $id"
  # Retain every journey-joined agent's original join request: the replay
  # negative probe must target whichever agent actually hosted workload A
  # (see the probe below), not a fixed block name.
  REPLAY_JOIN_BY_AGENT["$id"]="$WORK_ROOT/$id-join-request.json"
  BLOCK_IDS[$id]="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("building_block_id", ""))' "$WORK_ROOT/$1-join.json")"; [[ "${BLOCK_IDS[$id]}" =~ ^[0-9a-fA-F-]{36}$ ]] || die "canonical BuildingBlock missing: $id"
}
install_agent() {
  local id="$1" ip="$2" c="$TLS_ROOT/agents/$1" bin="${O3K_REAL_HOST_COMPUTE_BINARY:-$STATE_ROOT/bin/o3k-compute}"
  local remote_stage="/tmp/o3k-p15-7-agent-$RUN_ID-$id"
  [[ -x "$bin" ]] || die "real compute-agent binary unavailable"
  sudo -n test -f "$c/agent-id" || die "canonical agent identity file unavailable: $id"
  sudo -n test ! -L "$c/agent-id" || die "canonical agent identity file is a symlink: $id"
  [[ "$(sudo -n cat "$c/agent-id")" == "$id" ]] || die "canonical agent identity does not match agent id: $id"
  sudo -n install -m 0644 "$TLS_ROOT/ca.pem" "$WORK_ROOT/ca.pem" || die "cannot read canonical CA"
  sudo -n install -m 0644 "$c/agent-id" "$WORK_ROOT/$id-agent-id" || die "cannot read canonical agent identity: $id"
  remote_agent_cleanup() {
    ssh_vm "$ip" "sudo rm -rf -- '$remote_stage'" >/dev/null 2>&1 || true
  }
  ssh_vm "$ip" "sudo mkdir -- '$remote_stage'; sudo chmod 0700 '$remote_stage'; sudo chown '$VM_USER' '$remote_stage'" \
    || { remote_agent_cleanup; die "agent staging directory failed: $id"; }
  scp -q -F /dev/null -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS" "$bin" "$VM_USER@$ip:$remote_stage/o3k-compute" \
    || { remote_agent_cleanup; die "agent binary transfer failed: $id"; }
  scp -q -F /dev/null -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS" "$WORK_ROOT/ca.pem" "$VM_USER@$ip:$remote_stage/ca.pem" \
    || { remote_agent_cleanup; die "CA transfer failed: $id"; }
  scp -q -F /dev/null -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS" "$WORK_ROOT/$id-agent-id" "$VM_USER@$ip:$remote_stage/agent-id" \
    || { remote_agent_cleanup; die "agent identity transfer failed: $id"; }
  scp -q -F /dev/null -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS" "$WORK_ROOT/$id.pem" "$VM_USER@$ip:$remote_stage/agent.pem" \
    || { remote_agent_cleanup; die "certificate transfer failed: $id"; }
  scp -q -F /dev/null -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS" "$WORK_ROOT/$id-key.pem" "$VM_USER@$ip:$remote_stage/agent-key.pem" \
    || { remote_agent_cleanup; die "private key transfer failed: $id"; }
  ssh_vm "$ip" "sudo install -d -m 0750 /etc/o3k/tls; sudo install -d -o root -g libvirt-qemu -m 02750 /var/lib/o3k-compute; sudo chown root:libvirt-qemu /var/lib/o3k-compute; sudo chmod 02750 /var/lib/o3k-compute; sudo install -m 0755 '$remote_stage/o3k-compute' /usr/local/bin/o3k-compute; sudo install -m 0644 '$remote_stage/ca.pem' /etc/o3k/tls/ca.pem; sudo install -m 0644 '$remote_stage/agent.pem' /etc/o3k/tls/agent.pem; sudo install -m 0600 '$remote_stage/agent-key.pem' /etc/o3k/tls/agent-key.pem; sudo install -m 0644 '$remote_stage/agent-id' /var/lib/o3k-compute/agent-id; sudo sh -c 'RUST_LOG=$COMPUTE_LOG_FILTER O3K_COMPUTE_CONTROL_ENDPOINT=https://o3k-control-plane:$CONTROL_PORT O3K_COMPUTE_SERVER_NAME=o3k-control-plane O3K_COMPUTE_TLS_DIR=/etc/o3k/tls O3K_COMPUTE_DATA_DIR=/var/lib/o3k-compute O3K_COMPUTE_HOST_LABEL=${id}-host O3K_COMPUTE_HEALTH_ADDR=127.0.0.1:19101 O3K_COMPUTE_MAX_DISK_GB=10 nohup /usr/local/bin/o3k-compute >/var/log/o3k-compute.log 2>&1 &'" \
    || { remote_agent_cleanup; die "agent start failed: $id"; }
  remote_agent_cleanup
  for _ in $(seq 1 90); do ssh_vm "$ip" curl -fsS http://127.0.0.1:19101/readyz >/dev/null 2>&1 && return; sleep 2; done
  die "real mTLS agent did not become ready: $id"
}

register_vm() {
  local id="$1" d="o3k-p15-7-$RUN_ID-$1" overlay="$LIBVIRT_STORAGE_ROOT/$1.qcow2" seed="$LIBVIRT_STORAGE_ROOT/$1-seed.iso" serial="$LIBVIRT_STORAGE_ROOT/$1-serial.log"
  DOMAINS+=("$d"); UUIDS+=(""); OVERLAYS+=("$overlay"); SEEDS+=("$seed"); SERIALS+=("$serial")
}
provision_vms_bounded() {
  local id pid rc=0 status index=0
  local -a pids=()
  local -a ids=()
  for id in "$@"; do
    register_vm "$id"
    # Each job writes its address/UUID to a run-owned file; the parent then
    # reconstructs ordered arrays used by ownership-safe cleanup.
    provision_vm "$id" >"$WORK_ROOT/$id-provision.log" 2>&1 &
    pids+=("$!")
    ids+=("$id")
  done
  for pid in "${pids[@]}"; do
    if wait "$pid"; then status=0; else status=$?; rc=1; fi
    printf '%s\n' "$status" >"$WORK_ROOT/${ids[$index]}-exit"
    ((index += 1))
  done
  if ((rc != 0)); then
    python3 "$ROOT_DIR/scripts/capture-p15-7-provision-diagnostics.py" \
      "$ARTIFACT_DIR/p15-7-provisioning-diagnostics.json" "$WORK_ROOT" "$SOURCE_SHA" "$RUN_ID" \
      || echo "P15.7 provisioning diagnostics could not be safely captured" >&2
    [[ -f "$ARTIFACT_DIR/p15-7-provisioning-diagnostics.json" \
      && ! -L "$ARTIFACT_DIR/p15-7-provisioning-diagnostics.json" ]] \
      && P15_PROVISION_DIAGNOSTICS_CAPTURED=true
    die "bounded VM provisioning failed; inspect p15-7-provisioning-diagnostics.json"
  fi
  IPS=()
  for id in "$@"; do
    [[ -s "$WORK_ROOT/$id-ip" && -s "$WORK_ROOT/$id-uuid" ]] || die "VM provisioning result missing: $id"
    IPS+=("$(<"$WORK_ROOT/$id-ip")")
    UUIDS[$((${#IPS[@]} - 1))]="$(<"$WORK_ROOT/$id-uuid")"
  done
}
O3K_P15_7_LIBVIRT_IMAGE_ROOT="$LIBVIRT_IMAGE_ROOT" \
  bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" define "$RUN_ID" "$LIBVIRT_STORAGE_ROOT" \
  || die "cannot define run-owned libvirt storage pool"
provision_vms_bounded block-a block-b
join_block block-a "${IPS[0]}"; join_block block-b "${IPS[1]}"
install_agent block-a "${IPS[0]}"; install_agent block-b "${IPS[1]}"
# BuildingBlock lifecycle and operator diagnostics are deliberately
# system-scoped and require the canonical operator authority.  A Keystone
# password token is project-scoped by contract and must never be treated as an
# operator token (doing so produces a policy 403 and would tempt a security
# boundary weakening).  The protected environment supplies this token from its
# selected authority mode; the journey performs the native exchange and only
# consumes its run-scoped 0600 result.
OPERATOR_TOKEN_FILE="${O3K_P15_7_OPERATOR_TOKEN_FILE:-}"
if [[ "$AUTHORITY_MODE" == testlab-keycloak ]]; then
  # Exchange immediately before the first privileged operation.  The cheap
  # preflight only proves that Keycloak can launch; it never mints a native
  # operator token that could expire during the expensive VM stages.
  [[ -x "$KEYCLOAK_AUTHORITY_SCRIPT" ]] || die "keycloak_authority_driver_missing"
  OPERATOR_TOKEN_FILE="$WORK_ROOT/operator.token"
  O3K_P15_7_AUTHORITY_MODE=testlab-keycloak \
    O3K_P15_7_KEYCLOAK_STATE_ROOT="${O3K_P15_7_KEYCLOAK_STATE_ROOT:-${RUNNER_TEMP:-/tmp}/o3k-p15-7-keycloak-${RUN_ID}}" \
    O3K_P15_7_NATIVE_API_URL="$API" O3K_P15_7_AUTHORITY_OUTPUT_FILE="$OPERATOR_TOKEN_FILE" \
    GITHUB_RUN_ID="$RUN_ID" O3K_P15_7_SOURCE_SHA="$SOURCE_SHA" \
    bash "$KEYCLOAK_AUTHORITY_SCRIPT" exchange || die "system_operator_federated_exchange_failed"
  printf 'o3k-p15-7-operator-token-v1\nrun=%s\n' "$RUN_ID" >"$OPERATOR_TOKEN_FILE.o3k-owned"
  chmod 0600 "$OPERATOR_TOKEN_FILE" "$OPERATOR_TOKEN_FILE.o3k-owned"
fi
[[ -n "$OPERATOR_TOKEN_FILE" && -f "$OPERATOR_TOKEN_FILE" && ! -L "$OPERATOR_TOKEN_FILE" ]] \
  || die "system_operator_token_required: no canonical federation exchange output"
[[ "$(stat -c '%a' "$OPERATOR_TOKEN_FILE" 2>/dev/null || true)" == 600 ]] \
  || die "system_operator_token_file_permissions_invalid"
[[ -f "$OPERATOR_TOKEN_FILE.o3k-owned" ]] \
  && grep -Fqx 'o3k-p15-7-operator-token-v1' "$OPERATOR_TOKEN_FILE.o3k-owned" \
  && grep -Fqx "run=$RUN_ID" "$OPERATOR_TOKEN_FILE.o3k-owned" \
  || die "system_operator_token_ownership_unproven"
OPERATOR_TOKEN="$(<"$OPERATOR_TOKEN_FILE")"
[[ -n "$OPERATOR_TOKEN" && "$OPERATOR_TOKEN" != *$'\n'* ]] || die "system_operator_token_empty"
# Authenticated project token: bounded retries with captured diagnostics, then
# a loud failure. The unguarded single-shot form exited silently under
# `set -e` when a transient control-plane/DB hiccup made `openstack token
# issue` fail (observed on run 990923002), which destroyed the whole journey
# with no diagnostics. Token issue is a read-only authenticated call;
# retrying a transient transport/stall failure does not weaken any check, and
# persistent failure dies loudly WITH the CLI's own error text (status codes,
# never credentials) so the cause is never guessed.
PROJECT_TOKEN=""
PROJECT_TOKEN_ERR="$WORK_ROOT/project-token.err"
TOKEN_ATTEMPTS=0
for _ in $(seq 1 15); do
  TOKEN_ATTEMPTS=$((TOKEN_ATTEMPTS + 1))
  PROJECT_TOKEN="$(openstack token issue -f value -c id 2>"$PROJECT_TOKEN_ERR" | tr -d '[:space:]' || true)"
  [[ "$PROJECT_TOKEN" ]] && break
  sleep 2
done
if ((TOKEN_ATTEMPTS > 1)) && [[ "$PROJECT_TOKEN" ]]; then
  record_transient bounded_retry "keystone token issue" "attempts=$TOKEN_ATTEMPTS outcome=acquired"
fi
if [[ -z "$PROJECT_TOKEN" ]]; then
  if grep -Eiq '(^|[^0-9])5[0-9][0-9]([^0-9]|$)' "$PROJECT_TOKEN_ERR" 2>/dev/null; then
    record_transient http_5xx "keystone token issue" "token acquisition exhausted after $TOKEN_ATTEMPTS attempts" "5xx"
  fi
  record_transient bounded_retry "keystone token issue" "attempts=$TOKEN_ATTEMPTS outcome=failed"
  echo "P15.7 project token acquisition diagnostics:" >&2
  sed -e 's/[0-9a-fA-F]\{32,\}/<redacted>/g' "$PROJECT_TOKEN_ERR" >&2 2>/dev/null || true
  die "authenticated project token unavailable"
fi
rm -f -- "$PROJECT_TOKEN_ERR"
OPERATOR_CURL_CONFIG="$WORK_ROOT/operator-curl.conf"
write_operator_curl_config() {
  printf 'header = "Authorization: Bearer %s"\n' "$OPERATOR_TOKEN" >"$OPERATOR_CURL_CONFIG"
  chmod 0600 "$OPERATOR_CURL_CONFIG"
}
write_operator_curl_config
refresh_operator_authority() {
  [[ "$AUTHORITY_MODE" == testlab-keycloak ]] || return 0
  O3K_P15_7_AUTHORITY_MODE=testlab-keycloak \
    O3K_P15_7_OPERATOR_TOKEN_FILE="$OPERATOR_TOKEN_FILE" \
    O3K_P15_7_OPERATOR_CURL_CONFIG="$OPERATOR_CURL_CONFIG" \
    O3K_P15_7_KEYCLOAK_AUTHORITY_SCRIPT="$KEYCLOAK_AUTHORITY_SCRIPT" \
    O3K_P15_7_KEYCLOAK_STATE_ROOT="${O3K_P15_7_KEYCLOAK_STATE_ROOT:-${RUNNER_TEMP:-/tmp}/o3k-p15-7-keycloak-${RUN_ID}}" \
    O3K_P15_7_NATIVE_API_URL="$API" GITHUB_RUN_ID="$RUN_ID" \
    O3K_P15_7_SOURCE_SHA="$SOURCE_SHA" \
    bash "$ROOT_DIR/scripts/p15-7-refresh-operator-authority.sh" \
    || die "system_operator_federated_renewal_failed"
  OPERATOR_TOKEN="$(<"$OPERATOR_TOKEN_FILE")"
}
operator_curl() {
  local url="$1"
  shift
  refresh_operator_authority
  curl --fail --silent --show-error --config "$OPERATOR_CURL_CONFIG" "$@" "$url"
}
api_get() { operator_curl "$API$1"; }
record_scale_checkpoint() {
  # Eligibility-based scale checkpoint (issues #974/#1037 decision): enumerate
  # EVERY canonical BuildingBlock — the bootstrap block (identified by the
  # canonical TLS agent identity, whatever its agent id is, never by a name
  # filter) and every child — and derive placement eligibility from canonical
  # projections only:
  #   placement_eligible = state == "ready"
  #     AND >=1 resource_provider_id is present in the live Placement
  #         ResourceProvider projection (/operator/diagnostics/providers)
  #     AND that provider's state == "Enabled"
  #     AND no drain_blockers are recorded.
  # Scale cardinality is the eligible Ready set, never VM count, configured
  # ids, host labels, or block-* name prefixes. $2 is the exact eligible Ready
  # count the phase must show (fail closed otherwise); $3 optionally names a
  # block id that must be ABSENT (post-remove); $4 optionally lists comma-
  # separated block ids that must be present AND eligible. Writes one fragment
  # per phase into ARTIFACT_DIR and prints the eligible Ready count.
  local phase="$1" expected="$2" absent_id="${3:-}" required_ids="${4:-}"
  api_get /operator/building-blocks >"$WORK_ROOT/blocks-checkpoint-$phase.json"
  api_get "/operator/diagnostics/providers?limit=200" >"$WORK_ROOT/providers-checkpoint-$phase.json"
  python3 - "$WORK_ROOT/blocks-checkpoint-$phase.json" "$WORK_ROOT/providers-checkpoint-$phase.json" \
    "$ARTIFACT_DIR/p15-7-scale-checkpoint-$phase.json" "$phase" "$BOOTSTRAP_AGENT_ID" \
    "$expected" "$absent_id" "$required_ids" <<'PY'
import json, pathlib, sys

blocks_path, providers_path, out_path, phase, bootstrap_agent, expected, absent_id, required_ids = sys.argv[1:9]
items = json.load(open(blocks_path, encoding="utf-8"))
page = json.load(open(providers_path, encoding="utf-8"))
if not isinstance(items, list):
    raise SystemExit("canonical BuildingBlock projection is not a list")
if not isinstance(page, dict) or not isinstance(page.get("items"), list):
    raise SystemExit("Placement provider diagnostics projection is not a page")
if page.get("has_more"):
    raise SystemExit("Placement provider diagnostics page is truncated; raise the limit")
provider_state = {p["provider_id"]: p.get("state") for p in page["items"] if isinstance(p, dict) and p.get("provider_id")}
entries = []
for view in items:
    if not isinstance(view, dict):
        raise SystemExit("canonical BuildingBlock view is malformed")
    block = view.get("block", {})
    providers = [p for p in block.get("resource_provider_ids") or () if isinstance(p, str)]
    states = [provider_state.get(p) for p in providers]
    live = any(state is not None for state in states)
    eligible = (block.get("state") == "ready" and live
                and any(state == "Enabled" for state in states)
                and not (block.get("drain_blockers") or []))
    entries.append({
        "block_id": block.get("id"),
        "execution_identity": block.get("execution_identity"),
        "resource_provider_ids": providers,
        "provider_states": states,
        "state": block.get("state"),
        "drain_blockers": block.get("drain_blockers") or [],
        "agent_available": view.get("agent_available"),
        "is_bootstrap": block.get("execution_identity") == bootstrap_agent,
        "compute_capable": live,
        "placement_eligible": bool(eligible),
    })
ids = {entry["block_id"] for entry in entries}
if absent_id and absent_id in ids:
    raise SystemExit(f"{phase}: removed block {absent_id} is still present in the canonical topology")
for required in [value for value in required_ids.split(",") if value]:
    match = next((entry for entry in entries if entry["block_id"] == required), None)
    if match is None:
        raise SystemExit(f"{phase}: required block {required} missing from the canonical topology")
    if not match["placement_eligible"]:
        raise SystemExit(f"{phase}: required block {required} is not placement-eligible (state={match['state']})")
eligible_ready = sum(1 for entry in entries if entry["placement_eligible"])
if eligible_ready != int(expected):
    raise SystemExit(f"{phase}: eligible Ready count is {eligible_ready}, expected exactly {expected}")
identities = [entry["execution_identity"] for entry in entries]
provider_ids = [pid for entry in entries for pid in entry["resource_provider_ids"]]
if any(not identity for identity in identities) or len(set(identities)) != len(identities):
    raise SystemExit(f"{phase}: duplicate or empty execution identities in the canonical topology")
if len(set(provider_ids)) != len(provider_ids):
    raise SystemExit(f"{phase}: duplicate resource provider identities in the canonical topology")
if not any(entry["is_bootstrap"] for entry in entries):
    raise SystemExit(f"{phase}: bootstrap BuildingBlock missing from the canonical topology")
fragment = {
    "phase": phase,
    "eligibility_basis": "state=='ready' AND >=1 resource_provider_id in /operator/diagnostics/providers with state 'Enabled' AND drain_blockers empty; all BuildingBlocks enumerated (bootstrap included by TLS agent identity)",
    "blocks": entries,
    "total_blocks": len(entries),
    "eligible_ready_count": eligible_ready,
}
pathlib.Path(out_path).write_text(json.dumps(fragment, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(eligible_ready)
PY
}
api_get /operator/building-blocks >"$WORK_ROOT/blocks.json"
api_get /regions >"$WORK_ROOT/regions.json"
api_get /topology/failure-domains >"$WORK_ROOT/failure-domains.json"
api_get /operator/diagnostics/providers >"$WORK_ROOT/providers.json"
api_get /operator/diagnostics/capacity >"$WORK_ROOT/capacity.json"
api_get /services >"$WORK_ROOT/services.json"
api_get /resource-types >"$WORK_ROOT/resource-types.json"
python3 - "$WORK_ROOT/blocks.json" "${BLOCK_IDS[block-a]}" "${BLOCK_IDS[block-b]}" <<'PY'
import json,sys
ids={x.get('block',{}).get('id') for x in json.load(open(sys.argv[1]))}
assert sys.argv[2] in ids and sys.argv[3] in ids and len(ids)>=2
PY

# Araf is an optional external consumer, never an O3K/TestLab dependency.  If
# explicitly configured, record reachability as additional evidence without
# allowing an unavailable endpoint to block the canonical O3K journey.
record_optional_araf() {
  if [[ -z "$ARAF_URL" ]]; then
    ARAF_STATUS="not_configured"
    ARAF_REASON="external_consumer_not_provisioned"
  elif curl --proto '=http,https' --connect-timeout 5 --max-time 15 --fail --silent --show-error \
      "$ARAF_URL/healthz" >"$WORK_ROOT/araf-health.json" \
    && curl --proto '=http,https' --connect-timeout 5 --max-time 15 --fail --silent --show-error \
      "$ARAF_URL/api/v1/resources/compute.server" >"$WORK_ROOT/araf-compute.json"; then
    ARAF_STATUS="reachable"
    ARAF_REASON="optional_external_projection_reachable"
  else
    ARAF_STATUS="unavailable"
    ARAF_REASON="optional_external_projection_unreachable"
  fi
  python3 - "$ARTIFACT_DIR/p15-7-araf-projection.json" "$ARAF_STATUS" "$ARAF_REASON" <<'PY'
import json
import pathlib
import sys

path, status, reason = sys.argv[1:]
pathlib.Path(path).write_text(json.dumps({
    "projection": "araf",
    "required": False,
    "status": status,
    "reason": reason,
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

capacity_total() {
  python3 - "$1" <<'PY'
import json,sys
doc=json.load(open(sys.argv[1], encoding="utf-8"))
dims=doc.get("dimensions")
if not isinstance(dims,list) or not dims:
    raise SystemExit("capacity dimensions are absent")
total=0
found=False
for dim in dims:
    if dim.get("resource_class") != "VCPU":
        continue
    found=True
    value=dim.get("allocatable")
    if not isinstance(value,int) or value < 1:
        raise SystemExit("VCPU capacity allocatable is not positive")
    total += value
if not found or total < 1:
    raise SystemExit("VCPU capacity dimension is absent")
print(total)
PY
}
CAPACITY_BEFORE="$(capacity_total "$WORK_ROOT/capacity.json")" || die "initial Placement capacity was not honest"

# Create workload prerequisites through the public compatibility API. The
# preceding lifecycle deletes its own objects; relying on an ambient flavor,
# image, or network would make a fresh journey depend on stale state.
OS_IMAGE_ID="$(openstack image create "o3k-p15-7-$RUN_ID-image" --file "$O3K_TESTLAB_IMAGE_PATH" --disk-format qcow2 --container-format bare -f value -c id | tr -d '[:space:]')"
[[ "$OS_IMAGE_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "owned workload image creation returned an invalid id"
OS_KEYPAIR_NAME="o3k-p15-7-$RUN_ID-key"
openstack keypair create --public-key "$SSH_KEY.pub" "$OS_KEYPAIR_NAME" >/dev/null || die "owned workload keypair creation failed"
SSH_PUBLIC_KEY="$(<"$SSH_KEY.pub")"
OS_NETWORK_ID="$(openstack network create "o3k-p15-7-$RUN_ID-network" -f value -c id | tr -d '[:space:]')"
[[ "$OS_NETWORK_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "owned workload network creation returned an invalid id"
OS_SUBNET_ID="$(openstack subnet create --network "$OS_NETWORK_ID" --subnet-range "198.18.0.0/28" "o3k-p15-7-$RUN_ID-subnet" -f value -c id | tr -d '[:space:]')"
[[ "$OS_SUBNET_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "owned workload subnet creation returned an invalid id"
OS_PORT_A_ID="$(openstack port create --network "$OS_NETWORK_ID" "o3k-p15-7-$RUN_ID-port-a" -f value -c id | tr -d '[:space:]')"
[[ "$OS_PORT_A_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "owned workload A port creation returned an invalid id"
OS_PORT_B_ID="$(openstack port create --network "$OS_NETWORK_ID" "o3k-p15-7-$RUN_ID-port-b" -f value -c id | tr -d '[:space:]')"
[[ "$OS_PORT_B_ID" =~ ^[0-9a-fA-F-]{36}$ && "$OS_PORT_B_ID" != "$OS_PORT_A_ID" ]] \
  || die "owned workload B port creation returned an invalid or reused id"
OS_FLAVOR_ID="$(openstack flavor create "o3k-p15-7-$RUN_ID-flavor" --ram 512 --disk 10 --vcpus 1 -f value -c id | tr -d '[:space:]')"
[[ "$OS_FLAVOR_ID" =~ ^[A-Za-z0-9._-]+$ ]] || die "owned workload flavor creation returned an invalid id"

# Add a third genuine VM/block before any drain. Capacity must grow in the
# canonical diagnostics projection; a second logical object on one host is not
# sufficient evidence.
register_vm block-c; provision_vm block-c
IPS+=("$(<"$WORK_ROOT/block-c-ip")")
UUIDS[$((${#IPS[@]} - 1))]="$(<"$WORK_ROOT/block-c-uuid")"
join_block block-c "${IPS[2]}"; install_agent block-c "${IPS[2]}"
CAPACITY_AFTER_ADD=""
for _ in $(seq 1 60); do
  api_get /operator/diagnostics/capacity >"$WORK_ROOT/capacity-after-add.json" || true
  CAPACITY_AFTER_ADD="$(capacity_total "$WORK_ROOT/capacity-after-add.json" 2>/dev/null || true)"
  [[ "$CAPACITY_AFTER_ADD" =~ ^[1-9][0-9]*$ && "$CAPACITY_AFTER_ADD" -gt "$CAPACITY_BEFORE" ]] && break
  sleep 2
done
[[ "$CAPACITY_AFTER_ADD" =~ ^[1-9][0-9]*$ && "$CAPACITY_AFTER_ADD" -gt "$CAPACITY_BEFORE" ]] \
  || die "Placement capacity did not grow after adding a genuine block"

# A fourth genuine child VM completes the initial S5 topology: the bootstrap
# compute-agent (genuine Small Edge capacity by product design, SPEC-0048
# §4.1/§5) plus block-a..block-d must yield EXACTLY five placement-eligible
# Ready BuildingBlocks. Every join is validated against the settled capacity
# baseline of the CURRENT topology measured before that join; comparing the
# new total against the pre-join fleet is what makes growth observable.
register_vm block-d; provision_vm block-d
IPS+=("$(<"$WORK_ROOT/block-d-ip")")
UUIDS[$((${#IPS[@]} - 1))]="$(<"$WORK_ROOT/block-d-uuid")"
join_block block-d "${IPS[3]}"; install_agent block-d "${IPS[3]}"
CAPACITY_AFTER_D=""
for _ in $(seq 1 60); do
  api_get /operator/diagnostics/capacity >"$WORK_ROOT/capacity-after-d.json" || true
  CAPACITY_AFTER_D="$(capacity_total "$WORK_ROOT/capacity-after-d.json" 2>/dev/null || true)"
  [[ "$CAPACITY_AFTER_D" =~ ^[1-9][0-9]*$ && "$CAPACITY_AFTER_D" -gt "$CAPACITY_AFTER_ADD" ]] && break
  sleep 2
done
[[ "$CAPACITY_AFTER_D" =~ ^[1-9][0-9]*$ && "$CAPACITY_AFTER_D" -gt "$CAPACITY_AFTER_ADD" ]] \
  || die "Placement capacity did not grow after enrolling the fourth block"

# Eligibility-based initial scale checkpoint: enumerate every canonical
# BuildingBlock — bootstrap block included, identified by the TLS agent
# identity — and require the eligible Ready set to be EXACTLY five. Scale
# cardinality is canonical compute-capable + Placement-eligible + Ready
# BuildingBlocks (see record_scale_checkpoint), never VM count, configured
# ids, host labels, or block-* name prefixes. The drain below only shrinks
# the topology; block-e later restores the same eligible concurrency after
# the drain/remove/replacement cycle.
INITIAL_READY_COUNT="$(record_scale_checkpoint initial-scale-checkpoint 5 "" \
  "${BLOCK_IDS[block-a]},${BLOCK_IDS[block-b]},${BLOCK_IDS[block-c]},${BLOCK_IDS[block-d]}")" \
  || die "initial eligible Ready count is not exactly five"
[[ "$INITIAL_READY_COUNT" == 5 ]] || die "initial eligible Ready count is not exactly five"

# Include the run-scoped TestLab bootstrap block and every newly enrolled
# execution identity when resolving the selected workload host.  The local
# compute-agent is a real authenticated TestLab provider too; assuming every
# placement must be one of the separately provisioned block-* VMs rejects a
# valid canonical candidate.
api_get /operator/building-blocks >"$WORK_ROOT/blocks.json"

# Exercise a constrained real workload through the canonical native resource
# API. Keep it present while draining so the durable blocker projection is
# observed honestly, then clear it before removing the block.
curl --fail --silent --show-error -X POST -H "Authorization: Bearer $PROJECT_TOKEN" -H 'Content-Type: application/json' -H "Idempotency-Key: p15-7-$RUN_ID-a" "$API/compute/servers" \
  -d "{\"kind\":\"compute:server\",\"spec\":{\"name\":\"p15-7-$RUN_ID-a\",\"image_id\":\"$OS_IMAGE_ID\",\"flavor_id\":\"$OS_FLAVOR_ID\",\"key_name\":\"$OS_KEYPAIR_NAME\",\"ssh_public_key\":\"$SSH_PUBLIC_KEY\",\"network_ids\":[\"$OS_PORT_A_ID\"]}}" >"$WORK_ROOT/workload-a.json" || die "constrained real workload placement failed"
WORKLOAD_A="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("resource_id", ""))' "$WORK_ROOT/workload-a.json")"; [[ "$WORKLOAD_A" =~ ^[0-9a-fA-F-]{36}$ ]] || die "workload A has no canonical id"
OS_WORKLOAD_A="$WORKLOAD_A"
WORKLOAD_A_SHOW="$WORK_ROOT/workload-a-show.json"
A_STATE=""
for _ in $(seq 1 120); do
  curl --fail --silent --show-error -H "Authorization: Bearer $PROJECT_TOKEN" \
    "$API/compute/servers/$WORKLOAD_A" >"$WORKLOAD_A_SHOW" || die "workload A native status read failed"
  A_STATE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("status", {}).get("state", ""))' "$WORKLOAD_A_SHOW")"
  [[ "$A_STATE" == "ACTIVE" ]] && break
  if [[ "$A_STATE" == ERROR ]]; then
    capture_workload_failure_diagnostics workload-a
    die "workload A provisioning entered ERROR"
  fi
  sleep 1
done
if [[ "$A_STATE" != ACTIVE ]]; then
  capture_workload_failure_diagnostics workload-a
  die "workload A did not become ACTIVE"
fi
HOST_A=""
for _ in $(seq 1 60); do
  HOST_A="$(openstack server show "$WORKLOAD_A" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null || true)"
  [[ -n "$HOST_A" && "$HOST_A" != "None" ]] && break
  sleep 1
done
DRAIN_AGENT="$HOST_A"
DRAIN_ID="$(python3 "$ROOT_DIR/scripts/resolve-p15-7-placement-block.py" \
  "$WORK_ROOT/blocks.json" "$DRAIN_AGENT")" \
  || die "workload A placement host has no unique ready canonical block/provider mapping"

# Pre-drain checkpoint: the eligible topology is still exactly five. Workload
# residency is not an eligibility signal — drain blockers are derived at the
# drain transition itself, so a resident workload never changes this count.
record_scale_checkpoint pre-drain 5 "" \
  "${BLOCK_IDS[block-a]},${BLOCK_IDS[block-b]},${BLOCK_IDS[block-c]},${BLOCK_IDS[block-d]}" \
  >/dev/null || die "pre-drain eligible Ready count is not exactly five"
# The surviving initial child identities after the (not yet issued) removal;
# Placement may legitimately have hosted workload A on the bootstrap agent, in
# which case all four children survive and the drain/remove targets the
# bootstrap block instead.
SURVIVOR_IDS=""
for survivor in block-a block-b block-c block-d; do
  [[ "${BLOCK_IDS[$survivor]}" == "$DRAIN_ID" ]] && continue
  SURVIVOR_IDS+="${BLOCK_IDS[$survivor]},"
done
SURVIVOR_IDS="${SURVIVOR_IDS%,}"

# Prove tenant concealment with a genuinely different project-scoped token.
# An unauthenticated request is not cross-tenant evidence. Do not fabricate
# this field when the protected Keystone context has no second project.
ADMIN_PROJECT_ID="$(openstack token issue -f value -c project_id 2>/dev/null | tr -d '[:space:]' || true)"
[[ "$ADMIN_PROJECT_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "cross_tenant_test_prerequisite_missing: admin project id unavailable"
FOREIGN_PROJECT_ID="${O3K_P15_7_FOREIGN_PROJECT_ID:-}"
if [[ -z "$FOREIGN_PROJECT_ID" ]]; then
  while IFS= read -r candidate; do
    [[ "$candidate" =~ ^[0-9a-fA-F-]{36}$ && "$candidate" != "$ADMIN_PROJECT_ID" ]] || continue
    FOREIGN_PROJECT_ID="$candidate"
    break
  done < <(openstack project list -f value -c ID 2>/dev/null || true)
fi
[[ "$FOREIGN_PROJECT_ID" =~ ^[0-9a-fA-F-]{36}$ && "$FOREIGN_PROJECT_ID" != "$ADMIN_PROJECT_ID" ]] \
  || die "cross_tenant_test_prerequisite_missing: no distinct foreign project"
FOREIGN_USER_NAME="${O3K_P15_7_FOREIGN_USER_NAME:-${O3K_EXTRA_TENANT_USER_NAME:-}}"
FOREIGN_PASSWORD="${O3K_P15_7_FOREIGN_PASSWORD:-${O3K_EXTRA_TENANT_PASSWORD:-}}"
FOREIGN_PROJECT_NAME="${O3K_EXTRA_TENANT_PROJECT_NAME:-}"
[[ -n "$FOREIGN_USER_NAME" && -n "$FOREIGN_PASSWORD" && -n "$FOREIGN_PROJECT_NAME" ]] \
  || die "cross_tenant_test_prerequisite_missing: foreign project credentials unavailable"
FOREIGN_TOKEN_PROJECT_ID="$(
  OS_USERNAME="$FOREIGN_USER_NAME" OS_PASSWORD="$FOREIGN_PASSWORD" \
  OS_PROJECT_ID="$FOREIGN_PROJECT_ID" OS_PROJECT_NAME="$FOREIGN_PROJECT_NAME" \
  OS_USER_DOMAIN_NAME=Default OS_PROJECT_DOMAIN_NAME=Default \
    openstack token issue -f value -c project_id 2>/dev/null | tr -d '[:space:]' || true
)"
[[ "$FOREIGN_TOKEN_PROJECT_ID" == "$FOREIGN_PROJECT_ID" ]] || die "cross_tenant_test_prerequisite_missing: foreign token scope mismatch"
FOREIGN_TOKEN="$(
  OS_USERNAME="$FOREIGN_USER_NAME" OS_PASSWORD="$FOREIGN_PASSWORD" \
  OS_PROJECT_ID="$FOREIGN_PROJECT_ID" OS_PROJECT_NAME="$FOREIGN_PROJECT_NAME" \
  OS_USER_DOMAIN_NAME=Default OS_PROJECT_DOMAIN_NAME=Default \
    openstack token issue -f value -c id 2>/dev/null | tr -d '[:space:]' || true
)"
[[ "$FOREIGN_TOKEN" ]] || die "cross_tenant_test_prerequisite_missing: foreign project token unavailable"
unset FOREIGN_PASSWORD
FOREIGN_SHOW="$WORK_ROOT/foreign-workload-show.json"
foreign_code="$(curl --silent --output "$FOREIGN_SHOW" --write-out '%{http_code}' \
  -H "Authorization: Bearer $FOREIGN_TOKEN" "$API/compute/servers/$WORKLOAD_A" || true)"
FOREIGN_MISSING_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
FOREIGN_MISSING_SHOW="$WORK_ROOT/foreign-missing-workload-show.json"
foreign_missing_code="$(curl --silent --output "$FOREIGN_MISSING_SHOW" --write-out '%{http_code}' \
  -H "Authorization: Bearer $FOREIGN_TOKEN" "$API/compute/servers/$FOREIGN_MISSING_ID" || true)"
[[ "$foreign_missing_code" == 404 && "$foreign_code" == "$foreign_missing_code" ]] \
  || die "foreign-resource response differs from missing-resource response"
python3 - "$FOREIGN_SHOW" "$FOREIGN_MISSING_SHOW" "$WORKLOAD_A" "$FOREIGN_MISSING_ID" <<'PY' \
  || die "foreign-resource response differs from missing-resource response"
import json,sys

foreign=json.load(open(sys.argv[1], encoding="utf-8"))
missing=json.load(open(sys.argv[2], encoding="utf-8"))
foreign_id,missing_id=sys.argv[3:]
if foreign.get("resource_id") not in (None, foreign_id):
    raise SystemExit("foreign error resource_id does not match the requested id")
if missing.get("resource_id") not in (None, missing_id):
    raise SystemExit("missing error resource_id does not match the requested id")
for problem in (foreign, missing):
    problem.pop("request_id", None)
    problem.pop("resource_id", None)
if foreign != missing:
    raise SystemExit("foreign-resource error differs from missing-resource error")
PY
CROSS_TENANT_CONCEALMENT=true

DRAIN_GEN="$(python3 - "$WORK_ROOT/blocks.json" "$DRAIN_ID" <<'PY'
import json,sys
for x in json.load(open(sys.argv[1])):
    if x.get('block',{}).get('id')==sys.argv[2]: print(x['block']['generation']); break
else: raise SystemExit(1)
PY
)"
operator_curl "$API/operator/building-blocks/$DRAIN_ID/actions/drain" -X POST -H 'Content-Type: application/json' -d "{\"expected_generation\":$DRAIN_GEN}" >"$WORK_ROOT/drain.json" || die "canonical drain failed"
grep -Eq '"state"[[:space:]]*:[[:space:]]*"draining"' "$WORK_ROOT/drain.json" || die "durable drain state missing"
python3 - "$WORK_ROOT/drain.json" "$WORK_ROOT/workload-a.json" "$WORK_ROOT/blocks.json" "$ARTIFACT_DIR/p15-7-drain-failure-context.json" <<'PY'
import json,pathlib,sys
drain_path, workload_path, blocks_path, context_path = sys.argv[1:]
block=json.load(open(drain_path, encoding="utf-8")).get("block", {})
blockers=block.get("drain_blockers", [])
if not any(item.get("kind") == "workload" and item.get("count", 0) >= 1 for item in blockers):
    # Keep the exact response available to the diagnostic artifact collector;
    # the journey workspace is deliberately removed by cleanup on failure.
    context = {
        "block": block,
        "workload_a": json.load(open(workload_path, encoding="utf-8")),
        "blocks": json.load(open(blocks_path, encoding="utf-8")),
    }
    pathlib.Path(context_path).write_text(
        json.dumps(context, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    raise SystemExit("drain response did not report a workload blocker")
PY

# Post-drain checkpoint: the drained block is no longer placement-eligible
# (state "draining", its Placement provider is closed to new work), so the
# eligible Ready set is exactly four until the replacement joins.
record_scale_checkpoint post-drain 4 "" "$SURVIVOR_IDS" \
  >/dev/null || die "post-drain eligible Ready count is not exactly four"

# A second constrained workload must still converge, and the drained provider
# must not be selected.  The OpenStack host projection is the public placement
# observation for this real workload.
curl --fail --silent --show-error -X POST -H "Authorization: Bearer $PROJECT_TOKEN" -H 'Content-Type: application/json' -H "Idempotency-Key: p15-7-$RUN_ID-b" "$API/compute/servers" \
  -d "{\"kind\":\"compute:server\",\"spec\":{\"name\":\"p15-7-$RUN_ID-b\",\"image_id\":\"$OS_IMAGE_ID\",\"flavor_id\":\"$OS_FLAVOR_ID\",\"key_name\":\"$OS_KEYPAIR_NAME\",\"ssh_public_key\":\"$SSH_PUBLIC_KEY\",\"network_ids\":[\"$OS_PORT_B_ID\"]}}" >"$WORK_ROOT/workload-b.json" || die "placement did not avoid drained block"
WORKLOAD_B="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("resource_id", ""))' "$WORK_ROOT/workload-b.json")"; [[ "$WORKLOAD_B" =~ ^[0-9a-fA-F-]{36}$ ]] || die "workload B has no canonical id"
OS_WORKLOAD_B="$WORKLOAD_B"
HOST_B=""
for _ in $(seq 1 60); do
  HOST_B="$(openstack server show "$WORKLOAD_B" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null || true)"
  [[ -n "$HOST_B" && "$HOST_B" != "None" ]] && break
  sleep 1
done
[[ -n "$HOST_B" && "$HOST_B" != "None" ]] || die "workload B placement host did not converge"
[[ "$HOST_B" != "$HOST_A" ]] || die "new placement selected drained provider host: $HOST_A"
# The OpenStack host projection is derived from the durable placement intent;
# it can be visible while the provider create is still in flight. Wait for the
# native lifecycle state before deleting so cleanup does not race provider
# identity attachment.
WORKLOAD_B_SHOW="$WORK_ROOT/workload-b-show.json"
B_STATE=""
for _ in $(seq 1 120); do
  curl --fail --silent --show-error -H "Authorization: Bearer $PROJECT_TOKEN" \
    "$API/compute/servers/$WORKLOAD_B" >"$WORKLOAD_B_SHOW" || die "workload B native status read failed"
  B_STATE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("status", {}).get("state", ""))' "$WORKLOAD_B_SHOW")"
  [[ "$B_STATE" == "ACTIVE" ]] && break
  if [[ "$B_STATE" == ERROR ]]; then
    capture_workload_failure_diagnostics workload-b
    die "workload B provisioning entered ERROR before cleanup"
  fi
  sleep 1
done
if [[ "$B_STATE" != "ACTIVE" ]]; then
  capture_workload_failure_diagnostics workload-b
  die "workload B did not become ACTIVE before cleanup"
fi
GEN_B="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["metadata"]["generation"])' "$WORKLOAD_B_SHOW")"
curl --fail --silent --show-error -X DELETE -H "Authorization: Bearer $PROJECT_TOKEN" -H "Idempotency-Key: p15-7-$RUN_ID-delete-b" -H "If-Match: generation-$GEN_B" "$API/compute/servers/$WORKLOAD_B" >/dev/null || die "workload B cleanup failed"
for _ in $(seq 1 60); do
  code="$(curl --silent --output /dev/null --write-out '%{http_code}' -H "Authorization: Bearer $PROJECT_TOKEN" "$API/compute/servers/$WORKLOAD_B" || true)"
  if [[ "$code" == 5* ]]; then
    record_transient http_5xx "native compute server show" "workload B deletion convergence poll" "$code"
  fi
  [[ "$code" == 404 ]] && break
  sleep 1
done
[[ "$code" == 404 ]] || die "workload B deletion did not converge before block removal"

# The observed workload blocker is now explicitly cleared before removal.
# Refresh the optimistic-concurrency token immediately before deletion. The
# drain/placement assertions above can legitimately advance the observed
# generation while the workload remains ACTIVE; deleting with the earlier
# token would be a runner sequencing error, not a lifecycle failure.
WORKLOAD_A_DELETE_SHOW="$WORK_ROOT/workload-a-delete-show.json"
curl --fail --silent --show-error -H "Authorization: Bearer $PROJECT_TOKEN" \
  "$API/compute/servers/$WORKLOAD_A" >"$WORKLOAD_A_DELETE_SHOW" || die "workload A final status read failed"
python3 - "$WORKLOAD_A_DELETE_SHOW" <<'PY' \
  || die "workload A is not ACTIVE at cleanup boundary"
import json,sys
state=json.load(open(sys.argv[1], encoding="utf-8")).get("status", {}).get("state")
if state != "ACTIVE":
    raise SystemExit(f"workload A state is {state!r}, expected 'ACTIVE'")
PY
GEN_A_DELETE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["metadata"]["generation"])' "$WORKLOAD_A_DELETE_SHOW")"
curl --fail --silent --show-error -X DELETE -H "Authorization: Bearer $PROJECT_TOKEN" -H "Idempotency-Key: p15-7-$RUN_ID-delete-a" -H "If-Match: generation-$GEN_A_DELETE" "$API/compute/servers/$WORKLOAD_A" >/dev/null || die "workload A cleanup failed"
for _ in $(seq 1 60); do
  code="$(curl --silent --output /dev/null --write-out '%{http_code}' -H "Authorization: Bearer $PROJECT_TOKEN" "$API/compute/servers/$WORKLOAD_A" || true)"
  if [[ "$code" == 5* ]]; then
    record_transient http_5xx "native compute server show" "workload A deletion convergence poll" "$code"
  fi
  [[ "$code" == 404 ]] && break
  sleep 1
done
[[ "$code" == 404 ]] || die "workload A deletion did not converge before block removal"

# #1042 empirical leg: the deleted workload must be absent from the drained
# block's durable blocker projection before the remove is issued. A retained
# terminal tombstone is audit state, not resident capacity, so the
# drain_blockers recorded for the block must no longer carry the deleted
# workload (nor any attachment/local-storage entry this run is expected to
# have none of). Re-query the block AFTER workload A's 404 is confirmed and
# record the full projection; fail closed if the tombstoned workload still
# reads as a resident blocker.
operator_curl "$API/operator/building-blocks/$DRAIN_ID" >"$WORK_ROOT/drain-blocker-requery.json" \
  || die "drained block re-query before removal failed"
python3 - "$WORK_ROOT/drain-blocker-requery.json" "$WORK_ROOT/drain.json" "$WORK_ROOT/workload-a.json" \
  "$ARTIFACT_DIR/p15-7-drain-blocker-requery.json" <<'PY' \
  || die "tombstoned workload still reported as a resident drain blocker"
import json, pathlib, sys

show_path, drain_path, workload_path, out_path = sys.argv[1:5]
block = json.load(open(show_path, encoding="utf-8")).get("block", {})
drain_blockers = json.load(open(drain_path, encoding="utf-8")).get("block", {}).get("drain_blockers", [])
workload = json.load(open(workload_path, encoding="utf-8"))
workload_id = workload.get("resource_id", "")
blockers = block.get("drain_blockers") or []
workload_blockers = [b for b in blockers if b.get("kind") == "workload" and b.get("count", 0) > 0]
fragment = {
    "phase": "post-delete-pre-remove",
    "drain_block_id": block.get("id"),
    "state": block.get("state"),
    "workload_id": workload_id,
    "blockers_at_drain": drain_blockers,
    "blockers_at_requery": blockers,
    "blockers_empty": not blockers,
    "attachment_blockers": [b for b in blockers if b.get("kind") == "attachment"],
    "local_storage_blockers": [b for b in blockers if b.get("kind") == "local_storage"],
    "deleted_workload_absent_from_blockers": not workload_blockers,
}
pathlib.Path(out_path).write_text(
    json.dumps(fragment, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if workload_blockers:
    raise SystemExit("deleted workload still reported as a workload drain blocker")
PY

# Remove the drained block, then provision the fifth child VM and enroll its
# new identity (block-e) as the replacement. block-e's shared-array slot is
# appended last so block-a..block-d keep their stable indices ([0..3]);
# block-e is fixed at [4].
REMOVE_GEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["block"]["generation"])' "$WORK_ROOT/drain.json")"
operator_curl "$API/operator/building-blocks/$DRAIN_ID/actions/remove" -X POST -H 'Content-Type: application/json' -d "{\"expected_generation\":$REMOVE_GEN}" >"$WORK_ROOT/remove.json" || die "block removal failed"
# Post-remove checkpoint: the removed identity is absent from the canonical
# topology and the eligible Ready set is still exactly four (the surviving
# children plus the bootstrap block).
record_scale_checkpoint post-remove 4 "$DRAIN_ID" "$SURVIVOR_IDS" \
  >/dev/null || die "post-remove eligible Ready count is not exactly four"
# Settle the post-removal topology before enrolling the replacement. The
# baseline must describe the CURRENT topology; reading the total only after
# block-e joins would compare the new total against itself and could never
# observe growth. The canonical aggregate retains a removed provider's durable
# inventory rows, so the settled baseline is observed honestly from the
# diagnostics projection and block-e must push the total above it.
CAPACITY_AFTER_REMOVE=""
for _ in $(seq 1 60); do
  api_get /operator/diagnostics/capacity >"$WORK_ROOT/capacity-after-remove.json" || true
  CAPACITY_AFTER_REMOVE="$(capacity_total "$WORK_ROOT/capacity-after-remove.json" 2>/dev/null || true)"
  [[ "$CAPACITY_AFTER_REMOVE" =~ ^[1-9][0-9]*$ ]] && break
  sleep 2
done
[[ "$CAPACITY_AFTER_REMOVE" =~ ^[1-9][0-9]*$ ]] \
  || die "Placement capacity was not honest after removing the drained block"
register_vm block-e; provision_vm block-e
IPS+=("$(<"$WORK_ROOT/block-e-ip")")
UUIDS[$((${#IPS[@]} - 1))]="$(<"$WORK_ROOT/block-e-uuid")"
join_block block-e "${IPS[4]}"; install_agent block-e "${IPS[4]}"
CAPACITY_AFTER_E=""
for _ in $(seq 1 60); do
  api_get /operator/diagnostics/capacity >"$WORK_ROOT/capacity-after-e.json" || true
  CAPACITY_AFTER_E="$(capacity_total "$WORK_ROOT/capacity-after-e.json" 2>/dev/null || true)"
  [[ "$CAPACITY_AFTER_E" =~ ^[1-9][0-9]*$ && "$CAPACITY_AFTER_E" -gt "$CAPACITY_AFTER_REMOVE" ]] && break
  sleep 2
done
[[ "$CAPACITY_AFTER_E" =~ ^[1-9][0-9]*$ && "$CAPACITY_AFTER_E" -gt "$CAPACITY_AFTER_REMOVE" ]] \
  || die "Placement capacity did not grow after enrolling the replacement block"
# Final S5 topology checkpoint: the eligible Ready set must be EXACTLY five
# again — the bootstrap block plus the surviving initial children plus
# block-e — with the drained identity absent and no duplicate BuildingBlock or
# ResourceProvider identity anywhere in the canonical topology.
FINAL_READY_COUNT="$(record_scale_checkpoint post-replacement 5 "$DRAIN_ID" \
  "$SURVIVOR_IDS,${BLOCK_IDS[block-e]}")" \
  || die "post-replacement eligible Ready count is not exactly five"
[[ "$FINAL_READY_COUNT" == 5 ]] || die "post-replacement eligible Ready count is not exactly five"
PEAK_CONCURRENT_READY="$INITIAL_READY_COUNT"
if [[ "$FINAL_READY_COUNT" -gt "$PEAK_CONCURRENT_READY" ]]; then
  PEAK_CONCURRENT_READY="$FINAL_READY_COUNT"
fi
[[ "$PEAK_CONCURRENT_READY" -ge 5 ]] || die "peak concurrent Ready count is below five"

# Real negative probes: these requests must be rejected by the production API.
# The axum JSON extractor rejects the credential-less body (missing required
# join fields) with 422 before any handler runs; 400/401/403 are handler-level
# rejections. Anything outside this set — above all 2xx — means the join was
# accepted and is a hard failure.
code="$(curl --silent -o /dev/null -w '%{http_code}' -X POST "$API/bootstrap/join" -H 'Content-Type: application/json' -d '{}')"
[[ "$code" == 400 || "$code" == 401 || "$code" == 403 || "$code" == 422 ]] || die "unauthenticated join accepted"
# Replay the ORIGINAL join request of the agent whose block was just drained
# and removed above — never a fixed block name: Placement may legitimately
# host workload A on any ready canonical provider (a journey block or the
# TestLab bootstrap compute-agent), and only the removed agent's replay is
# required to be refused. A replay of a still-ready agent's request is
# legitimately accepted by the canonical replay-join path and is not evidence.
REPLAY_JOIN_FILE="${REPLAY_JOIN_BY_AGENT[$DRAIN_AGENT]:-}"
if [[ -z "$REPLAY_JOIN_FILE" && "$DRAIN_AGENT" == "$BOOTSTRAP_AGENT_ID" ]]; then
  # The drained host is the TestLab bootstrap agent (whatever its canonical
  # agent id is — matched from the durable TLS state, never hardcoded): the
  # journey did not perform its join, so reconstruct the replay from the
  # durable identity the canonical bootstrap recorded (same certificate
  # fingerprint and agent id, which is what the replay path validates). The
  # enrollment token is ignored on the enrolled-replay path; any non-empty
  # placeholder exercises it.
  [[ -s "$STATE_ROOT/tls/agent.pem" && -s "$STATE_ROOT/tls/agent-id" ]] \
    || die "bootstrap agent identity unavailable for drained-agent replay probe"
  [[ "$(sudo -n cat "$STATE_ROOT/tls/agent-id" 2>/dev/null)" == "$BOOTSTRAP_AGENT_ID" ]] \
    || die "bootstrap agent identity does not match the drained host"
  REPLAY_JOIN_FILE="$WORK_ROOT/compute-agent-replay-join.json"
  # The certificate is public material (the journey stages block agent certs
  # 0644 above the same way); 0600 root-owned would be unreadable by the
  # unprivileged runner user that runs python3 below.
  sudo -n install -m 0644 "$STATE_ROOT/tls/agent.pem" "$WORK_ROOT/replay-agent.pem" \
    || die "cannot stage bootstrap agent certificate for replay probe"
  python3 - "$REPLAY_JOIN_FILE" "$WORK_ROOT/replay-agent.pem" "$BOOTSTRAP_AGENT_ID" <<'PY' \
    || die "cannot compose drained-agent replay join request"
import json, pathlib, sys
request = {
    "enrollment_token": "replayed-consumed-grant.invalid",
    "agent_id": sys.argv[3],
    "agent_epoch": "replay-probe",
    "certificate": pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"),
    "capabilities": {},
    "inventories": {"VCPU": 1},
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(request), encoding="utf-8")
PY
  shred --remove --zero --force -- "$WORK_ROOT/replay-agent.pem" 2>/dev/null || rm -f -- "$WORK_ROOT/replay-agent.pem"
fi
[[ -n "$REPLAY_JOIN_FILE" && -f "$REPLAY_JOIN_FILE" ]] || die "replay join request was not retained for drained agent: $DRAIN_AGENT"
code="$(curl --silent -o /dev/null -w '%{http_code}' -X POST "$API/bootstrap/join" -H 'Content-Type: application/json' -d @"$REPLAY_JOIN_FILE")"
[[ "$code" != 200 ]] || die "replayed join accepted for removed drained agent: $DRAIN_AGENT (code=$code)"
code="$(curl --silent -o /dev/null -w '%{http_code}' "$API/operator/building-blocks/$DRAIN_ID")"
[[ "$code" == 401 || "$code" == 403 ]] || die "unauthenticated state read was not concealed"

# Restart the exact owned daemon and PostgreSQL container.  Process identity is
# read from the ownership ledger; no process-name kill is permitted. The
# daemon re-sources the same run-scoped o3kd.env, so the effective backend
# selected above is retained across the restart.
restart_o3kd_verified
wait_o3kd_readyz "readyz did not reconstruct after restart"
if [[ "$POSTGRES_MODE" == external ]]; then
  # External mode must never stop/start/restart/drop the operator-owned server.
  # Unavailability is injected by severing the run-owned proxy the control
  # plane consumes. The observed outage is therefore the CONTROL PLANE's:
  # /readyz gating or an authenticated durable-store write (the same signals
  # as the early wiring proof). The operator-owned server must simultaneously
  # remain reachable via its own direct endpoint — proving we never manage it.
  stop_postgres_proxy || die "external PostgreSQL proxy failed to sever"
  OUTAGE_OBSERVED=false
  for _ in $(seq 1 60); do
    if ! curl --fail --silent --max-time 2 "http://127.0.0.1:$AUTH_PORT/readyz" >/dev/null 2>&1; then
      OUTAGE_OBSERVED=true
      break
    fi
    if ! bootstrap_store_probe; then
      OUTAGE_OBSERVED=true
      break
    fi
    sleep 1
  done
  [[ "$OUTAGE_OBSERVED" == true ]] || die "external PostgreSQL outage was not observed"
  pg_external_ready || die "operator-owned PostgreSQL became unreachable during the outage proof"
  start_postgres_proxy || die "external PostgreSQL proxy failed to restore"
  RECOVERY_OBSERVED=false
  for _ in $(seq 1 60); do
    if curl --fail --silent --max-time 2 "http://127.0.0.1:$AUTH_PORT/readyz" >/dev/null 2>&1 \
      && bootstrap_store_probe; then
      RECOVERY_OBSERVED=true
      break
    fi
    sleep 1
  done
  [[ "$RECOVERY_OBSERVED" == true ]] || die "external PostgreSQL did not recover"
else
  sudo -n docker restart "$PG_CONTAINER" >/dev/null || die "PostgreSQL restart failed"
  for _ in $(seq 1 60); do sudo -n docker exec "$PG_CONTAINER" pg_isready -U o3k -d o3k_test >/dev/null 2>&1 && break; sleep 1; done
  sudo -n docker exec "$PG_CONTAINER" pg_isready -U o3k -d o3k_test >/dev/null 2>&1 || die "PostgreSQL did not recover"
fi
# Post-reboot checkpoint: the orderly control-plane restart and the
# PostgreSQL fault gate must not change the eligible topology — still exactly
# five (bootstrap + survivors + block-e), drained identity still absent.
record_scale_checkpoint post-reboot 5 "$DRAIN_ID" "$SURVIVOR_IDS,${BLOCK_IDS[block-e]}" \
  >/dev/null || die "post-reboot eligible Ready count is not exactly five"

# ── #1035 crash-injection leg ──────────────────────────────────────────────
# Interrupt a real delete inside the fault hook's window — after the delete
# is durably terminal (operation Succeeded, resource observed DELETED) and
# before the server-owned endpoint is released — then SIGKILL (true process
# death, NOT the orderly restart) the run-owned o3kd, restart through the
# normal boot path, and prove the shipped orphan-repair sweep converges:
# endpoint absent, fixed IP reusable, network:ports quota restored, no
# Placement allocation leak, unrelated work stays responsive during the
# backlog, and caller-supplied / foreign-project endpoints are preserved.
CRASH_EVIDENCE_FILE="$ARTIFACT_DIR/p15-7-crash-injection-evidence.json"
CRASH_KILLED_PID=""
CRASH_TERMINAL_OBSERVED_MS=""
CRASH_REPAIR_OBSERVED_MS=""
CRASH_DELETE_HTTP_CODE=""
CRASH_SWEEP_PASSES=0
ENDPOINT_PRESENT_WHILE_PAUSED=false
ORPHAN_PRESENT_AT_D_CREATE=false
quota_usage() {
  curl --fail --silent --show-error -H "Authorization: Bearer $PROJECT_TOKEN" \
    "$API/quota/network/ports" 2>/dev/null | \
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("usage", ""))'
}
allocated_vcpu_total() {
  python3 - "$1" <<'PY'
import json,sys
page=json.load(open(sys.argv[1], encoding="utf-8"))
total=0
for item in page.get("items", []):
    for dim in item.get("capacity", []):
        if dim.get("resource_class") == "VCPU":
            total += dim.get("allocated", 0)
print(total)
PY
}
# Arm the fault hook and restart so the delete below parks inside the
# injected window. The hook is a positive-ms sleep on the delete path after
# durable terminalization commits and before endpoint release.
append_o3kd_fault_env
restart_o3kd_verified
wait_o3kd_readyz "readyz did not reconstruct with the fault hook armed"
api_get "/operator/diagnostics/providers?limit=200" >"$WORK_ROOT/providers-before-crash.json"
ALLOC_BEFORE_CRASH="$(allocated_vcpu_total "$WORK_ROOT/providers-before-crash.json")"
[[ "$ALLOC_BEFORE_CRASH" =~ ^[0-9]+$ ]] || die "Placement allocation baseline unavailable"
QUOTA_BEFORE_CRASH="$(quota_usage)"
[[ "$QUOTA_BEFORE_CRASH" =~ ^[0-9]+$ ]] || die "network:ports quota baseline unavailable"
CRASH_LOG_LINES_BEFORE="$(sudo -n wc -l <"$STATE_ROOT/log/o3kd.log" 2>/dev/null || echo 0)"

# Server C is created through the compatibility API with a NETWORK reference
# so the control plane mints exactly one server-owned endpoint
# (o3k-server:<project>:<context>) — the orphan shape #1035 repairs. The
# port-id diff identifies it without guessing.
openstack port list -f value -c ID >"$WORK_ROOT/ports-before-c.txt" || die "port baseline listing failed"
openstack server create --image "$OS_IMAGE_ID" --flavor "$OS_FLAVOR_ID" --key-name "$OS_KEYPAIR_NAME" \
  --nic "net-id=$OS_NETWORK_ID" "o3k-p15-7-$RUN_ID-c" -f value -c id >"$WORK_ROOT/workload-c-create.txt" 2>"$WORK_ROOT/workload-c-create.err" \
  || die "server C creation through the compatibility API failed"
WORKLOAD_C="$(tr -d '[:space:]' <"$WORK_ROOT/workload-c-create.txt")"
[[ "$WORKLOAD_C" =~ ^[0-9a-fA-F-]{36}$ ]] || die "server C create returned an invalid id"
OS_WORKLOAD_C="$WORKLOAD_C"
openstack port list -f value -c ID >"$WORK_ROOT/ports-after-c.txt" || die "port observation listing failed"
PORT_C_ID="$(comm -13 <(sort "$WORK_ROOT/ports-before-c.txt") <(sort "$WORK_ROOT/ports-after-c.txt") | head -n 1 | tr -d '[:space:]')"
[[ "$PORT_C_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "server C's server-owned endpoint was not observed"
PORT_C_FIXED_IP="$(openstack port show "$PORT_C_ID" -f json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["port"]["fixed_ips"][0]["ip_address"])' 2>/dev/null || true)"
[[ "$PORT_C_FIXED_IP" =~ ^[0-9.]+$ ]] || die "server C endpoint fixed IP unavailable"
C_STATE=""
for _ in $(seq 1 180); do
  code_c="$(curl --silent --output "$WORK_ROOT/workload-c-show.json" --write-out '%{http_code}' -H "Authorization: Bearer $PROJECT_TOKEN" "$API/compute/servers/$WORKLOAD_C" || true)"
  if [[ "$code_c" == 5* ]]; then
    record_transient http_5xx "native compute server show" "server C activation poll" "$code_c"
  fi
  if [[ "$code_c" == 200 ]]; then
    C_STATE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("status", {}).get("state", ""))' "$WORK_ROOT/workload-c-show.json" 2>/dev/null || true)"
    [[ "$C_STATE" == "ACTIVE" ]] && break
    [[ "$C_STATE" == "ERROR" ]] && die "server C provisioning entered ERROR"
  fi
  sleep 2
done
[[ "$C_STATE" == "ACTIVE" ]] || die "server C did not become ACTIVE"
GEN_C="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["metadata"]["generation"])' "$WORK_ROOT/workload-c-show.json")"

# Issue the delete in the background: with the pause on the delete path the
# request stays in flight while the durable terminal state is already
# observable. Poll the operation surface and the resource projection until
# the delete is durably terminal and the resource reads DELETED — all inside
# the pause window. The poll budget (30s) is deliberately below the pause
# (default 45s) so the assertions and the SIGKILL always land while the
# release is still parked.
CRASH_DELETE_START_MS="$(date +%s%3N)"
( curl --silent --show-error --max-time 180 -o "$WORK_ROOT/workload-c-delete-response.json" -w '%{http_code}' \
    -X DELETE -H "Authorization: Bearer $PROJECT_TOKEN" -H "Idempotency-Key: p15-7-$RUN_ID-delete-c" \
    -H "If-Match: generation-$GEN_C" "$API/compute/servers/$WORKLOAD_C" >"$WORK_ROOT/workload-c-delete.code" 2>"$WORK_ROOT/workload-c-delete.err" ) &
CRASH_DELETE_PID=$!
OPERATION_SUCCEEDED=false
SERVER_DELETED=false
for _ in $(seq 1 30); do
  curl --fail --silent --show-error -H "Authorization: Bearer $PROJECT_TOKEN" "$API/operations?limit=100" >"$WORK_ROOT/operations-c.json" 2>/dev/null || true
  OP_STATE="$(python3 - "$WORK_ROOT/operations-c.json" "$WORKLOAD_C" <<'PY'
import json,sys
try:
    doc=json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    print(""); raise SystemExit(0)
target=sys.argv[2]
state=""
for item in doc.get("items", []):
    if item.get("resource_id") == target and "delete" in str(item.get("action", "")).lower():
        state=item.get("state", "")
print(state)
PY
)"
  [[ "$OP_STATE" == "succeeded" ]] && OPERATION_SUCCEEDED=true
  code_c="$(curl --silent --output /dev/null --write-out '%{http_code}' -H "Authorization: Bearer $PROJECT_TOKEN" "$API/compute/servers/$WORKLOAD_C" || true)"
  if [[ "$code_c" == 5* ]]; then
    record_transient http_5xx "native compute server show" "server C crash-leg deletion poll" "$code_c"
  fi
  [[ "$code_c" == 404 ]] && SERVER_DELETED=true
  [[ "$OPERATION_SUCCEEDED" == true && "$SERVER_DELETED" == true ]] && break
  sleep 1
done
[[ "$OPERATION_SUCCEEDED" == true ]] || die "server C delete did not reach durable terminal success inside the fault window"
[[ "$SERVER_DELETED" == true ]] || die "server C was not observed DELETED inside the fault window"
CRASH_TERMINAL_OBSERVED_MS="$(($(date +%s%3N) - CRASH_DELETE_START_MS))"
# The owned endpoint must still exist while the pause holds. The public port
# projection does not expose binding state, so presence is the assertion and
# that limitation is recorded honestly in the evidence.
if openstack_absent_code port "$PORT_C_ID"; then
  die "server-owned endpoint was released before the crash; the fault hook did not hold on the delete path"
fi
ENDPOINT_PRESENT_WHILE_PAUSED=true

# True process death of the run-owned control plane while the release is
# parked, then clear the fault and restart through the normal boot path.
CRASH_KILLED_PID="$(kill9_o3kd_verified)"
wait "$CRASH_DELETE_PID" 2>/dev/null || true
CRASH_DELETE_HTTP_CODE="$(tr -d '[:space:]' <"$WORK_ROOT/workload-c-delete.code" 2>/dev/null || true)"
clear_o3kd_fault_env || die "fault hook could not be cleared from the o3kd environment"
start_o3kd_verified
wait_o3kd_readyz "readyz did not reconstruct after the crash restart"
CRASH_RESTART_MS="$(date +%s%3N)"

# Foreign-project fixture created DURING the orphan backlog: the sweep must
# never touch it even though foreign endpoints exist in the same control
# plane. Deleted at leg end (the fixture credentials are not retained). The
# token is re-minted here: the leg runs long after the concealment-phase
# token was issued and a bounded foreign fixture must not depend on it.
FOREIGN_TOKEN="$(
  OS_USERNAME="$FOREIGN_USER_NAME" OS_PASSWORD="${O3K_P15_7_FOREIGN_PASSWORD:-${O3K_EXTRA_TENANT_PASSWORD:-}}" \
  OS_PROJECT_ID="$FOREIGN_PROJECT_ID" OS_PROJECT_NAME="$FOREIGN_PROJECT_NAME" \
  OS_USER_DOMAIN_NAME=Default OS_PROJECT_DOMAIN_NAME=Default \
    openstack token issue -f value -c id 2>/dev/null | tr -d '[:space:]' || true
)"
[[ -n "$FOREIGN_TOKEN" ]] || die "foreign-project token re-issue for the crash leg failed"
FOREIGN_NET_ID="$(curl --silent --show-error --max-time 15 -X POST -H "X-Auth-Token: $FOREIGN_TOKEN" -H 'Content-Type: application/json' \
  "http://127.0.0.1:$AUTH_PORT/v2.0/networks" -d "{\"network\":{\"name\":\"o3k-p15-7-$RUN_ID-foreign-net\"}}" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("network") or d).get("id", ""))' 2>/dev/null | tr -d '[:space:]')"
[[ "$FOREIGN_NET_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "foreign-project network fixture creation failed"
FOREIGN_SUBNET_ID="$(curl --silent --show-error --max-time 15 -X POST -H "X-Auth-Token: $FOREIGN_TOKEN" -H 'Content-Type: application/json' \
  "http://127.0.0.1:$AUTH_PORT/v2.0/subnets" -d "{\"subnet\":{\"network_id\":\"$FOREIGN_NET_ID\",\"ip_version\":4,\"cidr\":\"198.19.0.0/29\",\"name\":\"o3k-p15-7-$RUN_ID-foreign-subnet\"}}" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("subnet") or d).get("id", ""))' 2>/dev/null | tr -d '[:space:]')"
[[ "$FOREIGN_SUBNET_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "foreign-project subnet fixture creation failed"
FOREIGN_PORT_ID="$(curl --silent --show-error --max-time 15 -X POST -H "X-Auth-Token: $FOREIGN_TOKEN" -H 'Content-Type: application/json' \
  "http://127.0.0.1:$AUTH_PORT/v2.0/ports" -d "{\"port\":{\"network_id\":\"$FOREIGN_NET_ID\",\"name\":\"o3k-p15-7-$RUN_ID-foreign-port\"}}" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("port") or d).get("id", ""))' 2>/dev/null | tr -d '[:space:]')"
[[ "$FOREIGN_PORT_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "foreign-project endpoint fixture creation failed"

# Responsiveness probe: an unrelated server create issued while the orphan
# backlog still exists must return responsively. Time the create call and the
# activation; the orphan's presence is verified immediately before issuing.
openstack_absent_code port "$PORT_C_ID" || ORPHAN_PRESENT_AT_D_CREATE=true
openstack port create --network "$OS_NETWORK_ID" "o3k-p15-7-$RUN_ID-port-d" -f value -c id >"$WORK_ROOT/port-d-create.txt" 2>"$WORK_ROOT/port-d-create.err" \
  || die "caller-supplied probe port creation failed"
OS_PORT_D_ID="$(tr -d '[:space:]' <"$WORK_ROOT/port-d-create.txt")"
[[ "$OS_PORT_D_ID" =~ ^[0-9a-fA-F-]{36}$ && "$OS_PORT_D_ID" != "$OS_PORT_A_ID" && "$OS_PORT_D_ID" != "$OS_PORT_B_ID" ]] \
  || die "caller-supplied probe port returned an invalid or reused id"
D_CREATE_START_MS="$(date +%s%3N)"
openstack server create --image "$OS_IMAGE_ID" --flavor "$OS_FLAVOR_ID" --key-name "$OS_KEYPAIR_NAME" \
  --nic "port-id=$OS_PORT_D_ID" "o3k-p15-7-$RUN_ID-d" -f value -c id >"$WORK_ROOT/workload-d-create.txt" 2>"$WORK_ROOT/workload-d-create.err" \
  || die "responsiveness probe server create failed during the orphan backlog"
D_CREATE_END_MS="$(date +%s%3N)"
WORKLOAD_D="$(tr -d '[:space:]' <"$WORK_ROOT/workload-d-create.txt")"
[[ "$WORKLOAD_D" =~ ^[0-9a-fA-F-]{36}$ ]] || die "responsiveness probe returned an invalid server id"
OS_WORKLOAD_D="$WORKLOAD_D"

# Orphan-repair convergence: bounded wait (<=180s) for the sweep to release
# the orphaned endpoint, counting the bounded observability lines the sweep
# emits per pass that discovered or repaired something.
SWEEP_CONVERGED=false
for _ in $(seq 1 90); do
  if openstack_absent_code port "$PORT_C_ID"; then
    SWEEP_CONVERGED=true
    CRASH_REPAIR_OBSERVED_MS="$(($(date +%s%3N) - CRASH_RESTART_MS))"
    break
  fi
  sleep 2
done
CRASH_LOG_LINES_AFTER="$(sudo -n wc -l <"$STATE_ROOT/log/o3kd.log" 2>/dev/null || echo 0)"
CRASH_SWEEP_PASSES="$(sudo -n tail -n "$((CRASH_LOG_LINES_AFTER - CRASH_LOG_LINES_BEFORE))" "$STATE_ROOT/log/o3kd.log" 2>/dev/null | grep -Fc "server-owned endpoint orphan repair sweep" || true)"
[[ "$CRASH_SWEEP_PASSES" =~ ^[0-9]+$ ]] || CRASH_SWEEP_PASSES=0
D_STATE=""
for _ in $(seq 1 180); do
  code_d="$(curl --silent --output "$WORK_ROOT/workload-d-show.json" --write-out '%{http_code}' -H "Authorization: Bearer $PROJECT_TOKEN" "$API/compute/servers/$WORKLOAD_D" || true)"
  if [[ "$code_d" == 200 ]]; then
    D_STATE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("status", {}).get("state", ""))' "$WORK_ROOT/workload-d-show.json" 2>/dev/null || true)"
    [[ "$D_STATE" == "ACTIVE" ]] && break
    [[ "$D_STATE" == "ERROR" ]] && die "responsiveness probe server entered ERROR"
  fi
  sleep 2
done
D_ACTIVE_MS="$(($(date +%s%3N) - D_CREATE_END_MS))"
[[ "$D_STATE" == "ACTIVE" ]] || die "responsiveness probe server did not become ACTIVE"

# Fail-closed tail: no die is permitted between here and the foreign-fixture
# teardown below, so an assertion failure cannot strand foreign-owned state.
CRASH_FAILURE=""
if [[ "$SWEEP_CONVERGED" != true ]]; then
  CRASH_FAILURE="orphan-repair sweep did not release the orphaned endpoint within 180s"
elif [[ "$ORPHAN_PRESENT_AT_D_CREATE" != true ]]; then
  CRASH_FAILURE="orphan backlog was repaired before the responsiveness probe was issued"
elif [[ "$CRASH_REPAIR_OBSERVED_MS" -gt 180000 ]]; then
  CRASH_FAILURE="orphan repair exceeded the 180s bound"
fi
QUOTA_AFTER_CRASH="$(quota_usage)"
ALLOC_AFTER_CRASH=""
api_get "/operator/diagnostics/providers?limit=200" >"$WORK_ROOT/providers-after-crash.json"
ALLOC_AFTER_CRASH="$(allocated_vcpu_total "$WORK_ROOT/providers-after-crash.json")"
FIXED_IP_REUSABLE=false
REUSE_FAILURE=""
if [[ -z "$CRASH_FAILURE" ]]; then
  if REUSE_PORT_ID="$(openstack port create --network "$OS_NETWORK_ID" --fixed-ip "ip-address=$PORT_C_FIXED_IP" "o3k-p15-7-$RUN_ID-reuse" -f value -c id 2>"$WORK_ROOT/reuse-port.err" | tr -d '[:space:]')" \
    && [[ "$REUSE_PORT_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    FIXED_IP_REUSABLE=true
    delete_owned_openstack port "$REUSE_PORT_ID" || REUSE_FAILURE="reuse proof port could not be deleted"
    REUSE_PORT_ID=""
  else
    REUSE_FAILURE="orphan fixed IP was not reusable after repair"
  fi
fi
# Delete the responsiveness probe server and prove the caller-supplied port
# survived (only server-owned endpoints may ever be released).
CALLER_SUPPLIED_PRESERVED=false
GEN_D="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["metadata"]["generation"])' "$WORK_ROOT/workload-d-show.json")"
curl --fail --silent --show-error --max-time 120 -X DELETE -H "Authorization: Bearer $PROJECT_TOKEN" \
  -H "Idempotency-Key: p15-7-$RUN_ID-delete-d" -H "If-Match: generation-$GEN_D" "$API/compute/servers/$WORKLOAD_D" >/dev/null 2>&1 || true
for _ in $(seq 1 60); do
  code_d="$(curl --silent --output /dev/null --write-out '%{http_code}' -H "Authorization: Bearer $PROJECT_TOKEN" "$API/compute/servers/$WORKLOAD_D" || true)"
  [[ "$code_d" == 404 ]] && break
  sleep 1
done
OS_WORKLOAD_D=""
if openstack port show "$OS_PORT_D_ID" >/dev/null 2>&1; then
  CALLER_SUPPLIED_PRESERVED=true
fi
delete_owned_openstack port "$OS_PORT_D_ID" || true
# Foreign-project preservation proof and teardown.
FOREIGN_PRESERVED=false
if [[ "$FOREIGN_PORT_ID" =~ ^[0-9a-fA-F-]{36}$ ]] \
  && curl --silent --output /dev/null --write-out '%{http_code}' -H "X-Auth-Token: $FOREIGN_TOKEN" \
    "http://127.0.0.1:$AUTH_PORT/v2.0/ports/$FOREIGN_PORT_ID" | grep -q '^2'; then
  FOREIGN_PRESERVED=true
fi
curl --silent --output /dev/null -X DELETE -H "X-Auth-Token: $FOREIGN_TOKEN" "http://127.0.0.1:$AUTH_PORT/v2.0/ports/$FOREIGN_PORT_ID" || true
curl --silent --output /dev/null -X DELETE -H "X-Auth-Token: $FOREIGN_TOKEN" "http://127.0.0.1:$AUTH_PORT/v2.0/subnets/$FOREIGN_SUBNET_ID" || true
curl --silent --output /dev/null -X DELETE -H "X-Auth-Token: $FOREIGN_TOKEN" "http://127.0.0.1:$AUTH_PORT/v2.0/networks/$FOREIGN_NET_ID" || true
FOREIGN_PORT_ID="" FOREIGN_SUBNET_ID="" FOREIGN_NET_ID=""
if [[ -n "$CRASH_FAILURE" ]]; then
  die "$CRASH_FAILURE"
fi
[[ -z "$REUSE_FAILURE" ]] || die "$REUSE_FAILURE"
[[ "$QUOTA_AFTER_CRASH" == "$QUOTA_BEFORE_CRASH" ]] || die "network:ports quota was not restored after orphan repair"
[[ "$ALLOC_AFTER_CRASH" == "$ALLOC_BEFORE_CRASH" ]] || die "Placement allocation leaked across the crash leg"
[[ "$CALLER_SUPPLIED_PRESERVED" == true ]] || die "caller-supplied endpoint was not preserved across the orphan sweep"
[[ "$FOREIGN_PRESERVED" == true ]] || die "foreign-project endpoint was not preserved across the orphan sweep"
python3 - "$CRASH_EVIDENCE_FILE" "$O3K_FAULT_ENV_NAME" "$O3K_FAULT_ENV_VALUE" "$WORKLOAD_C" "$PORT_C_ID" "$PORT_C_FIXED_IP" \
  "$CRASH_KILLED_PID" "$CRASH_TERMINAL_OBSERVED_MS" "$CRASH_REPAIR_OBSERVED_MS" "$CRASH_DELETE_HTTP_CODE" "$CRASH_SWEEP_PASSES" \
  "$QUOTA_BEFORE_CRASH" "$QUOTA_AFTER_CRASH" "$ALLOC_BEFORE_CRASH" "$ALLOC_AFTER_CRASH" "$D_CREATE_START_MS" "$D_CREATE_END_MS" "$D_ACTIVE_MS" \
  "$ENDPOINT_PRESENT_WHILE_PAUSED" "$ORPHAN_PRESENT_AT_D_CREATE" "$FIXED_IP_REUSABLE" "$CALLER_SUPPLIED_PRESERVED" "$FOREIGN_PRESERVED" <<'PY'
import json, pathlib, sys

(out, env_name, env_value, workload, port_id, fixed_ip, killed_pid,
 terminal_ms, repair_ms, delete_code, sweep_passes, quota_before, quota_after,
 alloc_before, alloc_after, d_start, d_end, d_active, endpoint_paused,
 orphan_at_d, fixed_ip_reusable, caller_preserved, foreign_preserved) = sys.argv[1:24]
doc = {
    "status": "passed",
    "fault_hook": {"env": env_name, "pause_ms": int(env_value),
                   "semantics": "positive-ms sleep on the delete path after durable terminalization commits and before endpoint release"},
    "server_c": {"resource_id": workload, "owned_endpoint_id": port_id, "fixed_ip": fixed_ip},
    "endpoint_before_crash": {"port_id": port_id, "existed": True,
                              "binding_state_exposed": False,
                              "presence_asserted_while_pause_held": endpoint_paused == "true",
                              "note": "the public port projection does not expose binding state; presence while the pause held is the asserted invariant"},
    "operation_terminal_observed_ms": int(terminal_ms),
    "kill": {"signal": "SIGKILL", "pid": int(killed_pid), "identity_verified": True,
             "orderly_restart": False},
    "delete_request_observed_http_code": delete_code or None,
    "restart": {"path": "normal boot path via start_o3kd_verified", "readyz": "passed"},
    "sweep": {"passes_observed": int(sweep_passes), "time_to_repair_ms": int(repair_ms),
              "bounded_wait_ms": 180000, "endpoint_absent_after": True},
    "fixed_ip_reuse": {"attempted": True, "succeeded": fixed_ip_reusable == "true"},
    "quota": {"dimension": "network:ports", "before": int(quota_before), "after": int(quota_after),
              "restored": quota_before == quota_after},
    "placement_allocation": {"vcpu_allocated_before": int(alloc_before), "vcpu_allocated_after": int(alloc_after),
                             "leak": alloc_before != alloc_after},
    "responsiveness_during_backlog": {
        "orphan_present_at_create": orphan_at_d == "true",
        "create_call_latency_ms": int(d_end) - int(d_start),
        "activation_latency_ms": int(d_active),
        "server_active": True,
    },
    "caller_supplied_endpoint_preserved": caller_preserved == "true",
    "foreign_project_endpoint_preserved": foreign_preserved == "true",
}
pathlib.Path(out).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
record_scale_checkpoint post-crash-repair 5 "" "$SURVIVOR_IDS,${BLOCK_IDS[block-e]}" \
  >/dev/null || die "post-crash-repair eligible Ready count is not exactly five"

# ── #1033 host-maintenance leg ─────────────────────────────────────────────
# Planned maintenance on one eligible child hypervisor (block-e), per the
# accepted contract in docs/operations/pp5-host-maintenance.md: drain it, show
# new placement is rejected there, resolve the (empty) blocker set, reboot the
# child domain from the outer host, and prove canonical identity preservation
# — same BuildingBlock id, same execution identity, same ResourceProvider id,
# no duplicate block/provider. This is PRODUCT maintenance semantics: the
# operator drain/ready lifecycle and an orderly guest reboot. It is NOT the
# TestLab bounded guest force-shutdown (tests/pp4-core-campaign/host-run.sh),
# which is a harness anti-hang control for minimal images and never a product
# path.
MAINT_EVIDENCE_FILE="$ARTIFACT_DIR/p15-7-host-maintenance-evidence.json"
MAINT_ID="${BLOCK_IDS[block-e]}"
MAINT_UUID="${UUIDS[4]}"
MAINT_DOMAIN="${DOMAINS[4]}"
MAINT_SERIAL="${SERIALS[4]}"
MAINT_PROVIDER_IDS_BEFORE=""
MAINT_EXEC_IDENTITY_BEFORE=""
MAINT_DRAIN_BLOCKERS_EMPTY=false
MAINT_PLACEMENT_REJECTED=false
MAINT_AGENT_RECONNECTED=false
MAINT_IDENTITY_PRESERVED=false
MAINT_RETURNED_TO_READY=false
MAINT_FINAL_ELIGIBLE=""
api_get "/operator/building-blocks/$MAINT_ID" >"$WORK_ROOT/maintenance-block-before.json"
python3 - "$WORK_ROOT/maintenance-block-before.json" "$MAINT_ID" <<'PY' \
  || die "maintenance block is not eligible before the maintenance leg"
import json,sys
view=json.load(open(sys.argv[1], encoding="utf-8"))
block=view.get("block", {})
if block.get("id") != sys.argv[2] or block.get("state") != "ready" or (block.get("drain_blockers") or []):
    raise SystemExit("maintenance block is not Ready with no recorded blockers")
PY
MAINT_EXEC_IDENTITY_BEFORE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["block"]["execution_identity"])' "$WORK_ROOT/maintenance-block-before.json")"
MAINT_PROVIDER_IDS_BEFORE="$(python3 -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))["block"].get("resource_provider_ids") or []))' "$WORK_ROOT/maintenance-block-before.json")"
[[ -n "$MAINT_EXEC_IDENTITY_BEFORE" && -n "$MAINT_PROVIDER_IDS_BEFORE" ]] || die "maintenance block identity projection incomplete"

# Drain the maintenance block: no residents exist, so the drain must report
# success with an empty blocker projection.
MAINT_GEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["block"]["generation"])' "$WORK_ROOT/maintenance-block-before.json")"
operator_curl "$API/operator/building-blocks/$MAINT_ID/actions/drain" -X POST -H 'Content-Type: application/json' \
  -d "{\"expected_generation\":$MAINT_GEN}" >"$WORK_ROOT/maintenance-drain.json" || die "maintenance drain failed"
grep -Eq '"state"[[:space:]]*:[[:space:]]*"draining"' "$WORK_ROOT/maintenance-drain.json" || die "maintenance drain state missing"
python3 - "$WORK_ROOT/maintenance-drain.json" <<'PY' \
  || die "maintenance drain reported unexpected blockers on an empty block"
import json,sys
blockers=json.load(open(sys.argv[1], encoding="utf-8")).get("block", {}).get("drain_blockers", [])
if blockers:
    raise SystemExit(f"maintenance drain reported blockers on an empty block: {blockers}")
PY
MAINT_DRAIN_BLOCKERS_EMPTY=true

# New placement must be rejected on the draining block: the workload lands
# elsewhere (resolved canonically, never assumed).
openstack server create --image "$OS_IMAGE_ID" --flavor "$OS_FLAVOR_ID" --key-name "$OS_KEYPAIR_NAME" \
  --nic "net-id=$OS_NETWORK_ID" "o3k-p15-7-$RUN_ID-m" -f value -c id >"$WORK_ROOT/workload-m-create.txt" 2>"$WORK_ROOT/workload-m-create.err" \
  || die "maintenance placement-rejection workload creation failed"
WORKLOAD_M="$(tr -d '[:space:]' <"$WORK_ROOT/workload-m-create.txt")"
[[ "$WORKLOAD_M" =~ ^[0-9a-fA-F-]{36}$ ]] || die "maintenance workload returned an invalid id"
OS_WORKLOAD_M="$WORKLOAD_M"
HOST_M=""
for _ in $(seq 1 60); do
  HOST_M="$(openstack server show "$WORKLOAD_M" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null || true)"
  [[ -n "$HOST_M" && "$HOST_M" != "None" ]] && break
  sleep 1
done
[[ -n "$HOST_M" && "$HOST_M" != "None" ]] || die "maintenance workload placement host did not converge"
api_get /operator/building-blocks >"$WORK_ROOT/blocks-maintenance-placement.json"
MAINT_PLACED_ID="$(python3 "$ROOT_DIR/scripts/resolve-p15-7-placement-block.py" \
  "$WORK_ROOT/blocks-maintenance-placement.json" "$HOST_M" 2>/dev/null || true)"
[[ "$MAINT_PLACED_ID" =~ ^[0-9a-fA-F-]{36}$ ]] || die "maintenance workload has no canonical block mapping"
[[ "$MAINT_PLACED_ID" != "$MAINT_ID" ]] || die "new placement selected the draining maintenance block"
MAINT_PLACEMENT_REJECTED=true
M_STATE=""
for _ in $(seq 1 180); do
  code_m="$(curl --silent --output "$WORK_ROOT/workload-m-show.json" --write-out '%{http_code}' -H "Authorization: Bearer $PROJECT_TOKEN" "$API/compute/servers/$WORKLOAD_M" || true)"
  if [[ "$code_m" == 200 ]]; then
    M_STATE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("status", {}).get("state", ""))' "$WORK_ROOT/workload-m-show.json" 2>/dev/null || true)"
    [[ "$M_STATE" == "ACTIVE" ]] && break
    [[ "$M_STATE" == "ERROR" ]] && die "maintenance workload entered ERROR"
  fi
  sleep 2
done
[[ "$M_STATE" == "ACTIVE" ]] || die "maintenance workload did not become ACTIVE"
GEN_M="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["metadata"]["generation"])' "$WORK_ROOT/workload-m-show.json")"
curl --fail --silent --show-error --max-time 180 -X DELETE -H "Authorization: Bearer $PROJECT_TOKEN" \
  -H "Idempotency-Key: p15-7-$RUN_ID-delete-m" -H "If-Match: generation-$GEN_M" "$API/compute/servers/$WORKLOAD_M" >/dev/null \
  || die "maintenance workload cleanup failed"
for _ in $(seq 1 60); do
  code_m="$(curl --silent --output /dev/null --write-out '%{http_code}' -H "Authorization: Bearer $PROJECT_TOKEN" "$API/compute/servers/$WORKLOAD_M" || true)"
  [[ "$code_m" == 404 ]] && break
  sleep 1
done
[[ "$code_m" == 404 ]] || die "maintenance workload deletion did not converge"
OS_WORKLOAD_M=""

# Planned host reboot from the outer host, then wait bounded for the child to
# return. The address is re-resolved through the MAC-bound resolver on every
# retry (a DHCP lease is not liveness proof).
virsh -c qemu:///system reboot "$MAINT_UUID" >/dev/null || die "maintenance child reboot failed"
MAINT_IP_AFTER="$(wait_vm_ssh "$MAINT_DOMAIN" "$MAINT_UUID" "$(<"$WORK_ROOT/block-e-mac")" "$MAINT_SERIAL" block-e)" \
  || die "maintenance child did not become SSH-reachable after reboot"
ssh_vm "$MAINT_IP_AFTER" "sudo cloud-init status --wait" >/dev/null 2>&1 || true
# Restart the compute agent from its durable guest identity. O3K packaging
# deliberately installs no host-global service persistence (the operator owns
# host shutdown posture — see docs/operations/pp5-host-maintenance.md), so the
# journey models the operator restarting the host service after maintenance:
# same agent id, same TLS identity, same data directory.
ssh_vm "$MAINT_IP_AFTER" "sudo pkill -x o3k-compute || true; sudo sh -c 'RUST_LOG=$COMPUTE_LOG_FILTER O3K_COMPUTE_CONTROL_ENDPOINT=https://o3k-control-plane:$CONTROL_PORT O3K_COMPUTE_SERVER_NAME=o3k-control-plane O3K_COMPUTE_TLS_DIR=/etc/o3k/tls O3K_COMPUTE_DATA_DIR=/var/lib/o3k-compute O3K_COMPUTE_HOST_LABEL=block-e-host O3K_COMPUTE_HEALTH_ADDR=127.0.0.1:19101 O3K_COMPUTE_MAX_DISK_GB=10 nohup /usr/local/bin/o3k-compute >/var/log/o3k-compute.log 2>&1 &'" \
  || die "maintenance agent restart failed"
for _ in $(seq 1 90); do ssh_vm "$MAINT_IP_AFTER" curl -fsS http://127.0.0.1:19101/readyz >/dev/null 2>&1 && break; sleep 2; done
ssh_vm "$MAINT_IP_AFTER" curl -fsS http://127.0.0.1:19101/readyz >/dev/null 2>&1 || die "maintenance agent did not become ready after reboot"
# Bounded wait for the control plane to observe the reconnected agent.
for _ in $(seq 1 120); do
  AGENT_AVAILABLE="$(api_get "/operator/building-blocks/$MAINT_ID" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("agent_available", ""))' 2>/dev/null || true)"
  [[ "$AGENT_AVAILABLE" == true ]] && break
  sleep 2
done
[[ "$AGENT_AVAILABLE" == true ]] || die "control plane did not observe the reconnected maintenance agent"
MAINT_AGENT_RECONNECTED=true

# Canonical identity preservation: same block id, same execution identity,
# same ResourceProvider ids, and no duplicate block or provider anywhere in
# the canonical topology.
api_get /operator/building-blocks >"$WORK_ROOT/blocks-maintenance-after.json"
python3 - "$WORK_ROOT/blocks-maintenance-after.json" "$MAINT_ID" "$MAINT_EXEC_IDENTITY_BEFORE" "$MAINT_PROVIDER_IDS_BEFORE" <<'PY' \
  || die "canonical identity was not preserved across the maintenance window"
import json,sys
items=json.load(open(sys.argv[1], encoding="utf-8"))
maint_id, exec_before, providers_before = sys.argv[2], sys.argv[3], sys.argv[4].split(",") if sys.argv[4] else []
matches=[x.get("block", {}) for x in items if x.get("block", {}).get("id") == maint_id]
if len(matches) != 1:
    raise SystemExit("maintenance block is missing or duplicated after the maintenance window")
block=matches[0]
if block.get("execution_identity") != exec_before:
    raise SystemExit("execution identity changed across the maintenance window")
if (block.get("resource_provider_ids") or []) != providers_before:
    raise SystemExit("ResourceProvider identity changed across the maintenance window")
identities=[x.get("block", {}).get("execution_identity") for x in items]
provider_ids=[p for x in items for p in (x.get("block", {}).get("resource_provider_ids") or [])]
if len(set(identities)) != len(identities) or len(set(provider_ids)) != len(provider_ids):
    raise SystemExit("duplicate canonical block or provider identity exists after the maintenance window")
PY
MAINT_IDENTITY_PRESERVED=true

# Return the block to Ready through the canonical operator transition
# (Draining -> Ready exists in the BuildingBlock state machine and is exposed
# as POST /operator/building-blocks/{id}/actions/ready; capacity reopens only
# after the durable block reaches Ready).
api_get "/operator/building-blocks/$MAINT_ID" >"$WORK_ROOT/maintenance-block-before-ready.json"
MAINT_GEN_READY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["block"]["generation"])' "$WORK_ROOT/maintenance-block-before-ready.json")" \
  || die "maintenance block generation unavailable before ready transition"
operator_curl "$API/operator/building-blocks/$MAINT_ID/actions/ready" -X POST -H 'Content-Type: application/json' \
  -d "{\"expected_generation\":$MAINT_GEN_READY}" >"$WORK_ROOT/maintenance-ready.json" || die "maintenance Draining->Ready transition failed"
grep -Eq '"state"[[:space:]]*:[[:space:]]*"ready"' "$WORK_ROOT/maintenance-ready.json" || die "maintenance ready state missing"
for _ in $(seq 1 60); do
  api_get "/operator/diagnostics/providers?limit=200" >"$WORK_ROOT/providers-maintenance-ready.json" || true
  MAINT_PROVIDER_STATE="$(python3 - "$WORK_ROOT/providers-maintenance-ready.json" "$MAINT_PROVIDER_IDS_BEFORE" <<'PY'
import json,sys
page=json.load(open(sys.argv[1], encoding="utf-8"))
provider=sys.argv[2].split(",")[0]
states={item.get("provider_id"): item.get("state") for item in page.get("items", [])}
print(states.get(provider, ""))
PY
)"
  [[ "$MAINT_PROVIDER_STATE" == Enabled ]] && break
  sleep 2
done
[[ "$MAINT_PROVIDER_STATE" == Enabled ]] || die "maintenance block provider did not reopen after the ready transition"
MAINT_RETURNED_TO_READY=true
MAINT_FINAL_ELIGIBLE="$(record_scale_checkpoint post-maintenance 5 "" "$SURVIVOR_IDS,${BLOCK_IDS[block-e]}")" \
  || die "post-maintenance eligible Ready count is not exactly five"
[[ "$MAINT_FINAL_ELIGIBLE" == 5 ]] || die "post-maintenance eligible Ready count is not exactly five"
python3 - "$MAINT_EVIDENCE_FILE" "$MAINT_ID" "$MAINT_EXEC_IDENTITY_BEFORE" "$MAINT_PROVIDER_IDS_BEFORE" \
  "$MAINT_DRAIN_BLOCKERS_EMPTY" "$MAINT_PLACEMENT_REJECTED" "$MAINT_AGENT_RECONNECTED" "$MAINT_IDENTITY_PRESERVED" \
  "$MAINT_RETURNED_TO_READY" "$MAINT_FINAL_ELIGIBLE" <<'PY'
import json, pathlib, sys

out, block_id, exec_identity, providers, blockers_empty, placement_rejected, \
    agent_reconnected, identity_preserved, returned_to_ready, final_eligible = sys.argv[1:11]
doc = {
    "status": "passed",
    "block_id": block_id,
    "execution_identity": exec_identity,
    "resource_provider_ids": providers.split(",") if providers else [],
    "semantics": "product planned-host maintenance (operator drain -> host reboot -> reconcile); NOT the TestLab bounded guest force-shutdown harness control",
    "drain": {"succeeded": True, "blockers_empty": blockers_empty == "true",
              "blockers": "no residents existed; the honest blocker projection is empty"},
    "placement_rejected_on_draining_block": placement_rejected == "true",
    "host_reboot": {"issued_from": "outer host via virsh reboot on the recorded domain UUID",
                    "guest_returned_ssh": True},
    "agent_restart": {"modeled": "operator restarts the host service; O3K installs no host-global service persistence",
                      "reconnected": agent_reconnected == "true"},
    "identity_preserved": {
        "same_building_block_id": True,
        "same_execution_identity": identity_preserved == "true",
        "same_resource_provider_ids": identity_preserved == "true",
        "no_duplicate_block_or_provider": identity_preserved == "true",
    },
    "returned_to_ready": {
        "operator_transition": "POST /operator/building-blocks/{id}/actions/ready (canonical Draining->Ready)",
        "succeeded": returned_to_ready == "true",
        "provider_reopened": returned_to_ready == "true",
    },
    "final_eligible_ready_count": int(final_eligible),
}
pathlib.Path(out).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

FOREIGN_AFTER="$(virsh -c qemu:///system list --all --uuid 2>/dev/null | sed '/^$/d' | sort)"
foreign_ok=true
while IFS= read -r uuid; do [[ -z "$uuid" || "$FOREIGN_AFTER" == *"$uuid"* ]] || foreign_ok=false; done <<<"$FOREIGN_BEFORE"
[[ "$foreign_ok" == true ]] || die "foreign libvirt state changed"

# SQLite parity remains an actual process boundary, not a boolean fixture.
cargo test --locked -p o3kd --all-features --test p15_1_topology_process --test p15_5_building_block_process -- --test-threads=1 >/dev/null || die "SQLite parity process boundary failed"
record_optional_araf
cleanup
assert_owned_domains_absent
[[ ! -e "$SSH_KEY" && ! -e "$KNOWN_HOSTS" ]] || die "owned journey files remain after cleanup"
JOURNEY_END_MS="$(date +%s%3N)"

python3 - "$EVIDENCE_FILE" "$ARTIFACT_DIR" "$SOURCE_SHA" "$PROFILE" "${#DOMAINS[@]}" "$JOURNEY_START_MS" "$JOURNEY_END_MS" "$CROSS_TENANT_CONCEALMENT" "$ARAF_STATUS" "$ARAF_REASON" "$DIAGNOSTIC_ONLY" "$POSTGRES_MODE" "$POSTGRES_SERVER_VERSION" "$POSTGRES_REDACTED_ENDPOINT" "$POSTGRES_SCHEMA_PREPARED" "$INITIAL_READY_COUNT" "$FINAL_READY_COUNT" "$PEAK_CONCURRENT_READY" "$DRAIN_AGENT" "$BOOTSTRAP_AGENT_ID" "${BLOCK_IDS[block-a]}" "${BLOCK_IDS[block-b]}" "${BLOCK_IDS[block-c]}" "${BLOCK_IDS[block-d]}" "${BLOCK_IDS[block-e]}" "$BACKEND_EFFECTIVE" "$BACKEND_PROOF_METHOD" "$BACKEND_PROOF_POOL_SESSIONS" "$BACKEND_PROOF_SEVER_OBSERVED" "$BACKEND_PROOF_RECOVERY_OBSERVED" <<'PY'
import json,pathlib,sys
path=pathlib.Path(sys.argv[1]); artifact=pathlib.Path(sys.argv[2]); sha=sys.argv[3].lower(); profile=sys.argv[4]; blocks=int(sys.argv[5]); start=int(sys.argv[6]); end=int(sys.argv[7]); cross_tenant=sys.argv[8] == "true"; araf_status=sys.argv[9]; araf_reason=sys.argv[10]; diagnostic_only=sys.argv[11] == "true"; postgres_mode=sys.argv[12]; postgres_version=sys.argv[13]; postgres_endpoint=sys.argv[14]; postgres_schema=sys.argv[15] == "true"; initial_ready=int(sys.argv[16]); final_ready=int(sys.argv[17]); peak_ready=int(sys.argv[18]); drain_agent=sys.argv[19]; bootstrap_agent=sys.argv[20]; child_block_ids=sys.argv[21:26]; backend_effective=sys.argv[26]; backend_proof_method=sys.argv[27]; backend_proof={"status":"passed","method":backend_proof_method}; pool_sessions=sys.argv[28]
if postgres_mode == "external":
    backend_proof["pool_sessions_observed"]=int(pool_sessions) if pool_sessions.isdigit() else None
    backend_proof["proxy_sever_unhealthy_observed"]=sys.argv[29] == "true"
    backend_proof["recovery_observed"]=sys.argv[30] == "true"

CHECKPOINT_PHASES=["initial-scale-checkpoint","pre-drain","post-drain","post-remove","post-replacement","post-reboot","post-crash-repair","post-maintenance"]
ELIGIBILITY_RULE=("placement_eligible = state=='ready' AND >=1 resource_provider_id present in "
                  "/operator/diagnostics/providers with state 'Enabled' AND no recorded drain_blockers; "
                  "every BuildingBlock is enumerated, including the bootstrap block (identified by the "
                  "canonical TLS agent identity, never filtered by name or label)")
checkpoints=[]
for phase in CHECKPOINT_PHASES:
    fragment_path=artifact / f"p15-7-scale-checkpoint-{phase}.json"
    checkpoints.append(json.loads(fragment_path.read_text(encoding="utf-8")))
initial_checkpoint=checkpoints[0]
final_checkpoint=checkpoints[CHECKPOINT_PHASES.index("post-replacement")]
bootstrap_entries=[entry for entry in initial_checkpoint["blocks"] if entry.get("is_bootstrap")]
if len(bootstrap_entries) != 1:
    raise SystemExit("initial checkpoint must identify exactly one bootstrap BuildingBlock")
bootstrap_block_id=bootstrap_entries[0]["block_id"]
def eligible_projection(checkpoint):
    eligible=[entry for entry in checkpoint["blocks"] if entry.get("placement_eligible")]
    return {"agents":[entry["execution_identity"] for entry in eligible],
            "block_ids":[entry["block_id"] for entry in eligible]}
initial_projection=eligible_projection(initial_checkpoint)
final_projection=eligible_projection(final_checkpoint)
if bootstrap_block_id not in initial_projection["block_ids"] or bootstrap_block_id not in final_projection["block_ids"]:
    raise SystemExit("bootstrap BuildingBlock must be in the initial and final eligible Ready sets")
child_agents=["block-a","block-b","block-c","block-d","block-e"]
enrolled_agents=[bootstrap_agent]+child_agents
enrolled_block_ids=[bootstrap_block_id]+list(child_block_ids)
if len(set(enrolled_block_ids)) != 6 or len(set(enrolled_agents)) != 6:
    raise SystemExit("enrolled canonical identities across the run must be six and distinct")

def load_fragment(name):
    return json.loads((artifact / name).read_text(encoding="utf-8"))
drain_blocker_requery=load_fragment("p15-7-drain-blocker-requery.json")
crash_repair=load_fragment("p15-7-crash-injection-evidence.json")
host_maintenance=load_fragment("p15-7-host-maintenance-evidence.json")
transient_path=artifact / "p15-7-transient-failures.jsonl"
transient_failures=[]
if transient_path.is_file():
    transient_failures=[json.loads(line) for line in transient_path.read_text(encoding="utf-8").splitlines() if line.strip()]
child_vms=[]
for lease_path in sorted(artifact.glob("p15-7-vm-lease-*.json")):
    child_vms.append(json.loads(lease_path.read_text(encoding="utf-8")))
if len(child_vms) != blocks or not all(vm.get("ssh_proof") for vm in child_vms):
    raise SystemExit("every provisioned child VM must carry lease evidence with an SSH proof")

def passed():
    return {"status":"passed"}
doc={
 "artifact_type":"o3k-p15-7-scale-composition-evidence","schema_version":1,"phase":"P15.7","status":"passed","evidence_tier":"protected-real-host","profile":profile,"tested_source_sha":sha,
 "execution":{"real_o3kd":passed(),"real_auth":passed(),"real_execution_boundary":passed(),"multiple_real_hosts":passed(),"sqlite_parity":passed(),"provider":"agent","hypervisor":"libvirt","database_backend":"postgres","block_count":blocks,"provisioned_vms":blocks},
 "scale_composition":{
  "counting_rule":"eligible_ready",
  "eligibility_rule":ELIGIBILITY_RULE,
  "bootstrap":{"agent_id":bootstrap_agent,"block_id":bootstrap_block_id},
  "enrolled_identities":{"count":6,"distinct":True,"agents":enrolled_agents,"block_ids":enrolled_block_ids},
  "initial_concurrent_ready":{"count":initial_ready,"agents":initial_projection["agents"],"block_ids":initial_projection["block_ids"]},
  "peak_concurrent_ready":{"count":peak_ready,"minimum":5,"met":peak_ready>=5},
  "final_concurrent_ready":{"count":final_ready,"agents":final_projection["agents"],"block_ids":final_projection["block_ids"]},
  "checkpoints":checkpoints,
  "drained_agent":drain_agent,"replacement_agent":"block-e","duplicate_identities":False},
 "database_ownership":{"mode":postgres_mode,"effective_backend":backend_effective,"backend_proof":backend_proof,"server_version":postgres_version or None,"redacted_endpoint":postgres_endpoint,"schema_prepared":postgres_schema,"fault_injection":("run-owned_proxy_sever_restore" if postgres_mode == "external" else "docker_restart"),"managed":postgres_mode=="disposable"},
 "journey":{"fresh_deployment":passed(),"init":passed(),"multiple_authenticated_joins":{"status":"passed","count":blocks,"each_authenticated":True},"topology":passed(),"capacity":passed(),"constrained_placement":passed(),"add_block_capacity_growth":passed(),"drain":{"status":"passed","no_new_placement":True,"blockers_observed":True,"evacuation_claimed":False,"blocker_requery":drain_blocker_requery},"remove_rejoin_replace":passed(),"restart_recovery":passed(),"crash_injection_repair":crash_repair,"host_maintenance":host_maintenance,"transient_failures":transient_failures,"projections_convergent":{"native":passed(),"openstack":passed(),"araf":{"required":False,"status":araf_status,"reason":araf_reason}}},
 "network_observation":{"child_vms":child_vms,"all_ssh_proven":True,
   "resolver_contract":"freshest valid owned DHCP lease for the expected MAC; cross-MAC and gateway addresses rejected; SSH is the liveness proof"},
 "security_negatives":{"unauthenticated_join_rejected":True,"replay_join_rejected":True,"cross_tenant_concealment":cross_tenant,"foreign_state_preserved":True},
 "restart_recovery":{"status":"passed","canonical_state_survived":True,"postgres":True,"sqlite_parity":True},
 "bootstrap_timing":{"measured":end>start,"duration_ms":end-start,"excludes_preprovisioned_external_work":True,"sample_count":1,"boundary":"fresh o3kd through five authenticated block joins","claim_scope":"profile-specific-measurement-only"},
 "leak_check":{"status":"passed","owned_leaks":0,"owned_inconsistencies":0,"foreign_state_changes":0},
 "defect_ledger":{"status":"passed","blockers":0,"high":0,"medium":0},
 "claim_validation":{"status":"passed","sources":["README.md","docs/ROADMAP.md","docs/status/current-state.yaml","compatibility/product-profiles.yaml","docs/compatibility/matrix.yaml","docs/architecture/p15-e2d-gap-register.md"],"unsupported_claims_preserved":True,"claims":["profile-specific protected P15.7 scale/composition convergence"]}}
if diagnostic_only:
 doc["artifact_type"]="o3k-p15-7-diagnostic-fast-lane-journey"
 doc["evidence_tier"]="diagnostic-only"
 doc["diagnostic_lane"]=True
 doc["final_completion_evidence"]=False
 doc.pop("defect_ledger")
 doc.pop("claim_validation")
path.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n",encoding="utf-8")
PY
if [[ "$DIAGNOSTIC_ONLY" == true ]]; then
  echo "P15.7 diagnostic journey completed; artifact is not completion evidence: $EVIDENCE_FILE"
else
  echo "P15.7 genuine journey completed: $EVIDENCE_FILE"
fi
