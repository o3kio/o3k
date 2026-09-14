#!/usr/bin/env bash
set -Eeuo pipefail

# Build and run an isolated O3K profile for one protected workflow run.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER_TEMP="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
[[ "$RUNNER_TEMP" == /* && "$RUNNER_TEMP" != *..* && -d "$RUNNER_TEMP" && ! -L "$RUNNER_TEMP" ]] \
  || { echo "disposable TestLab bootstrap failed: runner temp path is unsafe" >&2; exit 1; }
command -v realpath >/dev/null 2>&1 \
  || { echo "disposable TestLab bootstrap failed: realpath is unavailable" >&2; exit 1; }
RUNNER_TEMP="$(realpath -e -- "$RUNNER_TEMP")"
RUN_ID="${GITHUB_RUN_ID:-local-$$}"
SOURCE_COMMIT="${GITHUB_SHA:-$(git -C "$ROOT_DIR" rev-parse HEAD)}"
ARTIFACT_DIR="${O3K_REAL_HOST_ARTIFACT_DIR:-${ROOT_DIR}/target/real-host-workflow-artifacts}"
[[ "$RUN_ID" =~ ^[0-9]+$|^local-[0-9]+$ ]] \
  || { echo "disposable TestLab bootstrap failed: invalid workflow run id" >&2; exit 1; }
STATE_ROOT="${RUNNER_TEMP%/}/o3k-testlab/${RUN_ID}"
PID_ROOT="${RUNNER_TEMP%/}/o3k-testlab-pids/${RUN_ID}"
INVENTORY_ROOT="${RUNNER_TEMP%/}/o3k-testlab-inventory/${RUN_ID}"
SERVICE_STATE_BASE=/var/lib/o3k-testlab
if [[ "$RUN_ID" =~ ^local- ]]; then
  STATE_ROOT="${RUNNER_TEMP%/}/o3k-testlab/${RUN_ID}"
else
  STATE_ROOT="${SERVICE_STATE_BASE}/${RUN_ID}"
fi
SERVICE_ACCOUNT=o3k
COMPUTE_ACCOUNT=o3k-compute
# Native LVM commands require access to the device-mapper control node.  The
# disposable real-host profile may therefore run only the control-plane daemon
# as root when an explicitly configured LVM provider is selected; compute
# remains confined to its dedicated service account.
O3KD_ACCOUNT="${O3K_TESTLAB_O3KD_ACCOUNT:-o3k}"
if [[ "$O3KD_ACCOUNT" != "$SERVICE_ACCOUNT" && "$O3KD_ACCOUNT" != root ]]; then
  echo "disposable TestLab bootstrap failed: O3KD account must be o3k or root" >&2
  exit 1
fi
if [[ "$O3KD_ACCOUNT" == root ]] && [[ -z "${O3K_LVM_VOLUME_GROUP:-}" || -z "${O3K_LVM_THIN_POOL:-}" || -z "${O3K_LVM_PROVIDER_NAMESPACE:-}" ]]; then
  echo "disposable TestLab bootstrap failed: root O3KD account requires the explicit native-LVM profile" >&2
  exit 1
fi
ACCOUNT_LOCK=/run/lock/o3k-testlab-account.lock
APT_LOCK=/run/lock/o3k-testlab-apt.lock
AUTH_PORT="${O3K_TESTLAB_PORT:-18080}"
CONTROL_PORT="${O3K_TESTLAB_CONTROL_PORT:-18551}"
COMPUTE_HEALTH_PORT="${O3K_TESTLAB_COMPUTE_HEALTH_PORT:-19100}"
O3K_PROVIDER="${O3K_PROVIDER:-fake}"
BRIDGE_NAME="${O3K_COMPUTE_BRIDGE_NAME:-o3k-b${RUN_ID: -8}}"
case "${O3K_PROVIDER}" in
  fake|agent) ;;
  *) echo "disposable TestLab bootstrap failed: unsupported provider ${O3K_PROVIDER}" >&2; exit 1 ;;
esac
O3KD_PID=
COMPUTE_PID=
OPENSTACK_VENV="${O3K_OPENSTACK_VENV:-}"
O3KD_READY=false
COMPUTE_READY=false
ACCOUNT_CREATED=false
GROUP_CREATED=false
COMPUTE_ACCOUNT_CREATED=false
COMPUTE_GROUP_CREATED=false
SUPPLEMENTARY_GROUPS_ADDED=false
FAIL_REASON=bootstrap_failed

fail() { FAIL_REASON="$1"; echo "disposable TestLab bootstrap failed: $1" >&2; exit 1; }

process_matches() {
  local pid="$1" binary="$2" expected executable
  expected="$STATE_ROOT/bin/$binary"
  executable="$(sudo -n readlink "/proc/$pid/exe" 2>/dev/null)" || return 1
  [[ "$executable" == "$expected" ]]
}

process_start_ticks() {
  local pid="$1"
  sudo -n awk '{print $22}' "/proc/$pid/stat" 2>/dev/null
}

process_uid() {
  local pid="$1"
  # ps(1)'s default USER column truncates names such as o3k-compute to
  # `o3k-com+`, which would make a valid service look foreign during cleanup.
  sudo -n ps -o user:32= -p "$pid" 2>/dev/null | tr -d ' '
}

process_record_matches() {
  local pid="$1" start_ticks="$2" uid="$3" binary="$4" account="$5"
  [[ "$uid" == "$account" ]] \
    && [[ "$(process_uid "$pid")" == "$account" ]] \
    && [[ "$(process_start_ticks "$pid")" == "$start_ticks" ]] \
    && process_matches "$pid" "$binary"
}

stop_owned_process() {
  local pid="$1" binary="$2"
  sudo -n kill -0 "$pid" 2>/dev/null || return 0
  process_matches "$pid" "$binary" || {
    echo "disposable TestLab cleanup refused foreign process ${pid}" >&2
    return 1
  }
  sudo -n kill "$pid" || return 1
  for _ in $(seq 1 20); do
    sudo -n kill -0 "$pid" 2>/dev/null || return 0
    sleep 1
  done
  echo "disposable TestLab cleanup timed out stopping ${binary}" >&2
  return 1
}

remove_created_identity() {
  [[ "$ACCOUNT_CREATED" == true || "$GROUP_CREATED" == true \
    || "$COMPUTE_ACCOUNT_CREATED" == true || "$COMPUTE_GROUP_CREATED" == true ]] || return 0
  sudo -n flock -x "$ACCOUNT_LOCK" bash -c '
    set -euo pipefail
    pgrep -u o3k >/dev/null 2>&1 && exit 42 || true
    pgrep -u o3k-compute >/dev/null 2>&1 && exit 42 || true
    if [[ "$1" == true ]] && id o3k >/dev/null 2>&1; then userdel o3k; fi
    if [[ "$2" == true ]] && getent group o3k >/dev/null 2>&1; then groupdel o3k; fi
    if [[ "$3" == true ]] && id o3k-compute >/dev/null 2>&1; then userdel o3k-compute; fi
    if [[ "$4" == true ]] && getent group o3k-compute >/dev/null 2>&1; then groupdel o3k-compute; fi
  ' _ "$ACCOUNT_CREATED" "$GROUP_CREATED" "$COMPUTE_ACCOUNT_CREATED" "$COMPUTE_GROUP_CREATED"
}

remove_added_supplementary_groups() {
  [[ "$SUPPLEMENTARY_GROUPS_ADDED" == true ]] || return 0
  sudo -n test -f "$STATE_ROOT/.o3k-supplementary-groups-added" || return 0
  sudo -n flock -x "$ACCOUNT_LOCK" bash -c '
    set -euo pipefail
    while IFS= read -r group; do
      [[ -n "$group" ]] || continue
      getent group "$group" >/dev/null 2>&1 || continue
      id o3k >/dev/null 2>&1 || continue
      if id -nG o3k-compute | tr " " "\n" | grep -Fqx "$group"; then
        gpasswd --delete o3k-compute "$group" >/dev/null
      fi
    done <"$1"
  ' _ "$STATE_ROOT/.o3k-supplementary-groups-added"
  SUPPLEMENTARY_GROUPS_ADDED=false
}

write_result() {
  local status="$1" reason="$2"
  mkdir -p "$ARTIFACT_DIR"
  python3 - "$ARTIFACT_DIR/disposable-testlab-bootstrap.json" "$status" "$reason" \
    "$SOURCE_COMMIT" "$STATE_ROOT" "$O3KD_ACCOUNT" "$AUTH_PORT" \
    "${O3KD_PID:-}" "${COMPUTE_PID:-}" "$O3KD_READY" "$COMPUTE_READY" "$O3K_PROVIDER" <<'PY'
import json, sys, time
path, status, reason, commit, state, account, port, o3kd_pid, compute_pid, o3kd_ready, compute_ready, provider = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump({"artifact_type": "disposable-testlab-bootstrap", "status": status,
               "reason": reason, "redacted": True, "source_commit": commit,
               "state_directory": state, "service_account": account,
               "auth_url": f"http://127.0.0.1:{port}/v3", "username": "admin",
               "project": "admin", "project_id": "eba29e2d-53de-461d-ae91-ede7402713cb",
               "region": "RegionOne", "o3kd_pid": o3kd_pid or None,
               "compute_pid": compute_pid or None,
               "provider": provider,
               "readiness": {"o3kd": o3kd_ready == "true", "compute": compute_ready == "true"},
               "finished_at": int(time.time())}, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
}

failure_cleanup() {
  local status="$?"
  if ((status != 0)); then
    write_result failed "$FAIL_REASON" 2>/dev/null || true
    cleanup_failed=false
    [[ -z "$COMPUTE_PID" ]] || stop_owned_process "$COMPUTE_PID" o3k-compute || cleanup_failed=true
    [[ -z "$O3KD_PID" ]] || stop_owned_process "$O3KD_PID" o3kd || cleanup_failed=true
    if [[ "$cleanup_failed" == false ]]; then
      # Reuse the fail-closed cleanup path.  In particular, do not discard
      # the ownership ledger until libvirt, network, and DHCP state have
      # been inspected; a startup failure can still leave host resources.
      if [[ -x "$ROOT_DIR/scripts/cleanup-disposable-testlab.sh" ]]; then
        RUNNER_TEMP="$RUNNER_TEMP" GITHUB_RUN_ID="$RUN_ID" \
          O3K_TESTLAB_STATE_ROOT="$STATE_ROOT" O3K_TESTLAB_PID_ROOT="$PID_ROOT" \
          O3K_REAL_HOST_INVENTORY_ROOT="$INVENTORY_ROOT" \
          O3K_OPENSTACK_VENV="$OPENSTACK_VENV" O3K_TESTLAB_IMAGE_PATH="${IMAGE_PATH:-}" \
          bash "$ROOT_DIR/scripts/cleanup-disposable-testlab.sh" 2>/dev/null || cleanup_failed=true
      else
        cleanup_failed=true
      fi
    else
      echo "disposable TestLab cleanup incomplete; preserving owned state for retry" >&2
    fi
    [[ "$cleanup_failed" == false ]] || echo "disposable TestLab cleanup incomplete; preserving owned state for retry" >&2
  fi
  exit "$status"
}
trap failure_cleanup EXIT

[[ "$SOURCE_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]] || fail "invalid source commit"
[[ "$AUTH_PORT" =~ ^[0-9]+$ && "$CONTROL_PORT" =~ ^[0-9]+$ && "$COMPUTE_HEALTH_PORT" =~ ^[0-9]+$ ]] || fail "invalid service port"
[[ "$BRIDGE_NAME" =~ ^[A-Za-z0-9_-]{1,15}$ ]] || fail "invalid compute bridge name"
for command in cargo openssl python3 curl sudo getent id pgrep ss flock stat readlink realpath timeout ps nproc usermod gpasswd setpriv nohup setsid; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is unavailable"
done
sudo -n true 2>/dev/null || fail "passwordless sudo is required"
sudo -n test -d "$(dirname "$ACCOUNT_LOCK")" || fail "account lock directory is unavailable"
[[ "$(git -C "$ROOT_DIR" rev-parse HEAD)" == "$SOURCE_COMMIT" ]] || fail "checkout is not immutable"

GITHUB_RUN_ID="$RUN_ID" RUNNER_TEMP="$RUNNER_TEMP" O3K_TESTLAB_STATE_BASE="$SERVICE_STATE_BASE" \
  bash "$ROOT_DIR/scripts/cleanup-stale-testlab-processes.sh" || true

for port in "$AUTH_PORT" "$CONTROL_PORT" "$COMPUTE_HEALTH_PORT"; do
  ((port >= 1 && port <= 65535)) || fail "invalid service port ${port}"
done
for parent in "${RUNNER_TEMP}/o3k-testlab-pids" \
  "${RUNNER_TEMP}/o3k-testlab-inventory"; do
  if [[ -e "$parent" ]] && [[ ! -d "$parent" || -L "$parent" ]]; then
    fail "run state parent is not an owned directory: ${parent}"
  fi
done
if [[ ! -e "$STATE_ROOT" ]]; then
  [[ ! -e "$INVENTORY_ROOT" && ! -L "$INVENTORY_ROOT" ]] \
    || fail "run inventory state already exists without matching service state"
  for port in "$AUTH_PORT" "$CONTROL_PORT" "$COMPUTE_HEALTH_PORT"; do
    if ss -H -ltn 2>/dev/null | awk -v suffix=":${port}" \
      'length($4) >= length(suffix) && substr($4, length($4)-length(suffix)+1) == suffix {found=1} END {exit !found}'; then
      fail "run port ${port} is already occupied by an existing service"
    fi
  done
fi

REUSE=false
PASSWORD=
BOOTSTRAP_SECRET=
if [[ -e "$STATE_ROOT" ]]; then
  [[ -d "$STATE_ROOT" && ! -L "$STATE_ROOT" ]] || fail "run state is not a directory"
  [[ -f "$STATE_ROOT/.o3k-run-owned" && ! -L "$STATE_ROOT/.o3k-run-owned" ]] \
    || fail "existing run state is not owned by this bootstrap"
  marker="$(sudo -n cat "$STATE_ROOT/.o3k-run-owned" 2>/dev/null)" \
    || fail "cannot inspect existing run ownership marker"
  grep -Fqx 'o3k-disposable-testlab-v1' <<<"$marker" \
    || fail "existing run state has a foreign ownership marker"
  grep -Fqx "commit=$SOURCE_COMMIT" <<<"$marker" \
    || fail "existing run state belongs to a different source commit"
  [[ -d "$INVENTORY_ROOT" && ! -L "$INVENTORY_ROOT" ]] \
    || fail "existing run state has no inventory state"
  grep -Fqx 'o3k-disposable-inventory-v1' "$INVENTORY_ROOT/.o3k-inventory-owned" \
    || fail "existing inventory state is not owned by this bootstrap"
  PASSWORD="$(sudo -n cat "$STATE_ROOT/.password" 2>/dev/null)" \
    || fail "existing run state has no readable protected password"
  [[ "$PASSWORD" =~ ^[0-9a-f]{64}$ ]] \
    || fail "existing run state contains an invalid protected password"
  echo "::add-mask::${PASSWORD}"
  BOOTSTRAP_SECRET="$(sudo -n cat "$STATE_ROOT/.bootstrap-secret" 2>/dev/null)" \
    || fail "existing run state has no readable bootstrap secret"
  [[ "$BOOTSTRAP_SECRET" =~ ^[0-9a-f]{64}$ ]] \
    || fail "existing run state contains an invalid bootstrap secret"
  echo "::add-mask::${BOOTSTRAP_SECRET}"
  [[ -f "$PID_ROOT/o3kd.pid" && -f "$PID_ROOT/o3k-compute.pid" ]] \
    || fail "existing run state has no complete process identity"
  IFS='|' read -r O3KD_PID O3KD_START O3KD_UID O3KD_BINARY <"$PID_ROOT/o3kd.pid"
  IFS='|' read -r COMPUTE_PID COMPUTE_START COMPUTE_UID COMPUTE_BINARY <"$PID_ROOT/o3k-compute.pid"
  [[ "$O3KD_PID" =~ ^[0-9]+$ && "$COMPUTE_PID" =~ ^[0-9]+$ \
    && "$O3KD_START" =~ ^[0-9]+$ && "$COMPUTE_START" =~ ^[0-9]+$ \
    && "$O3KD_BINARY" == o3kd && "$COMPUTE_BINARY" == o3k-compute ]] \
    || fail "existing run state has an invalid process identity"
  process_record_matches "$O3KD_PID" "$O3KD_START" "$O3KD_UID" o3kd "$O3KD_ACCOUNT" \
    && process_record_matches "$COMPUTE_PID" "$COMPUTE_START" "$COMPUTE_UID" o3k-compute "$COMPUTE_ACCOUNT" \
    && sudo -n kill -0 "$O3KD_PID" 2>/dev/null && sudo -n kill -0 "$COMPUTE_PID" 2>/dev/null \
    || fail "existing run state services are not running"
  REUSE=true
fi

if [[ "$REUSE" == false ]]; then
umask 077
need_packages=false
command -v genisoimage >/dev/null 2>&1 || need_packages=true
command -v ssh-keygen >/dev/null 2>&1 || need_packages=true
python3 -m venv --help >/dev/null 2>&1 || need_packages=true
command -v pkg-config >/dev/null 2>&1 || need_packages=true
command -v protoc >/dev/null 2>&1 || need_packages=true
if [[ "$need_packages" == true ]] || ! pkg-config --exists libvirt 2>/dev/null; then
  command -v apt-get >/dev/null 2>&1 || fail "required host packages are missing and apt-get is unavailable"
  sudo -n test -d "$(dirname "$APT_LOCK")" || fail "package-manager lock directory is unavailable"
  sudo -n flock -x "$APT_LOCK" bash -c '
    set -euo pipefail
    timeout --signal=TERM --kill-after=30s 300s env DEBIAN_FRONTEND=noninteractive \
      apt-get -o DPkg::Lock::Timeout=300 update -qq
    timeout --signal=TERM --kill-after=30s 300s env DEBIAN_FRONTEND=noninteractive \
      apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends \
        genisoimage openssh-client python3-venv pkg-config libvirt-dev protobuf-compiler
  ' || fail "cannot install required host packages within the bounded package-manager timeout"
fi
sudo -n install -d -o root -g root -m 0755 "$SERVICE_STATE_BASE"
install -d -m 0755 "${PID_ROOT%/*}" "${INVENTORY_ROOT%/*}"
[[ ! -e "$INVENTORY_ROOT" && ! -L "$INVENTORY_ROOT" ]] || fail "run inventory state already exists"
install -d -m 0755 "$INVENTORY_ROOT"
printf 'o3k-disposable-inventory-v1\ncommit=%s\nrun=%s\n' "$SOURCE_COMMIT" "$RUN_ID" \
  >"$INVENTORY_ROOT/.o3k-inventory-owned"
chmod 0644 "$INVENTORY_ROOT/.o3k-inventory-owned"
account_state="$(sudo -n flock -x "$ACCOUNT_LOCK" bash -c '
  set -euo pipefail
  group_created=false
  account_created=false
  compute_group_created=false
  compute_account_created=false
  if ! getent group o3k >/dev/null 2>&1; then
    groupadd --system o3k
    group_created=true
  fi
  if ! id o3k >/dev/null 2>&1; then
    useradd --system --no-create-home --gid o3k --home-dir "$1" \
      --shell /usr/sbin/nologin o3k
    account_created=true
  fi
  if ! getent group o3k-compute >/dev/null 2>&1; then
    groupadd --system o3k-compute
    compute_group_created=true
  fi
  if ! id o3k-compute >/dev/null 2>&1; then
    useradd --system --no-create-home --gid o3k-compute --home-dir "$1/compute" \
      --shell /usr/sbin/nologin o3k-compute
    compute_account_created=true
  fi
  printf "%s %s %s %s\\n" "$account_created" "$group_created" \
    "$compute_account_created" "$compute_group_created"
' _ "$STATE_ROOT/home")" || fail "cannot provision packaged o3k service account"
read -r ACCOUNT_CREATED GROUP_CREATED COMPUTE_ACCOUNT_CREATED COMPUTE_GROUP_CREATED <<<"$account_state"
[[ "$O3KD_ACCOUNT" == root || "$(id -u "$O3KD_ACCOUNT")" != 0 ]] \
  || fail "o3k service account is root"
[[ "$(id -u "$COMPUTE_ACCOUNT")" != 0 ]] || fail "o3k-compute service account is root"
control_record="$(getent passwd "$SERVICE_ACCOUNT" || true)"
[[ "$control_record" == *":/usr/sbin/nologin" ]] \
  || fail "existing o3k account has an unsafe shell posture"
while read -r group; do
  [[ -z "$group" || "$group" == "$SERVICE_ACCOUNT" ]] \
    || fail "existing o3k account has an unexpected group: $group"
done < <(id -nG "$SERVICE_ACCOUNT" | tr ' ' '\n')
compute_record="$(getent passwd "$COMPUTE_ACCOUNT" || true)"
[[ "$compute_record" == *":/usr/sbin/nologin" ]] \
  || fail "existing o3k-compute account has an unsafe shell posture"
while read -r group; do
  case "$group" in
    ""|"$COMPUTE_ACCOUNT"|libvirt|kvm) ;;
    *) fail "existing o3k-compute account has an unexpected group: $group" ;;
  esac
done < <(id -nG "$COMPUTE_ACCOUNT" | tr ' ' '\n')

[[ ! -e "$PID_ROOT" && ! -L "$PID_ROOT" ]] || fail "run pid state already exists"
install -d -m 0700 "$PID_ROOT"
[[ ! -e "$STATE_ROOT" && ! -L "$STATE_ROOT" ]] || fail "run state already exists"
sudo -n install -d -o root -g root -m 0755 \
  "$STATE_ROOT" "$STATE_ROOT/bin" "$STATE_ROOT/log" "$STATE_ROOT/tls"
# The run root is shared by the control and compute service identities.  Keep
# it root-owned and traversable; private children below it carry the service
# ownership.  Cleanup validates this exact posture before removing state.
sudo -n chmod 0755 "$STATE_ROOT" "$STATE_ROOT/bin" "$STATE_ROOT/log" "$STATE_ROOT/tls"
sudo -n install -d -o "$(id -u "$SERVICE_ACCOUNT")" -g "$(id -g "$SERVICE_ACCOUNT")" -m 0700 \
  "$STATE_ROOT/data"
sudo -n install -d -o "$(id -u "$COMPUTE_ACCOUNT")" -g kvm -m 2710 \
  "$STATE_ROOT/compute-data"
sudo -n bash -c 'printf "o3k-disposable-testlab-v1\\ncommit=%s\\nrun=%s\\n" "$1" "$2" >"$3"; chmod 0600 "$3"' \
  _ "$SOURCE_COMMIT" "$RUN_ID" "$STATE_ROOT/.o3k-run-owned"
sudo -n bash -c 'printf "o3k-owned-v1 path=%s\\n" "$1" >"$2"; chmod 0640 "$2"' \
  _ "$STATE_ROOT" "$STATE_ROOT/.o3k-owned"
if [[ "$ACCOUNT_CREATED" == true ]]; then
  sudo -n bash -c 'printf "o3k-disposable-account-v1\\n" >"$1"; chmod 0600 "$1"' \
    _ "$STATE_ROOT/.o3k-account-created"
fi
if [[ "$GROUP_CREATED" == true ]]; then
  sudo -n bash -c 'printf "o3k-disposable-group-v1\\n" >"$1"; chmod 0600 "$1"' \
    _ "$STATE_ROOT/.o3k-group-created"
fi
if [[ "$COMPUTE_ACCOUNT_CREATED" == true ]]; then
  sudo -n bash -c 'printf "o3k-disposable-compute-account-v1\\n" >"$1"; chmod 0600 "$1"' \
    _ "$STATE_ROOT/.o3k-compute-account-created"
fi
if [[ "$COMPUTE_GROUP_CREATED" == true ]]; then
  sudo -n bash -c 'printf "o3k-disposable-compute-group-v1\\n" >"$1"; chmod 0600 "$1"' \
    _ "$STATE_ROOT/.o3k-compute-group-created"
fi
SUPPLEMENTARY_GROUPS_ADDED=true
sudo -n flock -x "$ACCOUNT_LOCK" bash -c '
  set -euo pipefail
  for group in libvirt kvm; do
    getent group "$group" >/dev/null 2>&1 \
      || { echo "required libvirt access group is unavailable: $group" >&2; exit 1; }
  done
  : >"$1"
  chmod 0600 "$1"
  for group in libvirt kvm; do
    if ! id -nG o3k-compute | tr " " "\n" | grep -Fqx "$group"; then
      usermod --append --groups "$group" o3k-compute
      printf "%s\n" "$group" >>"$1"
    fi
  done
' _ "$STATE_ROOT/.o3k-supplementary-groups-added" \
  || fail "cannot grant o3k access to libvirt and KVM"
if sudo -n test -s "$STATE_ROOT/.o3k-supplementary-groups-added"; then
  SUPPLEMENTARY_GROUPS_ADDED=true
else
  sudo -n rm -f -- "$STATE_ROOT/.o3k-supplementary-groups-added"
fi
command -v genisoimage >/dev/null 2>&1 || fail "genisoimage is unavailable after dependency setup"
command -v ssh-keygen >/dev/null 2>&1 || fail "ssh-keygen is unavailable after dependency setup"
python3 -m venv --help >/dev/null 2>&1 || fail "python3-venv is unavailable after dependency setup"
command -v pkg-config >/dev/null 2>&1 || fail "pkg-config is unavailable after dependency setup"
pkg-config --exists libvirt 2>/dev/null || fail "libvirt development files are unavailable after dependency setup"
command -v protoc >/dev/null 2>&1 || fail "protobuf compiler is unavailable after dependency setup"
cargo build --locked --release --bin o3kd --bin o3k
# virt-sys deliberately tolerates a missing pkg-config probe for docs builds;
# make the runtime link explicit after the host preflight proves libvirt exists.
RUSTFLAGS="${RUSTFLAGS:-} -l dylib=virt" \
  cargo build --locked --release --features libvirt --bin o3k-compute-bin
sudo -n install -m 0755 "$ROOT_DIR/target/release/o3kd" "$STATE_ROOT/bin/o3kd"
sudo -n install -m 0755 "$ROOT_DIR/target/release/o3k" "$STATE_ROOT/bin/o3k"
sudo -n install -m 0755 "$ROOT_DIR/target/release/o3k-compute-bin" "$STATE_ROOT/bin/o3k-compute"
extra_agent_ids=()
extra_agent_ids_file="$STATE_ROOT/.extra-agent-ids"
if [[ -n "${O3K_TESTLAB_ADDITIONAL_AGENT_IDS:-}" ]]; then
  extra_agent_ids_csv="${O3K_TESTLAB_ADDITIONAL_AGENT_IDS}"
  [[ "$extra_agent_ids_csv" != ,* && "$extra_agent_ids_csv" != *, \
    && "$extra_agent_ids_csv" != *,,* ]] \
    || fail "additional compute agent ids contain an empty entry"
  IFS=',' read -r -a extra_agent_ids <<<"$extra_agent_ids_csv"
  declare -A seen_extra_agent_ids=()
  for extra_agent_id in "${extra_agent_ids[@]}"; do
    [[ "$extra_agent_id" =~ ^[A-Za-z0-9._-]+$ && ${#extra_agent_id} -le 128 ]] \
      || fail "additional compute agent id is invalid"
    [[ -z "${seen_extra_agent_ids[$extra_agent_id]:-}" ]] \
      || fail "additional compute agent id is duplicated: $extra_agent_id"
    seen_extra_agent_ids[$extra_agent_id]=1
  done
  sudo -n bash -c 'file="$1"; shift; printf "%s\\n" "$@" >"$file"; chmod 0600 "$file"' \
    _ "$extra_agent_ids_file" "${extra_agent_ids[@]}"
else
  sudo -n rm -f -- "$extra_agent_ids_file"
fi
if ((${#extra_agent_ids[@]} > 0)); then
  printf 'canonical extra agent identities requested: %s\n' "${extra_agent_ids[*]}" >&2
fi
if ((${#extra_agent_ids[@]} > 0)); then
  sudo -n bash "$ROOT_DIR/packaging/bootstrap-certs.sh" --output-dir "$STATE_ROOT/tls" \
    --server-name o3k-control-plane --agent-id compute-agent \
    --extra-agent-ids-file "$extra_agent_ids_file"
else
  sudo -n bash "$ROOT_DIR/packaging/bootstrap-certs.sh" --output-dir "$STATE_ROOT/tls" \
    --server-name o3k-control-plane --agent-id compute-agent
fi
for extra_agent_id in "${extra_agent_ids[@]}"; do
  for extra_agent_file in agent.pem agent-key.pem agent-id agent-fingerprint; do
    [[ -f "$STATE_ROOT/tls/agents/$extra_agent_id/$extra_agent_file" && ! -L "$STATE_ROOT/tls/agents/$extra_agent_id/$extra_agent_file" ]] \
      || fail "canonical extra agent identity was not generated: ${extra_agent_id}/${extra_agent_file}"
  done
done
sudo -n chmod 0755 "$STATE_ROOT"
sudo -n install -m 0640 "$STATE_ROOT/tls/agent-id" "$STATE_ROOT/compute-data/agent-id"
AUTHORIZED_FINGERPRINT="$(sudo -n cat "$STATE_ROOT/tls/agent-fingerprint")" \
  || fail "cannot read generated agent fingerprint"
AUTHORIZED_AGENTS="compute-agent=$(printf '%q' "$AUTHORIZED_FINGERPRINT")"
for extra_agent_id in "${extra_agent_ids[@]}"; do
  extra_fingerprint="$(sudo -n cat "$STATE_ROOT/tls/agents/$extra_agent_id/agent-fingerprint")" \
    || fail "cannot read generated fingerprint for $extra_agent_id"
  AUTHORIZED_AGENTS+=",$extra_agent_id=$(printf '%q' "$extra_fingerprint")"
done

PASSWORD="$(openssl rand -hex 32)"
[[ "$PASSWORD" =~ ^[0-9a-f]{64}$ ]] || fail "generated password format is unsafe"
echo "::add-mask::${PASSWORD}"
BOOTSTRAP_SECRET="$(openssl rand -hex 32)"
[[ "$BOOTSTRAP_SECRET" =~ ^[0-9a-f]{64}$ ]] || fail "generated bootstrap secret format is unsafe"
echo "::add-mask::${BOOTSTRAP_SECRET}"
SIGNING_KEY="$(openssl rand -hex 48)"
password_tmp="$(mktemp "${RUNNER_TEMP%/}/o3k-password.XXXXXX")"
printf '%s\n' "$PASSWORD" >"$password_tmp"
chmod 0600 "$password_tmp"
sudo -n mv -f -- "$password_tmp" "$STATE_ROOT/.password"
bootstrap_secret_tmp="$(mktemp "${RUNNER_TEMP%/}/o3k-bootstrap-secret.XXXXXX")"
printf '%s\n' "$BOOTSTRAP_SECRET" >"$bootstrap_secret_tmp"
chmod 0600 "$bootstrap_secret_tmp"
sudo -n mv -f -- "$bootstrap_secret_tmp" "$STATE_ROOT/.bootstrap-secret"
o3kd_env_tmp="$(mktemp "${RUNNER_TEMP%/}/o3kd.env.XXXXXX")"
compute_env_tmp="$(mktemp "${RUNNER_TEMP%/}/o3k-compute.env.XXXXXX")"
cat >"$o3kd_env_tmp" <<EOF
O3K_DATA_DIR=$(printf '%q' "$STATE_ROOT/data")
O3K_LISTEN_ADDR=$(printf '%q' "127.0.0.1:${AUTH_PORT}")
O3K_PROVIDER=$(printf '%q' "$O3K_PROVIDER")
O3K_LOG_FORMAT=json
O3K_LOG_FILTER=$(printf '%q' "${O3K_LOG_FILTER:-warn}")
O3K_BOOTSTRAP_PASSWORD=$(printf '%q' "$PASSWORD")
O3K_BOOTSTRAP_SECRET=$(printf '%q' "$BOOTSTRAP_SECRET")
O3K_TOKEN_SIGNING_KEY=$(printf '%q' "$SIGNING_KEY")
O3K_COMPUTE_CONTROL_ADDR=$(printf '%q' "${O3K_TESTLAB_CONTROL_BIND_ADDR:-127.0.0.1}:${CONTROL_PORT}")
O3K_COMPUTE_SERVER_CERTIFICATE=$(printf '%q' "$STATE_ROOT/tls/server.pem")
O3K_COMPUTE_SERVER_PRIVATE_KEY=$(printf '%q' "$STATE_ROOT/tls/server-key.pem")
O3K_COMPUTE_CLIENT_CA=$(printf '%q' "$STATE_ROOT/tls/ca.pem")
O3K_COMPUTE_AUTHORIZED_AGENTS=$AUTHORIZED_AGENTS
EOF
if [[ -n "${O3K_DATABASE_BACKEND:-}" ]]; then
  printf 'O3K_DATABASE_BACKEND=%s\n' "$(printf '%q' "$O3K_DATABASE_BACKEND")" >>"$o3kd_env_tmp"
fi
if [[ -n "${O3K_DATABASE_URL:-}" ]]; then
  printf 'O3K_DATABASE_URL=%s\n' "$(printf '%q' "$O3K_DATABASE_URL")" >>"$o3kd_env_tmp"
fi
for lvm_variable in O3K_LVM_VOLUME_GROUP O3K_LVM_THIN_POOL O3K_LVM_PROVIDER_NAMESPACE; do
  if [[ -n "${!lvm_variable:-}" ]]; then
    printf '%s=%s\n' "$lvm_variable" "$(printf '%q' "${!lvm_variable}")" >>"$o3kd_env_tmp"
  fi
done
cat >"$compute_env_tmp" <<EOF
O3K_COMPUTE_DATA_DIR=$(printf '%q' "$STATE_ROOT/compute-data")
O3K_COMPUTE_CONTROL_ENDPOINT=$(printf '%q' "https://127.0.0.1:${CONTROL_PORT}")
O3K_COMPUTE_SERVER_NAME=o3k-control-plane
O3K_COMPUTE_HOST_LABEL=o3k-testlab
O3K_COMPUTE_TLS_DIR=$(printf '%q' "$STATE_ROOT/tls")
O3K_COMPUTE_HEALTH_ADDR=$(printf '%q' "127.0.0.1:${COMPUTE_HEALTH_PORT}")
O3K_COMPUTE_BRIDGE_NAME=$(printf '%q' "$BRIDGE_NAME")
O3K_COMPUTE_MAX_DISK_GB=10
# The compute daemon reads RUST_LOG directly. Keep the default at warn and let
# protected runs opt into scoped info filters via O3K_COMPUTE_LOG_FILTER.
RUST_LOG=$(printf '%q' "${O3K_COMPUTE_LOG_FILTER:-warn}")
EOF
if [[ "${O3K_AGENT_INSPECT_PROBE_ENABLED:-false}" == true ]]; then
  if [[ -n "${O3K_AGENT_INSPECT_PROBE_RESOURCE_FILE:-}" ]]; then
    probe_resource_file="${O3K_AGENT_INSPECT_PROBE_RESOURCE_FILE}"
    [[ "$probe_resource_file" == /* && "$probe_resource_file" != *..* ]] \
      || fail "agent inspect probe resource file is invalid"
    mkdir -p "$(dirname "$probe_resource_file")"
    touch "$probe_resource_file"
    chmod 0644 "$probe_resource_file"
    printf 'O3K_AGENT_INSPECT_PROBE_RESOURCE_FILE=%s\n' \
      "$(printf '%q' "$STATE_ROOT/agent-inspect-resource-id")" >>"$o3kd_env_tmp"
    sudo -n install -m 0644 -o "$(id -u)" -g "$(id -g)" /dev/null \
      "$STATE_ROOT/agent-inspect-resource-id"
    printf 'O3K_AGENT_INSPECT_SERVICE_RESOURCE_FILE=%s\n' \
      "$STATE_ROOT/agent-inspect-resource-id" >>"${GITHUB_ENV:-/dev/null}"
  else
    [[ "${O3K_AGENT_INSPECT_PROBE_RESOURCE_ID:-}" =~ ^[0-9a-fA-F-]{36}$ ]] \
      || fail "agent inspect probe resource id is invalid"
    printf 'O3K_AGENT_INSPECT_PROBE_RESOURCE_ID=%s\n' \
      "$(printf '%q' "$O3K_AGENT_INSPECT_PROBE_RESOURCE_ID")" >>"$o3kd_env_tmp"
  fi
  printf 'O3K_AGENT_INSPECT_PROBE_OUTPUT=%s/agent-inspect-probe.json\n' "$STATE_ROOT" >>"$o3kd_env_tmp"
  # The durable project ID for the TestLab lifecycle context is "eba29e2d-53de-461d-ae91-ede7402713cb".
  # This is the project_id field in the issued token (distinct from the project *name*
  # "admin" used by the CLI OS_PROJECT_NAME / OS_USERNAME bootstrap context). The
  # compute service enforces project isolation by comparing resource.project_id to the
  # caller's project_id argument: passing the project name instead of the project ID
  # produces a store-level NotFound on every probe call.
  printf 'O3K_AGENT_INSPECT_PROBE_PROJECT_ID=eba29e2d-53de-461d-ae91-ede7402713cb\n' >>"$o3kd_env_tmp"
  # Scope the o3kd log filter so that o3k_compute, o3k_reconciler, o3k_compute_agent,
  # and o3k_libvirt diagnostics remain visible during probe runs without enabling
  # global H2/SQLx debug noise that floods the log with raw frame data.
  _probe_log_base="${O3K_LOG_FILTER:-warn}"
  printf 'O3K_LOG_FILTER=%s\n' \
    "$(printf '%q' "${_probe_log_base},o3k_compute=info,o3k_reconciler=info,o3k_compute_agent=info,o3k_libvirt=info")" \
    >>"$o3kd_env_tmp"
fi
chmod 0600 "$o3kd_env_tmp" "$compute_env_tmp"
sudo -n mv -f -- "$o3kd_env_tmp" "$STATE_ROOT/o3kd.env"
sudo -n mv -f -- "$compute_env_tmp" "$STATE_ROOT/o3k-compute.env"
sudo -n chown "$SERVICE_ACCOUNT:$SERVICE_ACCOUNT" "$STATE_ROOT/o3kd.env" "$STATE_ROOT/.password" "$STATE_ROOT/.bootstrap-secret"
sudo -n chown "$COMPUTE_ACCOUNT:$COMPUTE_ACCOUNT" "$STATE_ROOT/o3k-compute.env"
sudo -n chmod 0600 "$STATE_ROOT/o3kd.env" "$STATE_ROOT/.password" "$STATE_ROOT/.bootstrap-secret" "$STATE_ROOT/o3k-compute.env"
sudo -n chgrp root "$STATE_ROOT/tls"
sudo -n chmod 0755 "$STATE_ROOT/tls"
for file in ca.pem server.pem agent.pem agent-id agent-fingerprint; do
  sudo -n chgrp root "$STATE_ROOT/tls/$file"
  sudo -n chmod 0644 "$STATE_ROOT/tls/$file"
done
sudo -n chgrp "$SERVICE_ACCOUNT" "$STATE_ROOT/tls/server-key.pem"
sudo -n chmod 0640 "$STATE_ROOT/tls/server-key.pem"
sudo -n chgrp "$COMPUTE_ACCOUNT" "$STATE_ROOT/tls/agent-key.pem"
sudo -n chmod 0640 "$STATE_ROOT/tls/agent-key.pem"
sudo -n install -m 0640 -o "$COMPUTE_ACCOUNT" -g "$COMPUTE_ACCOUNT" \
  "$STATE_ROOT/tls/agent-id" "$STATE_ROOT/compute-data/agent-id"
sudo -n install -d -o "$COMPUTE_ACCOUNT" -g kvm -m 0710 "$STATE_ROOT/compute-data/agent-id.artifacts"
sudo -n install -m 0600 -o "$SERVICE_ACCOUNT" -g "$SERVICE_ACCOUNT" /dev/null "$STATE_ROOT/log/o3kd.log"
sudo -n install -m 0600 -o "$COMPUTE_ACCOUNT" -g "$COMPUTE_ACCOUNT" /dev/null "$STATE_ROOT/log/o3k-compute.log"
# o3kd writes this probe result as its own service identity.  The run root is
# intentionally not writable by service accounts, so provision the file
# before startup while retaining the stable path consumed by the workflow.
sudo -n install -m 0600 -o "$SERVICE_ACCOUNT" -g "$SERVICE_ACCOUNT" /dev/null \
  "$STATE_ROOT/agent-inspect-probe.json"
# Host-network realization (TAP, bridge, gateway, and DHCP setup) is owned by
# the dedicated compute service. Validate the ambient-capability launch path
# before starting it, using a run-unique temporary link and deleting only that
# link afterwards. Console reads use the bounded libvirt console stream and do
# not bypass file DAC. CAP_NET_BIND_SERVICE and
# CAP_NET_RAW are required by the spawned dnsmasq: binding the DHCP server
# socket on UDP/67 needs the former, serving DHCP (raw socket) needs the
# latter (proven by the issue-87 re-probe capability matrix on dnsmasq 2.90).
network_probe_name="o3k-cp-${RUN_ID:0:8}"
sudo -n setpriv --reuid="$(id -u "$COMPUTE_ACCOUNT")" \
  --regid="$(id -g "$COMPUTE_ACCOUNT")" --init-groups \
  --inh-caps=+net_admin,+net_bind_service,+net_raw \
  --ambient-caps=+net_admin,+net_bind_service,+net_raw -- \
  ip link add name "$network_probe_name" type dummy \
  || fail "o3k-compute ambient CAP_NET_ADMIN capability is unavailable"
sudo -n ip link delete "$network_probe_name" \
  || fail "ambient CAP_NET_ADMIN probe link cleanup failed"
if ! sudo -n -u "$SERVICE_ACCOUNT" -- test -r "$STATE_ROOT/o3kd.env"; then
  sudo -n stat -c 'state-root=%U:%G:%a:%n env=%U:%G:%a:%n' \
    "$STATE_ROOT" "$STATE_ROOT/o3kd.env" 2>/dev/null || true
  sudo -n namei -l "$STATE_ROOT/o3kd.env" 2>/dev/null || true
  fail "o3k service account cannot traverse the run state root"
fi

start_service() {
  local name="$1" account="$2" env_file="$3" binary="$4" log_file="$5" pid_file="$6"
  local supervisor child candidate
  if [[ "$name" == o3k-compute ]]; then
    # CAP_NET_ADMIN must be ambient so helper processes such as ip(8) and
    # dnsmasq retain it across exec. CAP_NET_BIND_SERVICE + CAP_NET_RAW are ambient
    # so the spawned dnsmasq can bind UDP/67 and serve DHCP (issue-87 re-probe
    # matrix). setpriv applies all of them before dropping to the dedicated
    # service account; no daemon runs as root.
    sudo -n setpriv --reuid="$(id -u "$account")" \
      --regid="$(id -g "$account")" --init-groups \
      --inh-caps=+net_admin,+net_bind_service,+net_raw \
      --ambient-caps=+net_admin,+net_bind_service,+net_raw -- \
      setsid nohup bash -c 'set -a; . "$1"; set +a; exec "$2" >>"$3" 2>&1' _ \
      "$env_file" "$binary" "$log_file" >/dev/null 2>&1 &
  else
    sudo -n -u "$account" -- setsid nohup bash -c 'set -a; . "$1"; set +a; exec "$2" >>"$3" 2>&1' _ \
      "$env_file" "$binary" "$log_file" >/dev/null 2>&1 &
  fi
  supervisor=$!
  child=
  # A protected runner may be compiling the release binaries or handling a
  # concurrent libvirt operation immediately before launch.  Give the
  # packaged daemon a bounded observation window rather than treating a
  # transient scheduler delay as a service-account failure.
  for _ in $(seq 1 120); do
    while read -r candidate; do
      if process_matches "$candidate" "$(basename "$binary")"; then
        child="$candidate"
        break
      fi
    done < <(sudo -n pgrep -u "$account" -x "$(basename "$binary")" 2>/dev/null || true)
    [[ -n "$child" ]] && break
    sleep 0.25
  done
  if [[ -z "$child" ]]; then
    sudo -n kill "$supervisor" 2>/dev/null || true
    fail "$name did not start as the packaged service account"
  fi
  start_ticks="$(process_start_ticks "$child")"
  uid="$(process_uid "$child")"
  [[ "$start_ticks" =~ ^[0-9]+$ && "$uid" == "$account" ]] \
    || fail "$name did not expose a valid service identity"
  printf '%s|%s|%s|%s\n' "$child" "$start_ticks" "$uid" "$(basename "$binary")" >"$pid_file"
  if [[ "$name" == o3kd ]]; then O3KD_PID="$child"; else COMPUTE_PID="$child"; fi
}

wait_for_o3kd_health() {
  for _ in $(seq 1 60); do
    curl --fail --silent --max-time 2 "http://127.0.0.1:${AUTH_PORT}/healthz" >/dev/null 2>&1 && break
    sleep 1
  done
  curl --fail --silent --max-time 2 "http://127.0.0.1:${AUTH_PORT}/healthz" >/dev/null 2>&1 \
    || fail "o3kd health endpoint did not become ready"
}

wait_for_o3kd_control() {
  for _ in $(seq 1 60); do
    if (echo >/dev/tcp/127.0.0.1/"${CONTROL_PORT}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "o3kd authenticated control endpoint did not become reachable"
}

bootstrap_testlab() {
  local agent_id agent_epoch vcpus memory_mb disk_gb init_output enrollment_token join_attempt
  agent_id="$(sudo -n cat "$STATE_ROOT/tls/agent-id")"
  [[ "$agent_id" =~ ^[A-Za-z0-9._-]+$ ]] || fail "generated agent identity is invalid"
  agent_epoch="$(openssl rand -hex 16)"
  vcpus="$(nproc --all 2>/dev/null || true)"
  memory_mb="$(awk '/^MemTotal:/ {print int($2 / 1024); exit}' /proc/meminfo)"
  disk_gb="${O3K_COMPUTE_MAX_DISK_GB:-10}"
  [[ "$vcpus" =~ ^[1-9][0-9]*$ && "$memory_mb" =~ ^[1-9][0-9]*$ \
    && "$disk_gb" =~ ^[1-9][0-9]*$ ]] || fail "host inventory is unavailable for canonical join"

  export O3K_API_URL="http://127.0.0.1:${AUTH_PORT}/o3k/v1"
  export O3K_BOOTSTRAP_SECRET="$BOOTSTRAP_SECRET"
  init_output="$(mktemp "${RUNNER_TEMP%/}/o3k-init.XXXXXX")"
  trap 'rm -f -- "${init_output:-}"' RETURN
  # The output file is a runner-owned 0600 temporary; shell redirection is
  # intentionally performed before sudo so the service account never needs
  # write access to the runner temp directory.
  # shellcheck disable=SC2024
  sudo -n -u "$SERVICE_ACCOUNT" -- env O3K_API_URL="$O3K_API_URL" \
    O3K_BOOTSTRAP_SECRET="$BOOTSTRAP_SECRET" "$STATE_ROOT/bin/o3k" init \
    --agent-id "$agent_id" >"$init_output" \
    || fail "canonical o3k init failed"
  enrollment_token="$(python3 - "$init_output" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    response = json.load(stream)
token = response.get("enrollment_token")
if not isinstance(token, str) or not token:
    raise SystemExit("canonical init did not return an enrollment token")
print(token)
PY
  )" || fail "canonical init response was invalid"
  rm -f -- "$init_output"
  trap - RETURN

  # Startup reconciliation and the canonical placement write share the same
  # durable store.  A bounded retry lets that already-issued, single-use
  # grant converge across a transient store/provider conflict; the join
  # remains the production authenticated CLI path and never fabricates state.
  for join_attempt in $(seq 1 5); do
    if sudo -n -u "$SERVICE_ACCOUNT" -- env O3K_API_URL="$O3K_API_URL" \
      "$STATE_ROOT/bin/o3k" join --token "$enrollment_token" \
      --agent-id "$agent_id" --agent-epoch "$agent_epoch" \
      --certificate "$STATE_ROOT/tls/agent.pem" \
      --vcpus "$vcpus" --memory-mb "$memory_mb" --disk-gb "$disk_gb" \
      >/dev/null; then
      return 0
    fi
    if ((join_attempt < 5)); then
      echo "canonical authenticated o3k join attempt ${join_attempt}/5 did not converge; retrying" >&2
      sleep 2
    fi
  done
  fail "canonical authenticated o3k join failed after bounded retries"
}

wait_for_o3kd_ready() {
  for _ in $(seq 1 60); do
    curl --fail --silent --max-time 2 "http://127.0.0.1:${AUTH_PORT}/readyz" >/dev/null 2>&1 && break
    sleep 1
  done
  curl --fail --silent --max-time 2 "http://127.0.0.1:${AUTH_PORT}/readyz" >/dev/null 2>&1 \
    || fail "o3kd did not become ready"
  O3KD_READY=true
}

start_compute() {
  start_service o3k-compute "$COMPUTE_ACCOUNT" "$STATE_ROOT/o3k-compute.env" "$STATE_ROOT/bin/o3k-compute" \
    "$STATE_ROOT/log/o3k-compute.log" "$PID_ROOT/o3k-compute.pid"
}

wait_for_compute_ready() {
  for _ in $(seq 1 30); do
    curl --fail --silent --max-time 2 "http://127.0.0.1:${COMPUTE_HEALTH_PORT}/healthz" >/dev/null 2>&1 && break
    sleep 1
  done
  curl --fail --silent --max-time 2 "http://127.0.0.1:${COMPUTE_HEALTH_PORT}/healthz" >/dev/null 2>&1 \
    || fail "o3k-compute health endpoint did not become ready"
  curl --fail --silent --max-time 2 "http://127.0.0.1:${COMPUTE_HEALTH_PORT}/readyz" >/dev/null 2>&1 \
    || fail "o3k-compute libvirt/control-plane readiness did not become ready"
  COMPUTE_READY=true
}

start_service o3kd "$O3KD_ACCOUNT" "$STATE_ROOT/o3kd.env" "$STATE_ROOT/bin/o3kd" "$STATE_ROOT/log/o3kd.log" "$PID_ROOT/o3kd.pid"
wait_for_o3kd_health
wait_for_o3kd_control
bootstrap_testlab
start_compute
wait_for_compute_ready
wait_for_o3kd_ready
else
  echo "reusing authenticated disposable TestLab for run ${RUN_ID}"
  curl --fail --silent --max-time 2 "http://127.0.0.1:${AUTH_PORT}/readyz" >/dev/null 2>&1 \
    || fail "reused o3kd is not ready"
  curl --fail --silent --max-time 2 "http://127.0.0.1:${COMPUTE_HEALTH_PORT}/healthz" >/dev/null 2>&1 \
    || fail "reused o3k-compute is not healthy"
  O3KD_READY=true
  COMPUTE_READY=true
fi

if [[ -z "$OPENSTACK_VENV" ]]; then
  OPENSTACK_VENV="$(mktemp -d "${RUNNER_TEMP%/}/o3k-openstack-venv.XXXXXX")"
else
  [[ "$OPENSTACK_VENV" == "${RUNNER_TEMP%/}/o3k-openstack-venv."* ]] \
    || fail "OpenStack virtualenv is not run-owned"
fi
if [[ ! -x "$OPENSTACK_VENV/bin/openstack" ]]; then
  python3 -m venv "$OPENSTACK_VENV"
  PIP_CONFIG_FILE=/dev/null PIP_NO_CACHE_DIR=1 "$OPENSTACK_VENV/bin/python" -m pip install \
    --isolated --disable-pip-version-check --no-input "python-openstackclient==10.2.1"
fi
if [[ ! -f "$OPENSTACK_VENV/.o3k-venv-owned" ]]; then
  printf 'o3k-disposable-venv-v1\ncommit=%s\nrun=%s\n' "$SOURCE_COMMIT" "$RUN_ID" \
    >"$OPENSTACK_VENV/.o3k-venv-owned"
  chmod 0600 "$OPENSTACK_VENV/.o3k-venv-owned"
fi
grep -Fqx 'o3k-disposable-venv-v1' "$OPENSTACK_VENV/.o3k-venv-owned" \
  || fail "OpenStack virtualenv is not owned by this bootstrap"
export PATH="$OPENSTACK_VENV/bin:$PATH"
printf '%s\n' "$OPENSTACK_VENV/bin" >>"${GITHUB_PATH:-/dev/null}"
export OS_AUTH_URL="http://127.0.0.1:${AUTH_PORT}/v3" OS_USERNAME=admin OS_PASSWORD="$PASSWORD" \
  OS_PROJECT_NAME=admin OS_REGION_NAME=RegionOne OS_USER_DOMAIN_NAME=Default \
  OS_PROJECT_DOMAIN_NAME=Default OS_INTERFACE=public OS_IDENTITY_API_VERSION=3
OPENSTACK_CLOUD_CONFIG="$STATE_ROOT/openstack-clouds.yaml"
umask 077
OPENSTACK_CLOUD_CONFIG_TMP="$(mktemp "${RUNNER_TEMP%/}/openstack-clouds.yaml.XXXXXX")"
cat >"$OPENSTACK_CLOUD_CONFIG_TMP" <<EOF
clouds:
  o3k-testlab:
    auth:
      auth_url: $OS_AUTH_URL
      username: $OS_USERNAME
      password: $OS_PASSWORD
      project_name: $OS_PROJECT_NAME
      user_domain_name: $OS_USER_DOMAIN_NAME
      project_domain_name: $OS_PROJECT_DOMAIN_NAME
    region_name: $OS_REGION_NAME
    interface: $OS_INTERFACE
    image_api_version: "2"
    image_endpoint_override: http://127.0.0.1:${AUTH_PORT}/v2
EOF
sudo -n install -o "$(id -u)" -g "$(id -g)" -m 0600 \
  "$OPENSTACK_CLOUD_CONFIG_TMP" "$OPENSTACK_CLOUD_CONFIG"
rm -f -- "$OPENSTACK_CLOUD_CONFIG_TMP"
export OS_CLOUD=o3k-testlab OS_CLIENT_CONFIG_FILE="$OPENSTACK_CLOUD_CONFIG"
openstack token issue >/dev/null 2>&1 || fail "generated password failed OpenStack authentication"

printf 'O3K_TESTLAB_STATE_ROOT=%s\nO3K_REAL_HOST_SERVICE_ACCOUNT=%s\n' "$STATE_ROOT" "$(id -un)" >>"${GITHUB_ENV:-/dev/null}"
if [[ "${O3K_AGENT_INSPECT_PROBE_ENABLED:-false}" == true ]]; then
  printf 'O3K_AGENT_INSPECT_PROBE_OUTPUT=%s/agent-inspect-probe.json\n' "$STATE_ROOT" >>"${GITHUB_ENV:-/dev/null}"
fi
printf 'O3K_REAL_HOST_COMPUTE_BINARY=%s\n' "$STATE_ROOT/bin/o3k-compute" >>"${GITHUB_ENV:-/dev/null}"
printf 'O3K_REAL_HOST_NETWORK_CAPABILITY=ambient-net-admin\n' >>"${GITHUB_ENV:-/dev/null}"
printf 'O3K_REAL_HOST_DAEMON_ACCOUNT=%s\n' "$SERVICE_ACCOUNT" >>"${GITHUB_ENV:-/dev/null}"
printf 'O3K_REAL_HOST_COMPUTE_ACCOUNT=%s\n' "$COMPUTE_ACCOUNT" >>"${GITHUB_ENV:-/dev/null}"
printf 'O3K_COMPUTE_BRIDGE_NAME=%s\n' "$BRIDGE_NAME" >>"${GITHUB_ENV:-/dev/null}"
printf 'O3K_TESTLAB_PID_ROOT=%s\n' "$PID_ROOT" >>"${GITHUB_ENV:-/dev/null}"
printf 'O3K_REAL_HOST_PROTECTED_PATHS=%s\nO3K_REAL_HOST_INVENTORY_ROOT=%s\nO3K_OPENSTACK_VENV=%s\n' \
  "$INVENTORY_ROOT" "$INVENTORY_ROOT" "$OPENSTACK_VENV" >>"${GITHUB_ENV:-/dev/null}"
printf 'OS_AUTH_URL=%s\nOS_USERNAME=admin\nOS_PROJECT_NAME=admin\nOS_REGION_NAME=RegionOne\nOS_PASSWORD=%s\nOS_USER_DOMAIN_NAME=Default\nOS_PROJECT_DOMAIN_NAME=Default\nOS_INTERFACE=public\nOS_IDENTITY_API_VERSION=3\n' \
  "$OS_AUTH_URL" "$PASSWORD" >>"${GITHUB_ENV:-/dev/null}"
printf 'O3K_BOOTSTRAP_SECRET=%s\n' "$BOOTSTRAP_SECRET" >>"${GITHUB_ENV:-/dev/null}"
printf 'OS_CLOUD=%s\nOS_CLIENT_CONFIG_FILE=%s\n' "$OS_CLOUD" "$OPENSTACK_CLOUD_CONFIG" >>"${GITHUB_ENV:-/dev/null}"
write_result passed authenticated
trap - EXIT
echo "disposable TestLab bootstrap completed"
