#!/usr/bin/env bash
set -Eeuo pipefail

RUNNER_TEMP="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
RUN_ID="${GITHUB_RUN_ID:-}"
ACCOUNT_LOCK=/run/lock/o3k-testlab-account.lock
[[ "$RUN_ID" =~ ^[0-9]+$|^local-[0-9]+$ ]] || { echo "cleanup: invalid workflow run id" >&2; exit 1; }
[[ "$RUNNER_TEMP" == /* && "$RUNNER_TEMP" != *..* && -d "$RUNNER_TEMP" && ! -L "$RUNNER_TEMP" ]] \
  || { echo "cleanup: runner temp path is unsafe" >&2; exit 1; }
command -v realpath >/dev/null 2>&1 || { echo "cleanup: realpath is unavailable" >&2; exit 1; }
command -v gpasswd >/dev/null 2>&1 || { echo "cleanup: gpasswd is unavailable" >&2; exit 1; }
RUNNER_TEMP="$(realpath -e -- "$RUNNER_TEMP")"
sudo -n test -d "$(dirname "$ACCOUNT_LOCK")" \
  || { echo "cleanup: account lock directory is unavailable" >&2; exit 1; }
EXPECTED_ROOT="${RUNNER_TEMP%/}/o3k-testlab/${RUN_ID}"
EXPECTED_INVENTORY_ROOT="${RUNNER_TEMP%/}/o3k-testlab-inventory/${RUN_ID}"
EXPECTED_ROOT="/var/lib/o3k-testlab/${RUN_ID}"
if [[ "$RUN_ID" =~ ^local- || "${O3K_TESTLAB_STATE_ROOT:-}" == "${RUNNER_TEMP%/}/o3k-testlab/${RUN_ID}" ]]; then
  EXPECTED_ROOT="${RUNNER_TEMP%/}/o3k-testlab/${RUN_ID}"
fi
STATE_ROOT="${O3K_TESTLAB_STATE_ROOT:-$EXPECTED_ROOT}"
INVENTORY_ROOT="${O3K_REAL_HOST_INVENTORY_ROOT:-$EXPECTED_INVENTORY_ROOT}"
PID_ROOT="${O3K_TESTLAB_PID_ROOT:-${RUNNER_TEMP%/}/o3k-testlab-pids/${RUN_ID}}"
OPENSTACK_VENV="${O3K_OPENSTACK_VENV:-}"
IMAGE_PATH="${O3K_TESTLAB_IMAGE_PATH:-}"
[[ "$STATE_ROOT" == "$EXPECTED_ROOT" ]] || { echo "cleanup: state root is not run-owned" >&2; exit 1; }
[[ "$INVENTORY_ROOT" == "$EXPECTED_INVENTORY_ROOT" ]] \
  || { echo "cleanup: inventory root is not run-owned" >&2; exit 1; }
[[ "$PID_ROOT" == "${RUNNER_TEMP%/}/o3k-testlab-pids/${RUN_ID}" ]] \
  || { echo "cleanup: pid root is not run-owned" >&2; exit 1; }
for parent in "${RUNNER_TEMP}/o3k-testlab-pids" \
  "${RUNNER_TEMP}/o3k-testlab-inventory"; do
  if [[ -e "$parent" ]] && [[ ! -d "$parent" || -L "$parent" ]]; then
    echo "cleanup: run state parent is not an owned directory" >&2
    exit 1
  fi
done
if [[ -n "$OPENSTACK_VENV" ]]; then
  [[ "$(dirname -- "$OPENSTACK_VENV")" == "${RUNNER_TEMP%/}" \
    && "$(basename -- "$OPENSTACK_VENV")" == o3k-openstack-venv.* \
    && "$OPENSTACK_VENV" != *..* && ! -L "$OPENSTACK_VENV" ]] \
    || { echo "cleanup: OpenStack virtualenv is not run-owned" >&2; exit 1; }
  if [[ -e "$OPENSTACK_VENV" ]]; then
    [[ -d "$OPENSTACK_VENV" && ! -L "$OPENSTACK_VENV" ]] \
      || { echo "cleanup: OpenStack virtualenv is not a real directory" >&2; exit 1; }
    grep -Fqx 'o3k-disposable-venv-v1' "$OPENSTACK_VENV/.o3k-venv-owned" \
      || { echo "cleanup: virtualenv ownership marker is invalid" >&2; exit 1; }
  fi
fi
if [[ -n "$IMAGE_PATH" ]]; then
  [[ "$(dirname -- "$IMAGE_PATH")" == "${RUNNER_TEMP%/}" \
    && "$(basename -- "$IMAGE_PATH")" == cirros-0.6.3-x86_64-disk.img.* \
    && "$IMAGE_PATH" != *..* && ! -L "$IMAGE_PATH" ]] \
    || { echo "cleanup: image path is not run-owned" >&2; exit 1; }
  if [[ -e "$IMAGE_PATH" || -e "$IMAGE_PATH.o3k-owned" ]]; then
    grep -Fqx 'o3k-disposable-image-v1' "$IMAGE_PATH.o3k-owned" \
      || { echo "cleanup: image ownership marker is invalid" >&2; exit 1; }
  fi
fi
if [[ ! -e "$STATE_ROOT" ]]; then
  if [[ -e "$INVENTORY_ROOT" ]]; then
    [[ -d "$INVENTORY_ROOT" && ! -L "$INVENTORY_ROOT" ]] \
      || { echo "cleanup: inventory root is not a real directory" >&2; exit 1; }
    grep -Fqx 'o3k-disposable-inventory-v1' "$INVENTORY_ROOT/.o3k-inventory-owned" \
      || { echo "cleanup: inventory ownership marker is invalid" >&2; exit 1; }
    rm -rf -- "$INVENTORY_ROOT"
  fi
  [[ -z "$OPENSTACK_VENV" || ! -e "$OPENSTACK_VENV" ]] || rm -rf -- "$OPENSTACK_VENV"
  if [[ -n "$IMAGE_PATH" && -e "$IMAGE_PATH" ]]; then
    grep -Fqx 'o3k-disposable-image-v1' "$IMAGE_PATH.o3k-owned" \
      || { echo "cleanup: image ownership marker is invalid" >&2; exit 1; }
    rm -f -- "$IMAGE_PATH" "$IMAGE_PATH.o3k-owned"
  elif [[ -n "$IMAGE_PATH" && -e "$IMAGE_PATH.o3k-owned" ]]; then
    grep -Fqx 'o3k-disposable-image-v1' "$IMAGE_PATH.o3k-owned" \
      || { echo "cleanup: image ownership marker is invalid" >&2; exit 1; }
    rm -f -- "$IMAGE_PATH.o3k-owned"
  fi
  echo "disposable TestLab cleanup: no state to remove"
  exit 0
fi
[[ -d "$STATE_ROOT" && ! -L "$STATE_ROOT" ]] \
  || { echo "cleanup: state root is not a real directory" >&2; exit 1; }
sudo -n test -f "$STATE_ROOT/.o3k-run-owned" \
  && ! sudo -n test -L "$STATE_ROOT/.o3k-run-owned" \
  || { echo "cleanup: ownership marker is missing" >&2; exit 1; }
sudo -n grep -Fqx 'o3k-disposable-testlab-v1' "$STATE_ROOT/.o3k-run-owned" \
  || { echo "cleanup: ownership marker is invalid" >&2; exit 1; }
sudo -n grep -Fqx "run=$RUN_ID" "$STATE_ROOT/.o3k-run-owned" \
  || { echo "cleanup: ownership marker belongs to another run" >&2; exit 1; }
sudo -n grep -Fqx "o3k-owned-v1 path=$STATE_ROOT" "$STATE_ROOT/.o3k-owned" \
  || { echo "cleanup: O3K ownership marker is invalid" >&2; exit 1; }
state_metadata="$(sudo -n stat -c '%U:%G:%a' "$STATE_ROOT" 2>/dev/null)"
case "$state_metadata" in
  # The split control/compute topology deliberately keeps the shared run
  # root root-owned and traversable; only its private children are owned by
  # the service accounts.  Accept that exact ownership posture in addition
  # to the legacy single-account layouts.
  root:root:755|root:root:750|o3k:o3k:700|o3k:o3k:750|o3k:kvm:710) ;;
  *) echo "cleanup: state ownership or permissions are not O3K-owned" >&2; exit 1 ;;
esac
account_created=false
group_created=false
compute_account_created=false
compute_group_created=false
supplementary_groups_added=false
sudo -n grep -Fqx 'o3k-disposable-account-v1' "$STATE_ROOT/.o3k-account-created" 2>/dev/null \
  && account_created=true
sudo -n grep -Fqx 'o3k-disposable-group-v1' "$STATE_ROOT/.o3k-group-created" 2>/dev/null \
  && group_created=true
sudo -n grep -Fqx 'o3k-disposable-compute-account-v1' "$STATE_ROOT/.o3k-compute-account-created" 2>/dev/null \
  && compute_account_created=true
sudo -n grep -Fqx 'o3k-disposable-compute-group-v1' "$STATE_ROOT/.o3k-compute-group-created" 2>/dev/null \
  && compute_group_created=true
sudo -n test -s "$STATE_ROOT/.o3k-supplementary-groups-added" \
  && supplementary_groups_added=true

remove_added_supplementary_groups() {
  [[ "$supplementary_groups_added" == true ]] || return 0
  sudo -n flock -x "$ACCOUNT_LOCK" bash -c '
    set -euo pipefail
    while IFS= read -r group; do
      [[ -n "$group" ]] || continue
      getent group "$group" >/dev/null 2>&1 || continue
      id o3k-compute >/dev/null 2>&1 || continue
      if id -nG o3k-compute | tr " " "\n" | grep -Fqx "$group"; then
        gpasswd --delete o3k-compute "$group" >/dev/null
      fi
    done <"$1"
  ' _ "$STATE_ROOT/.o3k-supplementary-groups-added" \
    || { echo "cleanup: cannot restore o3k supplementary groups" >&2; return 1; }
  supplementary_groups_added=false
}

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
  # Keep the full account name; ps(1)'s default USER column truncates
  # o3k-compute and causes safe owned-process cleanup to fail closed.
  sudo -n ps -o user:32= -p "$pid" 2>/dev/null | tr -d ' '
}

process_record_matches() {
  local pid="$1" start_ticks="$2" uid="$3" binary="$4"
  [[ "$uid" == o3k || "$uid" == o3k-compute ]] \
    && [[ "$(process_uid "$pid")" == "$uid" ]] \
    && [[ "$(process_start_ticks "$pid")" == "$start_ticks" ]] \
    && process_matches "$pid" "$binary"
}

stop_owned_process() {
  local pid="$1" start_ticks="$2" uid="$3" binary="$4"
  sudo -n kill -0 "$pid" 2>/dev/null || return 0
  process_record_matches "$pid" "$start_ticks" "$uid" "$binary" \
    || { echo "cleanup: refusing to signal a foreign process" >&2; return 1; }
  sudo -n kill "$pid" || return 1
  for _ in $(seq 1 20); do
    sudo -n kill -0 "$pid" 2>/dev/null || return 0
    sleep 1
  done
  echo "cleanup: service did not stop" >&2
  return 1
}

# Never discard the run ledger while host resources may still exist.  The
# ledger is the only durable record allowing a later retry to identify and
# clean those resources safely.
assert_no_owned_host_state() {
  [[ -x "$STATE_ROOT/bin/o3k-compute" ]] || return 0
  command -v virsh >/dev/null 2>&1 || { echo "cleanup: libvirt inspection tool is unavailable" >&2; return 1; }
  sudo -n virsh -c qemu:///system uri >/dev/null 2>&1 \
    || { echo "cleanup: libvirt state could not be inspected" >&2; return 1; }
  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    xml="$(sudo -n virsh -c qemu:///system dumpxml "$domain" 2>/dev/null)" \
      || { echo "cleanup: domain inspection failed for $domain" >&2; return 1; }
    if grep -Fq 'managed_by="o3k-compute"' <<<"$xml" && grep -Fq '<o3k:domain' <<<"$xml"; then
      echo "cleanup: refusing to discard state while O3K-owned libvirt domain exists: $domain" >&2
      return 1
    fi
  done < <(sudo -n virsh -c qemu:///system list --all --name 2>/dev/null) \
    || { echo "cleanup: libvirt domain listing failed" >&2; return 1; }

  # Host network ownership belongs to the compute service's private state,
  # not the control-plane data directory.  Checking the latter silently
  # discarded the only ledger that could authorize safe cleanup.
  local manifest="$STATE_ROOT/compute-data/network/ownership.json"
  if [[ -e "$manifest" ]]; then
    [[ -f "$manifest" && ! -L "$manifest" ]] || { echo "cleanup: network ownership manifest is unsafe" >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || { echo "cleanup: cannot inspect network ownership manifest" >&2; return 1; }
    local names
    names="$(python3 - "$manifest" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    manifest = json.load(stream)
bridge = manifest.get("bridge") or {}
if bridge.get("created_by_o3k") and bridge.get("name"):
    print(bridge["name"])
for name, record in (manifest.get("taps") or {}).items():
    if record.get("created_by_o3k") and name:
        print(name)
PY
    )" || { echo "cleanup: network ownership manifest is corrupt" >&2; return 1; }
    if [[ -n "$names" ]]; then
      command -v ip >/dev/null 2>&1 || { echo "cleanup: network inspection tool is unavailable" >&2; return 1; }
      local links
      links="$(sudo -n ip -o link show 2>/dev/null)" || { echo "cleanup: network state could not be inspected" >&2; return 1; }
      while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        grep -Eq "^[0-9]+: ${name}(@[^:]+)?:" <<<"$links" \
          && { echo "cleanup: refusing to discard state while O3K-owned network link exists: $name" >&2; return 1; }
      done <<<"$names"
    fi
  fi

  # If a crash happened before the network ledger was persisted, the
  # deterministic disposable bridge name is still a conservative fence.  Do
  # not discard the run state while that link exists: without the ledger there
  # is no proof that deleting it would be safe.
  local expected_bridge="${O3K_COMPUTE_BRIDGE_NAME:-o3k-b${RUN_ID: -8}}"
  if [[ "$expected_bridge" =~ ^[A-Za-z0-9_-]{1,15}$ ]] && command -v ip >/dev/null 2>&1; then
    local links
    links="$(sudo -n ip -o link show 2>/dev/null)" \
      || { echo "cleanup: network state could not be inspected" >&2; return 1; }
    if grep -Eq "^[0-9]+: ${expected_bridge}(@[^:]+)?[:]" <<<"$links"; then
      echo "cleanup: refusing to discard state while disposable bridge exists: $expected_bridge" >&2
      return 1
    fi
  fi

  local dhcp_root="$STATE_ROOT/compute-data/dhcp"
  if [[ -d "$dhcp_root" && ! -L "$dhcp_root" ]]; then
    while IFS= read -r pidfile; do
      [[ -n "$pidfile" ]] || continue
      local pid raw cmdline
      raw="$(sudo -n cat "$pidfile" 2>/dev/null)" || return 1
      [[ "$raw" =~ ^[0-9]+$ ]] || { echo "cleanup: malformed DHCP pidfile $pidfile" >&2; return 1; }
      pid="$raw"
      if sudo -n kill -0 "$pid" 2>/dev/null; then
        cmdline="$(sudo -n tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null)" \
          || { echo "cleanup: DHCP process identity is unreadable" >&2; return 1; }
        [[ "$cmdline" == *"$dhcp_root"* ]] \
          || { echo "cleanup: DHCP pidfile points to an unverified live process: $pid" >&2; return 1; }
        echo "cleanup: refusing to discard state while O3K DHCP process exists: $pid" >&2
        return 1
      fi
    done < <(find "$dhcp_root" -maxdepth 1 -type f -name 'dnsmasq-*.pid' -print)
  elif [[ -e "$dhcp_root" ]]; then
    echo "cleanup: DHCP state root is unsafe" >&2
    return 1
  fi
}
for pid_file in "$PID_ROOT/o3kd.pid" "$PID_ROOT/o3k-compute.pid"; do
  if [[ -f "$pid_file" ]]; then
    IFS='|' read -r pid start_ticks uid binary extra <"$pid_file"
    [[ -z "${extra:-}" && "$pid" =~ ^[0-9]+$ && "$start_ticks" =~ ^[0-9]+$ \
      && ( "$binary" == o3kd || "$binary" == o3k-compute ) ]] \
      || { echo "cleanup: invalid process identity" >&2; exit 1; }
    stop_owned_process "$pid" "$start_ticks" "$uid" "$binary" || exit 1
  fi
done
for _ in $(seq 1 20); do
  alive=false
  for pid_file in "$PID_ROOT/o3kd.pid" "$PID_ROOT/o3k-compute.pid"; do
    [[ -f "$pid_file" ]] || continue
    IFS='|' read -r pid start_ticks uid binary extra <"$pid_file"
    [[ -z "${extra:-}" && "$pid" =~ ^[0-9]+$ && "$start_ticks" =~ ^[0-9]+$ \
      && ( "$binary" == o3kd || "$binary" == o3k-compute ) ]] \
      || { echo "cleanup: invalid process identity" >&2; exit 1; }
    if sudo -n kill -0 "$pid" 2>/dev/null; then
      process_record_matches "$pid" "$start_ticks" "$uid" "$binary" \
        || { echo "cleanup: refusing to wait on a foreign process" >&2; exit 1; }
      alive=true
    fi
  done
  [[ "$alive" == false ]] && break
  sleep 1
done
[[ "$alive" == false ]] || { echo "cleanup: service did not stop" >&2; exit 1; }
# The PID ledger is run-temp scoped.  A mismatched RUNNER_TEMP can make both
# records invisible while the run-owned executables are still serving.  Never
# discard STATE_ROOT until /proc proves that neither exact run-owned binary is
# live; if a process is present without its matching ledger record, fail
# closed and retain the state for identity-verified recovery.
for binary in o3kd o3k-compute; do
  expected_exe="$STATE_ROOT/bin/$binary"
  expected_pid_file="$PID_ROOT/$binary.pid"
  for proc_exe in /proc/[0-9]*/exe; do
    [[ -e "$proc_exe" ]] || continue
    pid="${proc_exe#/proc/}"
    pid="${pid%/exe}"
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    actual_exe="$(sudo -n readlink "$proc_exe" 2>/dev/null || true)"
    case "$actual_exe" in
      "$expected_exe"|"$expected_exe (deleted)") ;;
      *) continue ;;
    esac
    if [[ ! -f "$expected_pid_file" ]]; then
      echo "cleanup: refusing to discard state: unrecorded run-owned service process $binary pid=$pid" >&2
      exit 1
    fi
    IFS='|' read -r recorded_pid _recorded_ticks _recorded_uid recorded_binary _extra <"$expected_pid_file"
    if [[ "$recorded_pid" != "$pid" || "$recorded_binary" != "$binary" ]]; then
      echo "cleanup: refusing to discard state: unrecorded run-owned service process $binary pid=$pid" >&2
      exit 1
    fi
    echo "cleanup: refusing to discard state: service did not stop $binary pid=$pid" >&2
    exit 1
  done
done
assert_no_owned_host_state || exit 1
remove_added_supplementary_groups || exit 1
if [[ "$account_created" == true || "$group_created" == true || \
      "$compute_account_created" == true || "$compute_group_created" == true ]]; then
  sudo -n flock -x "$ACCOUNT_LOCK" bash -c '
    set -euo pipefail
    pgrep -u o3k >/dev/null 2>&1 && exit 0 || true
    pgrep -u o3k-compute >/dev/null 2>&1 && exit 0 || true
    if [[ "$1" == true ]] && id o3k >/dev/null 2>&1; then userdel o3k || true; fi
    if [[ "$2" == true ]] && getent group o3k >/dev/null 2>&1; then groupdel o3k || true; fi
    if [[ "$3" == true ]] && id o3k-compute >/dev/null 2>&1; then userdel o3k-compute || true; fi
    if [[ "$4" == true ]] && getent group o3k-compute >/dev/null 2>&1; then groupdel o3k-compute || true; fi
  ' _ "$account_created" "$group_created" "$compute_account_created" "$compute_group_created" || true
fi
sudo -n rm -rf -- "$STATE_ROOT"
rm -rf -- "$PID_ROOT"
if [[ -e "$INVENTORY_ROOT" ]]; then
  [[ -d "$INVENTORY_ROOT" && ! -L "$INVENTORY_ROOT" ]] \
    || { echo "cleanup: inventory root is not a real directory" >&2; exit 1; }
  grep -Fqx 'o3k-disposable-inventory-v1' "$INVENTORY_ROOT/.o3k-inventory-owned" \
    || { echo "cleanup: inventory ownership marker is invalid" >&2; exit 1; }
  rm -rf -- "$INVENTORY_ROOT"
fi
if [[ -n "$OPENSTACK_VENV" && -e "$OPENSTACK_VENV" ]]; then
  grep -Fqx 'o3k-disposable-venv-v1' "$OPENSTACK_VENV/.o3k-venv-owned" \
    || { echo "cleanup: refusing to remove an unowned virtualenv" >&2; exit 1; }
  rm -rf -- "$OPENSTACK_VENV"
fi
if [[ -n "$IMAGE_PATH" && -e "$IMAGE_PATH" ]]; then
  grep -Fqx 'o3k-disposable-image-v1' "$IMAGE_PATH.o3k-owned" \
    || { echo "cleanup: refusing to remove an unowned image" >&2; exit 1; }
  rm -f -- "$IMAGE_PATH"
  rm -f -- "$IMAGE_PATH.o3k-owned"
fi
echo "disposable TestLab cleanup completed"
