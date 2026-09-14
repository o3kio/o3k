#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOTSTRAP="$ROOT_DIR/scripts/bootstrap-disposable-testlab.sh"
CLEANUP="$ROOT_DIR/scripts/cleanup-disposable-testlab.sh"

python3 - "$BOOTSTRAP" "$CLEANUP" "$ROOT_DIR/.github/workflows/real-host-validation.yml" <<'PY'
from pathlib import Path
import sys

bootstrap = Path(sys.argv[1]).read_text(encoding="utf-8")
cleanup = Path(sys.argv[2]).read_text(encoding="utf-8")
workflow = Path(sys.argv[3]).read_text(encoding="utf-8")
assert 'PASSWORD="$(openssl rand -hex 32)"' in bootstrap
assert 'echo "::add-mask::${PASSWORD}"' in bootstrap
assert bootstrap.index('echo "::add-mask::${PASSWORD}"') < bootstrap.index('O3K_BOOTSTRAP_PASSWORD=')
assert 'BOOTSTRAP_SECRET="$(openssl rand -hex 32)"' in bootstrap
assert 'O3K_BOOTSTRAP_SECRET=' in bootstrap
assert '.bootstrap-secret' in bootstrap
assert 'OS_PASSWORD=%s\\n' in bootstrap
assert 'OS_PROJECT_NAME=admin' in bootstrap
assert '--no-create-home' in bootstrap
assert 'o3k-disposable-account-v1' in bootstrap
assert 'protobuf-compiler' in bootstrap
assert 'cargo build --locked --release --bin o3kd --bin o3k' in bootstrap
assert 'bootstrap_testlab() {' in bootstrap
assert '"$STATE_ROOT/bin/o3k" init' in bootstrap
assert '"$STATE_ROOT/bin/o3k" join' in bootstrap
assert 'O3K_REAL_HOST_COMPUTE_BINARY' in bootstrap
assert 'O3K_REAL_HOST_NETWORK_CAPABILITY=ambient-net-admin' in bootstrap
assert 'usermod --append --groups "$group" o3k-compute' in bootstrap
assert 'agent-id.artifacts' in bootstrap
assert '--ambient-caps=+net_admin' in bootstrap
assert '--init-groups' in bootstrap
assert 'nohup bash -c' in bootstrap
assert 'O3K_COMPUTE_BRIDGE_NAME' in bootstrap
assert 'O3K_TESTLAB_ADDITIONAL_AGENT_IDS' in bootstrap
assert 'extra_agent_args+=(--extra-agent-id "$extra_agent_id")' in bootstrap
assert 'canonical extra agent identity was not generated' in bootstrap
assert 'O3K_TESTLAB_CONTROL_BIND_ADDR' in bootstrap
assert 'o3k-b${RUN_ID: -8}' in bootstrap
assert 'O3K_COMPUTE_BRIDGE_NAME=%s\\n' in bootstrap
assert 'SERVICE_STATE_BASE=/var/lib/o3k-testlab' in bootstrap
assert 'SupplementaryGroups' not in bootstrap
assert '.o3k-supplementary-groups-added' in bootstrap
assert 'usermod --append --groups "$group" o3k-compute' in bootstrap
assert 'usermod --append --groups "$group" o3k\n' not in bootstrap
assert 'gpasswd --delete o3k' in bootstrap
assert 'gpasswd --delete o3k-compute' in cleanup
assert 'o3k-disposable-compute-account-v1' in bootstrap
assert 'o3k-disposable-compute-group-v1' in bootstrap
assert 'compute_account_created' in cleanup
assert 'compute_group_created' in cleanup
assert 'install -d -o root -g root -m 0755' in bootstrap
assert 'agent-inspect-probe.json' in bootstrap
assert 'cleanup-disposable-testlab.sh' in bootstrap
assert 'ownership ledger until libvirt, network, and DHCP state have' in bootstrap
assert 'O3K_TESTLAB_IMAGE_PATH="${IMAGE_PATH:-}"' in bootstrap
assert 'sudo -n rm -rf -- "$STATE_ROOT"' not in bootstrap
assert '/readyz' in bootstrap
assert 'GITHUB_PATH' in bootstrap
assert 'O3K_REAL_HOST_PROTECTED_PATHS=%s\\nO3K_REAL_HOST_INVENTORY_ROOT=%s' in bootstrap
assert 'ps -o user:32=' in bootstrap
assert 'ps -o user:32=' in cleanup
assert '"$uid" == o3k || "$uid" == o3k-compute' in cleanup
assert 'assert_no_owned_host_state()' in cleanup
assert 'refusing to discard state while O3K-owned libvirt domain exists' in cleanup
assert 'refusing to discard state while O3K-owned network link exists' in cleanup
assert 'STATE_ROOT/compute-data/network/ownership.json' in cleanup
assert 'STATE_ROOT/compute-data/dhcp' in cleanup
assert 'refusing to discard state while disposable bridge exists' in cleanup
assert 'refusing to discard state while O3K DHCP process exists' in cleanup
assert cleanup.index('assert_no_owned_host_state || exit 1') < cleanup.index('sudo -n rm -rf -- "$STATE_ROOT"')
ready_start = bootstrap.index('wait_for_o3kd_ready() {')
ready_end = bootstrap.index('\n}', ready_start)
ready_block = bootstrap[ready_start:ready_end]
assert 'for _ in $(seq 1 60);' in ready_block
assert 'sleep 1' in ready_block
assert ready_block.count('/readyz"') == 2
launch_start = bootstrap.index('start_service o3kd ')
assert bootstrap.index('wait_for_o3kd_health', launch_start) < bootstrap.index('wait_for_o3kd_control', launch_start)
assert bootstrap.index('wait_for_o3kd_control', launch_start) < bootstrap.index('bootstrap_testlab', launch_start)
assert bootstrap.index('bootstrap_testlab', launch_start) < bootstrap.index('start_compute', launch_start)
assert bootstrap.index('start_compute', launch_start) < bootstrap.index('wait_for_compute_ready', launch_start)
assert bootstrap.index('wait_for_compute_ready', launch_start) < bootstrap.index('wait_for_o3kd_ready', launch_start)
assert 'userdel o3k' in cleanup
assert 'OS_PASSWORD:' not in workflow
assert workflow.count('scripts/bootstrap-disposable-testlab.sh') >= 2
assert workflow.count('scripts/cleanup-disposable-testlab.sh') >= 2
PY

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/o3k-disposable-bootstrap-test.XXXXXX")"
trap 'rm -rf -- "$tmp_root"' EXIT
chmod 0755 "$tmp_root"
run_id=local-991
state="$tmp_root/o3k-testlab/$run_id"
pid_root="$tmp_root/o3k-testlab-pids/$run_id"
venv="$tmp_root/o3k-openstack-venv.test"
image="$tmp_root/cirros-0.6.3-x86_64-disk.img.test"
mkdir -p "$state" "$pid_root" "$venv"
printf 'o3k-disposable-venv-v1\n' >"$venv/.o3k-venv-owned"
mkdir -p "$state/bin"
cp /bin/sleep "$state/bin/o3kd"
printf 'o3k-disposable-testlab-v1\ncommit=test\nrun=%s\n' "$run_id" >"$state/.o3k-run-owned"
printf 'o3k-owned-v1 path=%s\n' "$state" >"$state/.o3k-owned"
sudo chown -R o3k:o3k "$state"
sudo chmod 0700 "$state"
sudo -n -u o3k -- "$state/bin/o3kd" 60 & supervisor_pid=$!
sleep 0.2
service_pid="$(sudo -n pgrep -P "$supervisor_pid" -u o3k 2>/dev/null || true)"
if [[ -z "$service_pid" ]]; then
  service_pid="$(sudo -n pgrep -u o3k -f "$state/bin/o3kd" | head -n1)"
fi
start_ticks="$(sudo -n awk '{print $22}' "/proc/$service_pid/stat")"
printf '%s|%s|o3k|o3kd\n' "$service_pid" "$start_ticks" >"$pid_root/o3kd.pid"
touch "$image"
printf 'o3k-disposable-image-v1\n' >"$image.o3k-owned"

RUNNER_TEMP="$tmp_root" GITHUB_RUN_ID="$run_id" \
  O3K_TESTLAB_STATE_ROOT="$state" O3K_TESTLAB_PID_ROOT="$pid_root" \
  O3K_OPENSTACK_VENV="$venv" O3K_TESTLAB_IMAGE_PATH="$image" \
  bash "$CLEANUP"

[[ ! -e "$state" && ! -e "$pid_root" && ! -e "$venv" && ! -e "$image" && ! -e "$image.o3k-owned" ]]
! sudo -n kill -0 "$service_pid" 2>/dev/null

# The split-account bootstrap uses a root-owned, traversable run root so
# neither daemon owns the other daemon's state.  Cleanup must still recognize
# and remove that explicitly marked O3K-owned root.
mkdir -p "$state"
printf 'o3k-disposable-testlab-v1\ncommit=test\nrun=%s\n' "$run_id" >"$state/.o3k-run-owned"
printf 'o3k-owned-v1 path=%s\n' "$state" >"$state/.o3k-owned"
sudo chown -R root:root "$state"
sudo chmod 0755 "$state"
RUNNER_TEMP="$tmp_root" GITHUB_RUN_ID="$run_id" O3K_TESTLAB_STATE_ROOT="$state" \
  O3K_TESTLAB_PID_ROOT="$pid_root" bash "$CLEANUP"
[[ ! -e "$state" ]]

mkdir -p "$state"
printf 'foreign-state\n' >"$state/.o3k-run-owned"
if RUNNER_TEMP="$tmp_root" GITHUB_RUN_ID="$run_id" O3K_TESTLAB_STATE_ROOT="$state" \
  O3K_TESTLAB_PID_ROOT="$pid_root" bash "$CLEANUP" 2>/dev/null; then
  echo "cleanup accepted a foreign state marker" >&2
  exit 1
fi
[[ -e "$state/.o3k-run-owned" ]]

echo "disposable TestLab bootstrap contract tests passed"
