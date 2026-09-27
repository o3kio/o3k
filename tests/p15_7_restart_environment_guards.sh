#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$ROOT_DIR/scripts/p15-7-real-host-journey.sh" <<'PY'
import os
from pathlib import Path
import re
import subprocess
import sys

source = Path(sys.argv[1]).read_text()
checks = re.findall(
    r'sudo -n cat "/proc/\$(?:new_pid|RESTARTED_O3KD_PID)/environ"'
    r' 2>/dev/null \| tr.*?\| grep[^\n;]+(?=; then)', source, re.S)
assert len(checks) == 7, f'expected seven live environment checks, got {len(checks)}'
# A real /proc environment larger than pipe buffers reproduces the early
# grep -q/SIGPIPE false rejection without exposing any real credentials.
environment = {
    'PATH': os.environ['PATH'], 'O3K_DATA_DIR': '/tmp/pp5-guard/data',
    'REPAIR_RELEASE': '/tmp/pp5-guard/release', 'REPAIR_TIMEOUT': '30000',
    'CREATE_WAITER': '/tmp/pp5-guard/waiter',
    'REPAIR_CHECKPOINT': '/tmp/pp5-guard/checkpoint',
    'REPLAY_SUPPRESS_RESOURCE': '00000000-0000-0000-0000-000000000001',
    'REPLAY_SUPPRESS_RUN': 'guard-run',
    **{f'PADDING_{i}': 'x' * 4096 for i in range(64)},
}
process = subprocess.Popen(['sleep', '60'], env=environment)
try:
    test_env = {
        'PATH': os.environ['PATH'], 'new_pid': str(process.pid),
        'RESTARTED_O3KD_PID': str(process.pid), 'STATE_ROOT': '/tmp/pp5-guard',
        'O3K_REPAIR_RELEASE_ENV_NAME': 'REPAIR_RELEASE',
        'CRASH_REPAIR_RELEASE_FILE': '/tmp/pp5-guard/release',
        'O3K_REPAIR_TIMEOUT_ENV_NAME': 'REPAIR_TIMEOUT',
        'CONTENDING_CREATE_REPAIR_PAUSE_MS': '30000',
        'O3K_CREATE_WAITER_ENV_NAME': 'CREATE_WAITER',
        'CRASH_REPAIR_WAITER_FILE': '/tmp/pp5-guard/waiter',
        'O3K_REPAIR_CHECKPOINT_ENV_NAME': 'REPAIR_CHECKPOINT',
        'CRASH_REPAIR_CHECKPOINT_FILE': '/tmp/pp5-guard/checkpoint',
        'O3K_REPLAY_SUPPRESS_RESOURCE_ENV_NAME': 'REPLAY_SUPPRESS_RESOURCE',
        'WORKLOAD_C': '00000000-0000-0000-0000-000000000001',
        'O3K_REPLAY_SUPPRESS_RUN_ENV_NAME': 'REPLAY_SUPPRESS_RUN',
        'RUN_ID': 'guard-run',
    }
    for index, check in enumerate(checks):
        command = 'set -o pipefail\n' + check.replace('sudo -n cat', 'cat', 1)
        result = subprocess.run(['bash', '-c', command], env=test_env,
                                capture_output=True, timeout=5)
        assert result.returncode == 0, (
            f'live environment check {index + 1} falsely rejected an exact match '
            f'(exit {result.returncode})')
        assert not result.stdout, 'environment verifier printed matched values'
        wrong = dict(test_env)
        for field in ('STATE_ROOT', 'CRASH_REPAIR_RELEASE_FILE',
                      'CONTENDING_CREATE_REPAIR_PAUSE_MS', 'CRASH_REPAIR_WAITER_FILE',
                      'CRASH_REPAIR_CHECKPOINT_FILE', 'WORKLOAD_C', 'RUN_ID'):
            wrong[field] = 'wrong-value'
        assert subprocess.run(['bash', '-c', command], env=wrong,
                              capture_output=True, timeout=5).returncode != 0
        unreadable = dict(test_env, new_pid='0', RESTARTED_O3KD_PID='0')
        assert subprocess.run(['bash', '-c', command], env=unreadable,
                              capture_output=True, timeout=5).returncode != 0
    launcher = source.split('start_o3kd_verified() {', 1)[1].split('\nstop_o3kd_orderly()', 1)[0]
    ledger = launcher.index('>"${O3K_TESTLAB_PID_ROOT:')
    env_check = launcher.index('if ! sudo -n cat')
    assert ledger < env_check, 'verified replacement must be recorded before later rejection'
finally:
    process.terminate()
    process.wait(timeout=5)
print('P15.7 restart environment guards PASS: exact matches, mismatches, missing process, early ledger')
PY
