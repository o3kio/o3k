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
assert len(checks) == 8, f'expected eight live environment checks, got {len(checks)}'
# A real /proc environment larger than pipe buffers reproduces the early
# grep -q/SIGPIPE false rejection without exposing any real credentials.
environment = {
    'PATH': os.environ['PATH'], 'O3K_DATA_DIR': '/tmp/pp5-guard/data',
    'REPAIR_RELEASE': '/tmp/pp5-guard/data/p15-7-orphan-repair-run/release', 'REPAIR_TIMEOUT': '30000',
    'CREATE_WAITER': '/tmp/pp5-guard/data/p15-7-orphan-repair-run/contention-waiter',
    'REPAIR_CHECKPOINT': '/tmp/pp5-guard/data/p15-7-orphan-repair-run/checkpoint.json',
    'REPLAY_SUPPRESS_RESOURCE': '00000000-0000-0000-0000-000000000001',
    'REPLAY_SUPPRESS_RUN': 'guard-run',
    'O3K_PP5_RUN_ID': 'guard-run',
    **{f'PADDING_{i}': 'x' * 4096 for i in range(64)},
}
process = subprocess.Popen(['sleep', '60'], env=environment)
try:
    test_env = {
        'PATH': os.environ['PATH'], 'new_pid': str(process.pid),
        'RESTARTED_O3KD_PID': str(process.pid), 'STATE_ROOT': '/tmp/pp5-guard',
        'O3K_REPAIR_RELEASE_ENV_NAME': 'REPAIR_RELEASE',
        'CRASH_REPAIR_RELEASE_FILE': '/tmp/pp5-guard/data/p15-7-orphan-repair-run/release',
        'O3K_REPAIR_TIMEOUT_ENV_NAME': 'REPAIR_TIMEOUT',
        'CONTENDING_CREATE_REPAIR_PAUSE_MS': '30000',
        'O3K_CREATE_WAITER_ENV_NAME': 'CREATE_WAITER',
        'CRASH_REPAIR_WAITER_FILE': '/tmp/pp5-guard/data/p15-7-orphan-repair-run/contention-waiter',
        'O3K_REPAIR_CHECKPOINT_ENV_NAME': 'REPAIR_CHECKPOINT',
        'CRASH_REPAIR_CHECKPOINT_FILE': '/tmp/pp5-guard/data/p15-7-orphan-repair-run/checkpoint.json',
        'O3K_REPLAY_SUPPRESS_RESOURCE_ENV_NAME': 'REPLAY_SUPPRESS_RESOURCE',
        'WORKLOAD_C': '00000000-0000-0000-0000-000000000001',
        'O3K_REPLAY_SUPPRESS_RUN_ENV_NAME': 'REPLAY_SUPPRESS_RUN',
        'O3K_PP5_RUN_ENV_NAME': 'O3K_PP5_RUN_ID',
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
    repair_env = source.split('append_o3kd_repair_pause_env() {', 1)[1].split('\nremove_o3kd_repair_pause_env()', 1)[0]
    assert '$STATE_ROOT/data/p15-7-orphan-repair-$RUN_ID' in repair_env, 'repair seam must use the private run-scoped data directory'
    assert 'install -d -o "${O3K_REAL_HOST_DAEMON_ACCOUNT:-o3k}"' in repair_env, 'repair seam directory must be daemon-owned'
    assert 'O3K_PP5_RUN_ENV_NAME' in repair_env, 'repair seam must persist the live PP5 run identity'
    assert 'PP5 run identity missing from o3kd environment' in repair_env, 'repair seam must fail closed when run identity is not persisted'
    remove_env = source.split('remove_o3kd_repair_pause_env() {', 1)[1].split('\nclear_o3kd_fault_env()', 1)[0]
    assert 'O3K_PP5_RUN_ENV_NAME=' in remove_env, 'repair cleanup must remove only the run identity seam'
    diagnostics = source.split('write_orphan_repair_diagnostics() {', 1)[1].split('\nstop_contending_create()', 1)[0]
    assert 'sudo -n tail -n 2000' in diagnostics, 'orphan diagnostics must read the protected daemon log through sudo'
    assert 'failure_step' in diagnostics and 'failure_kind' in diagnostics and 'failure_errno' in diagnostics, \
        'bounded diagnostics must retain sanitized publication step/kind/errno'
    assert 'checkpoint_publication_error_observed": bool(publication_failure_events)' in diagnostics, \
        'publication-error detection must use structured failure events'
    assert 'checkpoint could not be published' not in diagnostics, \
        'publication-error detection must not rely on the stale message substring'
    assert 'rm -f -- "$log_snapshot"' in diagnostics, 'raw daemon-log snapshot must be removed after redaction'
    assert 'endpoint_status="$(fetch_redacted_json "http://127.0.0.1:$AUTH_PORT/v2.0/ports/$PORT_C_ID" "$endpoint_raw" X-Auth-Token)"' in diagnostics, 'endpoint diagnostics must retain the Neutron token header contract'
    assert 'X-Auth-Token) header_value="$PROJECT_TOKEN"' in diagnostics, 'Neutron diagnostics must send the token without a Bearer prefix'
    assert 'X-Auth-Token) header_value="Bearer $PROJECT_TOKEN"' not in diagnostics, 'Bearer must never be prepended to X-Auth-Token'
    assert 'Authorization) header_value="Bearer $PROJECT_TOKEN"' in diagnostics, 'native diagnostics must retain Bearer authentication'
    timeline = source.split('write_orphan_repair_timeline() {', 1)[1].split('\nwrite_orphan_repair_diagnostics()', 1)[0]
    assert 'event.startswith("orphan_repair_")' in timeline, 'timeline must select structured repair events'
    assert 'events[-1000:]' in timeline, 'timeline artifact must stay bounded'
    assert 'owner_controller_id' in timeline and 'fencing_token' in timeline, 'timeline must retain coordination identity and fencing fields'
    assert 'rm -f -- "$log_snapshot"' in timeline, 'timeline must remove its raw daemon-log suffix'
    classifier = source.split('classify_failure() {', 1)[1].split('\nwrite_failure_artifact()', 1)[0]
    assert classifier.index('*orphan*|*repair*') < classifier.index('*source*|*checkout*'), 'orphan failures must not be shadowed by resource/source substring matching'
    classifier_fn = source.split('classify_failure() {', 1)[1].split('\nwrite_failure_artifact()', 1)[0]
    classifier_fn = 'classify_failure() {' + classifier_fn
    classified = subprocess.run(
        ['bash', '-c', classifier_fn + "\nclassify_failure 'orphan repair did not publish the resource-scoped checkpoint'"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert classified == 'orphan_repair', f'orphan checkpoint failure was classified as {classified!r}'
    assert source.index('run_checkpoint_path_diagnostic') < source.index('provision_vms_bounded block-a block-b'), \
        'checkpoint path diagnostic must run before VM provisioning'
    assert 'O3K_CHECKPOINT_BOUNDARY_ROOT=' in source, 'runner must pass the checkpoint boundary diagnostic root'
finally:
    process.terminate()
    process.wait(timeout=5)
print('P15.7 restart environment guards PASS: exact matches, mismatches, missing process, early ledger')
PY
