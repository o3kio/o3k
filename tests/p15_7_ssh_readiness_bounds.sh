#!/usr/bin/env bash
# P15.7 readiness SSH watchdog regression (handoff HIGH finding).
#
# A guest that accepts an SSH connection but never completes the read-only
# readiness command must not stall wait_vm_ssh: the readiness-only watchdog
# (readiness_probe in scripts/p15-7-real-host-journey.sh) bounds the `true`
# liveness probe and the boot-id read at 15s with TERM plus a bounded KILL
# grace, records every probe (timestamps, exact exit, timeout classification,
# VM/purpose identity) to a bounded sanitized JSONL, and leaves ssh_vm itself
# unbounded for longer legitimate cloud-init/diagnostic commands.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JOURNEY="$ROOT_DIR/scripts/p15-7-real-host-journey.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-readiness.XXXXXX")"
trap 'rm -rf -- "${WORK_DIR}"' EXIT

[[ -f "$JOURNEY" ]] || { echo "missing journey script: $JOURNEY" >&2; exit 1; }

# Extract the real function definitions under test from the journey so the
# regression exercises production code, not a copy.
extract_function() {
  awk -v name="$1" '$0 ~ "^"name"\\(\\) \\{" {f=1} f {print} f && /^}/ {exit}' "$JOURNEY"
}
extract_function ssh_vm >"$WORK_DIR/functions.sh"
awk '/^SSH_VM_OPTS=/{print; exit}' "$JOURNEY" >"$WORK_DIR/ssh_vm_opts.sh"
extract_function readiness_probe >>"$WORK_DIR/functions.sh"
grep -q '^SSH_VM_OPTS=' "$WORK_DIR/ssh_vm_opts.sh" || { echo "SSH_VM_OPTS definition not found in journey" >&2; exit 1; }
grep -q '^ssh_vm()' "$WORK_DIR/functions.sh" || { echo "ssh_vm definition not found in journey" >&2; exit 1; }
grep -q '^readiness_probe()' "$WORK_DIR/functions.sh" || { echo "readiness_probe watchdog not found in journey (readiness probes are unbounded)" >&2; exit 1; }

# SSH stub that accepts a connection but never completes the command.
mkdir -p "$WORK_DIR/stub-hang" "$WORK_DIR/stub-ok"
cat >"$WORK_DIR/stub-hang/ssh" <<'STUB'
#!/usr/bin/env bash
# Accepts the connection, never completes the read-only command.
exec sleep 3600
STUB
chmod +x "$WORK_DIR/stub-hang/ssh"

# SSH stub that completes the read-only commands quickly (positive control).
cat >"$WORK_DIR/stub-ok/ssh" <<'STUB'
#!/usr/bin/env bash
for arg in "$@"; do
  case "$arg" in
    true) exit 0 ;;
    /proc/sys/kernel/random/boot_id) printf '11111111-2222-3333-4444-555555555555\n'; exit 0 ;;
  esac
done
exit 0
STUB
chmod +x "$WORK_DIR/stub-ok/ssh"

run_case() {
  local stub_dir="$1" expected_probe_count="$2"
  local probe_log="$WORK_DIR/probes-$expected_probe_count.jsonl"
  : >"$probe_log"
  (
    PATH="$stub_dir:/usr/bin:/bin"
    SSH_KEY="$WORK_DIR/key" KNOWN_HOSTS="$WORK_DIR/known_hosts" VM_USER="tester"
    O3K_P15_7_SSH_READINESS_PROBE_LOG="$probe_log"
    # shellcheck disable=SC1091
    . "$WORK_DIR/ssh_vm_opts.sh"
    . "$WORK_DIR/functions.sh"
    start_ms="$(date +%s%3N)"
    set +e
    readiness_probe "vm-hang" "readiness-true" "192.0.2.1" true >/dev/null 2>&1
    first_exit=$?
    readiness_probe "vm-hang" "readiness-boot-id" "192.0.2.1" cat /proc/sys/kernel/random/boot_id >/dev/null 2>&1
    second_exit=$?
    set -e
    end_ms="$(date +%s%3N)"
    printf 'first_exit=%s\nsecond_exit=%s\nelapsed_ms=%s\n' "$first_exit" "$second_exit" "$((end_ms - start_ms))"
  ) >"$WORK_DIR/result-$expected_probe_count.txt"
}

# 1. Hanging SSH: both read-only probes must be bounded by the watchdog.
run_case "$WORK_DIR/stub-hang" 2
# shellcheck disable=SC1091
. "$WORK_DIR/result-2.txt"
[[ "$first_exit" =~ ^(124|137|143)$ ]] || { echo "readiness-true probe was not watchdog-bounded (exit=$first_exit)" >&2; exit 1; }
[[ "$second_exit" =~ ^(124|137|143)$ ]] || { echo "readiness-boot-id probe was not watchdog-bounded (exit=$second_exit)" >&2; exit 1; }
# 2x15s watchdog with bounded kill grace, sequential: allow generous slack but
# prove termination was driven by the watchdog, not the 3600s stub command.
(( elapsed_ms < 120000 )) || { echo "readiness probes exceeded watchdog bound (elapsed_ms=$elapsed_ms)" >&2; exit 1; }
python3 - "$WORK_DIR/probes-2.jsonl" <<'PY'
import json, pathlib, sys
lines = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.strip()]
assert len(lines) == 2, f"expected 2 recorded probes, got {len(lines)}"
for record in lines:
    assert record["timed_out"] is True, record
    assert record["exit_code"] in (124, 137, 143), record
    assert record["vm_id"] == "vm-hang", record
    assert record["finish_ms"] >= record["start_ms"], record
assert {record["purpose"] for record in lines} == {"readiness-true", "readiness-boot-id"}, lines
PY

# 2. Healthy SSH: probes pass through quickly, are recorded, and are not
# classified as timeouts.
run_case "$WORK_DIR/stub-ok" 2
# shellcheck disable=SC1091
. "$WORK_DIR/result-2.txt"
[[ "$first_exit" == 0 && "$second_exit" == 0 ]] || { echo "healthy readiness probes failed (first=$first_exit second=$second_exit)" >&2; exit 1; }
python3 - "$WORK_DIR/probes-2.jsonl" <<'PY'
import json, pathlib, sys
lines = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.strip()]
assert len(lines) == 2, f"expected 2 recorded probes, got {len(lines)}"
for record in lines:
    assert record["timed_out"] is False, record
    assert record["exit_code"] == 0, record
PY

# 3. ssh_vm must remain unbounded for legitimate long commands: the watchdog
# is opt-in per readiness probe, not a global ssh_vm timeout.
grep -q 'SSH_READINESS_TIMEOUT' "$WORK_DIR/functions.sh" || true
if grep '^ssh_vm()' "$JOURNEY" | grep -q 'timeout'; then
  echo "ssh_vm must not carry a global timeout" >&2
  exit 1
fi

echo "P15.7 SSH readiness watchdog regression passed"
