#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-real-host-guards.XXXXXX")"
trap 'rm -rf -- "${WORK_DIR}"' EXIT
FAKE_BIN="${WORK_DIR}/bin"
mkdir -p "${FAKE_BIN}"
for command in ip qemu-img openstack curl; do
    printf '#!/usr/bin/env bash\nexit 0\n' >"${FAKE_BIN}/${command}"
    chmod +x "${FAKE_BIN}/${command}"
done
cat >"${FAKE_BIN}/virsh" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == "-c qemu:///system uri" ]]; then echo qemu:///system; fi
if [[ "$*" == "-c qemu:///system list --all --name" && "${O3K_FAKE_VIRSH_DIRTY:-false}" == true ]]; then
    echo o3k-preexisting-domain
fi
if [[ "$*" == "-c qemu:///system list --all --name" && "${O3K_FAKE_VIRSH_STALE_P157:-false}" == true ]]; then
    [[ -f "${O3K_FAKE_VIRSH_STALE_STATE:?}" ]] || echo o3k-p15-7-12345-block-b
fi
if [[ "$*" == "-c qemu:///system list --all --name" && "${O3K_FAKE_VIRSH_STALE_P157_UNOWNED:-false}" == true ]]; then
    echo o3k-p15-7-12345-block-b
fi
if [[ "$*" == "-c qemu:///system dumpxml o3k-p15-7-12345-block-b" && "${O3K_FAKE_VIRSH_STALE_P157:-false}" == true ]]; then
    echo '<domain><description>o3k-p15-7-journey-owned=12345</description></domain>'
fi
if [[ "$*" == "-c qemu:///system dumpxml o3k-p15-7-12345-block-b" && "${O3K_FAKE_VIRSH_STALE_P157_UNOWNED:-false}" == true ]]; then
    echo '<domain><description>unrelated domain</description></domain>'
fi
if [[ "$*" == "-c qemu:///system destroy o3k-p15-7-12345-block-b" || "$*" == "-c qemu:///system undefine o3k-p15-7-12345-block-b --nvram" || "$*" == "-c qemu:///system undefine o3k-p15-7-12345-block-b" ]]; then
    : >"${O3K_FAKE_VIRSH_STALE_STATE:?}"
fi
if [[ "$*" == "-c qemu:///system domuuid o3k-p15-7-12345-block-b" && ! -f "${O3K_FAKE_VIRSH_STALE_STATE:-}" ]]; then
    echo 00000000-0000-0000-0000-000000000123
    exit 0
fi
if [[ "$*" == "-c qemu:///system domuuid o3k-p15-7-12345-block-b" ]]; then
    exit 1
fi
SH
chmod +x "${FAKE_BIN}/virsh"
cat >"${FAKE_BIN}/ip" <<'SH'
#!/usr/bin/env bash
if [[ "${O3K_FAKE_IP_DIRTY:-false}" == true ]]; then
    echo '2: foreign0: <BROADCAST> mtu 1500 state UP'
fi
if [[ "${O3K_FAKE_IP_OWNED_LEAK:-false}" == true ]]; then
    echo '3: o3k-tap-leak: <BROADCAST> mtu 1500 state UP'
fi
if [[ "${O3K_FAKE_IP_UNSTABLE:-false}" == true ]]; then
    counter_file="${O3K_FAKE_IP_COUNTER:?}"
    count=0
    [[ -f "${counter_file}" ]] && count="$(<"${counter_file}")"
    count=$((count + 1))
    printf '%s\n' "${count}" >"${counter_file}"
    echo "${count}: unstable0: <BROADCAST> mtu 1500 state UP"
fi
SH
chmod +x "${FAKE_BIN}/ip"
cat >"${FAKE_BIN}/openstack" <<'SH'
#!/usr/bin/env bash
if [[ "${O3K_FAKE_OPENSTACK_FAILURE:-false}" == true ]]; then
    echo 'Authorization: Bearer password=should-not-appear' >&2
    exit 1
fi
if [[ "$*" == flavor\ list\ * ]]; then
    if [[ "${O3K_FAKE_OPENSTACK_LEAK:-false}" == true ]]; then
        echo '[{"ID":"leaked-openstack-resource","Name":"o3k-testlab-flavor"}]'
    else
        echo '[]'
    fi
    exit 0
fi
if [[ "$*" == *" list "* && "${O3K_FAKE_OPENSTACK_LEAK:-false}" == true ]]; then
    case "$*" in
        server\ list\ *) name=o3k-testlab-server ;;
        image\ list\ *) name=o3k-testlab-image ;;
        network\ list\ *) name=o3k-testlab-network ;;
        subnet\ list\ *) name=o3k-testlab-subnet ;;
        *) name=o3k-testlab-flavor ;;
    esac
    printf '[{"ID":"leaked-openstack-resource","Name":"%s"}]\n' "$name"
    exit 0
fi
if [[ "$*" == *" list "* ]]; then
    echo '[]'
    exit 0
fi
SH
chmod +x "${FAKE_BIN}/openstack"

export PATH="${FAKE_BIN}:${PATH}" O3K_REAL_HOST_ARTIFACT_DIR="${WORK_DIR}/artifacts"
export O3K_REAL_HOST_KVM_PATH=/dev/null GITHUB_REPOSITORY=o3kio/o3k
export GITHUB_EVENT_NAME=workflow_dispatch GITHUB_HEAD_REF= GITHUB_BASE_REF= GITHUB_REF=refs/heads/main
export GITHUB_OUTPUT="${WORK_DIR}/github-output" O3K_TEST_SECRET=do-not-upload-this-value
export O3K_REAL_HOST_OPENSTACK_INVENTORY=true OS_PASSWORD=fake-password
export O3K_REAL_HOST_PROTECTED_PATHS="${WORK_DIR}/protected-state.txt"
export O3K_REAL_HOST_WORKFLOW_RUN_ID=guard-run-1 O3K_REAL_HOST_WORKFLOW_RUN_ATTEMPT=1
export GITHUB_SHA=0123456789abcdef0123456789abcdef01234567
mkdir -p "${O3K_REAL_HOST_ARTIFACT_DIR}"
printf 'original protected state\n' >"${O3K_REAL_HOST_PROTECTED_PATHS}"
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/runner-capabilities.json" <<'PY'
import json, sys
json.dump({"artifact_type": "runner-capabilities", "schema_version": 1,
           "status": "passed", "redacted": True,
           "workflow_run_id": "guard-run-1", "workflow_run_attempt": "1",
           "source_commit": "0123456789abcdef0123456789abcdef01234567",
           "finished_at": 1},
          open(sys.argv[1], "w", encoding="utf-8"))
PY
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/disposable-testlab-bootstrap.json" <<'PY'
import json, sys
json.dump({"artifact_type": "disposable-testlab-bootstrap", "status": "passed",
           "provider": "agent", "redacted": True},
          open(sys.argv[1], "w", encoding="utf-8"))
PY

bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"
grep -qx 'ready=true' "${GITHUB_OUTPUT}"
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "ready" and value["redacted"] is True
assert set(value["inventory_baseline"]["openstack"]["resources"]) == {
    "server", "image", "network", "subnet", "flavor"
}
assert "do-not-upload-this-value" not in json.dumps(value)
assert "environment_variables" not in value
assert value["inventory_baseline"]["foreign_state"]["protected_paths_sha256"]
assert value["inventory_baseline"]["network_links"] == []
PY

python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/disposable-testlab-bootstrap.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["provider"] = "fake"
json.dump(value, open(path, "w", encoding="utf-8"))
PY
if bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"; then
    echo "fake provider was accepted for real-host evidence" >&2
    exit 1
fi
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "blocked"
assert value["reason"] == "provider_mode_not_agent"
assert value["provider"] == "fake"
PY
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/disposable-testlab-bootstrap.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["provider"] = "agent"
json.dump(value, open(path, "w", encoding="utf-8"))
PY

unset O3K_REAL_HOST_PROTECTED_PATHS
if bash "${ROOT_DIR}/scripts/real-host-owned-inventory.sh" "${WORK_DIR}/missing-protected-paths.json"; then
    echo "missing protected-path configuration was accepted" >&2
    exit 1
fi
export O3K_REAL_HOST_PROTECTED_PATHS="${WORK_DIR}/protected-state.txt"

export O3K_FAKE_OPENSTACK_FAILURE=true
if bash "${ROOT_DIR}/scripts/real-host-owned-inventory.sh" "${WORK_DIR}/failed-openstack.json"; then
    echo "failed OpenStack inventory was accepted" >&2
    exit 1
fi
python3 - "${WORK_DIR}/failed-openstack.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "unavailable"
assert value["reason"] == "command_failed:openstack:server:list:unknown"
assert "should-not-appear" not in json.dumps(value)
assert "Authorization" not in json.dumps(value)
PY
unset O3K_FAKE_OPENSTACK_FAILURE

unset OS_PASSWORD
if bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"; then
    echo "requested OpenStack inventory without credentials was accepted" >&2
    exit 1
fi
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "blocked"
assert value["reason"] == "owned_inventory_unavailable"
PY
export OS_PASSWORD=fake-password

export O3K_FAKE_IP_UNSTABLE=true O3K_FAKE_IP_COUNTER="${WORK_DIR}/ip-counter"
if bash "${ROOT_DIR}/scripts/real-host-owned-inventory.sh" "${WORK_DIR}/unstable.json"; then
    echo "unstable inventory was accepted" >&2
    exit 1
fi
python3 - "${WORK_DIR}/unstable.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "unavailable" and value["reason"] == "inventory_not_stable"
PY
unset O3K_FAKE_IP_UNSTABLE O3K_FAKE_IP_COUNTER

python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/runner-capabilities.json" <<'PY'
import json, sys
json.dump({"artifact_type": "runner-capabilities", "schema_version": 1,
           "status": "failed", "reason": "runner_labels_mismatch", "redacted": True,
           "workflow_run_id": "guard-run-1", "workflow_run_attempt": "1",
           "source_commit": "0123456789abcdef0123456789abcdef01234567",
           "finished_at": 1},
          open(sys.argv[1], "w", encoding="utf-8"))
PY
: >"${GITHUB_OUTPUT}"
if bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"; then
    echo "failed capability probe was accepted" >&2
    exit 1
fi
if grep -q '^ready=true$' "${GITHUB_OUTPUT}"; then
    echo "failed capability probe marked guard ready" >&2
    exit 1
fi
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value == {"artifact_type": "real-host-workflow-result",
                 "status": "blocked", "reason": "capability_probe_failed",
                 "redacted": True, "finished_at": value["finished_at"]}
PY

python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/runner-capabilities.json" <<'PY'
import json, sys
json.dump({"artifact_type": "runner-capabilities", "schema_version": 1,
           "status": "passed", "redacted": True,
           "workflow_run_id": "guard-run-1", "workflow_run_attempt": "1",
           "source_commit": "0123456789abcdef0123456789abcdef01234567",
           "finished_at": 1},
          open(sys.argv[1], "w", encoding="utf-8"))
PY

export GITHUB_REPOSITORY=attacker/o3k-rust
if bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"; then
    echo "non-canonical repository was accepted" >&2
    exit 1
fi
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "blocked" and value["reason"] == "non_canonical_repository"
PY

export GITHUB_REPOSITORY=o3kio/o3k
export GITHUB_REF=refs/heads/feature-untrusted
if bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"; then
    echo "non-main source ref was accepted" >&2
    exit 1
fi
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "blocked" and value["reason"] == "untrusted_source_ref"
PY
export GITHUB_REF=refs/heads/main

export O3K_FAKE_VIRSH_DIRTY=true
if bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"; then
    echo "pre-existing owned resource was accepted" >&2
    exit 1
fi
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "blocked" and value["reason"] == "baseline_not_clean"
assert "do-not-upload-this-value" not in json.dumps(value)
PY
unset O3K_FAKE_VIRSH_DIRTY
bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"

export O3K_FAKE_VIRSH_STALE_P157=true O3K_FAKE_VIRSH_STALE_STATE="${WORK_DIR}/stale-p157-state"
rm -f -- "${O3K_FAKE_VIRSH_STALE_STATE}"
bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"
test -f "${O3K_FAKE_VIRSH_STALE_STATE}"
unset O3K_FAKE_VIRSH_STALE_P157 O3K_FAKE_VIRSH_STALE_STATE

export O3K_FAKE_VIRSH_STALE_P157_UNOWNED=true O3K_FAKE_VIRSH_STALE_STATE="${WORK_DIR}/stale-p157-unowned-state"
rm -f -- "${O3K_FAKE_VIRSH_STALE_STATE}"
if bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"; then
    echo "unowned P15.7-shaped domain unexpectedly passed the baseline guard" >&2
    exit 1
fi
test ! -e "${O3K_FAKE_VIRSH_STALE_STATE}"
unset O3K_FAKE_VIRSH_STALE_P157_UNOWNED O3K_FAKE_VIRSH_STALE_STATE
bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"

python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/libvirt-result.json" <<'PY'
import json, sys
json.dump({"status": "passed", "redacted": True}, open(sys.argv[1], "w", encoding="utf-8"))
PY
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/compute-agent-process-mtls-result.json" <<'PY'
import json, sys
json.dump({
    "artifact_type": "compute-agent-process-mtls",
    "status": "passed",
    "redacted": True,
    "scope": "o3kd-compute-service-to-scheduler-to-agent-to-libvirt",
    "evidence": {
        "command": "inspect",
        "command_state": "accepted",
        "operation_state": "succeeded",
        "observation_state": "running",
        "observation_operation_state": "succeeded",
        "resource_source": "real-lifecycle-server",
        "redacted": True,
        "transitions": ["accepted", "operation_succeeded", "observation_succeeded"],
        "transport": "mutual_tls",
    },
}, open(sys.argv[1], "w", encoding="utf-8"))
PY
export O3K_REAL_HOST_WORKFLOW_STEP_STATUS=success
bash "${ROOT_DIR}/scripts/real-host-post-run-guard.sh"
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
val = json.load(open(sys.argv[1], encoding="utf-8"))
assert val["status"] == "passed", f"Line 255 failed, val={val}"
PY
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/resource-leak-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["artifact_type"] == "resource-leak-result"
assert value["status"] == "passed"
PY

# The overall guard must not turn a failed P15.7 journey into a green workflow.
bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/p15-7-gate-result.json" <<'PY'
import json, sys
json.dump({"artifact_type": "o3k-p15-7-gate-result", "status": "failed",
           "reason": "evidence_validation_failed", "redacted": True},
          open(sys.argv[1], "w", encoding="utf-8"))
PY
export O3K_REAL_HOST_P15_7_STEP_STATUS=failure
if bash "${ROOT_DIR}/scripts/real-host-post-run-guard.sh"; then
    echo "failed P15.7 gate was accepted as workflow pass" >&2
    exit 1
fi
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed" and value["reason"] == "p15_7_gate_failed", value
assert value["p15_7_step_status"] == "failure"
assert value["p15_7_status"] == "failed"
PY
unset O3K_REAL_HOST_P15_7_STEP_STATUS
rm -f "${O3K_REAL_HOST_ARTIFACT_DIR}/p15-7-gate-result.json"

# schema_version 3 snapshots (extended inventory) are accepted by both guards
V3_ROOT="${WORK_DIR}/v3-state"
mkdir -p "${V3_ROOT}/data/dhcp"
printf '{"config": null, "bindings": {}}\n' >"${V3_ROOT}/data/dhcp/state.json"
for migration in "${ROOT_DIR}"/crates/o3k-store/migrations/*.sql; do
    sqlite3 "${V3_ROOT}/data/o3k.sqlite" <"${migration}"
done
export O3K_REAL_HOST_STATE_ROOT="${V3_ROOT}"
bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
baseline = value["inventory_baseline"]
assert baseline["schema_version"] == 3, baseline.get("schema_version")
assert baseline["status"] == "available", baseline
assert baseline["managed_state"]["status"] == "available", baseline["managed_state"]
assert baseline["durable"]["status"] == "available", baseline["durable"]
assert baseline["dhcp"]["status"] == "available", baseline["dhcp"]
PY
bash "${ROOT_DIR}/scripts/real-host-post-run-guard.sh"
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/resource-leak-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "passed", value
PY
unset O3K_REAL_HOST_STATE_ROOT

export O3K_REAL_HOST_WORKFLOW_STEP_STATUS=success
bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"
printf 'mutated protected state\n' >"${O3K_REAL_HOST_PROTECTED_PATHS}"
export O3K_FAKE_VIRSH_DIRTY=true O3K_FAKE_OPENSTACK_LEAK=true O3K_FAKE_IP_DIRTY=true O3K_FAKE_IP_OWNED_LEAK=true
if bash "${ROOT_DIR}/scripts/real-host-post-run-guard.sh"; then
    echo "owned resource leak was accepted" >&2
    exit 1
fi
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed" and value["reason"] == "resource_leak_detected"
assert "o3k-preexisting-domain" in value["leaks"]["domains"]
assert "o3k-tap-leak" in value["leaks"]["network_links"]
assert "leaked-openstack-resource" in value["leaks"]["openstack"]["image"]
assert "leaked-openstack-resource" in value["leaks"]["openstack"]["flavor"]
assert value["foreign_state_changed"] is True
assert "foreign0" not in json.dumps(value)
assert "do-not-upload-this-value" not in json.dumps(value)
PY
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/resource-leak-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed"
assert value["foreign_state_changed"] is True
PY
unset O3K_FAKE_VIRSH_DIRTY O3K_FAKE_OPENSTACK_LEAK O3K_FAKE_IP_DIRTY O3K_FAKE_IP_OWNED_LEAK

python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/runner-capabilities.json" <<'PY'
import json, sys
value = {"artifact_type": "runner-capabilities", "schema_version": 1,
         "status": "passed", "redacted": True, "finished_at": 1,
         "workflow_run_id": "old-run", "workflow_run_attempt": "1",
         "source_commit": "0123456789abcdef0123456789abcdef01234567"}
json.dump(value, open(sys.argv[1], "w", encoding="utf-8"))
PY
if bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"; then
    echo "stale capability artifact was accepted" >&2
    exit 1
fi
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "blocked"
assert value["reason"] == "capability_probe_unavailable"
PY

python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/runner-capabilities.json" <<'PY'
import json, sys
json.dump({"artifact_type": "runner-capabilities", "schema_version": 1,
           "status": "passed", "redacted": True, "finished_at": 1,
           "workflow_run_id": "guard-run-1", "workflow_run_attempt": "1",
           "source_commit": "0123456789abcdef0123456789abcdef01234567"},
          open(sys.argv[1], "w", encoding="utf-8"))
PY

python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/libvirt-result.json" <<'PY'
import json, sys
json.dump({"status": "skipped", "redacted": True}, open(sys.argv[1], "w", encoding="utf-8"))
PY
bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"
if bash "${ROOT_DIR}/scripts/real-host-post-run-guard.sh"; then
    echo "skipped lifecycle was accepted as a pass" >&2
    exit 1
fi
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data.get("status") == "skipped", f"Expected skipped, got {data}"
PY

bash "${ROOT_DIR}/scripts/real-host-pre-run-guard.sh"
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/libvirt-result.json" <<'PY'
import json, sys
json.dump({"status": "passed", "redacted": True}, open(sys.argv[1], "w", encoding="utf-8"))
PY
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/compute-agent-process-mtls-result.json" <<'PY'
import json, sys
json.dump({"artifact_type": "compute-agent-process-mtls", "status": "failed",
           "reason": "process_probe_failed_test", "redacted": True},
          open(sys.argv[1], "w", encoding="utf-8"))
PY
export O3K_REAL_HOST_WORKFLOW_STEP_STATUS=success
if bash "${ROOT_DIR}/scripts/real-host-post-run-guard.sh"; then
    echo "failed compute agent process probe was accepted as workflow pass" >&2
    exit 1
fi
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/real-host-workflow-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value.get("status") == "failed", f"Expected failed status, got {value}"
assert value.get("reason") == "compute_agent_process_probe_failed", f"Expected probe failed reason, got {value}"
PY
python3 - "${O3K_REAL_HOST_ARTIFACT_DIR}/resource-leak-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value.get("status") == "passed", f"Expected passed leak status, got {value}"
assert value.get("reason") == "no_resource_leak_detected", f"Expected no leak reason, got {value}"
PY

python3 - "${ROOT_DIR}/.github/workflows/real-host-validation.yml" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
preflight_text = pathlib.Path(sys.argv[1]).with_name("p15-7-protected-preflight.yml").read_text(encoding="utf-8")
for needle in ("P15.7 protected preflight", "id-token: write",
               "scripts/p15-7-protected-preflight.sh", "target_sha:",
               "if-no-files-found: error",
               '"${GITHUB_WORKSPACE}/target/lvm-real-guest-artifacts"'):
    assert needle in preflight_text, needle
workflow_step = text.split("      - name: Run public real-host lifecycle\n", 1)[1]
workflow_step = workflow_step.split("        run: bash tests/testlab-libvirt.sh\n", 1)[0]
assert "          OS_PASSWORD:" not in workflow_step
for needle in ("workflow_dispatch:",
               "runs-on: [self-hosted, linux, x64, kvm, libvirt, o3k-testlab]",
               "cancel-in-progress: false", "environment: o3k-real-host-validation",
               "Allocate run-scoped TestLab ports", "O3K_TESTLAB_COMPUTE_HEALTH_PORT",
               "Bootstrap disposable TestLab",
               "scripts/bootstrap-disposable-testlab.sh",
               "O3K_PROVIDER: agent",
               "O3K_AGENT_INSPECT_PROBE_RESOURCE_FILE:",
               "scripts/cleanup-disposable-testlab.sh",
               "disposable-testlab-bootstrap.json",
               "Probe runner capabilities", "runner-capabilities.json",
               "Download and verify CirrOS image",
               "CIRROS_IMAGE_SHA256: 7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b",
               "sha256sum --check --strict --status",
               "O3K_TESTLAB_IMAGE_PATH=",
               "continue-on-error: true", "timeout-minutes: 120",
               "contents: read",
               "if: always()", "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
               "retention-days: 14",
               "target/real-host-workflow-artifacts/console-result.json",
               "Run compute-agent process-boundary evidence",
               "tests/real-compute-agent-process-mtls.sh",
               "compute-agent-process-mtls-result.json",
               "Run P15.7 scale/composition convergence gate",
               "tests/p15_7_scale_composition.sh",
               "Protected P15.7 authority and capacity preflight",
               "scripts/p15-7-protected-preflight.sh",
               "O3K_P15_7_OPERATOR_EXCHANGE_COMMAND:",
               "O3K_P15_7_OIDC_ISSUER:",
               "O3K_P15_7_OIDC_AUDIENCE:",
               "O3K_P15_7_OIDC_DISCOVERY_URL:",
               "O3K_P15_7_REAL_HOST: \"1\"",
               "O3K_P15_7_PROFILE: small-edge-cloud",
               "O3K_P15_7_OPERATOR_TOKEN_FILE",
               "O3K_P15_7_JOURNEY_COMMAND:",
               "p15-7-scale-composition-evidence.json",
               "p15-7-gate-result.json",
               "O3K_REAL_HOST_P15_7_STEP_STATUS:",
               "Install pinned P13.4 provider tools and build runtime",
               "scripts/ci/apt-provision.sh install unzip",
               "scripts/p13_2_provider_tools.sh",
               "OpenTofu v1.12.6",
               "2840ef5e25598f85591cf984825a8a19b9de498782cfe253e6d3e78740fbd5dc",
               "Provision disposable tagged P13.4 LVM profile",
               "scripts/lvm-testlab-profile.sh provision",
               "Run P13.4 native Volume provider gate",
               "tests/p13_4_provider_volume_smoke.sh",
               "O3K_LVM_VOLUME_GROUP",
               "Run P13.4 VolumeAttachment provider gate",
               "tests/p13_4_provider_volume_attachment_smoke.sh",
               "Run P13.4 storage recovery and fencing tests",
               "Start disposable P13.4 PostgreSQL",
               "-p o3k-store --test postgres_p13_4_storage",
               "Run P13.4 real LVM/libvirt guest gate",
               "scripts/real-lvm-guest-gate.sh",
               "p13-4-storage-evidence.json",
               "lvm-real-guest-result.json",
               "Stop storage-phase disposable TestLab",
               "Prepare fresh generic TestLab image",
               "phase=generic",
               "steps.generic_image.outcome == 'success'",
               "Bootstrap fresh generic TestLab",
               "Fresh generic TestLab pre-run guard",
               "steps.generic_guard.outputs.ready == 'true'"):
    assert needle in text, needle
assert "Repair prior protected artifact ownership" in text
assert 'sudo -n chown -R "$(id -u):$(id -g)"' in text
assert '"${GITHUB_WORKSPACE}/target/debug"' in text
assert "github.repository == 'o3kio/o3k'" in text
assert "github.event_name == 'workflow_dispatch'" in text
assert "github.ref == 'refs/heads/main' || inputs.target_sha != ''" in text
assert "ref: ${{ inputs.target_sha || github.sha }}" in text
assert "persist-credentials: false" in text
assert "Verify immutable source checkout" in text
assert text.index("Verify immutable source checkout") < text.index("Protected P15.7 authority and capacity preflight")
assert text.index("Protected P15.7 authority and capacity preflight") < text.index("Bootstrap disposable TestLab")
assert "if: always() && steps.protected_preflight.outcome == 'success'" in text
assert text.count("if: always() && steps.protected_preflight.outcome == 'success'") >= 5
assert "id-token: write" in text
assert "O3K_P15_7_OPERATOR_TOKEN:" not in text
assert "p15-7-postgres-ownership.json" in text
# The embedded ownership JSON must start at column zero after YAML block
# scalar dedentation; retaining the shell indentation makes Python fail before
# the generic TestLab and falsely blocks the protected journey.
assert re.search(r"p15-7-postgres-ownership\.json <<'PY'\n          import json, subprocess, sys", text)
assert not re.search(r"p15-7-postgres-ownership\.json <<'PY'\n\s{12}import json, subprocess, sys", text)
assert "--label o3k.owner=o3k" in text
assert "container_id" in text
assert "target/real-host-workflow-artifacts/console.log" not in text
assert "target/real-host-workflow-artifacts/server-show.json" not in text
p15_image_step = text.split("      - name: Prepare pinned P15.7 VM host image\n", 1)[1]
p15_image_step = p15_image_step.split("      - name: Run P15.7 scale/composition convergence gate\n", 1)[0]
# Large owned images are tracked by their marker and exact cleanup path. They
# must not enter the protected-path inventory, whose bounded file-size policy
# is intentionally fail-closed.
assert "O3K_REAL_HOST_PROTECTED_PATHS" not in p15_image_step
assert "if: steps.protected_preflight.outcome == 'success' && steps.guard.outputs.ready == 'true'" in text
assert "test \"${outcome}\" = success" in text
assert pathlib.Path(sys.argv[1]).parents[2].joinpath("scripts/real-host-owned-inventory.sh").exists()
post_guard = pathlib.Path(sys.argv[1]).parents[2].joinpath("scripts/real-host-post-run-guard.sh").read_text(encoding="utf-8")
assert "compute-agent-process-mtls-result.json" in post_guard
assert "compute_agent_process_probe_failed" in post_guard
assert "p15-7-gate-result.json" in post_guard
assert "p15_7_gate_failed" in post_guard
assert "p15_7_gate_blocked" in post_guard
o3kd = pathlib.Path(sys.argv[1]).parents[2].joinpath("bins/o3kd/src/composition/compute.rs").read_text(encoding="utf-8")
probe = o3kd.split("async fn run_agent_inspect_probe(", 1)[1]
assert ".inspect_server(" in probe
assert "registry.dispatch_command" not in probe
assert "o3kd-compute-service-to-scheduler-to-agent-to-libvirt" in probe
PY
echo "real-host workflow guard tests passed"
