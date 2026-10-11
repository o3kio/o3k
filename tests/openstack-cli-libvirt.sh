#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${O3K_TESTLAB_ARTIFACT_DIR:-${ROOT_DIR}/target/testlab-artifacts}"
DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-cli.XXXXXX")"
mkdir -p "${ARTIFACT_DIR}"
rm -f "${ARTIFACT_DIR}/openstack-cli-result.json" "${ARTIFACT_DIR}/openstack-cli-error.log" \
    "${ARTIFACT_DIR}/server-show.json" "${ARTIFACT_DIR}/server-list.json" \
    "${ARTIFACT_DIR}/server-show-after-reboot.json" \
    "${ARTIFACT_DIR}/console.log" "${ARTIFACT_DIR}/console-error.log" \
    "${ARTIFACT_DIR}/console-result.json"
IMAGE_ID=
KEYPAIR_ID=
NETWORK_ID=
SUBNET_ID=
PORT_ID=
FLAVOR_ID=
SERVER_ID=
CREATED_IMAGE_ID=
CREATED_KEYPAIR_ID=
CREATED_NETWORK_ID=
CREATED_SUBNET_ID=
CREATED_PORT_ID=
CREATED_FLAVOR_ID=
CREATED_SERVER_ID=
CLEANUP_IMAGE_STATUS=
CLEANUP_KEYPAIR_STATUS=
CLEANUP_NETWORK_STATUS=
CLEANUP_SUBNET_STATUS=
CLEANUP_PORT_STATUS=
CLEANUP_FLAVOR_STATUS=
CLEANUP_SERVER_STATUS=
RESOURCE_SUFFIX="${O3K_TESTLAB_RESOURCE_SUFFIX:-}"
if [[ -n "${RESOURCE_SUFFIX}" && ! "${RESOURCE_SUFFIX}" =~ ^[A-Za-z0-9-]+$ ]]; then
    echo "O3K_TESTLAB_RESOURCE_SUFFIX contains unsafe characters" >&2
    exit 2
fi
name_with_suffix() {
    local base="$1"
    [[ -n "${RESOURCE_SUFFIX}" ]] && printf '%s-%s' "$base" "$RESOURCE_SUFFIX" || printf '%s' "$base"
}
SERVER_NAME="$(name_with_suffix o3k-testlab-server)"
EXPECTED_FIXED_IP=192.0.2.2
CONFIG_DRIVE_ENABLED="${O3K_TESTLAB_CONFIG_DRIVE:-true}"
case "${CONFIG_DRIVE_ENABLED}" in
    true|false) ;;
    *) echo "O3K_TESTLAB_CONFIG_DRIVE must be true or false" >&2; exit 2 ;;
esac
if [[ "${CONFIG_DRIVE_ENABLED}" == true ]]; then
    CONFIG_DRIVE_ARGS=(--config-drive true)
else
    CONFIG_DRIVE_ARGS=(--no-config-drive)
fi
SERVER_ACTIVE=false
SERVER_CONFIG_DRIVE=false
SERVER_FIXED_IP=
CONSOLE_BOOT_MARKER=false
CONSOLE_POLL_ATTEMPTS=0
CONSOLE_POLL_SUCCEEDED=false
SERVER_RESTART_ACTIVE=false
SERVER_RESTART_CONFIG_DRIVE=false
SERVER_RESTART_FIXED_IP=

validate_server_json() {
    local kind="$1" path="$2" expected_id="$3"
    python3 - "${kind}" "${path}" "${expected_id}" "${EXPECTED_FIXED_IP}" "${CONFIG_DRIVE_ENABLED}" <<'PY'
import json
import sys

kind, path, expected_id, expected_fixed_ip, expected_config_drive = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    value = json.load(stream)

if kind == "show":
    if not isinstance(value, dict) or str(value.get("id", "")) != expected_id:
        raise SystemExit("server show did not identify the created server")
    if str(value.get("status", "")).upper() != "ACTIVE":
        raise SystemExit("server show did not prove ACTIVE state")
    config_drive = value.get("config_drive")
    config_drive_enabled = config_drive in {True, "True", "true", 1}
    if config_drive_enabled != (expected_config_drive == "true"):
        raise SystemExit("server show did not match requested config-drive state")
    addresses = []
    def collect(node):
        if isinstance(node, dict):
            if "addr" in node:
                addresses.append(str(node["addr"]))
            for child in node.values():
                collect(child)
        elif isinstance(node, list):
            for child in node:
                collect(child)
        elif isinstance(node, str):
            addresses.append(node)
    collect(value.get("addresses", {}))
    if expected_fixed_ip not in addresses:
        raise SystemExit("server show did not prove the expected fixed IP")
elif kind == "list":
    rows = value if isinstance(value, list) else (
        value.get("servers", []) if isinstance(value, dict) else []
    )
    if not any(
        isinstance(row, dict)
        and next(
            (str(item) for key, item in row.items() if str(key).lower() == "id"),
            "",
        )
        == expected_id
        for row in rows
    ):
        raise SystemExit("server list did not contain the created server")
else:
    raise SystemExit(f"unknown server JSON validation kind: {kind}")
PY
}

validate_server_absent_list() {
    local path="$1" expected_id="$2"
    python3 - "${path}" "${expected_id}" <<'PY'
import json
import sys

path, expected_id = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    value = json.load(stream)
if not isinstance(value, list):
    raise SystemExit("server list response is not an array")
if any(isinstance(row, dict) and str(row.get("id", "")) == expected_id for row in value):
    raise SystemExit("server list still contains the deleted server")
PY
}

write_console_result() {
    local status="$1" reason="$2" marker_found="${3:-false}"
    python3 - "${ARTIFACT_DIR}/console-result.json" "${status}" "${reason}" \
        "${marker_found}" "${CONSOLE_POLL_ATTEMPTS}" \
        "${O3K_TESTLAB_CONSOLE_ATTEMPTS:-30}" <<'PY'
import json
import os
import sys
import tempfile
import time

path, status, reason, marker_found, attempts, max_attempts = sys.argv[1:]
directory = os.path.dirname(path)
fd, temporary = tempfile.mkstemp(prefix="console-result.", suffix=".tmp", dir=directory)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump({
            "artifact_type": "openstack-cli-console-result",
            "status": status,
            "assertion": "cirros_boot_marker",
            "marker_found": marker_found == "true",
            "polling": {
                "attempts": int(attempts),
                "max_attempts": int(max_attempts),
            },
            "reason": reason,
            "redacted": True,
            "finished_at": int(time.time()),
        }, output, indent=2, sort_keys=True)
        output.write("\n")
    os.replace(temporary, path)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PY
}

console_request() {
    local server_id="$1" output_path="$2" timeout_seconds="${O3K_TESTLAB_CONSOLE_REQUEST_TIMEOUT_SECONDS:-15}"
    local status

    # Use a dedicated Python process because it can create and terminate the
    # complete client session without ever signaling this lifecycle shell.
    if python3 - "${server_id}" "${output_path}" \
        "${ARTIFACT_DIR}/console-error.log" "${timeout_seconds}" <<'PY'
import os
import signal
import subprocess
import sys

server_id, output_path, error_path, timeout_seconds = sys.argv[1:]
with open(output_path, "wb") as output, open(error_path, "wb") as error:
    process = subprocess.Popen(
        ["openstack", "console", "log", "show", server_id],
        stdout=output,
        stderr=error,
        start_new_session=True,
    )
    try:
        process.wait(timeout=float(timeout_seconds))
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise SystemExit(124)
    raise SystemExit(process.returncode)
PY
    then
        status=0
    else
        status=$?
    fi
    return "${status}"
}

wait_for_server_status() {
    local server_id="$1" wanted="$2" attempts="${3:-30}"
    local status
    for _ in $(seq 1 "${attempts}"); do
        status="$(openstack server show "${server_id}" -f value -c status 2>/dev/null || true)"
        [[ "${status}" == "${wanted}" ]] && return 0
        [[ "${status}" == "ERROR" ]] && return 1
        sleep 2
    done
    return 1
}

server_is_absent() {
    local server_id="$1"
    local show_error="${DATA_DIR}/server-delete-show.error"
    local list_output="${DATA_DIR}/server-delete-list.json"
    local list_error="${DATA_DIR}/server-delete-list.error"

    if openstack server show "${server_id}" -f json \
        >"${DATA_DIR}/server-delete-show.json" 2>"${show_error}"; then
        return 1
    fi
    if grep -Eiq 'not[ -]?found|could not find|no server|404' "${show_error}"; then
        return 0
    fi
    if ! openstack server list --name "${SERVER_NAME}" -f json \
        >"${list_output}" 2>"${list_error}"; then
        return 1
    fi
    validate_server_absent_list "${list_output}" "${server_id}"
}

resource_is_absent() {
    local resource="$1" resource_id="$2"
    local show_output="${DATA_DIR}/${resource}-delete-show.json"
    local show_error="${DATA_DIR}/${resource}-delete-show.error"

    if openstack "${resource}" show "${resource_id}" -f json \
        >"${show_output}" 2>"${show_error}"; then
        return 1
    fi
    grep -Eiq 'not[ -]?found|could not find|no .*found|404' "${show_error}"
}

delete_resource_and_verify_absent() {
    local resource="$1" resource_id="$2"
    # A failed delete has an unknown outcome. Always observe before deciding
    # that cleanup failed; a timeout may have removed the resource already.
    openstack "${resource}" delete "${resource_id}" >/dev/null 2>&1 || true
    if resource_is_absent "${resource}" "${resource_id}"; then
        case "${resource}" in
            image) CLEANUP_IMAGE_STATUS=verified_absent ;;
            keypair) CLEANUP_KEYPAIR_STATUS=verified_absent ;;
            network) CLEANUP_NETWORK_STATUS=verified_absent ;;
            subnet) CLEANUP_SUBNET_STATUS=verified_absent ;;
            port) CLEANUP_PORT_STATUS=verified_absent ;;
            flavor) CLEANUP_FLAVOR_STATUS=verified_absent ;;
        esac
        return 0
    fi
    case "${resource}" in
        image) CLEANUP_IMAGE_STATUS=not_verified ;;
        keypair) CLEANUP_KEYPAIR_STATUS=not_verified ;;
        network) CLEANUP_NETWORK_STATUS=not_verified ;;
        subnet) CLEANUP_SUBNET_STATUS=not_verified ;;
        port) CLEANUP_PORT_STATUS=not_verified ;;
        flavor) CLEANUP_FLAVOR_STATUS=not_verified ;;
    esac
    return 1
}

cleanup_resources() {
    local cleanup_ok=1
    if [[ -n "${SERVER_ID}" ]]; then
        local server_deleted=false
        # Delete has an unknown outcome if the API request times out or the
        # provider is still converging. Retry while observing absence so a
        # transient Nova/libvirt state does not strand the VM and its domain.
        for _ in {1..15}; do
            openstack server delete --wait "${SERVER_ID}" >/dev/null 2>&1 || true
            if server_is_absent "${SERVER_ID}"; then
                server_deleted=true
                break
            fi
            sleep 2
        done
        if [[ "${server_deleted}" != true ]]; then
            CLEANUP_SERVER_STATUS=not_verified
            cleanup_ok=0
        else
            CLEANUP_SERVER_STATUS=verified_absent
            SERVER_ID=
        fi
    fi
    if [[ -n "${FLAVOR_ID}" ]]; then
        if delete_resource_and_verify_absent flavor "${FLAVOR_ID}"; then
            FLAVOR_ID=
        else
            cleanup_ok=0
        fi
    fi
    if [[ -n "${PORT_ID}" ]]; then
        if delete_resource_and_verify_absent port "${PORT_ID}"; then
            PORT_ID=
        else
            cleanup_ok=0
        fi
    fi
    if [[ -n "${KEYPAIR_ID}" ]]; then
        if delete_resource_and_verify_absent keypair "${KEYPAIR_ID}"; then
            KEYPAIR_ID=
        else
            cleanup_ok=0
        fi
    fi
    if [[ -n "${SUBNET_ID}" ]]; then
        if delete_resource_and_verify_absent subnet "${SUBNET_ID}"; then
            SUBNET_ID=
        else
            cleanup_ok=0
        fi
    fi
    if [[ -n "${NETWORK_ID}" ]]; then
        if delete_resource_and_verify_absent network "${NETWORK_ID}"; then
            NETWORK_ID=
        else
            cleanup_ok=0
        fi
    fi
    if [[ -n "${IMAGE_ID}" ]]; then
        if delete_resource_and_verify_absent image "${IMAGE_ID}"; then
            IMAGE_ID=
        else
            cleanup_ok=0
        fi
    fi
    return "$((1 - cleanup_ok))"
}

write_result() {
    local status="$1" reason="$2" cleanup_status="${3:-not_run}"
    python3 - "${ARTIFACT_DIR}/openstack-cli-result.json" "${status}" "${reason}" "${cleanup_status}" \
        "${CREATED_IMAGE_ID}" "${CREATED_NETWORK_ID}" "${CREATED_SUBNET_ID}" \
        "${CREATED_PORT_ID}" \
        "${CREATED_KEYPAIR_ID}" "${CREATED_FLAVOR_ID}" "${CREATED_SERVER_ID}" \
        "${CLEANUP_IMAGE_STATUS}" "${CLEANUP_KEYPAIR_STATUS}" "${CLEANUP_NETWORK_STATUS}" \
        "${CLEANUP_SUBNET_STATUS}" "${CLEANUP_FLAVOR_STATUS}" \
        "${CLEANUP_PORT_STATUS}" \
        "${CLEANUP_SERVER_STATUS}" "${SERVER_ACTIVE}" "${SERVER_CONFIG_DRIVE}" \
        "${SERVER_FIXED_IP}" "${CONSOLE_BOOT_MARKER}" \
        "${SERVER_RESTART_ACTIVE}" "${SERVER_RESTART_CONFIG_DRIVE}" \
        "${SERVER_RESTART_FIXED_IP}" "${GITHUB_RUN_ID:-}" "${RESOURCE_SUFFIX}" <<'PY'
import json, sys, time
# Normative resource membership for the openstack-cli-e2e artifact; must stay
# in sync with contracts/release-e2e-evidence.schema.json (enforced by
# tests/release-e2e-evidence.sh). Values pair positionally with these tuples.
RESOURCE_KEYS = ("image_id", "keypair_id", "network_id", "subnet_id", "port_id", "flavor_id", "server_id")
CLEANUP_KEYS = ("image", "keypair", "network", "subnet", "port", "flavor", "server")
(
    path, status, reason, cleanup_status, image_id, network_id, subnet_id,
    port_id, keypair_id, flavor_id, server_id, image_status, keypair_status, network_status, subnet_status,
    flavor_status, port_status, server_status, server_active, server_config_drive,
    server_fixed_ip, console_boot_marker, restart_active, restart_config_drive,
    restart_fixed_ip, workflow_run_id, testlab_phase_id,
) = sys.argv[1:]
resource_values = (image_id, keypair_id, network_id, subnet_id, port_id, flavor_id, server_id)
cleanup_values = (image_status, keypair_status, network_status, subnet_status, port_status, flavor_status, server_status)
result = {
    "artifact_type": "openstack-cli-e2e",
    "status": status,
    "reason": reason,
    "profile": "libvirt",
    "public_api_only": True,
    "redacted": True,
    "cleanup": {"status": cleanup_status},
    "finished_at": int(time.time()),
}
if workflow_run_id:
    result["workflow_run_id"] = workflow_run_id
if testlab_phase_id:
    result["testlab_phase_id"] = testlab_phase_id
cleanup_resources = {
    name: value for name, value in zip(CLEANUP_KEYS, cleanup_values) if value
}
if cleanup_resources:
    result["cleanup"]["resources"] = cleanup_resources
resources = {
    name: value for name, value in zip(RESOURCE_KEYS, resource_values) if value
}
if resources:
    result["resources"] = resources
if status == "passed":
    result["lifecycle"] = {
        "create": True, "show": True, "list": True, "stop": True,
        "start": True, "reboot": True, "console": True, "delete": True,
    }
    result["acceptance"] = {
        "status": "ACTIVE" if server_active == "true" else "unknown",
        "fixed_ip": server_fixed_ip,
        "config_drive": server_config_drive == "true",
        "console_boot_marker": console_boot_marker == "true",
        "restart": {
            "status": "ACTIVE" if restart_active == "true" else "unknown",
            "fixed_ip": restart_fixed_ip,
            "config_drive": restart_config_drive == "true",
        },
    }
with open(path, "w", encoding="utf-8") as output:
    json.dump(result, output, indent=2)
    output.write("\n")
PY
}

on_exit() {
    local exit_code="$?"
    if ((exit_code != 0)); then
        if [[ -f "${ARTIFACT_DIR}/console-result.json" ]] \
            && python3 - "${ARTIFACT_DIR}/console-result.json" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        result = json.load(stream)
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if result.get("status") == "pending" else 1)
PY
        then
            write_console_result failed "console polling interrupted before terminal evidence"
        fi
        local cleanup_status=passed
        cleanup_resources || cleanup_status=failed
        write_result failed "CLI workflow failed (exit ${exit_code})" "${cleanup_status}"
    fi
    rm -rf "${DATA_DIR}"
    exit "$exit_code"
}
trap on_exit EXIT

write_console_result pending "console polling not started"

for command in openstack curl; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        write_result skipped "missing command: ${command}"
        echo "OpenStack CLI workflow skipped: missing ${command}" >&2
        exit 0
    fi
done
if [[ "${O3K_TESTLAB_PROFILE:-libvirt}" != libvirt ]]; then
    write_result skipped "O3K_TESTLAB_PROFILE is not libvirt"
    exit 0
fi
IMAGE_PATH="${O3K_TESTLAB_IMAGE_PATH:-}"
if [[ -z "${IMAGE_PATH}" || ! -f "${IMAGE_PATH}" ]]; then
    write_result skipped "O3K_TESTLAB_IMAGE_PATH must point to a local guest image"
    echo "OpenStack CLI workflow skipped: configure O3K_TESTLAB_IMAGE_PATH" >&2
    exit 0
fi

# Use the OpenStack client's environment configuration directly. This avoids
# interpolating credentials and endpoint values into hand-written YAML, where
# colons, quotes, or newlines could change the parsed configuration.
# Preserve an explicitly configured disposable cloud profile.  The protected
# bootstrap supplies an Image v2 endpoint override because the native O3K
# catalog root does not advertise Cinder-style image API versions.  Standalone
# runs without a cloud profile continue to use the environment-variable
# defaults below.
if [[ -z "${OS_CLOUD:-}" && -z "${OS_CLIENT_CONFIG_FILE:-}" ]]; then
    unset OS_CLOUD OS_CLIENT_CONFIG_FILE
fi
export OS_AUTH_URL="${OS_AUTH_URL:-http://127.0.0.1:8080/v3}"
export OS_USERNAME="${OS_USERNAME:-admin}"
export OS_PROJECT_NAME="${OS_PROJECT_NAME:-eba29e2d-53de-461d-ae91-ede7402713cb}"
export OS_REGION_NAME="${OS_REGION_NAME:-RegionOne}"
export OS_USER_DOMAIN_NAME=Default OS_PROJECT_DOMAIN_NAME=Default
export OS_INTERFACE=public OS_IDENTITY_API_VERSION=3
if [[ -z "${OS_PASSWORD:-}" ]]; then
    write_result skipped "OS_PASSWORD is not configured"
    echo "OpenStack CLI workflow skipped: configure OS_PASSWORD" >&2
    exit 0
fi

if ! openstack token issue >/dev/null 2>&1; then
    write_result skipped "OpenStack endpoint is unavailable or authentication failed"
    echo "OpenStack CLI workflow skipped: endpoint/authentication unavailable" >&2
    exit 0
fi

# The remainder deliberately uses only OpenStack CLI calls. Resource IDs are
# captured in the redacted artifact; credentials and response bodies are not
# uploaded. The public CLI does not expose operation IDs here.
# CirrOS publishes this disk as qcow2. Preserve that format in Glance so the
# compute agent can build a qcow2 overlay with the correct backing format.
IMAGE_ID="$(openstack image create "$(name_with_suffix o3k-testlab-image)" --file "${IMAGE_PATH}" --disk-format qcow2 --container-format bare -f value -c id)"
CREATED_IMAGE_ID="${IMAGE_ID}"
CLEANUP_IMAGE_STATUS=pending
KEYPAIR_PUBLIC_KEY="${DATA_DIR}/o3k-testlab-keypair.pub"
KEYPAIR_NAME="$(name_with_suffix o3k-testlab-keypair)"
ssh-keygen -q -t ed25519 -N '' -C o3k-testlab -f "${DATA_DIR}/o3k-testlab-keypair" >/dev/null
chmod 0600 "${DATA_DIR}/o3k-testlab-keypair"
chmod 0644 "${KEYPAIR_PUBLIC_KEY}"
openstack keypair create --public-key "${KEYPAIR_PUBLIC_KEY}" "${KEYPAIR_NAME}" >/dev/null
KEYPAIR_ID="${KEYPAIR_NAME}"
CREATED_KEYPAIR_ID="${KEYPAIR_ID}"
CLEANUP_KEYPAIR_STATUS=pending
NETWORK_ID="$(openstack network create "$(name_with_suffix o3k-testlab-network)" -f value -c id)"
CREATED_NETWORK_ID="${NETWORK_ID}"
CLEANUP_NETWORK_STATUS=pending
SUBNET_ID="$(openstack subnet create --network "${NETWORK_ID}" --subnet-range 192.0.2.0/29 "$(name_with_suffix o3k-testlab-subnet)" -f value -c id)"
CREATED_SUBNET_ID="${SUBNET_ID}"
CLEANUP_SUBNET_STATUS=pending
PORT_ID="$(openstack port create --network "${NETWORK_ID}" "$(name_with_suffix o3k-testlab-port)" -f value -c id)"
CREATED_PORT_ID="${PORT_ID}"
CLEANUP_PORT_STATUS=pending
FLAVOR_ID="$(openstack flavor create "$(name_with_suffix o3k-testlab-flavor)" --ram 512 --disk 10 --vcpus 1 -f value -c id)"
CREATED_FLAVOR_ID="${FLAVOR_ID}"
CLEANUP_FLAVOR_STATUS=pending
# The public CLI's value formatter may include a leading/trailing blank line
# when a provider emits progress diagnostics.  Normalize only the UUID field
# before using it as a path/resource identity; never pass surrounding output
# through as an identifier.
SERVER_ID="$(openstack server create --wait --image "${IMAGE_ID}" --flavor "${FLAVOR_ID}" --key-name "${KEYPAIR_NAME}" "${CONFIG_DRIVE_ARGS[@]}" --nic "port-id=${PORT_ID}" "${SERVER_NAME}" -f value -c id | tr -d '[:space:]')"
[[ "${SERVER_ID}" =~ ^[0-9a-fA-F-]{36}$ ]] || {
    echo "OpenStack CLI returned an invalid server UUID" >&2
    exit 1
}
CREATED_SERVER_ID="${SERVER_ID}"
CLEANUP_SERVER_STATUS=pending
if [[ -n "${O3K_AGENT_INSPECT_PROBE_RESOURCE_FILE:-}" ]]; then
    [[ "${O3K_AGENT_INSPECT_PROBE_RESOURCE_FILE}" == /* \
        && "${O3K_AGENT_INSPECT_PROBE_RESOURCE_FILE}" != *..* ]] \
        || { echo "agent inspect probe resource file is invalid" >&2; exit 1; }
    printf '%s\n' "${SERVER_ID}" >"${O3K_AGENT_INSPECT_PROBE_RESOURCE_FILE}"
    chmod 0644 "${O3K_AGENT_INSPECT_PROBE_RESOURCE_FILE}"
    if [[ -n "${O3K_AGENT_INSPECT_SERVICE_RESOURCE_FILE:-}" ]]; then
        [[ "${O3K_AGENT_INSPECT_SERVICE_RESOURCE_FILE}" == /* \
            && "${O3K_AGENT_INSPECT_SERVICE_RESOURCE_FILE}" != *..* ]] \
            || { echo "agent inspect service resource file is invalid" >&2; exit 1; }
        printf '%s\n' "${SERVER_ID}" >"${O3K_AGENT_INSPECT_SERVICE_RESOURCE_FILE}"
        chmod 0644 "${O3K_AGENT_INSPECT_SERVICE_RESOURCE_FILE}"
    fi
    # Synchronize with the live process-boundary probe: wait for it to
    # reach a terminal result before any destructive lifecycle action.
    # The probe dispatches inspect through the real compute-service
    # boundary while the server is still ACTIVE.
    if [[ -n "${O3K_AGENT_INSPECT_PROBE_OUTPUT:-}" ]]; then
        probe_output="${O3K_AGENT_INSPECT_PROBE_OUTPUT}"
        # The service-side probe has a bounded five-minute deadline because a
        # real libvirt create/observation can exceed one minute on a cold
        # protected host.  Wait for the same deadline before performing any
        # destructive lifecycle action or reporting a false lifecycle failure.
        probe_deadline="${O3K_AGENT_INSPECT_PROBE_DEADLINE_SECONDS:-300}"
        probe_waited=0
        while [[ "${probe_waited}" -lt "${probe_deadline}" ]]; do
            if [[ -f "${probe_output}" ]]; then
                probe_status=$(python3 - "${probe_output}" 2>/dev/null <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        d = json.load(f)
    print(d.get("status", "unknown"))
except Exception:
    print("unknown")
PY
                )
                # The service owns this redacted result and may protect it
                # from unprivileged readers.  A visible-but-unreadable file
                # is not a pending result: use the same non-interactive,
                # bounded sudo read as the process-boundary harness.  Never
                # fall back to emitting the file contents or treating a read
                # failure as success.
                if [[ "${probe_status}" == "unknown" ]] && command -v sudo >/dev/null 2>&1 \
                    && sudo -n test -r "${probe_output}" 2>/dev/null; then
                    probe_status=$(sudo -n python3 - "${probe_output}" 2>/dev/null <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        d = json.load(f)
    print(d.get("status", "unknown"))
except Exception:
    print("unknown")
PY
                    )
                fi
                if [[ "${probe_status}" == "passed" ]]; then
                    echo "agent inspect probe passed"
                    if [[ -n "${O3K_REAL_HOST_ARTIFACT_DIR:-}" ]]; then
                        mkdir -p "${O3K_REAL_HOST_ARTIFACT_DIR}"
                        if ! cp -f "${probe_output}" "${O3K_REAL_HOST_ARTIFACT_DIR}/agent-inspect-probe.json" 2>/dev/null; then
                            sudo -n cat "${probe_output}" 2>/dev/null | cat >"${O3K_REAL_HOST_ARTIFACT_DIR}/agent-inspect-probe.json" || true
                            chmod 0600 "${O3K_REAL_HOST_ARTIFACT_DIR}/agent-inspect-probe.json" 2>/dev/null || true
                        fi
                    fi
                    break
                elif [[ "${probe_status}" == "failed" ]]; then
                    echo "agent inspect probe failed" >&2
                    exit 1
                fi
            fi
            sleep 1
            probe_waited=$((probe_waited + 1))
        done
        if [[ "${probe_waited}" -ge "${probe_deadline}" ]]; then
            echo "agent inspect probe timed out after ${probe_deadline}s" >&2
            exit 1
        fi
    fi
fi
openstack server show "${SERVER_ID}" -f json >"${ARTIFACT_DIR}/server-show.json"
python3 - "${ARTIFACT_DIR}/server-show.json" "${ARTIFACT_DIR}/server-show-evidence.json" <<'PY'
import json
import sys

source, destination = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    value = json.load(stream)
evidence = {
    "id": value.get("id"),
    "status": value.get("status"),
    "config_drive": value.get("config_drive"),
    "addresses": value.get("addresses", {}),
    "redacted": True,
}
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(evidence, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
validate_server_json show "${ARTIFACT_DIR}/server-show.json" "${SERVER_ID}"
SERVER_ACTIVE=true
SERVER_CONFIG_DRIVE="${CONFIG_DRIVE_ENABLED}"
SERVER_FIXED_IP="${EXPECTED_FIXED_IP}"
openstack server list --name "${SERVER_NAME}" -f json >"${ARTIFACT_DIR}/server-list.json"
python3 - "${ARTIFACT_DIR}/server-list.json" "${ARTIFACT_DIR}/server-list-evidence.json" <<'PY'
import json
import sys

source, destination = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    value = json.load(stream)
rows = value if isinstance(value, list) else value.get("servers", [])
def field(row, wanted):
    return next(
        (item for key, item in row.items() if str(key).lower() == wanted),
        None,
    )
evidence = {
    "rows": [
        {key: field(row, key) for key in ("id", "name", "status")}
        for row in rows
        if isinstance(row, dict)
    ],
    "redacted": True,
}
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(evidence, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
validate_server_json list "${ARTIFACT_DIR}/server-list.json" "${SERVER_ID}"
for _ in $(seq 1 "${O3K_TESTLAB_CONSOLE_ATTEMPTS:-30}"); do
    CONSOLE_POLL_ATTEMPTS=$((CONSOLE_POLL_ATTEMPTS + 1))
    write_console_result pending "console polling in progress"
    if console_request "${SERVER_ID}" "${ARTIFACT_DIR}/console.log" \
        && [[ -s "${ARTIFACT_DIR}/console.log" ]]; then
        CONSOLE_POLL_SUCCEEDED=true
        break
    fi
    sleep "${O3K_TESTLAB_CONSOLE_INTERVAL_SECONDS:-1}"
done
if [[ "${CONSOLE_POLL_SUCCEEDED}" != true ]]; then
    {
        printf 'artifact_type=console-file-size-evidence\n'
        if [[ -n "${O3K_TESTLAB_STATE_ROOT:-}" && -d "${O3K_TESTLAB_STATE_ROOT}/data" ]]; then
            find "${O3K_TESTLAB_STATE_ROOT}/data" -maxdepth 5 -type f -path '*/console/*' \
                -printf '%p %s bytes\n' 2>/dev/null | sort
        else
            printf 'console_state_root=unavailable\n'
        fi
    } >"${ARTIFACT_DIR}/console-file-size-evidence.txt"
    chmod 0644 "${ARTIFACT_DIR}/console-file-size-evidence.txt"
    write_console_result failed "console polling did not produce non-empty output"
    [[ -s "${ARTIFACT_DIR}/console.log" ]]
fi
if ! grep -Eiq 'cirros|login:' "${ARTIFACT_DIR}/console.log"; then
    write_console_result failed "console output did not contain a CirrOS boot marker"
    echo "console output did not contain a CirrOS boot marker" >&2
    exit 1
fi
CONSOLE_BOOT_MARKER=true
write_console_result passed "CirrOS boot marker found" true
tail -c 65536 "${ARTIFACT_DIR}/console.log" >"${ARTIFACT_DIR}/console.log.tmp"
mv "${ARTIFACT_DIR}/console.log.tmp" "${ARTIFACT_DIR}/console.log"
openstack server stop "${SERVER_ID}"
wait_for_server_status "${SERVER_ID}" SHUTOFF \
  || { echo "server did not reach SHUTOFF after stop" >&2; exit 1; }
openstack server start "${SERVER_ID}"
wait_for_server_status "${SERVER_ID}" ACTIVE \
  || { echo "server did not reach ACTIVE after start" >&2; exit 1; }
openstack server reboot --hard "${SERVER_ID}"
wait_for_server_status "${SERVER_ID}" ACTIVE \
  || { echo "server did not reach ACTIVE after reboot" >&2; exit 1; }
openstack server show "${SERVER_ID}" -f json >"${ARTIFACT_DIR}/server-show-after-reboot.json"
validate_server_json show "${ARTIFACT_DIR}/server-show-after-reboot.json" "${SERVER_ID}"
SERVER_RESTART_ACTIVE=true
SERVER_RESTART_CONFIG_DRIVE="${CONFIG_DRIVE_ENABLED}"
SERVER_RESTART_FIXED_IP="${EXPECTED_FIXED_IP}"
openstack server delete --wait "${SERVER_ID}"
if ! server_is_absent "${SERVER_ID}"; then
    echo "server deletion was not verified" >&2
    exit 1
fi
CLEANUP_SERVER_STATUS=verified_absent
SERVER_ID=
delete_resource_and_verify_absent keypair "${KEYPAIR_NAME}"
CLEANUP_KEYPAIR_STATUS=verified_absent
KEYPAIR_ID=
delete_resource_and_verify_absent flavor "${FLAVOR_ID}"
CLEANUP_FLAVOR_STATUS=verified_absent
FLAVOR_ID=
delete_resource_and_verify_absent port "${PORT_ID}"
CLEANUP_PORT_STATUS=verified_absent
PORT_ID=
delete_resource_and_verify_absent subnet "${SUBNET_ID}"
CLEANUP_SUBNET_STATUS=verified_absent
SUBNET_ID=
delete_resource_and_verify_absent network "${NETWORK_ID}"
CLEANUP_NETWORK_STATUS=verified_absent
NETWORK_ID=
delete_resource_and_verify_absent image "${IMAGE_ID}"
CLEANUP_IMAGE_STATUS=verified_absent
IMAGE_ID=
write_result passed "CLI lifecycle completed" passed

# Self-check the passed artifact against the normative release-evidence
# contract so a passed run never claims evidence the gate would reject.
# Guarded: the validator is only a check, never required to emit evidence.
if command -v python3 >/dev/null 2>&1 \
    && [[ -f "${ROOT_DIR}/scripts/validate-release-e2e-evidence.py" ]]; then
    if ! python3 "${ROOT_DIR}/scripts/validate-release-e2e-evidence.py" \
        "${ARTIFACT_DIR}/openstack-cli-result.json"; then
        echo "passed E2E artifact violates contracts/release-e2e-evidence.schema.json" >&2
        exit 1
    fi
fi
