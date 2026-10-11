#!/usr/bin/env bash
set -Eeuo pipefail

# Portable test suite for the independent resource-leak verifier
# (scripts/real-host-leak-verifier.py) and the schema_version 3 collector
# (scripts/real-host-owned-inventory.py).
#
# Unlike the guard tests, the durable predicates are exercised against a REAL
# sqlite3 database built from the actual migration files
# (crates/o3k-store/migrations/*.sql), so the non-terminal
# operation/command/transfer predicates and the placement/allocation tables
# are the real ones.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-leak-verifier.XXXXXX")"
trap 'rm -rf -- "${WORK_DIR}"' EXIT
FAKE_BIN="${WORK_DIR}/bin"
STATE_ROOT="${WORK_DIR}/state"
PID_ROOT="${WORK_DIR}/pids"
ARTIFACT_ROOT="${STATE_ROOT}/data/agent-id.artifacts"
mkdir -p "${FAKE_BIN}" "${STATE_ROOT}/data" "${PID_ROOT}"

REAL_SQLITE3="$(command -v sqlite3)"
if [[ -z "${REAL_SQLITE3}" ]]; then
    echo "sqlite3 is required for this test suite" >&2
    exit 1
fi

# Fake commands: virsh/ip/openstack are stateful via env toggles; sqlite3
# forwards to the real binary.
cat >"${FAKE_BIN}/virsh" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == "-c qemu:///system list --all --name" ]]; then
    if [[ "${O3K_FAKE_VIRSH_DIRTY:-false}" == true ]]; then
        echo o3k-0123456789abcdef0123
    fi
    if [[ "${O3K_FAKE_VIRSH_ORPHAN:-false}" == true ]]; then
        echo o3k-aaaaaaaaaaaaaaaaaaaa
    fi
    if [[ "${O3K_FAKE_VIRSH_FOREIGN:-false}" == true ]]; then
        echo foreign-domain-1
    fi
    exit 0
fi
if [[ "$*" == "-c qemu:///system pool-list --all --name" ]]; then
    if [[ -n "${O3K_FAKE_VIRSH_FOREIGN_POOL_NAME:-}" ]]; then
        printf '%s\n' "${O3K_FAKE_VIRSH_FOREIGN_POOL_NAME}"
    fi
    exit 0
fi
if [[ "$*" == "-c qemu:///system dumpxml"* ]]; then
    name="${*: -1}"
    if [[ "${name}" == "canary-dom" ]]; then
        echo '<domain type="kvm"><uuid>11111111-1111-1111-1111-111111111111</uuid><name>canary-dom</name></domain>'
        exit 0
    fi
    if [[ "${O3K_FAKE_CANARY_DOM_MISSING:-false}" == true ]]; then
        echo "error: failed to get domain '${name}'" >&2
        exit 1
    fi
    echo '<domain type="kvm"><uuid>11111111-1111-1111-1111-111111111111</uuid><name>canary-dom</name></domain>'
    exit 0
fi
exit 0
SH
cat >"${FAKE_BIN}/ip" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == "-o link show" ]]; then
    if [[ "${O3K_FAKE_IP_OWNED:-false}" == true ]]; then
        echo '2: o3k-br0: <BROADCAST> mtu 1500 state UP'
        echo '3: o3ktap-deadbeef: <BROADCAST> mtu 1500 master o3k-br0 state UP'
    fi
    if [[ "${O3K_FAKE_IP_FOREIGN:-false}" == true ]]; then
        echo '5: eth0: <BROADCAST> mtu 1500 state UP'
    fi
    exit 0
fi
if [[ "$*" == "-j link show"* ]]; then
    if [[ "${O3K_FAKE_CANARY_LINK_MISSING:-false}" == true ]]; then
        echo '[]'
        exit 0
    fi
    echo '[{"ifname":"canary-link0","link_type":"bridge"}]'
    exit 0
fi
if [[ "$*" == "-j addr show"* ]]; then
    if [[ "${O3K_FAKE_CANARY_LINK_MISSING:-false}" == true ]]; then
        echo '[]'
        exit 0
    fi
    if [[ "${O3K_FAKE_CANARY_LINK_CHANGED:-false}" == true ]]; then
        echo '[{"ifname":"canary-link0","addr_info":[{"local":"10.9.9.9"}]}]'
        exit 0
    fi
    echo '[{"ifname":"canary-link0","addr_info":[{"local":"192.0.2.99"}]}]'
    exit 0
fi
exit 0
SH
cat >"${FAKE_BIN}/openstack" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == flavor\ list\ * ]]; then
    echo '[]'
    exit 0
fi
if [[ "$*" == *" list "* ]]; then
    echo '[]'
    exit 0
fi
exit 0
SH
cat >"${FAKE_BIN}/sqlite3" <<SH
#!/usr/bin/env bash
exec "${REAL_SQLITE3}" "\$@"
SH
chmod +x "${FAKE_BIN}/virsh" "${FAKE_BIN}/ip" "${FAKE_BIN}/openstack" "${FAKE_BIN}/sqlite3"

export O3K_REAL_HOST_PROTECTED_PATHS="${WORK_DIR}/protected-state.txt"
printf 'protected baseline\n' >"${O3K_REAL_HOST_PROTECTED_PATHS}"
export OS_PASSWORD=do-not-upload-this-value

DELETED_INSTANCE="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
NETWORK_ID="cccccccc-cccc-cccc-cccc-cccccccccccc"
CANARY_FILE="${WORK_DIR}/canary-file.txt"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

build_db() {
    local db="$1"
    local sql=""
    for migration in "${ROOT_DIR}"/crates/o3k-store/migrations/*.sql; do
        sql+="$(<"${migration}")\n"
    done
    printf '%b' "${sql}" | "${REAL_SQLITE3}" "${db}"
}

seed_db() {
    local db="$1"
    "${REAL_SQLITE3}" "${db}" <<SQL
INSERT INTO resources (id, kind, project_id, generation, observed_generation, desired_state, observed_state)
VALUES ('${DELETED_INSTANCE}', 'compute_instance', 'project-1', 2, 2, '{}', 'DELETED');
INSERT INTO provider_refs (resource_id, provider_name, provider_resource_id)
VALUES ('${DELETED_INSTANCE}', 'compute-agent', 'o3k-0123456789abcdef0123');
INSERT INTO operations (id, resource_id, state, kind) VALUES
 ('11111111-1111-1111-1111-111111111111', '${DELETED_INSTANCE}', 'succeeded', 'create'),
 ('22222222-2222-2222-2222-222222222222', '${DELETED_INSTANCE}', 'succeeded', 'lifecycle:delete');
INSERT INTO agent_commands (command_id, idempotency_key, operation_id, resource_id, agent_id, agent_epoch, payload_fingerprint_sha256, payload, state)
VALUES ('33333333-3333-3333-3333-333333333333', 'idem-1', '11111111-1111-1111-1111-111111111111', '${DELETED_INSTANCE}', 'compute-agent', '1', '$(printf 'x%.0s' {1..64})', X'00', 'succeeded');
INSERT INTO artifact_transfers (transfer_id, command_id, operation_id, resource_id, agent_id, agent_epoch, artifact_id, artifact_kind, sha256, size_bytes, format, chunk_size_bytes, chunk_count, state)
VALUES ('44444444-4444-4444-4444-444444444444', '33333333-3333-3333-3333-333333333333', '11111111-1111-1111-1111-111111111111', '${DELETED_INSTANCE}', 'compute-agent', '1', 'artifact-1', 'image_base', '$(printf '0%.0s' {1..64})', 1024, 'qcow2', 1024, 1, 'committed');
INSERT INTO network_networks (id, name, project_id, status) VALUES ('${NETWORK_ID}', 'net-1', 'project-1', 'ACTIVE');
INSERT INTO image_metadata (id, name, project_id, status, visibility, container_format, disk_format)
VALUES ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee', 'img-1', 'project-1', 'active', 'private', 'bare', 'qcow2');
SQL
}

# Build the clean fixture: expected-retained managed state + terminal durable
# rows only (deleted resource tombstones, succeeded operations/commands,
# committed transfers). Nothing here may be reported as a leak.
setup_clean_fixture() {
    mkdir -p "${ARTIFACT_ROOT}" \
        "${STATE_ROOT}/data/config-drive" \
        "${STATE_ROOT}/data/dhcp" \
        "${STATE_ROOT}/data/image-cache/base" \
        "${STATE_ROOT}/data/image-cache/overlays" \
        "${STATE_ROOT}/data/image-cache/ownership" \
        "${STATE_ROOT}/data/images/content" \
        "${STATE_ROOT}/data/network" \
        "${STATE_ROOT}/data/placement" \
        "${STATE_ROOT}/data/console"
    printf 'compute-agent\n' >"${STATE_ROOT}/data/agent-id"
    printf 'journal\n' >"${STATE_ROOT}/data/agent-id.commands"
    printf 'enabled\n' >"${STATE_ROOT}/data/agent-id.state"
    cat >"${ARTIFACT_ROOT}/.44444444-4444-4444-4444-444444444444.manifest" <<'JSON'
{"offer": {"transfer_id": "44444444-4444-4444-4444-444444444444", "command_id": "33333333-3333-3333-3333-333333333333", "operation_id": "11111111-1111-1111-1111-111111111111", "resource_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "agent_id": "compute-agent", "agent_epoch": "1", "artifact_id": "artifact-1", "artifact_kind": "image_base", "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "size_bytes": 1024, "format": "qcow2"}, "state": "committed", "bytes": 1024, "next_chunk": 1}
JSON
    rm -f "${ARTIFACT_ROOT}/.44444444-4444-4444-4444-444444444444.manifest"
    python3 - "${ARTIFACT_ROOT}" <<'PY'
import struct, sys
from pathlib import Path
# Binary artifact manifest in the exact layout written by
# crates/o3k-compute-agent/src/artifact.rs `atomic_manifest`:
# "O3KART1" magic, version byte, u32-le protobuf offer length, protobuf
# ArtifactOffer, then i32-le state, u64-le next_chunk, u64-le bytes.
def varint(value):
    out = b""
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out += bytes([byte | 0x80])
        else:
            out += bytes([byte])
            return out
def field_str(number, value):
    payload = value.encode()
    return varint(number << 3 | 2) + varint(len(payload)) + payload
def field_varint(number, value):
    return varint(number << 3) + varint(value)
offer = b"".join([
    field_str(1, "44444444-4444-4444-4444-444444444444"),
    field_str(2, "33333333-3333-3333-3333-333333333333"),
    field_str(3, "11111111-1111-1111-1111-111111111111"),
    field_str(4, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
    field_str(5, "compute-agent"),
    field_str(6, "artifact-1"),
    field_varint(7, 1),  # ARTIFACT_KIND_IMAGE_BASE
    field_str(8, "0" * 64),
    field_varint(9, 1024),
    field_str(10, "qcow2"),
    field_varint(11, 1024),
    field_varint(12, 1),
    field_varint(13, 4102444800000),
])
manifest = (b"O3KART1" + bytes([1]) + struct.pack("<I", len(offer)) + offer
            + struct.pack("<i", 3) + struct.pack("<I", 1) + struct.pack("<Q", 1024))
Path(sys.argv[1], ".44444444-4444-4444-4444-444444444444.manifest").write_bytes(manifest)
PY
    printf 'base-image\n' >"${STATE_ROOT}/data/image-cache/base/0000000000000000000000000000000000000000000000000000000000000000.qcow2"
    printf 'committed content\n' >"${STATE_ROOT}/data/images/content/eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
    printf '{"bridge": null, "taps": {}}\n' >"${STATE_ROOT}/data/network/ownership.json"
    printf '{"config": {"subnet": "192.0.2.0/29", "gateway": "192.0.2.1", "dns": ["192.0.2.1"], "interface": "o3k-br0", "lease_seconds": 3600}, "bindings": {}}\n' >"${STATE_ROOT}/data/dhcp/state.json"
    printf '# Managed by o3k-dhcp; do not edit.\ninterface=o3k-br0\n' >"${STATE_ROOT}/data/dhcp/dnsmasq.conf"
    printf '1786276274 02:83:c9:91:b1:e8 192.0.2.3 * 01:02:83:c9:91:b1:e8\n' >"${STATE_ROOT}/data/dhcp/dnsmasq.leases"
    build_db "${STATE_ROOT}/data/o3k.sqlite"
    seed_db "${STATE_ROOT}/data/o3k.sqlite"
}

collect() {
    local output="$1"
    shift
    collect_root "${STATE_ROOT}" "${output}" "$@"
}

collect_root() {
    local root="$1" output="$2"
    shift 2
    env O3K_REAL_HOST_STATE_ROOT="${root}" \
        O3K_REAL_HOST_CANARIES="${WORK_DIR}/canaries.json" \
        O3K_REAL_HOST_OPENSTACK_INVENTORY=true \
        PATH="${FAKE_BIN}:${PATH}" "$@" \
        bash "${ROOT_DIR}/scripts/real-host-owned-inventory.sh" "${output}"
}

canaries_config() {
    cat >"${WORK_DIR}/canaries.json" <<'JSON'
{"libvirt_domains": ["canary-dom"], "network_links": ["canary-link0"], "files": [{"path": "/abs/does/not/matter", "sha256": "1111111111111111111111111111111111111111111111111111111111111111"}]}
JSON
}

setup_clean_fixture
canaries_config
printf 'canary content v1\n' >"${CANARY_FILE}"
python3 - "${WORK_DIR}/canaries.json" "${CANARY_FILE}" <<'PY'
import json, sys
config = json.load(open(sys.argv[1], encoding="utf-8"))
config["files"] = [{"path": sys.argv[2], "sha256": "1111111111111111111111111111111111111111111111111111111111111111"}]
json.dump(config, open(sys.argv[1], "w", encoding="utf-8"))
PY
export O3K_FAKE_VIRSH_FOREIGN=true O3K_FAKE_IP_FOREIGN=true

# A foreign pool replacement with an unchanged count still changes the
# redacted host fingerprint; names must stay private in the artifact.
O3K_FAKE_VIRSH_FOREIGN_POOL_NAME=foreign-pool-a collect "${WORK_DIR}/foreign-pool-a.json"
O3K_FAKE_VIRSH_FOREIGN_POOL_NAME=foreign-pool-b collect "${WORK_DIR}/foreign-pool-b.json"
python3 - "${WORK_DIR}/foreign-pool-a.json" "${WORK_DIR}/foreign-pool-b.json" <<'PY'
import json, sys
before = json.load(open(sys.argv[1], encoding="utf-8"))["foreign_state"]
after = json.load(open(sys.argv[2], encoding="utf-8"))["foreign_state"]
assert before["pools_count"] == after["pools_count"] == 1
assert before["pools_sha256"] != after["pools_sha256"]
assert "foreign-pool-a" not in json.dumps(before)
assert "foreign-pool-b" not in json.dumps(after)
PY

# --- 1. deterministic canonicalization -----------------------------------
collect "${WORK_DIR}/det-a.json"
collect "${WORK_DIR}/det-b.json"
cmp -s "${WORK_DIR}/det-a.json" "${WORK_DIR}/det-b.json" \
    || fail "two inventory runs over the same host are not byte-identical"

# --- 2. owned vs foreign classification -----------------------------------
python3 - "${WORK_DIR}/det-a.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["schema_version"] == 3, value["schema_version"]
assert value["status"] == "available", value
assert value["domains"] == [], value["domains"]  # no owned domains in the fixture
assert value["network_links"] == [], value["network_links"]
assert value["foreign_state"]["domains_sha256"]
assert value["foreign_state"]["network_links_sha256"]
assert value["foreign_state"]["pools_sha256"]
assert value["foreign_state"]["pools_count"] == 0
assert "foreign-domain-1" not in json.dumps(value)
assert "eth0" not in json.dumps(value)
assert value["managed_state"]["status"] == "available"
assert value["durable"]["status"] == "available"
assert value["dhcp"]["status"] == "available"
assert value["processes"]["status"] == "not_checked"
assert value["canaries"]["status"] == "available"
assert value["canaries"]["libvirt_domains"][0]["present"] is True
assert value["canaries"]["libvirt_domains"][0]["uuid"] == "11111111-1111-1111-1111-111111111111"
assert value["canaries"]["files"][0]["present"] is True
PY
O3K_FAKE_IP_OWNED=true collect "${WORK_DIR}/owned-links.json"
python3 - "${WORK_DIR}/owned-links.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert "o3k-br0" in value["network_links"], value["network_links"]
assert "o3ktap-deadbeef" in value["network_links"], value["network_links"]
assert value["link_classifications"]["o3ktap-deadbeef"]["classification"] == "stale_owned"
PY

# --- 3. deleted/tombstone durable rows are NOT active leaks; 8. expected
#       cache/historical state is NOT falsely rejected ----------------------
collect "${WORK_DIR}/base-a.json"
collect "${WORK_DIR}/base-b.json"
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/base-b.json" \
    --scope clean --expect-state-root present --source-commit sha1 --runner r1 \
    --out "${WORK_DIR}/clean-verdict.json" || true
python3 - "${WORK_DIR}/clean-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "passed", value
assert value["owned_leaks"] == [], value["owned_leaks"]
assert value["inconsistencies"] == [], value["inconsistencies"]
assert value["foreign_changes"] == [], value["foreign_changes"]
assert set(value["expected_retained"]) == {"counts", "contracts"}, value["expected_retained"]
assert value["scope"] == "clean" and value["source_commit"] == "sha1"
PY

# --- 3b. a non-terminal command row whose owning operation is TERMINAL is
#       journal evidence (expected_retained), while one whose operation is
#       non-terminal for an absent resource stays inconsistent ---------------
cp "${STATE_ROOT}/data/o3k.sqlite" "${WORK_DIR}/journal.sqlite"
"${REAL_SQLITE3}" "${WORK_DIR}/journal.sqlite" <<SQL
INSERT INTO operations (id, resource_id, state, kind) VALUES
 ('66666666-6666-6666-6666-666666666666', '${DELETED_INSTANCE}', 'failed', 'lifecycle:delete'),
 ('77777777-7777-7777-7777-777777777777', '${DELETED_INSTANCE}', 'running', 'create');
INSERT INTO agent_commands (command_id, idempotency_key, operation_id, resource_id, agent_id, agent_epoch, payload_fingerprint_sha256, payload, state)
VALUES
 ('88888888-8888-8888-8888-888888888888', 'idem-j1', '66666666-6666-6666-6666-666666666666', '${DELETED_INSTANCE}', 'compute-agent', '1', '$(printf 'x%.0s' {1..64})', X'00', 'unknown_outcome'),
 ('99999999-9999-9999-9999-999999999999', 'idem-j2', '77777777-7777-7777-7777-777777777777', '${DELETED_INSTANCE}', 'compute-agent', '1', '$(printf 'x%.0s' {1..64})', X'00', 'accepted');
SQL
cp "${WORK_DIR}/journal.sqlite" "${STATE_ROOT}/data/o3k.sqlite"
collect "${WORK_DIR}/journal-after.json"
python3 - "${WORK_DIR}/journal-after.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
by_id = {e["id"]: e for e in value["durable"]["agent_commands"]["entries"]}
journal = by_id.get("88888888-8888-8888-8888-888888888888")
assert journal and journal["classification"] == "expected_retained", by_id
assert journal["operation_state"] == "failed", journal
stranded = by_id.get("99999999-9999-9999-9999-999999999999")
assert stranded and stranded["classification"] == "inconsistent", by_id
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/journal-after.json" \
    --scope journal --expect-state-root present \
    --out "${WORK_DIR}/journal-verdict.json" || true
python3 - "${WORK_DIR}/journal-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed", value
assert all(
    e["identity"] != "88888888-8888-8888-8888-888888888888"
    for e in value["inconsistencies"] + value["owned_leaks"]
), value
assert any(
    e["identity"] == "99999999-9999-9999-9999-999999999999"
    and e["classification"] == "inconsistent"
    for e in value["inconsistencies"]
), value["inconsistencies"]
PY
"${REAL_SQLITE3}" "${STATE_ROOT}/data/o3k.sqlite" \
    "DELETE FROM agent_commands WHERE command_id IN ('88888888-8888-8888-8888-888888888888','99999999-9999-9999-9999-999999999999'); DELETE FROM operations WHERE id IN ('66666666-6666-6666-6666-666666666666','77777777-7777-7777-7777-777777777777');" \
    >/dev/null

# --- 4. active allocation for an absent resource IS detected --------------
cp "${STATE_ROOT}/data/o3k.sqlite" "${WORK_DIR}/alloc.sqlite"
"${REAL_SQLITE3}" "${WORK_DIR}/alloc.sqlite" <<SQL
INSERT INTO placement_providers (id, node_id, state, generation) VALUES ('provider-1', 'node-1', 'Enabled', 1);
INSERT INTO placement_allocations (id, provider_id, consumer_id) VALUES ('55555555-5555-5555-5555-555555555555', 'provider-1', '${DELETED_INSTANCE}');
SQL
cp "${WORK_DIR}/alloc.sqlite" "${STATE_ROOT}/data/o3k.sqlite"
collect "${WORK_DIR}/alloc-after.json"
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/alloc-after.json" \
    --scope alloc --expect-state-root present \
    --out "${WORK_DIR}/alloc-verdict.json" || true
python3 - "${WORK_DIR}/alloc-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed", value
assert any(
    entry["kind"] == "placement_allocations"
    and entry["classification"] == "inconsistent"
    and entry["identity"] == "55555555-5555-5555-5555-555555555555"
    for entry in value["inconsistencies"]
), value["inconsistencies"]
PY
"${REAL_SQLITE3}" "${STATE_ROOT}/data/o3k.sqlite" \
    "DELETE FROM placement_allocations WHERE id = '55555555-5555-5555-5555-555555555555';" \
    >/dev/null

# --- 5. orphan host domain IS detected (stale_owned) -----------------------
O3K_FAKE_VIRSH_ORPHAN=true collect "${WORK_DIR}/orphan-dom-after.json"
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/orphan-dom-after.json" \
    --scope orphan-dom --expect-state-root present \
    --out "${WORK_DIR}/orphan-dom-verdict.json" || true
python3 - "${WORK_DIR}/orphan-dom-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed", value
assert any(
    entry["kind"] == "domain"
    and entry["classification"] == "stale_owned"
    and entry["identity"] == "o3k-aaaaaaaaaaaaaaaaaaaa"
    for entry in value["owned_leaks"] + value["inconsistencies"]
), value
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" negative-stale \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/orphan-dom-after.json" \
    --out "${WORK_DIR}/negative-stale-1.json" || true
python3 - "${WORK_DIR}/negative-stale-1.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["expected"] == "failed" and value["observed"] == "failed", value
assert value["stale_artifact_detected"] is True, value
assert any("o3k-aaaaaaaaaaaaaaaaaaaa" == o["identity"] for o in value["stale_objects"]), value
PY

# --- 5b. configured test injection root: entries are O3K-owned stale state
#       (negative-stale fixture), empty sink is clean, absent sink is valid
#       clean state, symlink sink fails closed --------------------------------
INJECTION_ROOT="${WORK_DIR}/injections"
mkdir -p "${INJECTION_ROOT}"
O3K_REAL_HOST_MANAGED_INJECTION_ROOT="${INJECTION_ROOT}" collect "${WORK_DIR}/inj-base.json"
python3 - "${WORK_DIR}/inj-base.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["injection_root"]["status"] == "available", value["injection_root"]
assert value["injection_root"]["entries"] == [], value["injection_root"]
PY
mkdir -p "${INJECTION_ROOT}/o3k-11111111-aaaa-4ccc-8ddd-eeeeeeeeeeee"
printf 'stale instance state\n' >"${INJECTION_ROOT}/o3k-11111111-aaaa-4ccc-8ddd-eeeeeeeeeeee/instance-state.json"
O3K_REAL_HOST_MANAGED_INJECTION_ROOT="${INJECTION_ROOT}" collect "${WORK_DIR}/inj-after.json"
python3 - "${WORK_DIR}/inj-after.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
entries = value["injection_root"]["entries"]
assert any(
    e["path"] == "o3k-11111111-aaaa-4ccc-8ddd-eeeeeeeeeeee/instance-state.json"
    and e["classification"] == "stale_owned"
    for e in entries
), entries
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/inj-base.json" --after "${WORK_DIR}/inj-after.json" \
    --scope injection --expect-state-root present \
    --out "${WORK_DIR}/inj-verdict.json" || true
python3 - "${WORK_DIR}/inj-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed", value
assert any(
    e["kind"] == "injection_root"
    and e["identity"] == "o3k-11111111-aaaa-4ccc-8ddd-eeeeeeeeeeee/instance-state.json"
    for e in value["owned_leaks"]
), value["owned_leaks"]
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" negative-stale \
    --baseline "${WORK_DIR}/inj-base.json" --after "${WORK_DIR}/inj-after.json" \
    --expect-state-root present --out "${WORK_DIR}/inj-negative.json" || true
python3 - "${WORK_DIR}/inj-negative.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["expected"] == "failed" and value["observed"] == "failed", value
assert value["stale_artifact_detected"] is True, value
assert any(
    "o3k-11111111-aaaa-4ccc-8ddd-eeeeeeeeeeee/instance-state.json" == o["identity"]
    for o in value["stale_objects"]
), value["stale_objects"]
PY
rm -rf "${INJECTION_ROOT}/o3k-11111111-aaaa-4ccc-8ddd-eeeeeeeeeeee"
O3K_REAL_HOST_MANAGED_INJECTION_ROOT="${INJECTION_ROOT}" collect "${WORK_DIR}/inj-clean.json"
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/inj-base.json" --after "${WORK_DIR}/inj-clean.json" \
    --scope injection-clean --expect-state-root present \
    --out "${WORK_DIR}/inj-clean-verdict.json" || true
python3 - "${WORK_DIR}/inj-clean-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "passed", value
PY
# An absent configured sink is valid clean state; a symlink inside the sink
# fails closed (unavailable), never an apparently clean snapshot.
O3K_REAL_HOST_MANAGED_INJECTION_ROOT="${WORK_DIR}/no-such-injections" collect "${WORK_DIR}/inj-absent.json"
python3 - "${WORK_DIR}/inj-absent.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "available", value
assert value["injection_root"]["status"] == "absent", value["injection_root"]
PY
mkdir -p "${WORK_DIR}/poison-injections"
ln -s /etc/passwd "${WORK_DIR}/poison-injections/evil"
if O3K_REAL_HOST_MANAGED_INJECTION_ROOT="${WORK_DIR}/poison-injections" \
    PATH="${FAKE_BIN}:${PATH}" \
    bash "${ROOT_DIR}/scripts/real-host-owned-inventory.sh" "${WORK_DIR}/inj-poison.json"; then
    fail "symlink inside the injection root was accepted"
fi
python3 - "${WORK_DIR}/inj-poison.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "unavailable", value
assert value["reason"] == "injection_root_unowned_path", value
PY

# --- 6. orphan TAP IS detected ---------------------------------------------
O3K_FAKE_IP_OWNED=true collect "${WORK_DIR}/orphan-tap-after.json"
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/orphan-tap-after.json" \
    --scope orphan-tap --expect-state-root present \
    --out "${WORK_DIR}/orphan-tap-verdict.json" || true
python3 - "${WORK_DIR}/orphan-tap-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed", value
assert any(
    entry["kind"] == "link"
    and entry["classification"] == "stale_owned"
    and entry["identity"] == "o3ktap-deadbeef"
    for entry in value["inconsistencies"]
), value
PY

# --- 6b. owned dnsmasq restart is identity-stable; a NEW owned dnsmasq
#       (different args digest) is a leak --------------------------------
python3 - "${WORK_DIR}/base-a.json" "${WORK_DIR}/dhcp-base.json" "${WORK_DIR}/dhcp-after.json" "${WORK_DIR}/dhcp-after-new.json" <<'PY'
import json, sys
base = json.load(open(sys.argv[1], encoding="utf-8"))
dhcp = base.get("dhcp", {})
owned = [{"pid": "100", "args_sha256": "a" * 64, "classification": "active_owned",
          "contract": "owned dnsmasq"}]
dhcp["processes"] = {"owned": owned, "foreign_count": 0, "foreign_args_sha256": ""}
base["dhcp"] = dhcp
json.dump(base, open(sys.argv[2], "w", encoding="utf-8"), sort_keys=True)
after = json.loads(json.dumps(base))
after["dhcp"]["processes"]["owned"] = [dict(owned[0], pid="200")]
json.dump(after, open(sys.argv[3], "w", encoding="utf-8"), sort_keys=True)
after_new = json.loads(json.dumps(base))
after_new["dhcp"]["processes"]["owned"] = [dict(owned[0], pid="300", args_sha256="b" * 64)]
json.dump(after_new, open(sys.argv[4], "w", encoding="utf-8"), sort_keys=True)
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/dhcp-base.json" --after "${WORK_DIR}/dhcp-after.json" \
    --scope dhcp-restart --expect-state-root present \
    --out "${WORK_DIR}/dhcp-restart-verdict.json"
python3 - "${WORK_DIR}/dhcp-restart-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "passed", value
assert not any(e["kind"] == "dhcp_process" for e in value["owned_leaks"]), value["owned_leaks"]
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/dhcp-base.json" --after "${WORK_DIR}/dhcp-after-new.json" \
    --scope dhcp-new --expect-state-root present \
    --out "${WORK_DIR}/dhcp-new-verdict.json" || true
python3 - "${WORK_DIR}/dhcp-new-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed", value
assert any(
    e["kind"] == "dhcp_process" and e["identity"] == "b" * 64
    for e in value["owned_leaks"]
), value["owned_leaks"]
PY

# --- 7. stale temp artifact IS detected ------------------------------------
printf 'half-written transfer\n' >"${ARTIFACT_ROOT}/.66666666-6666-6666-6666-666666666666.part"
collect "${WORK_DIR}/temp-after.json"
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/temp-after.json" \
    --scope stale-temp --expect-state-root present \
    --out "${WORK_DIR}/temp-verdict.json" || true
python3 - "${WORK_DIR}/temp-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed", value
assert any(
    entry["kind"] == "managed_state"
    and entry["classification"] == "stale_owned"
    and entry["identity"] == "agent-id.artifacts/.66666666-6666-6666-6666-666666666666.part"
    for entry in value["owned_leaks"]
), value
PY
rm -f "${ARTIFACT_ROOT}/.66666666-6666-6666-6666-666666666666.part"

# --- 9. foreign-state mutation IS detected (canary file + foreign link) ----
printf 'canary content v2\n' >"${CANARY_FILE}"
python3 - "${WORK_DIR}/canaries.json" "${CANARY_FILE}" <<'PY'
import json, sys
config = json.load(open(sys.argv[1], encoding="utf-8"))
config["files"] = [{"path": sys.argv[2], "sha256": "2222222222222222222222222222222222222222222222222222222222222222"}]
json.dump(config, open(sys.argv[1], "w", encoding="utf-8"))
PY
collect "${WORK_DIR}/mutated-after.json"
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/mutated-after.json" \
    --scope foreign-mut --expect-state-root present \
    --out "${WORK_DIR}/foreign-mut-verdict.json" || true
python3 - "${WORK_DIR}/foreign-mut-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed", value
assert any(
    entry["kind"] == "canary:files"
    and entry["change"] == "content_changed"
    for entry in value["foreign_changes"]
), value["foreign_changes"]
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" negative-foreign \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/mutated-after.json" \
    --out "${WORK_DIR}/negative-foreign-1.json" || true
python3 - "${WORK_DIR}/negative-foreign-1.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["expected"] == "failed" and value["observed"] == "failed", value
assert value["foreign_mutation_detected"] is True, value
assert any(e["change"] == "content_changed" for e in value["foreign_changes"]), value
PY

# --- 10. missing inventory source fails closed ------------------------------
# A CONFIGURED-BUT-MISSING state root is valid clean state (pre-bootstrap or
# post-cleanup host): every state-root-backed section records `absent` and
# the snapshot is available, so a clean-host baseline can pass with
# `--expect-state-root absent`. The verifier's expect-state-root and
# section-symmetry checks enforce fail-closed semantics at comparison time.
env O3K_REAL_HOST_STATE_ROOT="${WORK_DIR}/no-such-root" \
    PATH="${FAKE_BIN}:${PATH}" \
    bash "${ROOT_DIR}/scripts/real-host-owned-inventory.sh" "${WORK_DIR}/missing-root.json"
python3 - "${WORK_DIR}/missing-root.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "available", value
assert value["managed_state"]["status"] == "absent", value["managed_state"]
assert value["durable"]["status"] == "absent", value["durable"]
assert value["dhcp"]["status"] == "absent", value["dhcp"]
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/missing-root.json" --after "${WORK_DIR}/missing-root.json" \
    --scope absent-root --expect-state-root absent \
    --out "${WORK_DIR}/absent-root-verdict.json"
python3 - "${WORK_DIR}/absent-root-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "passed", value
PY
# An EXISTING state root whose database is missing is broken state and still
# fails closed (unavailable), never an apparently clean snapshot.
mkdir -p "${WORK_DIR}/broken-root/data"
if env O3K_REAL_HOST_STATE_ROOT="${WORK_DIR}/broken-root" \
    PATH="${FAKE_BIN}:${PATH}" \
    bash "${ROOT_DIR}/scripts/real-host-owned-inventory.sh" "${WORK_DIR}/broken-root.json"; then
    fail "state root without its database was accepted"
fi
python3 - "${WORK_DIR}/broken-root.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "unavailable", value
assert value["reason"].startswith("durable_database_missing"), value
PY
if env O3K_REAL_HOST_PID_ROOT="${WORK_DIR}/no-such-pids" \
    PATH="${FAKE_BIN}:${PATH}" \
    bash "${ROOT_DIR}/scripts/real-host-owned-inventory.sh" "${WORK_DIR}/missing-pidroot.json"; then
    fail "missing pid root was accepted"
fi
python3 - "${WORK_DIR}/missing-pidroot.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "unavailable" and value["reason"] == "pid_root_missing", value
PY
mkdir -p "${WORK_DIR}/no-sqlite-bin"
cat >"${WORK_DIR}/no-sqlite-bin/sqlite3" <<'SH'
#!/usr/bin/env bash
echo "sqlite3 is hidden" >&2
exit 127
SH
chmod +x "${WORK_DIR}/no-sqlite-bin/sqlite3"
if env O3K_REAL_HOST_STATE_ROOT="${STATE_ROOT}" \
    PATH="${WORK_DIR}/no-sqlite-bin:${FAKE_BIN}:${PATH}" \
    bash "${ROOT_DIR}/scripts/real-host-owned-inventory.sh" "${WORK_DIR}/no-sqlite.json"; then
    fail "missing sqlite3 was accepted"
fi
python3 - "${WORK_DIR}/no-sqlite.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "unavailable"
assert value["reason"] == "tool_unavailable:sqlite3", value
PY
python3 - "${WORK_DIR}/base-a.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["schema_version"] == 3 and value["status"] == "available"
PY

# --- 10b. installed layout: the state root IS the data dir -------------------
# The packaged install passes /var/lib/o3k directly as --data-dir, so the
# ledger and the managed subdirectories sit at the state root itself (no
# `data/` subdir). The collector must probe `data/` when present (testlab
# layout) and walk the root otherwise, finding the durable ledger in both
# places. The testlab-layout fixtures above keep passing unchanged.
INSTALLED_ROOT="${WORK_DIR}/installed-state"
setup_installed_fixture() {
    mkdir -p "${INSTALLED_ROOT}/dhcp" \
        "${INSTALLED_ROOT}/network" \
        "${INSTALLED_ROOT}/image-cache/base" \
        "${INSTALLED_ROOT}/console" \
        "${INSTALLED_ROOT}/config-drive" \
        "${INSTALLED_ROOT}/placement"
    printf 'compute-agent\n' >"${INSTALLED_ROOT}/agent-id"
    printf '{"bridge": null, "taps": {}}\n' >"${INSTALLED_ROOT}/network/ownership.json"
    printf '{"config": {"subnet": "192.0.2.0/29", "gateway": "192.0.2.1", "dns": ["192.0.2.1"], "interface": "o3k-br0", "lease_seconds": 3600}, "bindings": {}}\n' >"${INSTALLED_ROOT}/dhcp/state.json"
    printf '# Managed by o3k-dhcp; do not edit.\ninterface=o3k-br0\n' >"${INSTALLED_ROOT}/dhcp/dnsmasq.conf"
    build_db "${INSTALLED_ROOT}/o3k.sqlite"
    seed_db "${INSTALLED_ROOT}/o3k.sqlite"
}
setup_installed_fixture
collect_root "${INSTALLED_ROOT}" "${WORK_DIR}/installed-layout.json"
python3 - "${WORK_DIR}/installed-layout.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "available", value
assert value["managed_state"]["status"] == "available", value["managed_state"]
paths = {e["path"] for e in value["managed_state"]["entries"]}
assert "dhcp/state.json" in paths, paths
assert "network/ownership.json" in paths, paths
assert "agent-id" in paths, paths
# The ledger is covered by the durable section, never hashed as managed state.
assert not any(p.startswith("o3k.sqlite") for p in paths), paths
assert value["durable"]["status"] == "available", value["durable"]
assert value["durable"]["live_resources"] == [], value["durable"]["live_resources"]
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/installed-layout.json" --after "${WORK_DIR}/installed-layout.json" \
    --scope installed-layout --expect-state-root present \
    --out "${WORK_DIR}/installed-layout-verdict.json"
python3 - "${WORK_DIR}/installed-layout-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "passed", value
assert value["owned_leaks"] == [], value["owned_leaks"]
assert value["inconsistencies"] == [], value["inconsistencies"]
PY

# --- 11. secret-bearing values cannot enter result JSON ----------------------
for file in "${WORK_DIR}"/*.json; do
    if grep -q 'do-not-upload-this-value' "${file}"; then
        fail "secret value leaked into ${file}"
    fi
done
printf 'the password is do-not-upload-this-value\n' >"${CANARY_FILE}"
collect "${WORK_DIR}/secret-canary.json"
if grep -q 'do-not-upload-this-value' "${WORK_DIR}/secret-canary.json"; then
    fail "canary content leaked into the inventory"
fi

# --- 12. negative-stale fixture ----------------------------------------------
printf 'injected stale artifact\n' >"${ARTIFACT_ROOT}/.77777777-7777-7777-7777-777777777777.part"
collect "${WORK_DIR}/stale-injected.json"
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/stale-injected.json" \
    --scope stale-inject --expect-state-root present \
    --out "${WORK_DIR}/stale-inject-verdict.json" || true
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" negative-stale \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/stale-injected.json" \
    --out "${WORK_DIR}/negative-stale-2.json" || true
python3 - "${WORK_DIR}/stale-inject-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed", value
assert any(
    entry["identity"] == "agent-id.artifacts/.77777777-7777-7777-7777-777777777777.part"
    for entry in value["owned_leaks"]
), value
PY
python3 - "${WORK_DIR}/negative-stale-2.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "passed", value
assert value["expected"] == "failed" and value["observed"] == "failed", value
assert value["stale_artifact_detected"] is True, value
assert not any(
    str(o.get("kind", "")).startswith("canary:") for o in value["stale_objects"]
), value
PY
rm -f "${ARTIFACT_ROOT}/.77777777-7777-7777-7777-777777777777.part"

# --- 13. negative-foreign fixture --------------------------------------------
O3K_FAKE_CANARY_LINK_CHANGED=true collect "${WORK_DIR}/link-mutated.json"
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/link-mutated.json" \
    --scope link-mut --expect-state-root present \
    --out "${WORK_DIR}/link-mut-verdict.json" || true
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" negative-foreign \
    --baseline "${WORK_DIR}/base-a.json" --after "${WORK_DIR}/link-mutated.json" \
    --out "${WORK_DIR}/negative-foreign-2.json" || true
python3 - "${WORK_DIR}/link-mut-verdict.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "failed", value
assert any(
    entry["kind"] == "canary:network_links"
    and entry["identity"] == "canary-link0"
    for entry in value["foreign_changes"]
), value
PY
python3 - "${WORK_DIR}/negative-foreign-2.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["expected"] == "failed" and value["observed"] == "failed", value
assert value["foreign_mutation_detected"] is True, value
PY

# --- 14. aggregate: passes only when all scopes valid ------------------------
collect "${WORK_DIR}/final-clean-a.json"
collect "${WORK_DIR}/final-clean-b.json"
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/final-clean-a.json" --after "${WORK_DIR}/final-clean-b.json" \
    --scope normal-e2e --expect-state-root present \
    --source-commit deadbeefcafebabe --runner runner-7 \
    --out "${WORK_DIR}/normal.json" || true
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" compare \
    --baseline "${WORK_DIR}/final-clean-a.json" --after "${WORK_DIR}/final-clean-b.json" \
    --scope scenario-1 --expect-state-root present \
    --source-commit deadbeefcafebabe --runner runner-7 \
    --out "${WORK_DIR}/scenario-1.json" || true
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" negative-stale \
    --baseline "${WORK_DIR}/final-clean-a.json" --after "${WORK_DIR}/stale-injected.json" \
    --source-commit deadbeefcafebabe --runner runner-7 \
    --out "${WORK_DIR}/neg-stale.json" || true
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" negative-foreign \
    --baseline "${WORK_DIR}/final-clean-a.json" --after "${WORK_DIR}/mutated-after.json" \
    --source-commit deadbeefcafebabe --runner runner-7 \
    --out "${WORK_DIR}/neg-foreign.json" || true
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" aggregate \
    --normal "${WORK_DIR}/normal.json" \
    --results "${WORK_DIR}/scenario-1.json" "${WORK_DIR}/neg-stale.json" "${WORK_DIR}/neg-foreign.json" \
    --source-commit deadbeefcafebabe --runner runner-7 --started-at 1 \
    --out "${WORK_DIR}/resource-leak-result.json" || true
python3 - "${WORK_DIR}/resource-leak-result.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["artifact_type"] == "resource-leak-result", value
assert value["schema_version"] == 2, value
assert value["status"] == "passed", value
assert value["normal_e2e"]["status"] == "passed" and value["normal_e2e"]["cleanup_verified"] is True
assert value["failure_recovery"]["scenario_count"] == 1
assert value["failure_recovery"]["scenario_pass_count"] == 1
assert value["negative_tests"] == {"stale_artifact_detected": True, "foreign_mutation_detected": True}, value
assert value["cleanup"]["status"] == "passed"
assert value["source_commit"] == "deadbeefcafebabe" and value["runner"] == "runner-7"
assert value["started_at"] == 1 and isinstance(value["finished_at"], int)
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" aggregate \
    --normal "${WORK_DIR}/normal.json" \
    --results "${WORK_DIR}/missing-scope.json" \
    --source-commit deadbeefcafebabe --runner runner-7 --started-at 1 \
    --out "${WORK_DIR}/resource-leak-result-blocked.json" || true
python3 - "${WORK_DIR}/resource-leak-result-blocked.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "blocked", value
assert "result_invalid" in value["reason"], value
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" aggregate \
    --normal "${WORK_DIR}/normal.json" \
    --results "${WORK_DIR}/scenario-1.json" "${WORK_DIR}/neg-stale.json" "${WORK_DIR}/neg-foreign.json" \
    --source-commit other-commit --runner runner-7 --started-at 1 \
    --out "${WORK_DIR}/resource-leak-result-mismatch.json" || true
python3 - "${WORK_DIR}/resource-leak-result-mismatch.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "blocked" and value["reason"] == "source_commit_mismatch", value
PY
python3 "${ROOT_DIR}/scripts/real-host-leak-verifier.py" aggregate \
    --normal "${WORK_DIR}/normal.json" \
    --results "${WORK_DIR}/scenario-1.json" \
    --source-commit deadbeefcafebabe --runner runner-7 --started-at 1 \
    --out "${WORK_DIR}/resource-leak-result-no-neg.json" || true || true
python3 - "${WORK_DIR}/resource-leak-result-no-neg.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["status"] == "blocked" and value["reason"] == "negative_evidence_missing", value
PY

echo "real-host leak verifier tests passed"
