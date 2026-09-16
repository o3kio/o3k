#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-guards.XXXXXX")"
trap 'rm -rf -- "${WORK_DIR}"' EXIT
EVIDENCE="${WORK_DIR}/evidence.json"
# The mandatory P15.7 path must remain valid when no Araf endpoint is
# configured at all.  Keep this explicit so a future environment-level
# prerequisite cannot accidentally turn the optional consumer into a gate.
unset O3K_P15_7_ARAF_URL
python3 - "${EVIDENCE}" <<'PY'
import json, sys
sha = "0123456789abcdef0123456789abcdef01234567"
doc = {
  "artifact_type":"o3k-p15-7-scale-composition-evidence", "schema_version":1,
  "phase":"P15.7", "status":"passed", "evidence_tier":"protected-real-host",
  "profile":"small-edge-cloud",
  "tested_source_sha":sha,
  "execution":{"provider":"agent","hypervisor":"libvirt","database_backend":"postgres",
    "real_o3kd":True,"real_auth":True,"real_execution_boundary":True,
    "multiple_real_hosts":True,"block_count":2,"sqlite_parity":True},
  "journey":{"fresh_deployment":True,"init":True,"topology":True,"capacity":True,
    "constrained_placement":True,"add_block_capacity_growth":True,
    "multiple_authenticated_joins":{"status":"passed","count":2,"each_authenticated":True},
    "drain":{"status":"passed","no_new_placement":True,"blockers_observed":True,"evacuation_claimed":False},
    "remove_rejoin_replace":True,"restart_recovery":True,
    "projections_convergent":{"native":True,"openstack":True,
      "araf":{"required":False,"status":"not_configured",
        "reason":"external_consumer_not_provisioned"}}},
  "restart_recovery":{"status":"passed","canonical_state_survived":True,"postgres":True,"sqlite_parity":True},
  "security_negatives":{"unauthenticated_join_rejected":True,"replay_join_rejected":True,
    "cross_tenant_concealment":True,"foreign_state_preserved":True},
  "bootstrap_timing":{"measured":True,"sample_count":3,"boundary":"init request through ready state",
    "excludes_preprovisioned_external_work":True,"claim_scope":"profile-specific-measurement-only"},
  "leak_check":{"status":"passed","owned_leaks":0,"owned_inconsistencies":0,"foreign_state_changes":0},
  "defect_ledger":{"status":"passed","blockers":0,"high":0,"medium":0},
  "claim_validation":{"status":"passed","sources":["README.md","docs/ROADMAP.md",
    "docs/status/current-state.yaml","compatibility/product-profiles.yaml",
    "docs/compatibility/matrix.yaml","docs/architecture/p15-e2d-gap-register.md"],
    "unsupported_claims_preserved":True,"claims":["bounded small-edge profile convergence"]}
}
json.dump(doc, open(sys.argv[1], "w", encoding="utf-8"), indent=2)
PY

env -u O3K_P15_7_ARAF_URL python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}" \
  --expected-source-sha 0123456789abcdef0123456789abcdef01234567 \
  --expected-profile small-edge-cloud
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib
p = pathlib.Path(__import__('sys').argv[1]); d=json.loads(p.read_text())
d["execution"]["provider"] = "fake"; p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "fake provider accepted by P15.7 validator" >&2; exit 1
fi

# Araf is an optional external consumer. An artifact produced with no
# O3K_P15_7_ARAF_URL must remain valid, while a required Araf projection must
# fail closed.
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
d["execution"]["provider"] = "agent"
d["journey"]["projections_convergent"]["araf"] = {
    "required": False, "status": "not_applicable",
    "reason": "external_consumer_not_provisioned"
}
p.write_text(json.dumps(d))
PY
env -u O3K_P15_7_ARAF_URL python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}" \
  --expected-source-sha 0123456789abcdef0123456789abcdef01234567 \
  --expected-profile small-edge-cloud
python3 - "${EVIDENCE}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
d["journey"]["projections_convergent"]["araf"]["required"] = True
p.write_text(json.dumps(d))
PY
if python3 "${ROOT_DIR}/scripts/validate_p15_7_evidence.py" "${EVIDENCE}"; then
  echo "required Araf projection accepted by P15.7 validator" >&2; exit 1
fi

GATE_ARTIFACT_DIR="${WORK_DIR}/gate-artifacts"
if O3K_P15_7_REAL_HOST=1 O3K_PROVIDER=fake \
   O3K_P15_7_SOURCE_SHA=0123456789abcdef0123456789abcdef01234567 \
   O3K_REAL_HOST_ARTIFACT_DIR="${GATE_ARTIFACT_DIR}" \
   bash "${ROOT_DIR}/tests/p15_7_scale_composition.sh"; then
  echo "fake provider accepted by P15.7 gate" >&2; exit 1
fi
python3 - "${GATE_ARTIFACT_DIR}/p15-7-gate-result.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["status"] == "blocked" and doc["reason"] == "provider_mode_not_agent"
assert doc["redacted"] is True
PY
python3 - "${ROOT_DIR}/scripts/p15-7-real-host-journey.sh" <<'PY'
from pathlib import Path
import sys
journey = Path(sys.argv[1]).read_text(encoding="utf-8")
for required in ("virt-install", "qemu-img create", "block-a", "block-b", "block-c", "block-d", "o3k init",
                 "bootstrap/join", "actions/drain", "actions/remove", "docker restart",
                 "capacity_total", "CAPACITY_AFTER_ADD", "drain_blockers", "cargo test --locked -p o3kd",
                 "o3k-p15-7-journey-owned=", "o3k-p15-7-journey-owned-v1",
                 "rm -rf -- \"$WORK_ROOT\"", "second_real_host_required", "assert_owned_domains_absent",
                 "agent-id", "agent identity transfer failed", "/var/lib/o3k-compute/agent-id",
                 "actual_uuid", "DOMAINS+=(\"$d\")", "OVERLAYS+=(\"$overlay\")",
                 "UUIDS[$((${#IPS[@]} - 1))]=\"$(<\"$WORK_ROOT/block-c-uuid\")\"", "provision_vms_bounded", "REPLAY_JOIN_FILE",
                 "join-request.json", "remote_agent_cleanup", "sudo mkdir -- '$remote_stage'", "sudo rm -rf -- '$remote_stage'",
                 "canonical agent identity does not match agent id", "cross_tenant_test_prerequisite_missing",
                 "FOREIGN_PROJECT_ID", "FOREIGN_TOKEN_PROJECT_ID", "foreign token scope mismatch",
                 "foreign project can read workload A", "CROSS_TENANT_CONCEALMENT=true",
                 "record_optional_araf", "external_consumer_not_provisioned", "araf-projection.json",
                 "system_operator_token_required", "O3K_P15_7_OPERATOR_TOKEN_FILE", "O3K_P15_7_OPERATOR_TOKEN", "PROJECT_TOKEN",
                 "xml.etree.ElementTree", "net-dumpxml", "libvirt gateway unavailable",
                 "LIBVIRT_STORAGE_ROOT", "libvirt-storage-owned-v1", "LIBVIRT_QEMU_GROUP",
                 "sudo -n qemu-img create", "cannot stage pinned VM image for libvirt",
                 "qemu-img resize", "VM_DISK_SIZE_GB",
                 "cannot create run-owned libvirt storage workspace", "staged VM image digest mismatch",
                 "cannot stage cloud-init seed for libvirt", "network-config=$WORK_ROOT/network-config-$1",
                 "dhcp4: true", "dhcp6: false", "renderer: networkd", "set-name: eth0",
                 "macaddress: \"$mac\"", "mac=$mac", "net-dhcp-leases", "serial console tail",
                 "--serial \"file,path=$serial\"", "for (i = 1; i <= NF; i++)",
                 "awk '/MemTotal:/ {print int(\\$2/1024); exit}' /proc/meminfo"):
    assert required in journey, required
assert journey.index('[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]]') < journey.index('mkdir -p "$ARTIFACT_DIR" "$WORK_ROOT"')
assert "O3K_P15_7_JOURNEY_COMMAND" not in journey
assert 'operator_curl() {' in journey
assert 'refresh_operator_authority' in journey
assert 'secure_remove_credentials() {' in journey
assert 'secure_remove_credentials "$OPERATOR_CURL_CONFIG" "$SSH_KEY"' in journey
assert 'secure_remove_credentials "$OPERATOR_TOKEN_FILE" "$WORK_ROOT/operator.token"' in journey
assert 'shred --remove --zero --force -- "$secret_file"' in journey
assert 'Authorization: Bearer $PROJECT_TOKEN' in journey
assert 'openstack token issue -f value -c id' in journey
# Prevent recurrence of the bootstrap/identity and cleanup regressions that
# previously made a protected run appear healthier than it was.
assert 'sudo -n test -f "$TLS_ROOT/agents/$required_agent/agent.pem"' in journey
assert '-graft-points "user-data=$WORK_ROOT/user-data-$1" "meta-data=$WORK_ROOT/meta-data-$1"' in journey
assert 'ssh_vm "$ip" "sudo cloud-init status --wait"' in journey
assert 'ssh_vm "$ip" "sudo virsh -c qemu:///system uri"' in journey
assert 'if [[ "$cleanup_failed" == false ]]; then' in journey
assert 'delete_owned_openstack()' in journey
assert 'policy failures are deliberately not treated as absence' in journey
assert 'DRAIN_AGENT="$HOST_A"' in journey
assert '"$HOST_B" != "$HOST_A"' in journey
assert 'JOIN_REGION="${O3K_P15_7_REGION:-}"' in journey
assert '--region RegionOne' not in journey
assert 'resource_class") != "VCPU"' in journey
assert 'OS_WORKLOAD_A="$WORKLOAD_A"' in journey and 'OS_WORKLOAD_B="$WORKLOAD_B"' in journey
assert 'WORKLOAD_IMAGE="${O3K_TESTLAB_IMAGE_PATH:-}"' in journey
assert 'WORKLOAD_IMAGE_MARKER="${WORKLOAD_IMAGE}.o3k-owned"' in journey
assert "o3k-disposable-image-v1" in journey
assert "phase=generic" in journey
assert "araf_projection_prerequisite_missing" not in journey
PY
# libvirt emits both quote styles across supported versions. Keep gateway
# discovery independent of that XML serialization detail.
python3 - <<'PY'
import xml.etree.ElementTree as ET

for xml in (
    "<network><ip address='192.0.2.1' netmask='255.255.255.0'/></network>",
    '<network><ip address="192.0.2.2" netmask="255.255.255.0"/></network>',
):
    root = ET.fromstring(xml)
    gateway = next(
        e.get("address") for e in root.iter()
        if e.tag.rsplit("}", 1)[-1] == "ip" and e.get("address")
    )
    assert gateway.startswith("192.0.2."), gateway
PY
echo "P15.7 validator guards passed"
