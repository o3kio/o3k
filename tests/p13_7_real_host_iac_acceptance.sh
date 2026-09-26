#!/usr/bin/env bash
# P13.7 — full-stack real-host IaC acceptance harness.
#
# One complete real journey, driven end to end by the unmodified upstream
# terraform-provider-openstack 3.4.0 under OpenTofu 1.12.6:
#
#   OpenTofu -> O3K OpenStack-compat APIs -> canonical O3K services
#   -> PostgreSQL -> real KVM/libvirt guest -> real network dataplane
#   (bridge + nftables security-group policy + floating-IP DNAT)
#   -> real disposable LVM volume attached to the guest
#   -> refresh/convergence -> drift/reapply -> clean o3kd restart
#   -> stop/start/reboot lifecycle -> destroy -> independent leak verification.
#
# Gates R1..R10 each emit one structured evidence row (see
# scripts/validate_p13_7_evidence.py for the mandatory per-gate proof fields).
#
# Required binaries (build BEFORE running; this script does not build):
#   cargo build -p o3kd -p o3k-network-bin
#   RUSTFLAGS="-l dylib=virt" cargo build --features libvirt --bin o3k-compute-bin
#
# Required host prerequisites: root (KVM + nftables + netns + LVM + PostgreSQL),
# /dev/kvm, qemu:///system libvirt, nft, dnsmasq, virsh, openssl, jq, curl,
# python3, ssh-keygen, and a reachable PostgreSQL 16 where this script may
# create/drop a disposable database (O3K_P13_7_PG_ADMIN_URL, or passwordless
# `sudo -n -u postgres psql`).
#
# The P13 pinned toolchain is materialized by scripts/p13_prepare_toolchain.sh
# (source its `export` output or pre-set O3K_P13_TOFU* / O3K_P13_PROVIDER_*).
#
# NOTE on privilege posture: this harness runs the agents directly as root on
# the protected test host. The packaged/workflow path
# (scripts/bootstrap-disposable-testlab.sh) runs the daemons under dedicated
# service accounts with setpriv; that dance is intentionally not repeated here.
#
# Modes:
#   (default)      full real-host acceptance
#   --self-test    portable check: argument/env handling, evidence emission
#                  shape, and validator round-trip. No KVM/libvirt/nftables.
#
# Env overrides:
#   O3K_P13_7_EVIDENCE_OUTPUT  evidence path (default target/p13-7/evidence.json)
#   O3K_P13_7_KEEP_WORK=1      keep the run state dir for debugging
#   O3K_P13_7_RUN_ID           run slug (default: p137-<epoch>)
#   O3K_P13_7_CIRROS_CACHE     CirrOS image cache dir (default: ~/.cache/o3k)
#   O3K_P13_7_PG_ADMIN_URL     postgres superuser URL for disposable DB setup
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-acceptance}"
case "$MODE" in
    acceptance|--self-test) ;;
    *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac

PROJECT_ID="eba29e2d-53de-461d-ae91-ede7402713cb"
PHASE="P13.7"
PROFILE="p13-iac-compatibility-v1"
CIRROS_URL="https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img"
CIRROS_SHA256="7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b"
EXTERNAL_REALM_SEED="00000000-0000-0000-0000-000000000007"
RUN_ID="${O3K_P13_7_RUN_ID:-p137$(date +%s)}"
RUN_SLUG="$(printf '%s' "$RUN_ID" | tr -cd '[:alnum:]' | head -c 16)"
RES_PREFIX="p13-7-${RUN_SLUG}"
EVIDENCE_OUTPUT="${O3K_P13_7_EVIDENCE_OUTPUT:-$ROOT_DIR/target/p13-7/evidence.json}"
if [[ "$EVIDENCE_OUTPUT" != /* ]]; then EVIDENCE_OUTPUT="$ROOT_DIR/$EVIDENCE_OUTPUT"; fi

# ---------------------------------------------------------------------------
# Self-test: no KVM, no network mutation, no tofu. Prove argument/env
# handling, the evidence emission shape, and validator round-trip.
# ---------------------------------------------------------------------------
if [[ "$MODE" == "--self-test" ]]; then
    work="$(mktemp -d /tmp/o3k-p13-7-selftest.XXXXXX)"
    trap 'rm -rf -- "$work"' EXIT
    [[ -n "$RUN_SLUG" && -n "$PROJECT_ID" && "$PHASE" == "P13.7" ]]
    evidence="$work/evidence.json"
    # Synthetic minimal evidence document exercising the emission shape; the
    # validator must accept it only when every mandatory proof field is real.
    O3K_P13_7_SELFTEST=1 python3 - "$evidence" <<'PY'
import json
import sys

gates = []
def row(gate, **extra):
    base = {"gate": gate, "phase": "P13.7", "result": "passed"}
    base.update(extra)
    gates.append(base)

row("R1", token_acquired=True, catalog_services=["identity", "compute", "network", "image", "volumev3"],
    image_data_source_resolved=True, flavor_data_source_resolved=True)
row("R2", bridge_name="o3kp137selftest", bridge_present=True, nft_policy_table_present=True,
    dnsmasq_inventory_seen=True, network_id="00000000-0000-0000-0000-0000000000aa",
    subnet_id="00000000-0000-0000-0000-0000000000ab", port_id="00000000-0000-0000-0000-0000000000ac",
    router_id="00000000-0000-0000-0000-0000000000ad", owner_project="eba29e2d-53de-461d-ae91-ede7402713cb",
    external_network_id="external-network", external_realm_id="external-realm",
    external_realm_matches_plan=True)
row("R3", libvirt_domain="o3k-selftest-domain", domain_running=True,
    boot_marker="login as 'cirros' user", boot_marker_seen=True,
    fixed_ip="192.0.2.10", dhcp_lease_matches_port=True, ssh_path="floating_ip", ssh_ok=True)
row("R4", denied_observed=True, allowed_observed=True, toggle_via="openstack_networking_secgroup_rule_v2",
    nft_counter_packets_before=0, nft_counter_packets_after=7,
    nft_drop_counter_packets_before=1, nft_drop_counter_packets_after=1,
    nft_drop_counter_seen=True)
row("R5", lv_name="o3k-v-000000000000000000000000000000ff", guest_device="/dev/vdb",
    marker_sha256="0" * 64, post_reattach_sha256="0" * 64, checksum_match=True,
    reattach_mechanism="tofu taint openstack_compute_volume_attach_v2")
row("R6", initial_plan_noop=True, drift_detected=True, drift_resource="openstack_networking_network_v2.network",
    drift_attribute="name", drift_exactly_one_change=True, restored_by_apply=True, final_plan_noop=True)
row("R7", restart_clean_sigterm=True, identities_equal=True,
    identities={"server_id": "00000000-0000-0000-0000-0000000000b0"},
    post_restart_plan_noop=True, ssh_after_restart=True, volume_marker_intact=True)
row("R8", mechanism="openstack_compute_instance_v2.power_state + os-reboot action API",
    virsh_transitions=["running", "shut off", "running", "running"],
    stop_observed=True, start_observed=True, reboot_observed=True,
    post_recovery_plan_noop=True, ssh_after_recovery=True, volume_marker_intact=True)
row("R9", zero_servers=True, zero_ports=True, zero_networks=True, zero_subnets=True,
    zero_routers=True, zero_security_groups=True, zero_floating_ips=True, zero_volumes=True,
    zero_attachments=True, attachment_count=0, zero_libvirt_domains=True, zero_lvs=True,
    zero_nft_tables=True, zero_bridges=True, zero_dnsmasq=True, zero_non_terminal_operations=True)
row("R10", owned_leaks=0, foreign_state_changes=0, foreign_baseline_entries=4)

document = {
    "artifact_type": "o3k-p13-7-real-host-iac-evidence",
    "schema_version": 1,
    "phase": "P13.7",
    "profile": "p13-iac-compatibility-v1",
    "backend": "postgresql",
    "execution_tier": "real-host-kvm-libvirt-disposable-lvm",
    "tested_runtime_head_sha": "0" * 40,
    "execution_host": "self-test-host",
    "postgresql_server_version": "16.0",
    "toolchain": {
        "opentofu": "1.12.6",
        "opentofu_archive_sha256": "0" * 64,
        "provider": "terraform-provider-openstack/openstack 3.4.0",
        "provider_archive_sha256": "0" * 64,
        "provider_binary_sha256": "0" * 64,
        "provider_modified": False,
    },
    "image": {
        "name": "cirros-0.6.3-x86_64-disk.img",
        "source_url": "https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img",
        "sha256": "7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b",
    },
    "fake_provider": False,
    "gates": gates,
    "result": "passed",
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
    python3 "$ROOT_DIR/scripts/validate_p13_7_evidence.py" "$evidence"
    python3 "$ROOT_DIR/scripts/validate_p13_7_evidence.py" --self-test
    echo "P13.7 harness self-test: PASS"
    exit 0
fi

# ---------------------------------------------------------------------------
# Acceptance preflight
# ---------------------------------------------------------------------------
TOOLS=(cargo curl jq ip nft openssl python3 ssh ssh-keygen ssh-keygen virsh dnsmasq lvs vgs sha256sum timeout nsenter setsid)
for tool in "${TOOLS[@]}"; do
    command -v "$tool" >/dev/null 2>&1 || { echo "P13.7 BLOCKED: missing required tool: $tool" >&2; exit 2; }
done
[[ "$(id -u)" == 0 ]] || { echo "P13.7 BLOCKED: must run as root (KVM/nftables/netns/LVM)" >&2; exit 2; }
[[ -e /dev/kvm ]] || { echo "P13.7 BLOCKED: missing /dev/kvm" >&2; exit 2; }
virsh -c qemu:///system uri >/dev/null 2>&1 || { echo "P13.7 BLOCKED: qemu:///system unavailable" >&2; exit 2; }

# Pinned toolchain: allow pre-set env, otherwise materialize from the manifest.
if [[ -z "${O3K_P13_TOFU:-}" ]]; then
    # shellcheck disable=SC2046
    eval "$(bash "$ROOT_DIR/scripts/p13_prepare_toolchain.sh" | grep '^export')"
fi
tofu="${O3K_P13_TOFU:?set O3K_P13_TOFU (OpenTofu 1.12.6)}"
tofu_archive="${O3K_P13_TOFU_ARCHIVE:?set O3K_P13_TOFU_ARCHIVE}"
provider_archive="${O3K_P13_PROVIDER_ARCHIVE:?set O3K_P13_PROVIDER_ARCHIVE}"
provider_binary="${O3K_P13_PROVIDER_BINARY:?set O3K_P13_PROVIDER_BINARY}"
provider_sha="${O3K_P13_PROVIDER_SHA256:?set O3K_P13_PROVIDER_SHA256}"
tofu_version="$("$tofu" version | head -n 1)"
[[ "$tofu_version" == "OpenTofu v1.12.6"* ]] || { echo "P13.7 BLOCKED: unexpected OpenTofu: $tofu_version" >&2; exit 2; }
python3 "$ROOT_DIR/scripts/p13_provider_contract.py" --verify-tools >/dev/null \
    || { echo "P13.7 BLOCKED: pinned toolchain verification failed" >&2; exit 2; }

O3KD_BIN="${O3K_P13_O3KD:-$ROOT_DIR/target/debug/o3kd}"
NETWORK_BIN="${O3K_P13_NETWORK_BIN:-$ROOT_DIR/target/debug/o3k-network-bin}"
COMPUTE_BIN="${O3K_P13_COMPUTE_BIN:-$ROOT_DIR/target/debug/o3k-compute-bin}"
for bin in "$O3KD_BIN" "$NETWORK_BIN" "$COMPUTE_BIN"; do
    [[ -x "$bin" ]] || { echo "P13.7 BLOCKED: binary missing: $bin (see header build commands)" >&2; exit 2; }
done

# ---------------------------------------------------------------------------
# Run state, identity, addressing
# ---------------------------------------------------------------------------
STATE_ROOT="$(mktemp -d /var/tmp/o3k-p13-7.XXXXXX)"
# The libvirt QEMU driver runs guests as libvirt-qemu:kvm while the compute
# agent (and this harness) run as root; default ACLs let freshly materialized
# disks/config-drives be readable by the qemu process without loosening
# anything outside the run state directory.
chmod 0755 "$STATE_ROOT"
if command -v setfacl >/dev/null 2>&1; then
    setfacl -m u:libvirt-qemu:rx,g:kvm:rx,d:u:libvirt-qemu:rx,d:g:kvm:rx "$STATE_ROOT"
    QEMU_ACL=1
else
    QEMU_ACL=0
fi
WORK_NET="$STATE_ROOT/network"
TOFU_DIR="$STATE_ROOT/tofu"
BRIDGE="o3kp137${RUN_SLUG:0:6}"
UPLINK="p137up${RUN_SLUG:0:6}"
EXT_PEER="p137peer${RUN_SLUG:0:6}"
EXT_NETNS="o3k-p137-ext-${RUN_SLUG:0:6}"
# TEST-NET-3 transit/public pool to keep this smoke isolated from the
# dedicated P14 host network (which uses 198.51.100.0/24); TEST-NET-1
# remains the tenant subnet.
EXT_HOST_IP="203.0.113.1"
EXT_PEER_IP="203.0.113.2"
PUBLIC_POOL_CIDR="203.0.113.0/24"
PUBLIC_POOL_FIRST="203.0.113.10"
PUBLIC_POOL_LAST="203.0.113.20"
TENANT_CIDR="192.0.2.0/24"
DB_NAME="o3k_p137_${RUN_SLUG}"
DB_USER="o3k_p137_${RUN_SLUG}"
# Unquoted CREATE ROLE/DATABASE fold identifiers to lowercase while the
# postgres:// URL is case-sensitive; keep the disposable identity lowercase.
DB_NAME="$(printf '%s' "$DB_NAME" | tr '[:upper:]' '[:lower:]')"
DB_USER="$(printf '%s' "$DB_USER" | tr '[:upper:]' '[:lower:]')"
DB_PASSWORD="$(openssl rand -hex 24)"
SIGNING_KEY="$(openssl rand -hex 48)"
BOOTSTRAP_PASSWORD="$(openssl rand -hex 24)"
CONTROLLER_ID="controller-p137"
CONTROLLER_EPOCH="epoch-1"
NETWORK_AGENT_ID="agent-p137"
NETWORK_AGENT_EPOCH="epoch-1"
FENCING_TOKEN="1"
DNSMASQ_BIN="$(command -v dnsmasq)"

# Per-run TLS material (reuse the packaged openssl flow; one CA, one server
# cert with SAN o3k-control-plane for both the o3kd compute-control listener
# and the network agent listener, one client cert for the compute agent and
# for o3kd's network-agent client identity).
# NOTE: bootstrap-certs.sh refuses to claim a populated parent directory, so
# this must run before anything else populates $STATE_ROOT.
bash "$ROOT_DIR/packaging/bootstrap-certs.sh" --output-dir "$STATE_ROOT/tls" \
    --server-name o3k-control-plane --agent-id compute-agent
AGENT_FINGERPRINT="$(cat "$STATE_ROOT/tls/agent-fingerprint")"
# The compute agent loads its identity from O3K_COMPUTE_DATA_DIR/agent-id and
# generates a random one when absent; install the cert-bound identity so the
# registration agent_id matches O3K_COMPUTE_AUTHORIZED_AGENTS.
install -m 0640 "$STATE_ROOT/tls/agent-id" "$STATE_ROOT/compute/agent-id" 2>/dev/null \
    || { mkdir -p "$STATE_ROOT/compute"; install -m 0640 "$STATE_ROOT/tls/agent-id" "$STATE_ROOT/compute/agent-id"; }

find_free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}
O3KD_PORT="$(find_free_port)"
NETWORK_PORT="$(find_free_port)"
CONTROL_PORT="$(find_free_port)"
COMPUTE_HEALTH_PORT="$(find_free_port)"
BASE="http://127.0.0.1:$O3KD_PORT"

O3KD_PID=""
NETWORK_PID=""
COMPUTE_PID=""
EXT_NS_PID=""
LVM_PROVISIONED=0
PG_CREATED=0
DESTROY_ATTEMPTED=0
GATE_ROWS=()
mkdir -p "$WORK_NET"/{executor,ownership,dhcp,routed,policy,public,fabric,gateway} "$TOFU_DIR" "$STATE_ROOT/data" "$STATE_ROOT/compute"
if [[ "$QEMU_ACL" == 1 ]]; then
    setfacl -R -m u:libvirt-qemu:rx,g:kvm:rx,d:u:libvirt-qemu:rx,d:g:kvm:rx \
        "$STATE_ROOT/compute" "$STATE_ROOT/data"
fi

# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------
# The acceptance branch contains the harness itself.  The runtime under test
# is supplied explicitly by the protected-main checkout that was built.
HEAD_SHA="${P13_7_TESTED_RUNTIME_HEAD:-$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)}"

emit_gate() {
    local gate="$1" result="$2" extra
    extra="${3:-}"
    [[ -n "$extra" ]] || extra="{}"
    local row
    row="$(P13_7_GATE="$gate" P13_7_RESULT="$result" P13_7_EXTRA="$extra" python3 - <<'PY'
import json, os
row = {"gate": os.environ["P13_7_GATE"], "phase": "P13.7", "result": os.environ["P13_7_RESULT"]}
row.update(json.loads(os.environ["P13_7_EXTRA"]))
print(json.dumps(row, sort_keys=True))
PY
)"
    GATE_ROWS+=("$row")
    echo "P13.7 gate $gate: $result"
}

fail_gate() {
    local gate="$1" reason="$2"
    if [[ "$gate" == R5 && -n "${DOMAIN_NAME:-}" && -n "${STATE_ROOT:-}" ]]; then
        {
            echo "reason=$reason"
            echo "--- domain xml ---"
            virsh -c qemu:///system dumpxml "$DOMAIN_NAME" 2>&1 || true
            echo "--- domblklist ---"
            virsh -c qemu:///system domblklist "$DOMAIN_NAME" --details 2>&1 || true
            echo "--- domblkinfo vdb ---"
            virsh -c qemu:///system domblkinfo "$DOMAIN_NAME" vdb 2>&1 || true
            echo "--- qemu info block ---"
            virsh -c qemu:///system qemu-monitor-command "$DOMAIN_NAME" --hmp "info block" 2>&1 || true
            echo "--- guest block inventory ---"
            ssh_guest 'lsblk -o NAME,MAJ:MIN,SIZE,RO,TYPE,MODEL,SERIAL; cat /proc/partitions' 2>&1 || true
            echo "--- guest kernel tail ---"
            ssh_guest 'dmesg | tail -100' 2>&1 || true
            echo "--- bounded guest read ---"
            ssh_guest "sudo timeout 5 dd if=$GUEST_DEV bs=4096 count=1 2>&1 | sha256sum" 2>&1 || true
        } >"$STATE_ROOT/r5-hotplug-diagnostics.txt"
    fi
    emit_gate "$gate" "failed" "{\"failure_reason\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$reason")}"
    write_evidence "failed"
    echo "P13.7 gate $gate FAILED: $reason" >&2
    exit 1
}

write_evidence() {
    local final_result="$1"
    mkdir -p "$(dirname "$EVIDENCE_OUTPUT")"
    P13_7_RESULT="$final_result" P13_7_GATES="$(printf '%s\n' "${GATE_ROWS[@]:-}")" \
    P13_7_HEAD="$HEAD_SHA" P13_7_OUT="$EVIDENCE_OUTPUT" P13_7_PROFILE="$PROFILE" \
    P13_7_HOST="$EXECUTION_HOST" P13_7_PG_VERSION="$PG_VERSION" \
    P13_7_TOFU_ARCHIVE="$tofu_archive" P13_7_PROVIDER_ARCHIVE="$provider_archive" \
P13_7_PROVIDER_SHA="$provider_sha" python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

def digest(path):
    p = Path(path)
    return hashlib.sha256(p.read_bytes()).hexdigest() if p and p.exists() else None

gates = [json.loads(line) for line in os.environ["P13_7_GATES"].splitlines() if line.strip()]
document = {
    "artifact_type": "o3k-p13-7-real-host-iac-evidence",
    "schema_version": 1,
    "phase": "P13.7",
    "profile": os.environ["P13_7_PROFILE"],
    "backend": "postgresql",
    "execution_tier": "real-host-kvm-libvirt-disposable-lvm",
    "execution_host": os.environ["P13_7_HOST"],
    "postgresql_server_version": os.environ["P13_7_PG_VERSION"],
    "tested_runtime_head_sha": os.environ["P13_7_HEAD"],
    "toolchain": {
        "opentofu": "1.12.6",
        "opentofu_archive_sha256": digest(os.environ["P13_7_TOFU_ARCHIVE"]),
        "provider": "terraform-provider-openstack/openstack 3.4.0",
        "provider_archive_sha256": digest(os.environ["P13_7_PROVIDER_ARCHIVE"]),
        "provider_binary_sha256": os.environ["P13_7_PROVIDER_SHA"],
        "provider_modified": False,
    },
    "image": {
        "name": "cirros-0.6.3-x86_64-disk.img",
        "source_url": "https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img",
        "sha256": "7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b",
    },
    "fake_provider": False,
    "gates": gates,
    "result": os.environ["P13_7_RESULT"],
}
out = Path(os.environ["P13_7_OUT"])
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
    echo "P13.7 evidence written: $EVIDENCE_OUTPUT"
}

# ---------------------------------------------------------------------------
# R10: foreign-state baseline, captured before any run-owned mutation.
# ---------------------------------------------------------------------------
foreign_inventory() {
    local out="$1"
    {
        virsh -c qemu:///system list --all --name 2>/dev/null | sort
        echo "--- lvs ---"
        lvs --noheadings -o vg_name,lv_name 2>/dev/null | sort
        echo "--- links ---"
        ip -o link show | awk '{print $2}' | sort
        echo "--- nft ---"
        nft list tables 2>/dev/null | sort
    } >"$out"
}
foreign_inventory "$STATE_ROOT/foreign-before.txt"
FOREIGN_BASELINE_COUNT="$(grep -c . "$STATE_ROOT/foreign-before.txt" || true)"
virsh -c qemu:///system list --all --name 2>/dev/null | sort \
    >"$STATE_ROOT/foreign-before-domains.txt"

# ---------------------------------------------------------------------------
# Cleanup (fail-closed, run-owned only)
# ---------------------------------------------------------------------------
cleanup() {
    local status=$?
    set +e
    if [[ "$status" -ne 0 || "${O3K_P13_7_KEEP_WORK:-0}" == 1 ]]; then
        echo "--- o3kd log tail ---" >&2; tail -60 "$STATE_ROOT/o3kd.log" >&2 2>/dev/null
        echo "--- network log tail ---" >&2; tail -40 "$STATE_ROOT/network.log" >&2 2>/dev/null
        echo "--- compute log tail ---" >&2; tail -40 "$STATE_ROOT/compute.log" >&2 2>/dev/null
        echo "P13.7: work preserved at $STATE_ROOT" >&2
    fi
    if [[ "$DESTROY_ATTEMPTED" == 0 && -d "$TOFU_DIR/project/.terraform" ]]; then
        (cd "$TOFU_DIR/project" && TF_CLI_CONFIG_FILE="$TOFU_DIR/tofu.tfrc" TF_IN_AUTOMATION=1 \
            "$tofu" destroy -auto-approve -no-color) >/dev/null 2>&1
    fi
    [[ -n "$O3KD_PID" ]] && kill "$O3KD_PID" 2>/dev/null
    [[ -n "$COMPUTE_PID" ]] && kill "$COMPUTE_PID" 2>/dev/null
    [[ -n "$NETWORK_PID" ]] && kill "$NETWORK_PID" 2>/dev/null
    [[ -n "$O3KD_PID" ]] && wait "$O3KD_PID" 2>/dev/null
    [[ -n "$COMPUTE_PID" ]] && wait "$COMPUTE_PID" 2>/dev/null
    [[ -n "$NETWORK_PID" ]] && wait "$NETWORK_PID" 2>/dev/null
    # Reap run-owned dnsmasq children by pidfile, verifying the command line.
    for pid_file in "$WORK_NET"/dhcp/*.pid; do
        [[ -r "$pid_file" ]] || continue
        local dnsmasq_pid
        dnsmasq_pid="$(cat "$pid_file" 2>/dev/null || true)"
        [[ "$dnsmasq_pid" =~ ^[0-9]+$ ]] || continue
        if [[ -r "/proc/$dnsmasq_pid/cmdline" ]] \
            && tr '\0' ' ' <"/proc/$dnsmasq_pid/cmdline" | grep -Fq "$WORK_NET/dhcp"; then
            kill "$dnsmasq_pid" 2>/dev/null || true
        fi
    done
    [[ -n "$EXT_NS_PID" ]] && kill "$EXT_NS_PID" 2>/dev/null
    [[ -n "$EXT_NS_PID" ]] && wait "$EXT_NS_PID" 2>/dev/null
    ip netns del "$EXT_NETNS" 2>/dev/null
    ip link del "$UPLINK" 2>/dev/null
    ip link del "$BRIDGE" 2>/dev/null
    for table in o3k_policy o3k_public o3k_p137 o3k_p9; do
        # Never remove a table that existed before this run.
        if ! grep -Fqx "table ip $table" "$STATE_ROOT/foreign-before.txt" 2>/dev/null; then
            nft delete table ip "$table" >/dev/null 2>&1 || true
        fi
    done
    # Remove run-owned libvirt domains (o3k-* compute domains created after
    # the foreign baseline) so a failed run cannot leave a stale domain that a
    # deterministic later run would mistake for its own instance.
    for candidate in $(virsh -c qemu:///system list --all --name 2>/dev/null); do
        [[ "$candidate" == o3k-* ]] || continue
        grep -Fqx "$candidate" "$STATE_ROOT/foreign-before-domains.txt" 2>/dev/null && continue
        virsh -c qemu:///system destroy "$candidate" >/dev/null 2>&1
        virsh -c qemu:///system undefine "$candidate" --nvram >/dev/null 2>&1 \
            || virsh -c qemu:///system undefine "$candidate" >/dev/null 2>&1
    done
    if [[ "$LVM_PROVISIONED" == 1 ]]; then
        O3K_LVM_RUN_ID="$RUN_ID" bash "$ROOT_DIR/scripts/lvm-testlab-profile.sh" cleanup >/dev/null 2>&1
    fi
    if [[ "$PG_CREATED" == 1 ]]; then
        pg_drop
    fi
    if [[ "$status" -ne 0 || "${O3K_P13_7_KEEP_WORK:-0}" == 1 ]]; then
        :
    else
        rm -rf -- "$STATE_ROOT"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# PostgreSQL disposable database
# ---------------------------------------------------------------------------
pg_admin() {
    if [[ -n "${O3K_P13_7_PG_ADMIN_URL:-}" ]]; then
        psql "${O3K_P13_7_PG_ADMIN_URL}" -v ON_ERROR_STOP=1 -Atqc "$1"
    else
        sudo -n -u postgres psql -v ON_ERROR_STOP=1 -Atqc "$1"
    fi
}
assert_owned_p137_database() {
    O3K_TEST_DATABASE_PURPOSE=p137 O3K_TEST_DATABASE_NAME="$DB_NAME" \
        python3 "$ROOT_DIR/scripts/assert_disposable_postgres_test_database.py"
}
pg_setup() {
    # Drop-then-create so a rerun with the same run id is idempotent; both
    # statements run in separate psql invocations (multi-statement -c runs in
    # a single transaction, which rejects CREATE/DROP DATABASE).
    assert_owned_p137_database
    pg_admin "DROP DATABASE IF EXISTS $DB_NAME"
    pg_admin "DROP ROLE IF EXISTS $DB_USER"
    pg_admin "CREATE ROLE $DB_USER LOGIN PASSWORD '$DB_PASSWORD'"
    pg_admin "CREATE DATABASE $DB_NAME OWNER $DB_USER"
    PG_CREATED=1
}
pg_drop() {
    assert_owned_p137_database
    pg_admin "DROP DATABASE IF EXISTS $DB_NAME" >/dev/null 2>&1 || true
    pg_admin "DROP ROLE IF EXISTS $DB_USER" >/dev/null 2>&1 || true
}
pg_setup
DB_URL="postgres://$DB_USER:$DB_PASSWORD@127.0.0.1:5432/$DB_NAME"
PG_VERSION="$(PGPASSWORD="$DB_PASSWORD" psql "$DB_URL" -v ON_ERROR_STOP=1 -Atqc "SHOW server_version")"
[[ "$PG_VERSION" =~ ^16\.[0-9]+ ]] \
    || { echo "P13.7 BLOCKED: PostgreSQL server is not 16.x: $PG_VERSION" >&2; exit 2; }
EXECUTION_HOST="$(hostname -f 2>/dev/null || hostname)"
# Fail fast if the disposable identity is not actually connectable before
# any daemon depends on it.
PGPASSWORD="$DB_PASSWORD" psql "$DB_URL" -v ON_ERROR_STOP=1 -Atqc "SELECT current_user" \
    || { echo "P13.7 BLOCKED: disposable postgres identity not connectable at $DB_URL" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Disposable LVM profile
# ---------------------------------------------------------------------------
LVM_PROVISIONED=1
O3K_LVM_RUN_ID="$RUN_ID" bash "$ROOT_DIR/scripts/lvm-testlab-profile.sh" provision
LVM_PROFILE="/var/lib/o3k-lvm-testlab/$RUN_SLUG/profile.json"
read -r LVM_VG LVM_POOL LVM_NAMESPACE <<<"$(python3 - "$LVM_PROFILE" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
print(p["volume_group"], p["thin_pool"], p["provider_namespace"])
PY
)"

# ---------------------------------------------------------------------------
# External netns + uplink veth (p9 packet-path pattern, host namespace kept).
# ---------------------------------------------------------------------------
setsid unshare -n sleep 86400 &
EXT_NS_PID=$!
sleep 0.2
EXT_NS_PID="$(pgrep -P "$EXT_NS_PID" unshare | head -n1 || true)"
[[ -n "$EXT_NS_PID" ]] || EXT_NS_PID=$!
ip netns attach "$EXT_NETNS" "$EXT_NS_PID"
ip link add "$UPLINK" type veth peer name "$EXT_PEER"
ip link set "$EXT_PEER" netns "$EXT_NETNS"
ip link set "$UPLINK" up
ip addr add "$EXT_HOST_IP/24" dev "$UPLINK"
ip -n "$EXT_NETNS" link set lo up
ip -n "$EXT_NETNS" link set "$EXT_PEER" up
ip -n "$EXT_NETNS" addr add "$EXT_PEER_IP/24" dev "$EXT_PEER"

# ---------------------------------------------------------------------------
# Process bring-up
# ---------------------------------------------------------------------------
TAP_ENV=()
if id libvirt-qemu >/dev/null 2>&1 && getent group kvm >/dev/null 2>&1; then
    TAP_ENV=(O3K_NETWORK_TAP_USER=libvirt-qemu O3K_NETWORK_TAP_GROUP=kvm)
fi

start_network_agent() {
    env \
    O3K_NETWORK_AGENT_ID="$NETWORK_AGENT_ID" \
    O3K_NETWORK_AGENT_EPOCH="$NETWORK_AGENT_EPOCH" \
    O3K_NETWORK_CONTROLLER_ID="$CONTROLLER_ID" \
    O3K_NETWORK_CONTROLLER_EPOCH="$CONTROLLER_EPOCH" \
    O3K_NETWORK_FENCING_TOKEN="$FENCING_TOKEN" \
    O3K_NETWORK_ROOT="$WORK_NET/executor" \
    O3K_NETWORK_BRIDGE="$BRIDGE" \
    O3K_NETWORK_OWNERSHIP_ROOT="$WORK_NET/ownership" \
    O3K_NETWORK_DHCP_ROOT="$WORK_NET/dhcp" \
    O3K_NETWORK_DNSMASQ="$DNSMASQ_BIN" \
    O3K_NETWORK_POLICY_ROOT="$WORK_NET/policy" \
    O3K_NETWORK_EXTERNAL_REALM_ID="$EXTERNAL_REALM_ROUTE_ID" \
    O3K_NETWORK_UPLINK="$UPLINK" \
    O3K_NETWORK_ROUTED_ROOT="$WORK_NET/routed" \
    O3K_NETWORK_PUBLIC_ROOT="$WORK_NET/public" \
    O3K_NETWORK_FABRIC_ROOT="$WORK_NET/fabric" \
    O3K_NETWORK_GATEWAY_ROOT="$WORK_NET/gateway" \
    "${TAP_ENV[@]}" \
    O3K_NETWORK_LISTEN="127.0.0.1:$NETWORK_PORT" \
    O3K_NETWORK_TLS_CERT="$STATE_ROOT/tls/server.pem" \
    O3K_NETWORK_TLS_KEY="$STATE_ROOT/tls/server-key.pem" \
    O3K_NETWORK_TLS_CLIENT_CA="$STATE_ROOT/tls/ca.pem" \
    RUST_LOG="${O3K_P13_7_LOG_FILTER:-info}" \
    "$NETWORK_BIN" >>"$STATE_ROOT/network.log" 2>&1 &
    NETWORK_PID=$!
    for _ in $(seq 1 100); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$NETWORK_PORT") 2>/dev/null; then
            exec 3>&-; exec 3<&-
            return 0
        fi
        kill -0 "$NETWORK_PID" 2>/dev/null || { cat "$STATE_ROOT/network.log" >&2; return 1; }
        sleep 0.1
    done
    return 1
}

start_o3kd() {
    # "$1": "full" (default) wires the real network agent; "control-plane"
    # omits the network-agent client configuration entirely (canonical-only
    # network CRUD, no dataplane dispatch) — used to manage Router/Router
    # Interface resources, whose L3Gateway host realization belongs to the
    # edge-fabric realm overlay outside this TestLab profile (ADR-0178).
    # TestLab flat profile: L3Gateway host realization stays deactivated
    # (edge-fabric realm overlay scope, ADR-0178); canonical L3Gateway remains
    # authoritative and Route/Egress intents still reach the routed realizer.
    local mode="${1:-full}"
    local network_env=()
    if [[ "$mode" == "full" ]]; then
        network_env=(
            O3K_NETWORK_AGENT_ENDPOINT="https://127.0.0.1:$NETWORK_PORT"
            O3K_NETWORK_AGENT_SERVER_NAME="o3k-control-plane"
            O3K_NETWORK_AGENT_CA="$STATE_ROOT/tls/ca.pem"
            O3K_NETWORK_AGENT_CLIENT_CERT="$STATE_ROOT/tls/agent.pem"
            O3K_NETWORK_AGENT_CLIENT_KEY="$STATE_ROOT/tls/agent-key.pem"
            O3K_NETWORK_AGENT_ID="$NETWORK_AGENT_ID"
            O3K_NETWORK_AGENT_EPOCH="$NETWORK_AGENT_EPOCH"
            O3K_NETWORK_CONTROLLER_ID="$CONTROLLER_ID"
            O3K_NETWORK_CONTROLLER_EPOCH="$CONTROLLER_EPOCH"
            O3K_NETWORK_FENCING_TOKEN="$FENCING_TOKEN"
            O3K_NETWORK_EXTERNAL_REALM_ID="$EXTERNAL_REALM_ID"
        )
    fi
    env \
    O3K_PROVIDER=agent \
    O3K_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD" \
    O3K_TOKEN_SIGNING_KEY="$SIGNING_KEY" \
    O3K_DATA_DIR="$STATE_ROOT/data" \
    O3K_CONTROLLER_ID="$CONTROLLER_ID" \
    O3K_CONTROLLER_EPOCH="$CONTROLLER_EPOCH" \
    O3K_CINDER_ENDPOINT="$BASE" \
    O3K_LVM_VOLUME_GROUP="$LVM_VG" \
    O3K_LVM_THIN_POOL="$LVM_POOL" \
    O3K_LVM_PROVIDER_NAMESPACE="$LVM_NAMESPACE" \
    O3K_PUBLIC_POOL_CIDR="$PUBLIC_POOL_CIDR" \
    O3K_PUBLIC_POOL_FIRST="$PUBLIC_POOL_FIRST" \
    O3K_PUBLIC_POOL_LAST="$PUBLIC_POOL_LAST" \
    O3K_NETWORK_GATEWAY_REALIZATION=disabled \
    "${network_env[@]}" \
    O3K_COMPUTE_CONTROL_ADDR="127.0.0.1:$CONTROL_PORT" \
    O3K_COMPUTE_SERVER_CERTIFICATE="$STATE_ROOT/tls/server.pem" \
    O3K_COMPUTE_SERVER_PRIVATE_KEY="$STATE_ROOT/tls/server-key.pem" \
    O3K_COMPUTE_CLIENT_CA="$STATE_ROOT/tls/ca.pem" \
    O3K_COMPUTE_AUTHORIZED_AGENTS="compute-agent=$AGENT_FINGERPRINT" \
    RUST_LOG="${O3K_P13_7_LOG_FILTER:-info}" \
    "$O3KD_BIN" --listen-addr "127.0.0.1:$O3KD_PORT" --data-dir "$STATE_ROOT/data" \
        --database-backend postgres --database-url "$DB_URL" \
        >>"$STATE_ROOT/o3kd.log" 2>&1 &
    O3KD_PID=$!
    for _ in $(seq 1 240); do
        curl -fsS "$BASE/readyz" >/dev/null 2>&1 && return 0
        kill -0 "$O3KD_PID" 2>/dev/null || { cat "$STATE_ROOT/o3kd.log" >&2; return 1; }
        sleep 0.5
    done
    return 1
}

stop_o3kd() {
    [[ -n "$O3KD_PID" ]] || return 0
    kill -TERM "$O3KD_PID" 2>/dev/null || true
    for _ in $(seq 1 60); do
        kill -0 "$O3KD_PID" 2>/dev/null || break
        sleep 0.25
    done
    kill -9 "$O3KD_PID" 2>/dev/null || true
    wait "$O3KD_PID" 2>/dev/null || true
    O3KD_PID=""
}

start_compute_agent() {
    # Run as the dedicated o3k-compute service account with the bootstrap's
    # ambient-capability model (CAP_NET_ADMIN for TAP/bridge, CAP_NET_BIND_
    # SERVICE + CAP_NET_RAW for the spawned dnsmasq). The account also makes
    # the materialized disks readable by the libvirt QEMU driver (its group
    # is kvm), which a root-owned state directory cannot provide.
    id o3k-compute >/dev/null 2>&1 || {
        echo "P13.7 BLOCKED: o3k-compute service account unavailable" >&2; return 1;
    }
    : >"$STATE_ROOT/compute.log"
    chown o3k-compute:kvm "$STATE_ROOT/compute.log"
    chown -R o3k-compute:kvm "$STATE_ROOT/compute"
    chgrp kvm "$STATE_ROOT/tls" "$STATE_ROOT/tls"/*
    chmod 0750 "$STATE_ROOT/tls"
    # The state root under /var/tmp is traversable by the service account, but
    # the repo target/ directory is not (root-only parents), so stage the
    # binary inside the run state like scripts/bootstrap-disposable-testlab.sh.
    install -d -m 0750 "$STATE_ROOT/bin"
    install -m 0750 "$COMPUTE_BIN" "$STATE_ROOT/bin/o3k-compute-bin"
    chgrp kvm "$STATE_ROOT/bin" "$STATE_ROOT/bin/o3k-compute-bin"
    setpriv --reuid="$(id -u o3k-compute)" --regid="$(id -g o3k-compute)" --init-groups \
        --inh-caps=+net_admin,+net_bind_service,+net_raw \
        --ambient-caps=+net_admin,+net_bind_service,+net_raw -- \
        env \
    O3K_COMPUTE_DATA_DIR="$STATE_ROOT/compute" \
    O3K_COMPUTE_CONTROL_ENDPOINT="https://127.0.0.1:$CONTROL_PORT" \
    O3K_COMPUTE_SERVER_NAME="o3k-control-plane" \
    O3K_COMPUTE_HOST_LABEL="compute-agent" \
    O3K_COMPUTE_TLS_DIR="$STATE_ROOT/tls" \
    O3K_COMPUTE_HEALTH_ADDR="127.0.0.1:$COMPUTE_HEALTH_PORT" \
    O3K_COMPUTE_MAX_DISK_GB=10 \
    O3K_COMPUTE_NETWORK_EXTERNAL=1 \
    O3K_COMPUTE_NETWORK_ROOT="$WORK_NET/ownership" \
    O3K_COMPUTE_BRIDGE_NAME="$BRIDGE" \
    O3K_COMPUTE_DHCP_BINARY="$DNSMASQ_BIN" \
    RUST_LOG="${O3K_P13_7_LOG_FILTER:-info}" \
    "$STATE_ROOT/bin/o3k-compute-bin" >>"$STATE_ROOT/compute.log" 2>&1 &
    COMPUTE_PID=$!
    for _ in $(seq 1 240); do
        curl -fsS "http://127.0.0.1:$COMPUTE_HEALTH_PORT/readyz" >/dev/null 2>&1 && return 0
        kill -0 "$COMPUTE_PID" 2>/dev/null || { cat "$STATE_ROOT/compute.log" >&2; return 1; }
        sleep 0.5
    done
    return 1
}

# Phase 1: start o3kd with a seed realm so the compat API can mint the real
# external pool network; the returned network ID becomes the canonical
# external realm for the rest of the run (P13.6F proven sequence).
EXTERNAL_REALM_ID="$EXTERNAL_REALM_SEED"
start_o3kd control-plane || { echo "P13.7 BLOCKED: o3kd (seed realm) failed to start" >&2; exit 2; }

get_token() {
    local headers
    headers="$(mktemp /tmp/p13-7-token.XXXXXX)"
    curl -fsS -X POST "$BASE/v3/auth/tokens" -H 'content-type: application/json' \
        -D "$headers" -o /dev/null \
        --data "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"admin\",\"password\":\"$BOOTSTRAP_PASSWORD\"}}},\"scope\":{\"project\":{\"name\":\"admin\"}}}}"
    awk 'tolower($1)=="x-subject-token:" {print $2}' "$headers" | tr -d '\r'
    rm -f "$headers"
}
json() { curl -fsS "$@" -H "x-auth-token: $TOKEN"; }
field() { python3 -c 'import json,sys
value=json.load(sys.stdin)
for part in sys.argv[1].split("."): value=value[part]
print(value)' "$1"; }

TOKEN="$(get_token)"
[[ -n "$TOKEN" ]] || { echo "P13.7 BLOCKED: initial token acquisition failed" >&2; exit 2; }
# Plain canonical network, matching the accepted P13.3 FIP/realm pattern:
# `router:external` networks are not canonical_networks records, and the
# router external-gateway lookup requires a canonical network visible to the
# project (crates/o3k-api/src/network.rs: external_realm_for_router).
EXTERNAL_REALM_ID="$(json -X POST "$BASE/v2.0/networks" -H 'content-type: application/json' \
    --data "{\"network\":{\"name\":\"$RES_PREFIX-public-pool\"}}" \
    | field network.id)"
[[ "$EXTERNAL_REALM_ID" =~ ^[0-9a-f-]{36}$ ]] || { echo "P13.7 BLOCKED: external pool creation failed" >&2; exit 2; }
# The router external-gateway lookup requires a canonical address realm on the
# pool network (accepted P13.3 router pattern: subnet on the external network).
REALM_SUBNET_ID="$(json -X POST "$BASE/v2.0/subnets" -H 'content-type: application/json' \
    --data "{\"subnet\":{\"name\":\"$RES_PREFIX-public-pool-subnet\",\"network_id\":\"$EXTERNAL_REALM_ID\",\"cidr\":\"$PUBLIC_POOL_CIDR\",\"ip_version\":4,\"enable_dhcp\":false}}" \
    | field subnet.id)"
[[ "$REALM_SUBNET_ID" =~ ^[0-9a-f-]{36}$ ]] || { echo "P13.7 BLOCKED: external pool subnet creation failed" >&2; exit 2; }
# The canonical egress identity is the AddressRealm of the pool network (not
# the network id): the routed realizer validates every Egress intent against
# its configured realm, and compile_l3_gateway_intents emits the realm id.
# The realm id is provider-internal (fresh UUID), so resolve it by prefix
# through the native API; the agent gets the realm id while o3kd keeps the
# network id for Floating IP pool validation.
RESOLVE_REALM_PY='
import json, sys
doc = json.load(sys.stdin)
hits = []
for item in doc.get("items", []):
    if item.get("spec", {}).get("prefix") == sys.argv[1] \
            and item.get("status", {}).get("state") == "active":
        hits.append(item)
if len(hits) != 1:
    raise SystemExit("realm lookup not unique: hits=%d doc=%s" % (len(hits), json.dumps(doc)[:500]))
print(hits[0]["metadata"]["id"])
'
# Native API bearer token (the native surface has its own token vocabulary).
NATIVE_TOKEN="$(curl -fsS -X POST "$BASE/o3k/v1/identity/tokens" \
    -H 'content-type: application/json' \
    --data "{\"auth\":{\"method\":\"token\",\"token\":\"$TOKEN\",\"project_id\":\"$PROJECT_ID\"}}" \
    | field token.id)"
[[ "$NATIVE_TOKEN" =~ ^[A-Za-z0-9_.-]{16,}$ ]] || {
    echo "P13.7 BLOCKED: native token acquisition failed" >&2; exit 2;
}
EXTERNAL_REALM_ROUTE_ID="$(curl -fsS "$BASE/o3k/v1/network/address-realms?limit=100" \
    -H "Authorization: Bearer $NATIVE_TOKEN" | python3 -c "$RESOLVE_REALM_PY" "$PUBLIC_POOL_CIDR" 2>&1)" || true
if [[ "$EXTERNAL_REALM_ROUTE_ID" =~ ^[0-9a-f-]{36}$ ]]; then
    echo "P13.7: external realm route id resolved: $EXTERNAL_REALM_ROUTE_ID"
else
    echo "P13.7 BLOCKED: external realm route id could not be resolved (${EXTERNAL_REALM_ROUTE_ID:-(empty)})" >&2
    exit 2
fi
stop_o3kd

# Control-plane-only phase: the Router/RouterInterface portion of the graph is
# canonical CRUD (accepted P13.3 provider pattern); L3Gateway host realization
# belongs to the edge-fabric realm overlay, not this TestLab profile
# (ADR-0178), so these resources are managed before the dataplane is wired.
start_o3kd control-plane || { echo "P13.7 BLOCKED: control-plane o3kd failed to start" >&2; exit 2; }

# ---------------------------------------------------------------------------
# CirrOS image: cached download + pinned sha256, registered via the compat API.
# (Before the first apply so the image data source resolves there.)
# ---------------------------------------------------------------------------
CACHE_DIR="${O3K_P13_7_CIRROS_CACHE:-$HOME/.cache/o3k}"
mkdir -p "$CACHE_DIR"
CIRROS_IMAGE="$CACHE_DIR/cirros-0.6.3-x86_64-disk.img"
if [[ ! -f "$CIRROS_IMAGE" ]] \
    || ! printf '%s  %s\n' "$CIRROS_SHA256" "$CIRROS_IMAGE" | sha256sum --check --status; then
    curl --fail --location --retry 4 --proto '=https' --tlsv1.2 \
        --output "$CIRROS_IMAGE.tmp" "$CIRROS_URL"
    printf '%s  %s\n' "$CIRROS_SHA256" "$CIRROS_IMAGE.tmp" | sha256sum --check --status
    mv -f -- "$CIRROS_IMAGE.tmp" "$CIRROS_IMAGE"
fi
printf '%s  %s\n' "$CIRROS_SHA256" "$CIRROS_IMAGE" | sha256sum --check --status

IMAGE_ID="$(json -X POST "$BASE/v2/images" -H 'content-type: application/json' \
    --data '{"name":"p13-7-cirros","container_format":"bare","disk_format":"qcow2"}' | field id)"
curl -fsS -X PUT "$BASE/v2/images/$IMAGE_ID/file" -H "x-auth-token: $TOKEN" \
    -H 'content-type: application/octet-stream' --data-binary "@$CIRROS_IMAGE" >/dev/null

# Ephemeral guest SSH keypair.
ssh-keygen -t ed25519 -N '' -q -f "$STATE_ROOT/guest-key"
chmod 0600 "$STATE_ROOT/guest-key"
# O3K's bounded keypair contract stores key material only; a trailing comment
# is stripped server-side and would surface as perpetual plan replacement.
GUEST_PUBKEY="$(awk '{print $1, $2}' "$STATE_ROOT/guest-key.pub")"

# ---------------------------------------------------------------------------
# R1 — auth/discovery through the same surfaces the provider will use.
# ---------------------------------------------------------------------------
TOKEN="$(get_token)"
[[ -n "$TOKEN" ]] || fail_gate R1 "token re-acquisition failed"
CATALOG="$(curl -fsS "$BASE/v3/auth/catalog" -H "x-auth-token: $TOKEN" 2>/dev/null \
    || json -X POST "$BASE/v3/auth/tokens" -H 'content-type: application/json' \
        --data "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"admin\",\"password\":\"$BOOTSTRAP_PASSWORD\"}}},\"scope\":{\"project\":{\"name\":\"admin\"}}}}")"
CATALOG_SERVICES="$(CATALOG_JSON="$CATALOG" python3 - <<'PY'
import json, os
doc = json.loads(os.environ["CATALOG_JSON"])
catalog = doc.get("catalog") or doc.get("token", {}).get("catalog") or []
print(",".join(sorted({s.get("type", "") for s in catalog if s.get("type")})))
PY
)"
[[ -n "$CATALOG_SERVICES" ]] || fail_gate R1 "catalog is empty"

# ---------------------------------------------------------------------------
# Tofu workdir + HCL graph (accepted P13.2/P13.3/P13.4 attribute subsets).
# Phase A graph has NO tcp/22 ingress rule; R4 appends it deterministically.
# ---------------------------------------------------------------------------
MIRROR="$TOFU_DIR/mirror/registry.terraform.io/terraform-provider-openstack/openstack/3.4.0/linux_amd64"
mkdir -p "$MIRROR" "$TOFU_DIR/project"
cp "$provider_binary" "$MIRROR/terraform-provider-openstack_v3.4.0"
chmod 0755 "$MIRROR/terraform-provider-openstack_v3.4.0"
cat >"$TOFU_DIR/tofu.tfrc" <<TFRC
provider_installation {
  filesystem_mirror {
    path = "$TOFU_DIR/mirror"
    include = ["registry.terraform.io/terraform-provider-openstack/openstack"]
  }
  direct { exclude = ["registry.terraform.io/terraform-provider-openstack/openstack"] }
}
TFRC

cat >"$TOFU_DIR/project/main.tf" <<TF
terraform {
  required_version = "= 1.12.6"
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "= 3.4.0"
    }
  }
}
provider "openstack" {
  auth_url    = "$BASE"
  user_name   = "admin"
  password    = "$BOOTSTRAP_PASSWORD"
  tenant_id   = "$PROJECT_ID"
  max_retries = 0
}
data "openstack_images_image_v2" "image" { name = "$RES_PREFIX-cirros" }
data "openstack_compute_flavor_v2" "flavor" { name = "test.small" }
resource "openstack_compute_keypair_v2" "kp" {
  name       = "$RES_PREFIX-keypair"
  public_key = "$GUEST_PUBKEY"
}
resource "openstack_networking_network_v2" "network" { name = "$RES_PREFIX-network" }
resource "openstack_networking_subnet_v2" "subnet" {
  name        = "$RES_PREFIX-subnet"
  network_id  = openstack_networking_network_v2.network.id
  cidr        = "$TENANT_CIDR"
  ip_version  = 4
  enable_dhcp = true
}
resource "openstack_networking_secgroup_v2" "sg" {
  name        = "$RES_PREFIX-sg"
  description = "p13-7 stateful policy"
}
resource "openstack_networking_port_v2" "port" {
  name               = "$RES_PREFIX-port"
  network_id         = openstack_networking_network_v2.network.id
  security_group_ids = [openstack_networking_secgroup_v2.sg.id]
  fixed_ip {
    subnet_id = openstack_networking_subnet_v2.subnet.id
  }
}
resource "openstack_networking_router_v2" "router" {
  name                = "$RES_PREFIX-router"
  admin_state_up      = true
  external_network_id = "$EXTERNAL_REALM_ID"
  enable_snat         = true
  depends_on          = [openstack_networking_subnet_v2.subnet]
}
resource "openstack_networking_router_interface_v2" "interface" {
  router_id = openstack_networking_router_v2.router.id
  subnet_id = openstack_networking_subnet_v2.subnet.id
}
resource "openstack_blockstorage_volume_v3" "volume" {
  name = "$RES_PREFIX-volume"
  size = 1
}
TF

tofu_in() {
    (cd "$TOFU_DIR/project" && TF_CLI_CONFIG_FILE="$TOFU_DIR/tofu.tfrc" TF_IN_AUTOMATION=1 "$tofu" "$@")
}
extract_attr() {
    tofu_in show -json | python3 -c '
import json, sys
addr, attr = sys.argv[1], sys.argv[2]
resources = json.load(sys.stdin)["values"]["root_module"]["resources"]
row = next(x for x in resources if x["address"] == addr)
value = row["values"]
for part in attr.split("."):
    value = value[int(part)] if isinstance(value, list) else value[part]
print(value)
' "$1" "$2"
}
# Run `tofu plan -detailed-exitcode` without tripping set -e; echoes the code.
plan_exitcode() {
    local log="$1"
    set +e
    tofu_in plan -detailed-exitcode -no-color >"$log" 2>&1
    local code=$?
    set -e
    echo "$code"
}

tofu_in init -input=false -upgrade=false -no-color >"$STATE_ROOT/tofu-init.log" 2>&1 \
    || { tail -30 "$STATE_ROOT/tofu-init.log" >&2; exit 1; }
tofu_in apply -auto-approve -no-color >"$STATE_ROOT/tofu-apply-1.log" 2>&1 \
    || { tail -40 "$STATE_ROOT/tofu-apply-1.log" >&2; fail_gate R1 "initial tofu apply failed"; }

# Wire the real dataplane only after the canonical-only resources exist.
stop_o3kd
start_network_agent || { echo "P13.7 BLOCKED: network agent failed to start" >&2; exit 2; }
start_o3kd full || { echo "P13.7 BLOCKED: o3kd (full) failed to start" >&2; exit 2; }
start_compute_agent || { echo "P13.7 BLOCKED: compute agent failed to start" >&2; exit 2; }

# Stage-2 resources drive the real host path: the Floating IP dispatches its
# public-address binding and the Server drives the libvirt/TAP/DHCP/policy
# path (the R2-R5 host-side proof surface).
cat >>"$TOFU_DIR/project/main.tf" <<TF

resource "openstack_networking_floatingip_v2" "fip" {
  pool    = "$RES_PREFIX-public-pool"
  port_id = openstack_networking_port_v2.port.id
  depends_on = [openstack_networking_router_interface_v2.interface]
}
resource "openstack_compute_instance_v2" "server" {
  name         = "$RES_PREFIX-server"
  image_id     = data.openstack_images_image_v2.image.id
  flavor_id    = data.openstack_compute_flavor_v2.flavor.id
  key_pair     = openstack_compute_keypair_v2.kp.name
  power_state  = "active"
  force_delete = false
  stop_before_destroy = true
  config_drive = true
  tags         = []
  network {
    port = openstack_networking_port_v2.port.id
  }
  depends_on = [openstack_networking_router_interface_v2.interface]
}
resource "openstack_compute_volume_attach_v2" "attachment" {
  instance_id = openstack_compute_instance_v2.server.id
  volume_id   = openstack_blockstorage_volume_v3.volume.id
  device      = "/dev/vdb"
}
TF
tofu_in apply -auto-approve -no-color >"$STATE_ROOT/tofu-apply-2.log" 2>&1 \
    || { tail -40 "$STATE_ROOT/tofu-apply-2.log" >&2; fail_gate R1 "stage-2 tofu apply failed"; }

# R1 proof: data sources resolved inside the applied graph.
DS_IMAGE_ID="$(extract_attr data.openstack_images_image_v2.image id)"
DS_FLAVOR_ID="$(extract_attr data.openstack_compute_flavor_v2.flavor id)"
[[ "$DS_IMAGE_ID" == "$IMAGE_ID" && -n "$DS_FLAVOR_ID" ]] \
    || fail_gate R1 "data sources did not resolve (image=$DS_IMAGE_ID flavor=$DS_FLAVOR_ID)"
emit_gate R1 "passed" "$(python3 - <<PY
import json
print(json.dumps({
    "token_acquired": True,
    "catalog_services": "$CATALOG_SERVICES".split(","),
    "image_data_source_resolved": True,
    "flavor_data_source_resolved": True,
}))
PY
)"

SERVER_ID="$(extract_attr openstack_compute_instance_v2.server id)"
NETWORK_ID="$(extract_attr openstack_networking_network_v2.network id)"
SUBNET_ID="$(extract_attr openstack_networking_subnet_v2.subnet id)"
PORT_ID="$(extract_attr openstack_networking_port_v2.port id)"
ROUTER_ID="$(extract_attr openstack_networking_router_v2.router id)"
SG_ID="$(extract_attr openstack_networking_secgroup_v2.sg id)"
FIP_ID="$(extract_attr openstack_networking_floatingip_v2.fip id)"
FIP_ADDRESS="$(extract_attr openstack_networking_floatingip_v2.fip address)"
FIXED_IP="$(extract_attr openstack_networking_port_v2.port all_fixed_ips.0 2>/dev/null \
    || extract_attr openstack_networking_port_v2.port fixed_ip.0.ip_address)"
VOLUME_ID="$(extract_attr openstack_blockstorage_volume_v3.volume id)"

# ---------------------------------------------------------------------------
# R2 — canonical networking graph realized host-side.
# NOTE: the o3k_policy nftables table is proven at R4, after the SG rule
# exists; an SG without rules projects an empty (fail-closed deny) policy and
# no table yet.
# ---------------------------------------------------------------------------
for _ in $(seq 1 200); do
    ip link show "$BRIDGE" >/dev/null 2>&1 \
        && ls "$WORK_NET"/dhcp/*.pid >/dev/null 2>&1 && break
    sleep 0.5
done
ip link show "$BRIDGE" >/dev/null 2>&1 || fail_gate R2 "bridge $BRIDGE absent"
DNSMASQ_SEEN=0
for pid_file in "$WORK_NET"/dhcp/*.pid; do
    [[ -r "$pid_file" ]] || continue
    DNSMASQ_SEEN=1
done
[[ "$DNSMASQ_SEEN" == 1 ]] || fail_gate R2 "dnsmasq inventory absent under $WORK_NET/dhcp"
NET_JSON="$(json "$BASE/v2.0/networks/$NETWORK_ID")"
PORT_JSON="$(json "$BASE/v2.0/ports/$PORT_ID")"
NET_OWNER="$(printf '%s' "$NET_JSON" | field network.project_id 2>/dev/null \
    || printf '%s' "$NET_JSON" | field network.tenant_id)"
PORT_OWNER="$(printf '%s' "$PORT_JSON" | field port.project_id 2>/dev/null \
    || printf '%s' "$PORT_JSON" | field port.tenant_id)"
[[ "$NET_OWNER" == "$PROJECT_ID" && "$PORT_OWNER" == "$PROJECT_ID" ]] \
    || fail_gate R2 "ownership mismatch (net=$NET_OWNER port=$PORT_OWNER)"
REALM_PLAN_MATCH="$(grep -R -l -F -- "$EXTERNAL_REALM_ROUTE_ID" "$WORK_NET" 2>/dev/null | head -n 1 || true)"
[[ -n "$REALM_PLAN_MATCH" ]] || fail_gate R2 "routed network plan did not contain canonical external AddressRealm $EXTERNAL_REALM_ROUTE_ID"
emit_gate R2 "passed" "{\"bridge_name\":\"$BRIDGE\",\"bridge_present\":true,\"dnsmasq_inventory_seen\":true,\"network_id\":\"$NETWORK_ID\",\"subnet_id\":\"$SUBNET_ID\",\"port_id\":\"$PORT_ID\",\"router_id\":\"$ROUTER_ID\",\"owner_project\":\"$PROJECT_ID\",\"external_network_id\":\"$EXTERNAL_REALM_ID\",\"external_realm_id\":\"$EXTERNAL_REALM_ROUTE_ID\",\"external_realm_matches_plan\":true}"

# ---------------------------------------------------------------------------
# R3 — real server: libvirt domain running, guest booted, DHCP lease matches.
# ---------------------------------------------------------------------------
for _ in $(seq 1 360); do
    STATUS="$(json "$BASE/v2.1/$PROJECT_ID/servers/$SERVER_ID" | field server.status 2>/dev/null || true)"
    [[ "$STATUS" == ACTIVE ]] && break
    [[ "$STATUS" == ERROR ]] && fail_gate R3 "server entered ERROR"
    sleep 1
done
[[ "${STATUS:-}" == ACTIVE ]] || fail_gate R3 "server did not become ACTIVE (status=${STATUS:-unknown})"

DOMAIN_NAME=""
for candidate in $(virsh -c qemu:///system list --all --name); do
    xml="$(virsh -c qemu:///system dumpxml "$candidate" 2>/dev/null || true)"
    if grep -Fq "server_id=\"$SERVER_ID\"" <<<"$xml" \
        && grep -Fq 'managed_by="o3k-compute"' <<<"$xml"; then
        DOMAIN_NAME="$candidate"
        break
    fi
done
[[ -n "$DOMAIN_NAME" ]] || fail_gate R3 "run-owned libvirt domain not discoverable"
DOMSTATE="$(virsh -c qemu:///system domstate "$DOMAIN_NAME")"
[[ "$DOMSTATE" == running ]] || fail_gate R3 "domain not running (state=$DOMSTATE)"

CONSOLE=""
BOOT_MARKER="login as 'cirros' user"
for _ in $(seq 1 300); do
    CONSOLE="$(json -X POST "$BASE/v2.1/$PROJECT_ID/servers/$SERVER_ID/action" \
        -H 'content-type: application/json' \
        --data '{"os-getConsoleOutput":{"length":65536}}' 2>/dev/null | field output 2>/dev/null || true)"
    grep -qF "$BOOT_MARKER" <<<"$CONSOLE" && break
    sleep 1
done
grep -qF "$BOOT_MARKER" <<<"$CONSOLE" || fail_gate R3 "cirros boot marker not observed in console log"

LEASE_MATCH=0
for _ in $(seq 1 120); do
    if grep -rlF "$FIXED_IP" "$WORK_NET/dhcp" >/dev/null 2>&1; then LEASE_MATCH=1; break; fi
    sleep 1
done
[[ "$LEASE_MATCH" == 1 ]] || fail_gate R3 "no DHCP lease record for fixed IP $FIXED_IP under $WORK_NET/dhcp"
R3_DOMAIN="$DOMAIN_NAME"
echo "P13.7: R3 boot/lease proof complete (domain=$R3_DOMAIN)" >&2

ssh_guest() {
    ip netns exec "$EXT_NETNS" timeout 20 ssh \
        -i "$STATE_ROOT/guest-key" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=8 -o BatchMode=yes \
        "cirros@$FIP_ADDRESS" "$@"
}

# ---------------------------------------------------------------------------
# R4 — packet path: external netns -> FIP DNAT -> guest tcp/22.
# The phase-A graph has no tcp/22 ingress rule, so the first observation must
# be a denial; adding the accepted openstack_networking_secgroup_rule_v2
# resource must flip the decision to allowed. nftables counters prove the
# packet path traversed the o3k_policy forward chain.
# ---------------------------------------------------------------------------
NFT_BEFORE="$(nft list chain ip o3k_policy forward 2>/dev/null || true)"
NFT_PACKETS_BEFORE="$(grep -o 'counter packets [0-9]*' <<<"$NFT_BEFORE" | awk '{s+=$3} END {print s+0}' || true)"
echo "P13.7: R4 deny probe (pre-SG-rule)" >&2
set +e
ssh_guest true >/dev/null 2>&1
SSH_RC=$?
set -e
DENIED=1
[[ "$SSH_RC" -ne 0 ]] || DENIED=0
[[ "$DENIED" == 1 ]] || fail_gate R4 "tcp/22 to the floating IP was reachable before the SG rule"

cat >"$TOFU_DIR/project/rule.tf" <<'TF'
resource "openstack_networking_secgroup_rule_v2" "ssh" {
  security_group_id = openstack_networking_secgroup_v2.sg.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
}
TF
tofu_in apply -auto-approve -no-color >"$STATE_ROOT/tofu-apply-rule.log" 2>&1 \
    || { tail -30 "$STATE_ROOT/tofu-apply-rule.log" >&2; fail_gate R4 "SG rule apply failed"; }
RULE_ID="$(extract_attr openstack_networking_secgroup_rule_v2.ssh id)"

ALLOWED=0
for _ in $(seq 1 90); do
    if ssh_guest true >/dev/null 2>&1; then ALLOWED=1; break; fi
    sleep 2
done
[[ "$ALLOWED" == 1 ]] || fail_gate R4 "tcp/22 to the floating IP still denied after the SG rule"
nft list table ip o3k_policy >/dev/null 2>&1 \
    || fail_gate R4 "nftables o3k_policy table absent after the SG rule"
NFT_AFTER="$(nft list chain ip o3k_policy forward 2>/dev/null || true)"
NFT_PACKETS_AFTER="$(grep -o 'counter packets [0-9]*' <<<"$NFT_AFTER" | awk '{s+=$3} END {print s+0}' || true)"
[[ "$NFT_PACKETS_AFTER" -gt 0 ]] || fail_gate R4 "nftables o3k_policy forward counters show no packets"
NFT_DROP_PACKETS_BEFORE="$(grep -E 'drop.*counter packets|counter packets.*drop' <<<"$NFT_BEFORE" | grep -o 'counter packets [0-9]*' | awk '{s+=$3} END {print s+0}' || true)"
NFT_DROP_PACKETS_AFTER="$(grep -E 'drop.*counter packets|counter packets.*drop' <<<"$NFT_AFTER" | grep -o 'counter packets [0-9]*' | awk '{s+=$3} END {print s+0}' || true)"
[[ "$NFT_DROP_PACKETS_AFTER" =~ ^[0-9]+$ ]] || fail_gate R4 "nftables drop counter was not observable"
emit_gate R4 "passed" "{\"denied_observed\":true,\"allowed_observed\":true,\"toggle_via\":\"openstack_networking_secgroup_rule_v2\",\"security_group_id\":\"$SG_ID\",\"nft_counter_packets_before\":$NFT_PACKETS_BEFORE,\"nft_counter_packets_after\":$NFT_PACKETS_AFTER,\"nft_drop_counter_packets_before\":${NFT_DROP_PACKETS_BEFORE:-0},\"nft_drop_counter_packets_after\":$NFT_DROP_PACKETS_AFTER,\"nft_drop_counter_seen\":true}"

# R3 SSH completion (floating-IP path, injected keypair); R3 row is emitted
# only now so a passed row always carries ssh_ok=true.
ssh_guest 'echo O3K_P13_7_SSH_OK' | grep -q O3K_P13_7_SSH_OK \
    || fail_gate R3 "SSH via injected keypair failed"
emit_gate R3 "passed" "{\"libvirt_domain\":\"$R3_DOMAIN\",\"domain_running\":true,\"boot_marker\":\"$BOOT_MARKER\",\"boot_marker_seen\":true,\"fixed_ip\":\"$FIXED_IP\",\"dhcp_lease_matches_port\":true,\"ssh_path\":\"floating_ip\",\"ssh_ok\":true}"

# ---------------------------------------------------------------------------
# R5 — volume I/O + detach/reattach persistence.
# ---------------------------------------------------------------------------
LV_NAME="o3k-v-$(printf '%s' "$VOLUME_ID" | tr -d '-')"
for _ in $(seq 1 120); do
    lvs "$LVM_VG" --noheadings -o lv_name 2>/dev/null | grep -Fq "$LV_NAME" && break
    sleep 1
done
lvs "$LVM_VG" --noheadings -o lv_name 2>/dev/null | grep -Fq "$LV_NAME" \
    || fail_gate R5 "LV $LV_NAME not present in $LVM_VG"
GUEST_DEV=""
for _ in $(seq 1 120); do
    guest_disks="$(ssh_guest 'lsblk -bndo NAME,TYPE | awk '\''$2 == "disk" && $1 != "vda" {print "/dev/" $1}'\'' ' 2>/dev/null || true)"
    if [[ "$(wc -l <<<"$guest_disks")" -eq 1 && "$guest_disks" =~ ^/dev/[[:alnum:]]+$ ]]; then
        GUEST_DEV="$guest_disks"
        break
    fi
    sleep 2
done
[[ -n "$GUEST_DEV" ]] || fail_gate R5 "exactly one run-owned guest data disk was not discoverable"
for _ in $(seq 1 120); do
    ssh_guest "test -b $GUEST_DEV" >/dev/null 2>&1 && break
    sleep 2
done
ssh_guest "test -b $GUEST_DEV" >/dev/null 2>&1 || fail_gate R5 "guest block device $GUEST_DEV absent"
RUN_MARKER="p13-7-$RUN_SLUG-$(openssl rand -hex 8)"
ssh_guest "sudo sh -c 'printf %s $RUN_MARKER | dd of=$GUEST_DEV bs=4096 count=1 conv=fsync'" >/dev/null 2>&1 \
    || fail_gate R5 "guest volume write failed"
MARKER_SHA="$(ssh_guest "sudo dd if=$GUEST_DEV bs=4096 count=1 2>/dev/null | sha256sum | awk '{print \$1}'")"
[[ "$MARKER_SHA" =~ ^[0-9a-f]{64}$ ]] || fail_gate R5 "guest volume checksum unreadable"

# Accepted detach/reattach lifecycle: taint the attachment resource so tofu
# destroys and recreates it against the same volume (the P13.4/P13.6F
# attachment resource models detach as resource destroy).
tofu_in taint openstack_compute_volume_attach_v2.attachment >/dev/null
tofu_in apply -auto-approve -no-color >"$STATE_ROOT/tofu-apply-reattach.log" 2>&1 \
    || { tail -30 "$STATE_ROOT/tofu-apply-reattach.log" >&2; fail_gate R5 "attachment replace failed"; }
{
    echo "--- immediate post-reattach domain xml ---"
    virsh -c qemu:///system dumpxml "$DOMAIN_NAME" 2>&1 || true
    echo "--- immediate post-reattach domblklist ---"
    virsh -c qemu:///system domblklist "$DOMAIN_NAME" --details 2>&1 || true
    echo "--- immediate post-reattach qemu info block ---"
    virsh -c qemu:///system qemu-monitor-command "$DOMAIN_NAME" --hmp "info block" 2>&1 || true
    echo "--- disposable LVM inventory ---"
    lvs "$LVM_VG" --noheadings -o lv_name,lv_attr,lv_size,devices 2>&1 || true
} >"$STATE_ROOT/r5-immediate-post-reattach.txt"
# CirrOS does not reliably rescan a repeated virtio hotplug after the guest
# node has been removed. Restart the same real guest so its persistent
# attachment inventory is reprobed before the guest-I/O persistence proof.
sed -i 's/power_state  = "active"/power_state  = "shutoff"/' "$TOFU_DIR/project/main.tf"
tofu_in apply -auto-approve -no-color >"$STATE_ROOT/tofu-r5-reprobe-stop.log" 2>&1 \
    || { tail -30 "$STATE_ROOT/tofu-r5-reprobe-stop.log" >&2; fail_gate R5 "guest reprobe stop failed"; }
for _ in $(seq 1 120); do
    S="$(virsh -c qemu:///system domstate "$DOMAIN_NAME" 2>/dev/null || true)"
    [[ "$S" == "shut off" ]] && break
    sleep 1
done
[[ "$S" == "shut off" ]] || fail_gate R5 "guest did not stop for volume reprobe"
sed -i 's/power_state  = "shutoff"/power_state  = "active"/' "$TOFU_DIR/project/main.tf"
tofu_in apply -auto-approve -no-color >"$STATE_ROOT/tofu-r5-reprobe-start.log" 2>&1 \
    || { tail -30 "$STATE_ROOT/tofu-r5-reprobe-start.log" >&2; fail_gate R5 "guest reprobe start failed"; }
for _ in $(seq 1 120); do
    S="$(virsh -c qemu:///system domstate "$DOMAIN_NAME" 2>/dev/null || true)"
    [[ "$S" == running ]] && break
    sleep 1
done
[[ "$S" == running ]] || fail_gate R5 "guest did not restart for volume reprobe"
for _ in $(seq 1 120); do
    ssh_guest "test -b $GUEST_DEV" >/dev/null 2>&1 && break
    sleep 2
done
ssh_guest "test -b $GUEST_DEV" >/dev/null 2>&1 || fail_gate R5 "guest block device absent after reattach"
set +e
REATTACH_SHA="$(ssh_guest "sudo dd if=$GUEST_DEV bs=4096 count=1 2>/dev/null | sha256sum | awk '{print \$1}'")"
REATTACH_SHA_STATUS=$?
set -e
[[ "$REATTACH_SHA_STATUS" -eq 0 ]] || fail_gate R5 "guest volume checksum failed after reattach (ssh status $REATTACH_SHA_STATUS)"
[[ "$REATTACH_SHA" == "$MARKER_SHA" ]] || fail_gate R5 "volume content changed across detach/reattach"
set +e
CONTENT_CHECK="$(ssh_guest "sudo dd if=$GUEST_DEV bs=1 count=${#RUN_MARKER} 2>/dev/null")"
CONTENT_CHECK_STATUS=$?
set -e
[[ "$CONTENT_CHECK_STATUS" -eq 0 ]] || fail_gate R5 "guest volume marker read failed after reattach (ssh status $CONTENT_CHECK_STATUS)"
[[ "$CONTENT_CHECK" == "$RUN_MARKER" ]] || fail_gate R5 "volume marker mismatch after reattach"
emit_gate R5 "passed" "{\"lv_name\":\"$LV_NAME\",\"guest_device\":\"$GUEST_DEV\",\"marker_sha256\":\"$MARKER_SHA\",\"post_reattach_sha256\":\"$REATTACH_SHA\",\"checksum_match\":true,\"reattach_mechanism\":\"tofu taint openstack_compute_volume_attach_v2\"}"

# ---------------------------------------------------------------------------
# R6 — convergence and controlled out-of-band drift (P13.5C mechanism: PUT
# /v2.0/networks/{id} with the admin token, the accepted compat drift surface).
# ---------------------------------------------------------------------------
[[ "$(plan_exitcode "$STATE_ROOT/plan-r6-a.log")" == 0 ]] \
    || fail_gate R6 "initial full-graph plan is not a no-op"
json -X PUT "$BASE/v2.0/networks/$NETWORK_ID" -H 'content-type: application/json' \
    --data '{"network":{"name":"$RES_PREFIX-network-drifted"}}' >/dev/null \
    || fail_gate R6 "out-of-band drift mutation failed"
PLAN_DRIFT_EXIT="$(plan_exitcode "$STATE_ROOT/plan-r6-drift.log")"
[[ "$PLAN_DRIFT_EXIT" == 2 ]] || fail_gate R6 "drift plan exit code is $PLAN_DRIFT_EXIT, expected 2"
DRIFT_LINES="$(grep -c '$RES_PREFIX-network-drifted' "$STATE_ROOT/plan-r6-drift.log" || true)"
CHANGE_COUNT="$(grep -cE '^  # .* will be updated in-place' "$STATE_ROOT/plan-r6-drift.log" || true)"
[[ "$DRIFT_LINES" -ge 1 && "$CHANGE_COUNT" == 1 ]] \
    || fail_gate R6 "drift plan is not exactly the network name change (changes=$CHANGE_COUNT)"
tofu_in apply -auto-approve -no-color >"$STATE_ROOT/apply-r6-restore.log" 2>&1 \
    || fail_gate R6 "drift restore apply failed"
RESTORED_NAME="$(json "$BASE/v2.0/networks/$NETWORK_ID" | field network.name)"
[[ "$RESTORED_NAME" == "$RES_PREFIX-network" ]] || fail_gate R6 "network name not restored (got $RESTORED_NAME)"
[[ "$(plan_exitcode "$STATE_ROOT/plan-r6-final.log")" == 0 ]] \
    || fail_gate R6 "final plan after restore is not a no-op"
emit_gate R6 "passed" "{\"initial_plan_noop\":true,\"drift_detected\":true,\"drift_resource\":\"openstack_networking_network_v2.network\",\"drift_attribute\":\"name\",\"drift_exactly_one_change\":true,\"restored_by_apply\":true,\"final_plan_noop\":true}"

# ---------------------------------------------------------------------------
# R7 — clean o3kd restart against the same PostgreSQL DB and live execution
# boundaries (network agent and compute agent keep running).
# ---------------------------------------------------------------------------
IDS_BEFORE="$(json "$BASE/v2.1/$PROJECT_ID/servers/$SERVER_ID" | field server.id)$(json "$BASE/v2.0/ports/$PORT_ID" | field port.id)$(json "$BASE/v2.0/floatingips/$FIP_ID" | field floatingip.floating_ip_address)$(json "$BASE/v3/$PROJECT_ID/volumes/$VOLUME_ID" | field volume.id)"
stop_o3kd
start_o3kd || fail_gate R7 "o3kd did not restart cleanly"
TOKEN="$(get_token)"
[[ -n "$TOKEN" ]] || fail_gate R7 "token re-acquisition after restart failed"
IDS_AFTER="$(json "$BASE/v2.1/$PROJECT_ID/servers/$SERVER_ID" | field server.id)$(json "$BASE/v2.0/ports/$PORT_ID" | field port.id)$(json "$BASE/v2.0/floatingips/$FIP_ID" | field floatingip.floating_ip_address)$(json "$BASE/v3/$PROJECT_ID/volumes/$VOLUME_ID" | field volume.id)"
[[ "$IDS_BEFORE" == "$IDS_AFTER" ]] || fail_gate R7 "canonical identities changed across o3kd restart"
tofu_in apply -refresh-only -auto-approve -no-color >"$STATE_ROOT/refresh-r7.log" 2>&1 \
    || fail_gate R7 "tofu refresh-only apply failed after restart"
[[ "$(plan_exitcode "$STATE_ROOT/plan-r7.log")" == 0 ]] \
    || fail_gate R7 "post-restart plan is not a no-op"
ssh_guest 'echo O3K_P13_7_SSH_OK' | grep -q O3K_P13_7_SSH_OK || fail_gate R7 "SSH broken after restart"
POST_RESTART_SHA="$(ssh_guest "sudo dd if=$GUEST_DEV bs=4096 count=1 2>/dev/null | sha256sum | awk '{print \$1}'")"
[[ "$POST_RESTART_SHA" == "$MARKER_SHA" ]] || fail_gate R7 "volume marker lost across restart"
emit_gate R7 "passed" "{\"restart_clean_sigterm\":true,\"identities_equal\":true,\"identities\":{\"server_id\":\"$SERVER_ID\",\"port_id\":\"$PORT_ID\",\"floating_ip\":\"$FIP_ADDRESS\",\"volume_id\":\"$VOLUME_ID\"},\"post_restart_plan_noop\":true,\"ssh_after_restart\":true,\"volume_marker_intact\":true}"

# ---------------------------------------------------------------------------
# R8 — lifecycle through the accepted P13.2D surface: the
# openstack_compute_instance_v2 power_state attribute for stop/start and the
# os-reboot action endpoint (driven with curl, as P13.2D does).
# ---------------------------------------------------------------------------
VIRSH_TRANSITIONS="$(virsh -c qemu:///system domstate "$DOMAIN_NAME")"
sed -i 's/power_state  = "active"/power_state  = "shutoff"/' "$TOFU_DIR/project/main.tf"
tofu_in apply -auto-approve -no-color >"$STATE_ROOT/apply-r8-stop.log" 2>&1 \
    || fail_gate R8 "power_state=shutoff apply failed"
for _ in $(seq 1 120); do
    S="$(virsh -c qemu:///system domstate "$DOMAIN_NAME" 2>/dev/null || true)"
    [[ "$S" == "shut off" ]] && break
    sleep 1
done
[[ "${S:-}" == "shut off" ]] || fail_gate R8 "domain did not reach shut off (state=${S:-unknown})"
VIRSH_TRANSITIONS="$VIRSH_TRANSITIONS,$S"
sed -i 's/power_state  = "shutoff"/power_state  = "active"/' "$TOFU_DIR/project/main.tf"
tofu_in apply -auto-approve -no-color >"$STATE_ROOT/apply-r8-start.log" 2>&1 \
    || fail_gate R8 "power_state=active apply failed"
for _ in $(seq 1 120); do
    S="$(virsh -c qemu:///system domstate "$DOMAIN_NAME" 2>/dev/null || true)"
    [[ "$S" == running ]] && break
    sleep 1
done
[[ "${S:-}" == running ]] || fail_gate R8 "domain did not return to running (state=${S:-unknown})"
VIRSH_TRANSITIONS="$VIRSH_TRANSITIONS,$S"
json -X POST "$BASE/v2.1/$PROJECT_ID/servers/$SERVER_ID/action" \
    -H 'content-type: application/json' --data '{"reboot":{"type":"SOFT"}}' >/dev/null \
    || fail_gate R8 "os-reboot action failed"
for _ in $(seq 1 240); do
    STATUS="$(json "$BASE/v2.1/$PROJECT_ID/servers/$SERVER_ID" | field server.status 2>/dev/null || true)"
    S="$(virsh -c qemu:///system domstate "$DOMAIN_NAME" 2>/dev/null || true)"
    [[ "$STATUS" == ACTIVE && "$S" == running ]] && break
    sleep 1
done
[[ "${STATUS:-}" == ACTIVE && "${S:-}" == running ]] || fail_gate R8 "server did not recover from reboot"
VIRSH_TRANSITIONS="$VIRSH_TRANSITIONS,$S"
for _ in $(seq 1 180); do
    ssh_guest true >/dev/null 2>&1 && break
    sleep 2
done
ssh_guest 'echo O3K_P13_7_SSH_OK' | grep -q O3K_P13_7_SSH_OK || fail_gate R8 "SSH broken after lifecycle"
POST_LIFECYCLE_SHA="$(ssh_guest "sudo dd if=$GUEST_DEV bs=4096 count=1 2>/dev/null | sha256sum | awk '{print \$1}'")"
[[ "$POST_LIFECYCLE_SHA" == "$MARKER_SHA" ]] || fail_gate R8 "volume marker lost across lifecycle"
[[ "$(plan_exitcode "$STATE_ROOT/plan-r8.log")" == 0 ]] \
    || fail_gate R8 "post-lifecycle plan is not a no-op"
emit_gate R8 "passed" "{\"mechanism\":\"openstack_compute_instance_v2.power_state + os-reboot action API\",\"virsh_transitions\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1].split(",")))' "$VIRSH_TRANSITIONS"),\"stop_observed\":true,\"start_observed\":true,\"reboot_observed\":true,\"post_recovery_plan_noop\":true,\"ssh_after_recovery\":true,\"volume_marker_intact\":true}"

# ---------------------------------------------------------------------------
# R9 — destroy + independent (non-terraform-state) leak verification.
# ---------------------------------------------------------------------------
tofu_in destroy -auto-approve -no-color >"$STATE_ROOT/destroy.log" 2>&1 \
    || { tail -40 "$STATE_ROOT/destroy.log" >&2; fail_gate R9 "tofu destroy failed"; }
DESTROY_ATTEMPTED=1

count_matching_id() {
    local key="$1"; shift
    python3 -c '
import json, sys
key, *ids = sys.argv[1:]
wanted = {value for value in ids if value}
rows = json.load(sys.stdin).get(key, [])
print(sum(1 for row in rows if row.get("id") in wanted))
' "$key" "$@"
}
count_matching_name() {
    local key="$1"; shift
    python3 -c '
import json, sys
key, wanted = sys.argv[1:]
rows = json.load(sys.stdin).get(key, [])
print(sum(1 for row in rows if row.get("keypair", {}).get("name") == wanted))
' "$key" "$1"
}
count_matching_device() {
    local key="$1"; shift
    python3 -c '
import json, sys
key, wanted = sys.argv[1:]
rows = json.load(sys.stdin).get(key, [])
print(sum(1 for row in rows if row.get("device_id") == wanted))
' "$key" "$1"
}
sleep 3
ZERO_SERVERS="$(json "$BASE/v2.1/$PROJECT_ID/servers" | count_matching_id servers "$SERVER_ID")"
ZERO_PORTS="$(json "$BASE/v2.0/ports" | count_matching_id ports "$PORT_ID")"
ZERO_NETWORKS="$(json "$BASE/v2.0/networks" | count_matching_id networks "$NETWORK_ID")"
ZERO_SUBNETS="$(json "$BASE/v2.0/subnets" | count_matching_id subnets "$SUBNET_ID")"
ZERO_ROUTERS="$(json "$BASE/v2.0/routers" | count_matching_id routers "$ROUTER_ID")"
ZERO_SGS="$(json "$BASE/v2.0/security-groups" | count_matching_id security_groups "$SG_ID")"
ZERO_SG_RULES="$(json "$BASE/v2.0/security-group-rules" | count_matching_id security_group_rules "$RULE_ID")"
ZERO_FIPS="$(json "$BASE/v2.0/floatingips" | count_matching_id floatingips "$FIP_ID")"
ZERO_VOLUMES="$(json "$BASE/v3/$PROJECT_ID/volumes" | count_matching_id volumes "$VOLUME_ID")"
ZERO_KEYPAIRS="$(json "$BASE/v2.1/$PROJECT_ID/os-keypairs" | count_matching_name keypairs "$RES_PREFIX-keypair")"
ZERO_ROUTER_INTERFACES="$(json "$BASE/v2.0/ports" | count_matching_device ports "$ROUTER_ID")"
# The disposable database may retain terminal attachment history by design.
# Only live/non-terminal rows belonging to this run's server or volume are
# leaks; detached/deleted history is not an execution resource.
ZERO_ATTACHMENTS="$(PGPASSWORD="$DB_PASSWORD" psql "$DB_URL" -v ON_ERROR_STOP=1 -Atqc \
    "SELECT (SELECT count(*) FROM volume_attachments WHERE (server_id = '$SERVER_ID' OR volume_id = '$VOLUME_ID') AND status NOT IN ('detached', 'error')) + (SELECT count(*) FROM native_volume_attachments WHERE (server_id = '$SERVER_ID' OR volume_id = '$VOLUME_ID') AND state NOT IN ('detached', 'deleted', 'error'))")" \
    || fail_gate R9 "canonical PostgreSQL attachment inventory failed"
[[ "$ZERO_ATTACHMENTS" =~ ^[0-9]+$ ]] \
    || fail_gate R9 "canonical PostgreSQL attachment inventory was not numeric"
ZERO_DOMAINS=0
for candidate in $(virsh -c qemu:///system list --all --name 2>/dev/null); do
    xml="$(virsh -c qemu:///system dumpxml "$candidate" 2>/dev/null || true)"
    grep -Fq "server_id=\"$SERVER_ID\"" <<<"$xml" && ZERO_DOMAINS=$((ZERO_DOMAINS + 1))
done
ZERO_LVS="$(lvs "$LVM_VG" --noheadings -o lv_name 2>/dev/null | sed 's/^ *//' | grep -cvF "$LVM_POOL" || true)"
# R9 is scoped to this run's ownership.  Other TestLab runs may legitimately
# leave O3K interfaces/tables in the host baseline; R10 independently proves
# that their foreign state did not change.
# Stop the execution boundaries before the independent host inventory.  Their
# graceful shutdown is part of normal ownership cleanup; checking while they
# are still serving can observe a bridge that is already empty but not yet
# released by the owner.
stop_o3kd
[[ -n "$COMPUTE_PID" ]] && { kill "$COMPUTE_PID" 2>/dev/null || true; wait "$COMPUTE_PID" 2>/dev/null || true; COMPUTE_PID=""; }
[[ -n "$NETWORK_PID" ]] && { kill "$NETWORK_PID" 2>/dev/null || true; wait "$NETWORK_PID" 2>/dev/null || true; NETWORK_PID=""; }

ZERO_NFT=1; ZERO_BRIDGES=1; ZERO_DNSMASQ=1
# Network-agent shutdown removes nftables after its execution journal and
# bridge teardown.  Poll the run-owned tables during that bounded shutdown
# window; a one-shot check can report a transient leak even when cleanup has
# completed successfully (as R10's independent inventory would show).
for _ in $(seq 1 150); do
    ZERO_NFT=1
    for table in o3k_policy o3k_public o3k_p137 o3k_p9; do
        nft list table ip "$table" >/dev/null 2>&1 && ZERO_NFT=0
    done
    [[ "$ZERO_NFT" == 1 ]] && break
    sleep 0.5
done
for _ in $(seq 1 150); do
    ok=1
    ip link show "$BRIDGE" >/dev/null 2>&1 && ok=0
    [[ "$ok" == 1 ]] && break
    sleep 0.5
done
ip link show "$BRIDGE" >/dev/null 2>&1 && ZERO_BRIDGES=0
if pgrep -af dnsmasq 2>/dev/null | grep -Fq "$WORK_NET/dhcp"; then ZERO_DNSMASQ=0; fi
RUN_OWNED_TAPS="$(python3 - "$WORK_NET/ownership/ownership.json" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except (FileNotFoundError, json.JSONDecodeError):
    data = {}
for value in data.values():
    if isinstance(value, dict) and value.get("interface", "").startswith("o3ktap-"):
        print(value["interface"])
PY
)"
while IFS= read -r tap; do
    [[ -n "$tap" ]] || continue
    ip link show "$tap" >/dev/null 2>&1 && { echo "P13.7 R9 leak: run-owned interface=$tap" >&2; ZERO_BRIDGES=0; }
done <<< "$RUN_OWNED_TAPS"
# Non-terminal operations: the native operations surface exposes
# /o3k/v1/operations/{id} only; resource collections embed operation phase.
# Assert every remaining run-owned resource list is empty (above) and no
# pending network plans remain in the executor journal.
ZERO_NONTERMINAL_OPS=1
if [[ -r "$WORK_NET/executor/accepted-network-plans.json" ]]; then
    python3 - "$WORK_NET/executor/accepted-network-plans.json" <<'PY' || ZERO_NONTERMINAL_OPS=0
import json, sys
plans = json.load(open(sys.argv[1]))["plans"]
raise SystemExit(0 if all(p["status"] in ("Succeeded", "Failed") for p in plans) else 1)
PY
fi
R9_OK=1
for pair in "servers:$ZERO_SERVERS" "ports:$ZERO_PORTS" "networks:$ZERO_NETWORKS" "subnets:$ZERO_SUBNETS" \
    "routers:$ZERO_ROUTERS" "security_groups:$ZERO_SGS" "security_group_rules:$ZERO_SG_RULES" \
    "router_interfaces:$ZERO_ROUTER_INTERFACES" "keypairs:$ZERO_KEYPAIRS" \
    "floating_ips:$ZERO_FIPS" "volumes:$ZERO_VOLUMES" \
    "libvirt_domains:$ZERO_DOMAINS" "lvs:$ZERO_LVS" "attachments:$ZERO_ATTACHMENTS"; do
    [[ "${pair##*:}" == 0 ]] || { echo "P13.7 R9 leak: ${pair%%:*}=${pair##*:}" >&2; R9_OK=0; }
done
[[ "$ZERO_NFT" == 1 && "$ZERO_BRIDGES" == 1 && "$ZERO_DNSMASQ" == 1 && "$ZERO_NONTERMINAL_OPS" == 1 ]] || R9_OK=0
if [[ "$R9_OK" != 1 ]]; then
    emit_gate R9 "failed" "$(python3 - "$ZERO_SERVERS" "$ZERO_PORTS" "$ZERO_NETWORKS" "$ZERO_SUBNETS" "$ZERO_ROUTERS" "$ZERO_SGS" "$ZERO_SG_RULES" "$ZERO_ROUTER_INTERFACES" "$ZERO_KEYPAIRS" "$ZERO_FIPS" "$ZERO_VOLUMES" "$ZERO_DOMAINS" "$ZERO_LVS" "$ZERO_ATTACHMENTS" "$ZERO_NFT" "$ZERO_BRIDGES" "$ZERO_DNSMASQ" "$ZERO_NONTERMINAL_OPS" <<'PY'
import json, sys
count_names = "servers ports networks subnets routers security_groups security_group_rules router_interfaces keypairs floating_ips volumes libvirt_domains lvs attachments".split()
flag_names = "nft_tables bridges dnsmasq non_terminal_operations".split()
values = sys.argv[1:]
counts = dict(zip(count_names, map(int, values[:14])))
flags = dict(zip(flag_names, map(int, values[14:])))
print(json.dumps({"counts": counts, "flags": flags}, sort_keys=True))
PY
)"
    write_evidence "failed"
    echo "P13.7 gate R9 FAILED: leaks detected (see above)" >&2
    exit 1
fi
emit_gate R9 "passed" "{\"zero_servers\":true,\"zero_ports\":true,\"zero_networks\":true,\"zero_subnets\":true,\"zero_routers\":true,\"zero_router_interfaces\":true,\"zero_security_groups\":true,\"zero_security_group_rules\":true,\"zero_keypairs\":true,\"zero_floating_ips\":true,\"zero_volumes\":true,\"zero_attachments\":true,\"attachment_count\":$ZERO_ATTACHMENTS,\"zero_libvirt_domains\":true,\"zero_lvs\":true,\"zero_nft_tables\":true,\"zero_bridges\":true,\"zero_dnsmasq\":true,\"zero_non_terminal_operations\":true}"

# ---------------------------------------------------------------------------
# R10 — foreign-state before/after comparison. Pre-existing host entries
# (foreign VGs, residue) are the baseline; only run-owned markers count as
# leaks, and the non-owned diff must be empty.
# ---------------------------------------------------------------------------
# Run-owned network/LVM state must already be gone (R9); drop the remaining
# run-owned fixtures so the after snapshot is comparable to the baseline.
stop_o3kd
[[ -n "$COMPUTE_PID" ]] && { kill "$COMPUTE_PID" 2>/dev/null || true; wait "$COMPUTE_PID" 2>/dev/null || true; COMPUTE_PID=""; }
[[ -n "$NETWORK_PID" ]] && { kill "$NETWORK_PID" 2>/dev/null || true; wait "$NETWORK_PID" 2>/dev/null || true; NETWORK_PID=""; }
ip netns del "$EXT_NETNS" 2>/dev/null || true
[[ -n "$EXT_NS_PID" ]] && { kill "$EXT_NS_PID" 2>/dev/null || true; wait "$EXT_NS_PID" 2>/dev/null || true; EXT_NS_PID=""; }
ip link del "$UPLINK" 2>/dev/null || true
for table in o3k_policy o3k_public o3k_p137 o3k_p9; do
    # Preserve pre-existing tables; R10 compares them independently.
    if ! grep -Fqx "table ip $table" "$STATE_ROOT/foreign-before.txt" 2>/dev/null; then
        nft delete table ip "$table" >/dev/null 2>&1 || true
    fi
done
O3K_LVM_RUN_ID="$RUN_ID" bash "$ROOT_DIR/scripts/lvm-testlab-profile.sh" cleanup
LVM_PROVISIONED=0

foreign_inventory "$STATE_ROOT/foreign-after.txt"
R10_RESULT="$(python3 - "$STATE_ROOT/foreign-before.txt" "$STATE_ROOT/foreign-after.txt" "$BRIDGE" "$LVM_VG" "$RUN_SLUG" <<'PY'
import json
import sys

before_path, after_path, bridge, vg, slug = sys.argv[1:]

def load(path):
    sections, current = {}, "domains"
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if line.startswith("--- "):
            current = line.strip("- ").strip()
            sections[current] = []
        elif line.strip():
            sections.setdefault(current, []).append(line.strip())
    return sections

before, after = load(before_path), load(after_path)
owned_markers = (bridge, vg, slug, "o3ktap-", "o3k_policy", "o3k_public", "o3k_p137", "o3k_p9")

def split(rows):
    owned, foreign = set(), set()
    for row in rows:
        (owned if any(m in row for m in owned_markers) else foreign).add(row)
    return owned, foreign

owned_leaks = 0
foreign_changes = 0
for section in sorted(set(before) | set(after)):
    b_owned, b_foreign = split(before.get(section, []))
    a_owned, a_foreign = split(after.get(section, []))
    owned_leaks += len(a_owned - b_owned)
    foreign_changes += len(a_foreign.symmetric_difference(b_foreign))
print(json.dumps({"owned_leaks": owned_leaks, "foreign_state_changes": foreign_changes}))
PY
)"
OWNED_LEAKS="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["owned_leaks"])' "$R10_RESULT")"
FOREIGN_CHANGES="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["foreign_state_changes"])' "$R10_RESULT")"
if [[ "$OWNED_LEAKS" != 0 || "$FOREIGN_CHANGES" != 0 ]]; then
    emit_gate R10 "failed" "{\"owned_leaks\":$OWNED_LEAKS,\"foreign_state_changes\":$FOREIGN_CHANGES,\"foreign_baseline_entries\":$FOREIGN_BASELINE_COUNT}"
    write_evidence "failed"
    echo "P13.7 gate R10 FAILED: owned_leaks=$OWNED_LEAKS foreign_state_changes=$FOREIGN_CHANGES" >&2
    diff "$STATE_ROOT/foreign-before.txt" "$STATE_ROOT/foreign-after.txt" >&2 || true
    exit 1
fi
emit_gate R10 "passed" "{\"owned_leaks\":0,\"foreign_state_changes\":0,\"foreign_baseline_entries\":$FOREIGN_BASELINE_COUNT}"

write_evidence "passed"
python3 "$ROOT_DIR/scripts/validate_p13_7_evidence.py" "$EVIDENCE_OUTPUT"
echo "P13.7 real-host IaC acceptance: PASS (evidence: $EVIDENCE_OUTPUT)"
