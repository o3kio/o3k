#!/usr/bin/env bash
set -Eeuo pipefail

# Disposable nested three-host Fabric v3 gate. This is evidence tooling only;
# it does not create or modify canonical O3K state. The provider helper builds
# the accepted fixture and the commands below attach disposable endpoint
# namespaces to the provider-owned realm bridges.

: "${FABRIC_V3_3H_RUN_ID:?set the unique provider-gate run ID}"
: "${FABRIC_V3_3H_HELPER_BIN:?set FABRIC_V3_3H_HELPER_BIN to the built helper}"
: "${FABRIC_V3_3H_HOST_A_IP:?set host-a address}"
: "${FABRIC_V3_3H_HOST_B_IP:?set host-b address}"
: "${FABRIC_V3_3H_HOST_C_IP:?set host-c address}"
: "${FABRIC_V3_3H_KEY_A:?set host-a ssh key}"
: "${FABRIC_V3_3H_KEY_B:?set host-b ssh key}"
: "${FABRIC_V3_3H_KEY_C:?set host-c ssh key}"
: "${FABRIC_V3_3H_KNOWN_HOSTS_FILE:?set the run-owned SSH known-hosts file}"
: "${FABRIC_V3_3H_EVIDENCE_DIR:?set the run-owned provider-gate evidence directory}"

[[ "$FABRIC_V3_3H_RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] \
    || { echo "HARNESS_GAP: invalid provider-gate run ID" >&2; exit 2; }
[[ "${FABRIC_V3_3H_KEEP:-0}" == 0 ]] \
    || { echo "HARNESS_GAP: retaining provider-gate resources is forbidden" >&2; exit 2; }
python3 - "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_HOST_C_IP" <<'PYIP' \
    || { echo "HARNESS_GAP: provider-gate addresses must be three distinct IPv4 addresses" >&2; exit 2; }
import ipaddress,sys
ips=[ipaddress.ip_address(value) for value in sys.argv[1:]]
assert all(ip.version == 4 for ip in ips)
assert len(set(ips)) == 3
PYIP

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="$FABRIC_V3_3H_EVIDENCE_DIR"
[[ ! -L "$EVIDENCE_DIR" && -d "$EVIDENCE_DIR" ]] \
    || { echo "HARNESS_GAP: provider-gate evidence directory must be an existing non-symlink directory" >&2; exit 2; }
REMOTE_USER="${FABRIC_V3_3H_REMOTE_USER:-o3k}"
REMOTE_TMP_ROOT="/tmp/o3k-fabric-v3-three-host-${FABRIC_V3_3H_RUN_ID}"
RUN_ROOT="/var/lib/o3k-fabric-v3-three-host/${FABRIC_V3_3H_RUN_ID}"
REMOTE_HELPER="$REMOTE_TMP_ROOT/fabric-regression-3host-helper"
SSH_OPTS=(-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$FABRIC_V3_3H_KNOWN_HOSTS_FILE")
FOREIGN_CANARY="f3c$(printf '%x' "$BASHPID")"
GATE_PHASE=preflight
GATE_CLASSIFICATION=HARNESS_GAP
FOREIGN_CANARY_CREATED=0
QEMU_ROOT=""
QEMU_ARCHIVE=""
PACKET_CAPTURE_PID=""
PACKET_CAPTURE_LOCAL_PID=""
PACKET_CAPTURE_REMOTE=""
PACKET_CAPTURE_HOST=""
PACKET_CAPTURE_IP=""
PACKET_CAPTURE_KEY=""
PACKET_FAILED_OPERATION=""
PACKET_FAILED_EXIT_CODE=""
PACKET_FAILED_OBSERVER_TYPE=""
PACKET_FAILED_COMMAND_CLASS=""
PACKET_CAPTURE_PRESERVE_STATUS=0
PACKET_CAPTURE_FAILURE_OPERATION=""
GATE_OPERATION=""
GATE_OPERATION_EXIT_CODE=""
GATE_OBSERVER_TYPE=""
GATE_COMMAND_CLASS=""
GATE_FAILED_HOST=""

ssh_host() {
    local host="$1" ip="$2" key="$3"
    shift 3
    sudo ssh "${SSH_OPTS[@]}" -i "$key" "$REMOTE_USER@$ip" "$@"
}

prepare_fresh_wireguard_identity() {
    local host="$1" ip="$2" key="$3"
    ssh_host "$host" "$ip" "$key" \
        "set -e; parent=\$(dirname '$RUN_ROOT'); sudo test ! -L \"\$parent\"; if ! sudo test -e \"\$parent\"; then sudo install -d -m 0755 \"\$parent\"; fi; sudo python3 -c 'import os,stat,sys; s=os.lstat(sys.argv[1]); assert stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not (s.st_mode & 0o022)' \"\$parent\"; if sudo test -e '$RUN_ROOT' || sudo test -L '$RUN_ROOT'; then exit 1; fi; sudo install -d -m 0700 '$RUN_ROOT' '$RUN_ROOT/fabric-provider'; sudo sh -c 'umask 077; wg genkey > \"$RUN_ROOT/fabric-provider/wireguard-private.key\"'; sudo chmod 0600 '$RUN_ROOT/fabric-provider/wireguard-private.key'; sudo test -f '$RUN_ROOT/fabric-provider/wireguard-private.key'; sudo test ! -L '$RUN_ROOT/fabric-provider/wireguard-private.key'; sudo test \"\$(sudo stat -c %u:%a:%F '$RUN_ROOT/fabric-provider/wireguard-private.key')\" = '0:600:regular file'; sudo sh -c 'wg pubkey < \"$RUN_ROOT/fabric-provider/wireguard-private.key\"'"
}

verify_wireguard_identity() {
    local host="$1" ip="$2" key="$3" expected="$4"
    shift 4
    local -a expected_peers=("$@")
    local base="$EVIDENCE_DIR/wireguard-$host" status
    if (( ${#expected_peers[@]} < 1 || ${#expected_peers[@]} > 2 )); then
        GATE_CLASSIFICATION=HARNESS_GAP
        GATE_FAILED_HOST="$host"
        GATE_OPERATION="wireguard_expected_peers_validate_${host//-/_}"
        GATE_OPERATION_EXIT_CODE=2
        GATE_OBSERVER_TYPE=local_input_validation
        GATE_COMMAND_CLASS=wireguard_expected_peer_contract_validation
        return 2
    fi
    GATE_FAILED_HOST="$host"
    GATE_CLASSIFICATION=HARNESS_GAP
    GATE_OBSERVER_TYPE=ssh_sudo_read_only
    GATE_COMMAND_CLASS=wireguard_public_identity_observation
    GATE_OPERATION="wireguard_public_key_observe_${host//-/_}"
    if ssh_host "$host" "$ip" "$key" \
        "sudo timeout 15s ip netns exec o3k-fabric wg show o3k-wg public-key" \
        >"$base-runtime-public.key" 2>"$base-public-key-observer.stderr"; then
        GATE_OPERATION_EXIT_CODE=0
    else
        GATE_OPERATION_EXIT_CODE=$?
        return "$GATE_OPERATION_EXIT_CODE"
    fi
    GATE_OPERATION="wireguard_peers_observe_${host//-/_}"
    if ssh_host "$host" "$ip" "$key" \
        "sudo timeout 15s ip netns exec o3k-fabric wg show o3k-wg peers" \
        >"$base-runtime-peers.txt" 2>"$base-peers-observer.stderr"; then
        GATE_OPERATION_EXIT_CODE=0
    else
        GATE_OPERATION_EXIT_CODE=$?
        return "$GATE_OPERATION_EXIT_CODE"
    fi
    # Both public observations are preserved before the first assertion.
    GATE_OPERATION="wireguard_identity_compare_${host//-/_}"
    GATE_OBSERVER_TYPE=local_evidence_comparison
    GATE_COMMAND_CLASS=wireguard_public_identity_compare
    if python3 "$SCRIPT_ROOT/fabric-v3-wireguard-identity.py" \
        "$host" "$expected" "${expected_peers[@]}" \
        "$base-runtime-public.key" "$base-runtime-peers.txt" "$base-identity.json"; then
        GATE_OPERATION_EXIT_CODE=0
    else
        status=$?
        GATE_OPERATION_EXIT_CODE="$status"
        if (( status == 1 )); then
            GATE_CLASSIFICATION=PROVIDER_CONFORMANCE_DEFECT
        fi
        return "$status"
    fi
    GATE_FAILED_HOST=""
    GATE_OPERATION=""
    GATE_OPERATION_EXIT_CODE=""
    GATE_OBSERVER_TYPE=""
    GATE_COMMAND_CLASS=""
}

finish_gate() {
    local status=$?
    local original_status=$status
    local cleanup_status=0
    trap - EXIT
    set +e
    if (( PACKET_CAPTURE_PRESERVE_STATUS != 0 )); then
        status=1
        cleanup_status=1
    fi
    if (( original_status != 0 )); then
        printf 'FIRST FAILURE classification=%s phase=%s exit_code=%s\n' \
            "$GATE_CLASSIFICATION" "$GATE_PHASE" "$original_status" >&2
    fi
    if [[ -n "$PACKET_CAPTURE_PID$PACKET_CAPTURE_REMOTE" ]]; then
        if ! preserve_packet_capture; then
            PACKET_CAPTURE_PRESERVE_STATUS=1
            printf 'CLEANUP FAILURE phase=packet_capture_preservation\n' >&2
            status=1
            cleanup_status=1
        fi
    fi
    if (( FOREIGN_CANARY_CREATED )); then
        if ! ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
            "sudo ip link del '$FOREIGN_CANARY'" >/dev/null 2>&1; then
            printf 'CLEANUP FAILURE phase=foreign_canary_cleanup name=%s\n' \
                "$FOREIGN_CANARY" >&2
            status=1
            cleanup_status=1
        fi
    fi
    if [[ -n "$QEMU_ROOT" ]]; then
        if ! rm -rf -- "$QEMU_ROOT"; then
            printf 'CLEANUP FAILURE phase=local_qemu_initrd_cleanup path=%s\n' \
                "$QEMU_ROOT" >&2
            status=1
            cleanup_status=1
        fi
    fi
    if [[ -n "$QEMU_ARCHIVE" ]]; then
        if ! rm -f -- "$QEMU_ARCHIVE"; then
            printf 'CLEANUP FAILURE phase=local_qemu_initrd_archive_cleanup path=%s\n' \
                "$QEMU_ARCHIVE" >&2
            status=1
            cleanup_status=1
        fi
    fi
    if (( status != 0 )); then
        local failure_classification="$GATE_CLASSIFICATION"
        local failure_phase="$GATE_PHASE"
        local failure_code="$original_status"
        if (( original_status == 0 )); then
            failure_classification=CLEANUP_DEFECT
            failure_phase=exit_cleanup
            failure_code=1
        fi
        python3 - "$EVIDENCE_DIR/result.json" "$FABRIC_V3_3H_RUN_ID" \
            "$failure_classification" "$failure_phase" "$failure_code" \
            "$cleanup_status" "${PACKET_FAILED_OPERATION:-$GATE_OPERATION}" "${PACKET_FAILED_EXIT_CODE:-$GATE_OPERATION_EXIT_CODE}" \
            "${PACKET_FAILED_OBSERVER_TYPE:-$GATE_OBSERVER_TYPE}" "${PACKET_FAILED_COMMAND_CLASS:-$GATE_COMMAND_CLASS}" "$PACKET_CAPTURE_PRESERVE_STATUS" "$PACKET_CAPTURE_FAILURE_OPERATION" "$GATE_FAILED_HOST" <<'PYFAIL' || true
import json,pathlib,sys
path,run,classification,phase,code,cleanup_status,failed_operation,failed_operation_code,observer_type,command_class,capture_preserve_status,capture_failure_operation,failed_host=sys.argv[1:]
identity_path=pathlib.Path(path).parent / f"wireguard-{failed_host}-identity.json"
identity=None
if failed_host in {"host-a", "host-b", "host-c"} and identity_path.is_file():
    try:
        identity=json.loads(identity_path.read_text())
    except (OSError, json.JSONDecodeError):
        pass
pathlib.Path(path).write_text(json.dumps({
    "artifact_type":"fabric-v3-provider-gate",
    "run_id":run,
    "status":"failed",
    "classification":classification,
    "failed_phase":phase,
    "exit_code":int(code),
    "cleanup_status":int(cleanup_status),
    "failed_host": failed_host or None,
    "wireguard_identity_evidence": identity,
    "failed_operation": failed_operation or None,
    "failed_operation_exit_code": int(failed_operation_code) if failed_operation_code else None,
    "failed_observer_type": observer_type or None,
    "failed_command_class": command_class or None,
    "packet_capture_preserve_status": int(capture_preserve_status),
    "packet_capture_failure_operation": capture_failure_operation or None,
},sort_keys=True,indent=2)+"\n")
PYFAIL
    fi
    exit "$status"
}
trap finish_gate EXIT

record_packet_probe() {
    local label="$1" host="$2" ip="$3" key="$4" command="$5"
    local base="$EVIDENCE_DIR/traffic/packet-path/$label"
    mkdir -p "$(dirname "$base")"
    set +e
    ssh_host "$host" "$ip" "$key" "$command" >"$base.stdout" 2>"$base.stderr"
    local status=$?
    set -e
    printf '%s\n' "$status" >"$base.status"
    if (( status != 0 )); then
        PACKET_FAILED_OPERATION="packet_probe_$label"
        PACKET_FAILED_EXIT_CODE="$status"
        PACKET_FAILED_OBSERVER_TYPE="sudo_ssh"
        PACKET_FAILED_COMMAND_CLASS="network_namespace_ping_and_neighbor_probe"
    fi
    return "$status"
}

preserve_packet_capture() {
    local status=0
    if [[ -n "$PACKET_CAPTURE_PID" ]]; then
        if ! wait "$PACKET_CAPTURE_LOCAL_PID"; then
            status=1
            PACKET_CAPTURE_PRESERVE_STATUS=1
            PACKET_CAPTURE_FAILURE_OPERATION="packet_capture_wait"
        fi
        PACKET_CAPTURE_PID=""
        PACKET_CAPTURE_LOCAL_PID=""
    fi
    if [[ -n "$PACKET_CAPTURE_REMOTE" ]]; then
        if ! capture_remote_file "$PACKET_CAPTURE_HOST" "$PACKET_CAPTURE_IP" "$PACKET_CAPTURE_KEY" \
            "$PACKET_CAPTURE_REMOTE" traffic/packet-path/underlay-packet-path.txt; then
            status=1
            PACKET_CAPTURE_PRESERVE_STATUS=1
            PACKET_CAPTURE_FAILURE_OPERATION="packet_capture_retrieval"
        fi
        PACKET_CAPTURE_REMOTE=""
    fi
    return "$status"
}

capture_remote_file() {
    local host="$1" ip="$2" key="$3" remote_path="$4" artifact_path="$5"
    mkdir -p "$(dirname "$EVIDENCE_DIR/$artifact_path")"
    ssh_host "$host" "$ip" "$key" "sudo cat -- '$remote_path'" \
        >"$EVIDENCE_DIR/$artifact_path"
}

copy_helper() {
    for spec in "host-a $FABRIC_V3_3H_HOST_A_IP $FABRIC_V3_3H_KEY_A" \
        "host-b $FABRIC_V3_3H_HOST_B_IP $FABRIC_V3_3H_KEY_B" \
        "host-c $FABRIC_V3_3H_HOST_C_IP $FABRIC_V3_3H_KEY_C"; do
        read -r host ip key <<<"$spec"
        ssh_host "$host" "$ip" "$key" "mkdir -p '$REMOTE_TMP_ROOT' && chmod 0755 '$REMOTE_TMP_ROOT'"
        sudo scp "${SSH_OPTS[@]}" -i "$key" "$FABRIC_V3_3H_HELPER_BIN" \
            "$REMOTE_USER@$ip:$REMOTE_HELPER" >/dev/null
        ssh_host "$host" "$ip" "$key" "sudo chmod 755 '$REMOTE_HELPER'"
    done
    sudo scp "${SSH_OPTS[@]}" -i "$FABRIC_V3_3H_KEY_A" \
        "$SCRIPT_ROOT/fabric-v3-dhcp-discover.py" \
        "$REMOTE_USER@$FABRIC_V3_3H_HOST_A_IP:$REMOTE_TMP_ROOT/fabric-v3-dhcp-discover.py" >/dev/null
    ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo chmod 755 '$REMOTE_TMP_ROOT/fabric-v3-dhcp-discover.py'"
    sudo scp "${SSH_OPTS[@]}" -i "$FABRIC_V3_3H_KEY_A" \
        "$SCRIPT_ROOT/fabric-v3-vxlan-inject.py" \
        "$REMOTE_USER@$FABRIC_V3_3H_HOST_A_IP:$REMOTE_TMP_ROOT/fabric-v3-vxlan-inject.py" >/dev/null
    sudo scp "${SSH_OPTS[@]}" -i "$FABRIC_V3_3H_KEY_C" \
        "$SCRIPT_ROOT/fabric-v3-vxlan-inject.py" \
        "$REMOTE_USER@$FABRIC_V3_3H_HOST_C_IP:$REMOTE_TMP_ROOT/fabric-v3-vxlan-inject.py" >/dev/null
    ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo chmod 755 '$REMOTE_TMP_ROOT/fabric-v3-vxlan-inject.py'"
    ssh_host host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" \
        "sudo chmod 755 '$REMOTE_TMP_ROOT/fabric-v3-vxlan-inject.py'"
}

apply_host() {
    local host="$1" ip="$2" key="$3" p1h="$4" p1ip="$5" p1k="$6" p2h="$7" p2ip="$8" p2k="$9"
    ssh_host "$host" "$ip" "$key" \
        "sudo '$REMOTE_HELPER' --root '$RUN_ROOT' --mode apply --host-id '$host' --transport-ip '$ip' --peer '$p1h,$p1ip,$p1ip:65001,$p1k' --peer '$p2h,$p2ip,$p2ip:65001,$p2k'"
}

attach_endpoint() {
    local ip="$1" key="$2" name="$3" bridge="$4" addr="$5" mac="$6"
    ssh_host "endpoint-$name" "$ip" "$key" \
        "sudo ip netns del o3k-ep-$name 2>/dev/null || true; sudo ip netns add o3k-ep-$name; sudo ip link add o3k-v-$name type veth peer name eth0; sudo ip link set eth0 netns o3k-ep-$name; sudo ip link set o3k-v-$name master '$bridge'; sudo ip link set o3k-v-$name mtu 1390; sudo ip link set o3k-v-$name up; sudo ip netns exec o3k-ep-$name ip link set lo up; sudo ip netns exec o3k-ep-$name ip link set eth0 address '$mac'; sudo ip netns exec o3k-ep-$name ip link set eth0 mtu 1390; sudo ip netns exec o3k-ep-$name ip addr add '$addr/24' dev eth0; sudo ip netns exec o3k-ep-$name ip link set eth0 up; sudo ip netns exec o3k-ep-$name sysctl -qw net.ipv4.conf.all.rp_filter=0"
}

# Negative VXLAN probes must use the authenticated WireGuard route rather than
# accidentally placing cleartext VXLAN on the underlay. Verify the kernel's
# selected route and retain a concurrent physical-interface capture for each
# injection below.
assert_wireguard_route() {
    local host="$1" ip="$2" key="$3" peer_transport="$4" route
    route="$(ssh_host "$host" "$ip" "$key" \
        "sudo ip netns exec o3k-fabric ip route get '$peer_transport'")"
    grep -Eq 'dev o3k-wg([[:space:]]|$)' <<<"$route"
    echo "fabric-v3-three-host-gate: authenticated-inject-route host=$host route=$route"
}

capture_wireguard_underlay() {
    local host="$1" ip="$2" key="$3" peer_underlay="$4" output="$5" dev remote_output
    remote_output="$REMOTE_TMP_ROOT/$output"
    dev="$(ssh_host "$host" "$ip" "$key" \
        "ip -4 route get '$peer_underlay' | awk '{print \$3}'")"
    [[ "$dev" =~ ^[[:alnum:]_.-]+$ ]]
    ssh_host "$host" "$ip" "$key" \
        "sudo rm -f '$remote_output' '$remote_output.pid'; sudo sh -c 'tcpdump -G 15 -W 1 -nn -l -i $dev \"udp port 4789 or udp port 65001\" > $remote_output 2>&1 < /dev/null & echo \$! > $remote_output.pid'; for attempt in \$(seq 1 40); do sudo grep -q 'listening on' '$remote_output' && exit 0; sleep 0.05; done; exit 1"
    CAPTURE_DEV="$dev"
}

finish_wireguard_underlay_capture() {
    local host="$1" ip="$2" key="$3" output="$4" remote_output
    remote_output="$REMOTE_TMP_ROOT/$output"
    ssh_host "$host" "$ip" "$key" \
        "pid=\$(sudo cat '$remote_output.pid'); sudo kill -INT \"\$pid\" 2>/dev/null || true; for attempt in \$(seq 1 40); do sudo kill -0 \"\$pid\" 2>/dev/null || break; sleep 0.05; done; set -e; sudo cat '$remote_output'; sudo grep -q '65001' '$remote_output'; ! sudo grep -Eq '\\.4789: UDP' '$remote_output'"
    capture_remote_file "$host" "$ip" "$key" "$remote_output" "underlay/$host-$output"
    echo "fabric-v3-three-host-gate: negative-probe-encrypted-underlay host=$host interface=$CAPTURE_DEV passed"
}

GATE_PHASE=copy_run_tools
GATE_CLASSIFICATION=HARNESS_GAP
copy_helper
GATE_PHASE=wireguard_identity_prepare
GATE_CLASSIFICATION=HARNESS_GAP
GATE_OPERATION=wireguard_identity_prepare
GATE_OPERATION=wireguard_identity_prepare_host_a
AK="$(prepare_fresh_wireguard_identity host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A")"
GATE_OPERATION=wireguard_identity_prepare_host_b
BK="$(prepare_fresh_wireguard_identity host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B")"
GATE_OPERATION=wireguard_identity_prepare_host_c
CK="$(prepare_fresh_wireguard_identity host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C")"
[[ "$AK" =~ ^[A-Za-z0-9+/]{43}=$ && "$BK" =~ ^[A-Za-z0-9+/]{43}=$ && "$CK" =~ ^[A-Za-z0-9+/]{43}=$ ]]
printf '%s\n' "$AK" >"$EVIDENCE_DIR/wireguard-host-a-public.key"
printf '%s\n' "$BK" >"$EVIDENCE_DIR/wireguard-host-b-public.key"
printf '%s\n' "$CK" >"$EVIDENCE_DIR/wireguard-host-c-public.key"
existing_host_a_links="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" 'sudo ip -o link show')"
if grep -Eq "^[0-9]+: ${FOREIGN_CANARY}:" <<<"$existing_host_a_links"; then
    echo "fabric-v3-three-host-gate: foreign canary name collision: $FOREIGN_CANARY" >&2
    exit 1
fi
ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo ip link add '$FOREIGN_CANARY' type bridge"
FOREIGN_CANARY_CREATED=1
ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo ip link set '$FOREIGN_CANARY' up"
foreign_canary_before="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo ip -j -d link show dev '$FOREIGN_CANARY' | python3 -c 'import json,sys; x=json.load(sys.stdin)[0]; print(json.dumps({\"ifname\":x.get(\"ifname\"),\"flags\":x.get(\"flags\"),\"mtu\":x.get(\"mtu\"),\"address\":x.get(\"address\"),\"broadcast\":x.get(\"broadcast\"),\"kind\":x.get(\"linkinfo\",{}).get(\"info_kind\")},sort_keys=True))'")"
printf '%s\n' "$foreign_canary_before" >"$EVIDENCE_DIR/foreign-state-before.json"
GATE_PHASE=provider_apply
GATE_CLASSIFICATION=PROVIDER_CONFORMANCE_DEFECT
apply_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" host-b "$FABRIC_V3_3H_HOST_B_IP" "$BK" host-c "$FABRIC_V3_3H_HOST_C_IP" "$CK"
apply_host host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" host-a "$FABRIC_V3_3H_HOST_A_IP" "$AK" host-c "$FABRIC_V3_3H_HOST_C_IP" "$CK"
apply_host host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" host-a "$FABRIC_V3_3H_HOST_A_IP" "$AK" host-b "$FABRIC_V3_3H_HOST_B_IP" "$BK"
GATE_PHASE=wireguard_identity_verify
GATE_OPERATION=wireguard_identity_verify
# Realm A is hosted by A/B and Realm B by B/C. Thus the aggregate host-fabric
# peer set is B on A, A+C on B, and B on C; nonparticipants are not peers.
verify_wireguard_identity host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" "$AK" "$BK"
verify_wireguard_identity host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" "$BK" "$AK" "$CK"
verify_wireguard_identity host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" "$CK" "$BK"

attach_endpoint "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" a1 o3k-b-a1000000 10.0.0.10 02:00:00:00:a1:01
attach_endpoint "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" a2 o3k-b-a1000000 10.0.0.20 02:00:00:00:a1:02
attach_endpoint "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" b1 o3k-b-b1000000 10.0.0.10 02:00:00:00:b1:01
attach_endpoint "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" b2 o3k-b-b1000000 10.0.0.20 02:00:00:00:b1:02

GATE_PHASE=packet_path_and_wireguard
GATE_CLASSIFICATION=PROVIDER_CONFORMANCE_DEFECT
GATE_OPERATION=underlay_route_lookup
# Capture WireGuard transport packets on host-a's physical/nested underlay
# while the tenant ping traverses the overlay. The decoded capture must show
# only host transport addresses and UDP/65001, never tenant source addresses.
underlay_dev="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "ip -4 route get '$FABRIC_V3_3H_HOST_B_IP' | sed -n 's/.* dev \\([^ ]*\\).*/\1/p'")"
[[ -n "$underlay_dev" ]]
[[ "$underlay_dev" =~ ^[[:alnum:]_.-]+$ ]]
GATE_OPERATION=packet_capture_start
PACKET_CAPTURE_HOST="host-a"
PACKET_CAPTURE_IP="$FABRIC_V3_3H_HOST_A_IP"
PACKET_CAPTURE_KEY="$FABRIC_V3_3H_KEY_A"
PACKET_CAPTURE_REMOTE="$REMOTE_TMP_ROOT/underlay-packet-path.txt"
mkdir -p "$EVIDENCE_DIR/traffic/packet-path"
ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo timeout 12 tcpdump -nn -l -i '$underlay_dev' 'udp port 65001' -c 4 >'$PACKET_CAPTURE_REMOTE' 2>&1" \
    >"$EVIDENCE_DIR/traffic/packet-path/capture-ssh.stdout" \
    2>"$EVIDENCE_DIR/traffic/packet-path/capture-ssh.stderr" &
PACKET_CAPTURE_LOCAL_PID=$!
PACKET_FAILED_OPERATION="packet_capture_start"
PACKET_CAPTURE_PID="$PACKET_CAPTURE_LOCAL_PID"
if ! ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "for attempt in \$(seq 1 20); do sudo test -e '$PACKET_CAPTURE_REMOTE' && exit 0; sleep 0.1; done; exit 1" \
    >/dev/null 2>"$EVIDENCE_DIR/traffic/packet-path/capture-ready.stderr"; then
    PACKET_FAILED_OPERATION="packet_capture_readiness"
    PACKET_FAILED_EXIT_CODE=1
    PACKET_FAILED_OBSERVER_TYPE="sudo_ssh"
    PACKET_FAILED_COMMAND_CLASS="underlay_tcpdump_readiness_observation"
    if ! preserve_packet_capture; then PACKET_CAPTURE_PRESERVE_STATUS=1; fi
    exit 1
fi
GATE_OPERATION=""

record_packet_probe a1 host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" 'sudo ip netns exec o3k-ep-a1 ping -c 3 -W 2 10.0.0.20 && sudo ip netns exec o3k-ep-a1 ip neigh show 10.0.0.20' || { if ! preserve_packet_capture; then PACKET_CAPTURE_PRESERVE_STATUS=1; fi; exit 1; }
record_packet_probe a2 host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" 'sudo ip netns exec o3k-ep-a2 ping -c 3 -W 2 10.0.0.10 && sudo ip netns exec o3k-ep-a2 ip neigh show 10.0.0.10' || { if ! preserve_packet_capture; then PACKET_CAPTURE_PRESERVE_STATUS=1; fi; exit 1; }
record_packet_probe b1 host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" 'sudo ip netns exec o3k-ep-b1 ping -c 3 -W 2 10.0.0.20 && sudo ip netns exec o3k-ep-b1 ip neigh show 10.0.0.20' || { if ! preserve_packet_capture; then PACKET_CAPTURE_PRESERVE_STATUS=1; fi; exit 1; }
record_packet_probe b2 host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" 'sudo ip netns exec o3k-ep-b2 ping -c 3 -W 2 10.0.0.10 && sudo ip netns exec o3k-ep-b2 ip neigh show 10.0.0.10' || { if ! preserve_packet_capture; then PACKET_CAPTURE_PRESERVE_STATUS=1; fi; exit 1; }
preserve_packet_capture
PACKET_FAILED_OPERATION="packet_capture_validation"
if ! grep -q '4 packets captured' "$EVIDENCE_DIR/traffic/packet-path/underlay-packet-path.txt" \
    || grep -q '10\.0\.0\.' "$EVIDENCE_DIR/traffic/packet-path/underlay-packet-path.txt" \
    || ! grep -Fq "$FABRIC_V3_3H_HOST_A_IP" "$EVIDENCE_DIR/traffic/packet-path/underlay-packet-path.txt" \
    || ! grep -Fq "$FABRIC_V3_3H_HOST_B_IP" "$EVIDENCE_DIR/traffic/packet-path/underlay-packet-path.txt"; then
    PACKET_FAILED_EXIT_CODE=1
    exit 1
fi
PACKET_FAILED_OPERATION=""
PACKET_FAILED_EXIT_CODE=""
echo "fabric-v3-three-host-gate: underlay-wireguard-only=passed interface=$underlay_dev"

# Near-boundary traffic must cross at the derived tenant MTU. The next byte
# must produce an explicit local MTU error rather than a silent fabric drop.
ssh_host A1 "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo ip netns exec o3k-ep-a1 ping -c 3 -W 2 -M do -s 1362 10.0.0.20 >/dev/null; if sudo ip netns exec o3k-ep-a1 ping -c 1 -W 2 -M do -s 1363 10.0.0.20 >'$REMOTE_TMP_ROOT/mtu-oversize.txt' 2>&1; then exit 41; fi; grep -Eq 'message too long|Frag needed|mtu=1390' '$REMOTE_TMP_ROOT/mtu-oversize.txt'"
capture_remote_file A1 "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "$REMOTE_TMP_ROOT/mtu-oversize.txt" traffic/mtu-oversize.txt
echo 'fabric-v3-three-host-gate: tenant-mtu-boundary=passed'

# Build a tiny static endpoint guest and attach it to the actual provider TAP.
# This makes the probes cross the same TAP ingress used by a QEMU guest rather
# than treating writes to an unattached TAP as guest traffic.
qemu_root="$(mktemp -d /tmp/fabric-v3-qemu-initrd.XXXXXX)"
QEMU_ROOT="$qemu_root"
QEMU_ARCHIVE="$qemu_root.cpio.gz"
mkdir -p "$qemu_root/bin" "$qemu_root/dev" "$qemu_root/proc" "$qemu_root/sys"
gcc -static -O2 "$SCRIPT_ROOT/fabric-v3-spoof-guest.c" -o "$qemu_root/spoof"
cp "$(command -v busybox)" "$qemu_root/bin/busybox"
for applet in sh mount sleep ip poweroff grep; do
    ln -s busybox "$qemu_root/bin/$applet"
done
cat >"$qemu_root/init" <<'GUEST_INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mode=unknown
for arg in $(cat /proc/cmdline); do case "$arg" in mode=*) mode=${arg#mode=};; esac; done
/bin/ip link set lo up
/bin/ip link set eth0 up
n=0
while ! /bin/ip link show eth0 | /bin/grep -q LOWER_UP; do
  n=$((n+1)); [ "$n" -ge 40 ] && break; /bin/sleep 0.05
done
/spoof "$mode"
/bin/sleep 0.2
/bin/poweroff -f
GUEST_INIT
chmod +x "$qemu_root/init"
(cd "$qemu_root" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1 > "$QEMU_ARCHIVE")
sudo scp "${SSH_OPTS[@]}" -i "$FABRIC_V3_3H_KEY_A" "$QEMU_ARCHIVE" \
    "$REMOTE_USER@$FABRIC_V3_3H_HOST_A_IP:$REMOTE_TMP_ROOT/initrd.cpio.gz" >/dev/null
rm -rf -- "$QEMU_ROOT"
QEMU_ROOT=""
rm -f -- "$QEMU_ARCHIVE"
QEMU_ARCHIVE=""

GATE_PHASE=endpoint_anti_spoof
GATE_CLASSIFICATION=PROVIDER_CONFORMANCE_DEFECT
# Inject each invalid endpoint identity from a KVM guest attached to A1's
# provider TAP, requiring its corresponding O3K nftables counter to increase.
for spec in 'wrong-mac|ether saddr !=' 'wrong-ip|ip saddr !=' \
    'arp-mac|arp saddr ether !=' 'arp-ip|arp saddr ip !='; do
    mode="${spec%%|*}"
    rule="${spec#*|}"
    table="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo nft list tables bridge | grep -m1 '^table bridge o3k-as-' | cut -d ' ' -f 3")"
    line="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo nft list table bridge '$table' | grep -F '$rule' | grep -F 'o3k-t-' | head -1")"
    tap="$(sed -n 's/.*iifname "\([^"]*\)".*/\1/p' <<<"$line")"
    before="$(sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' <<<"$line")"
    [[ -n "$tap" && -n "$before" ]]
    ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo timeout 15 qemu-system-x86_64 -machine accel=kvm -cpu host -m 128 -kernel /boot/vmlinuz-\$(uname -r) -initrd '$REMOTE_TMP_ROOT/initrd.cpio.gz' -append 'console=ttyS0 rdinit=/init mode=$mode' -display none -serial file:'$REMOTE_TMP_ROOT/qemu-guest-$mode.log' -monitor none -no-reboot -netdev tap,id=n1,ifname=$tap,script=no,downscript=no -device virtio-net-pci,netdev=n1; rc=\$?; if [ \"\$rc\" -eq 0 ] || [ \"\$rc\" -eq 124 ]; then exit 0; else exit \"\$rc\"; fi"
    ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo grep -q 'sent guest probe $mode' '$REMOTE_TMP_ROOT/qemu-guest-$mode.log'"
    capture_remote_file host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "$REMOTE_TMP_ROOT/qemu-guest-$mode.log" "antispoof/qemu-guest-$mode.log"
    after_line="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo nft list table bridge '$table' | grep -F '$rule' | grep -F 'iifname \"$tap\"' | head -1")"
    after="$(sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' <<<"$after_line")"
    ((after > before))
    echo "fabric-v3-three-host-gate: antispoof-$mode=passed counter=$before->$after"
done

GATE_PHASE=overlapping_realm_isolation
GATE_CLASSIFICATION=PROVIDER_CONFORMANCE_DEFECT
# Identical addresses in Realm A and Realm B must stay on their own L2 island.
ssh_host B2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo ip netns exec o3k-ep-b2 timeout 5 tcpdump -n -l -i eth0 arp >'$REMOTE_TMP_ROOT/cross-realm.txt' 2>&1" & cap_overlap=$!
sleep 1
ssh_host A1 "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    'sudo ip netns exec o3k-ep-a1 ping -c 2 -W 2 10.0.0.20 >/dev/null'
wait "$cap_overlap" || true
ssh_host B2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "grep -q '0 packets captured' '$REMOTE_TMP_ROOT/cross-realm.txt'"
capture_remote_file B2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "$REMOTE_TMP_ROOT/cross-realm.txt" isolation/cross-realm.txt
echo 'fabric-v3-three-host-gate: overlapping-realm-isolation=passed'

GATE_PHASE=unknown_vni_admission
GATE_CLASSIFICATION=PROVIDER_CONFORMANCE_DEFECT
# Unknown VNI is authenticated at WireGuard ingress but has no local VXLAN
# device. Prove it reaches the decrypted WG boundary, increments the bounded
# netdev rejection counter, and is absent at every endpoint.
auth_table='o3k-fabric-auth'
echo 'fabric-v3-three-host-gate: authenticated-peer-vni-ingress-rules'
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    'sudo ip netns exec o3k-fabric nft -a list table netdev o3k-fabric-auth'
echo 'fabric-v3-three-host-gate: per-realm-bridge-vni-admission-rules'
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    'sudo ip netns exec o3k-fabric nft -a list table bridge o3k-fabric-vni-auth'
before_unknown_line="$(ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo ip netns exec o3k-fabric nft list table netdev '$auth_table' | grep -F 'counter' | grep -F 'drop'")"
before_unknown="$(sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' <<<"$before_unknown_line")"
[[ -n "$before_unknown" ]]
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo ip netns exec o3k-fabric timeout 5 tcpdump -nn -l -i o3k-wg 'udp dst port 4789' >'$REMOTE_TMP_ROOT/unknown-vni-wg.txt' 2>&1" & cap_unknown_wg=$!
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo ip netns exec o3k-ep-a2 timeout 5 tcpdump -nn -l -i eth0 arp >'$REMOTE_TMP_ROOT/unknown-vni-endpoint.txt' 2>&1" & cap_unknown_ep=$!
sleep 1
assert_wireguard_route host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" "$FABRIC_V3_3H_HOST_B_IP"
capture_wireguard_underlay host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "$FABRIC_V3_3H_HOST_B_IP" fabric-v3-unknown-vni-underlay.txt
ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo ip netns exec o3k-fabric python3 '$REMOTE_TMP_ROOT/fabric-v3-vxlan-inject.py' '$FABRIC_V3_3H_HOST_A_IP' '$FABRIC_V3_3H_HOST_B_IP' 999 02:00:00:00:a1:01 10.0.0.10"
finish_wireguard_underlay_capture host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" fabric-v3-unknown-vni-underlay.txt
wait "$cap_unknown_wg" || true
wait "$cap_unknown_ep" || true
after_unknown_line="$(ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo ip netns exec o3k-fabric nft list table netdev '$auth_table' | grep -F 'counter' | grep -F 'drop'")"
after_unknown="$(sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' <<<"$after_unknown_line")"
((after_unknown > before_unknown))
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "grep -q 'vni 999' '$REMOTE_TMP_ROOT/unknown-vni-wg.txt' && grep -q '0 packets captured' '$REMOTE_TMP_ROOT/unknown-vni-endpoint.txt'"
capture_remote_file A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "$REMOTE_TMP_ROOT/unknown-vni-wg.txt" isolation/unknown-vni-wireguard.txt
capture_remote_file A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "$REMOTE_TMP_ROOT/unknown-vni-endpoint.txt" isolation/unknown-vni-endpoint.txt
echo "fabric-v3-three-host-gate: unknown-vni-dropped-before-vxlan counter=$before_unknown->$after_unknown"

GATE_PHASE=nonparticipant_peer_admission
GATE_CLASSIFICATION=PROVIDER_CONFORMANCE_DEFECT
# Host C is authenticated and enrolled, but it is not a Realm A participant.
# A Realm A VNI frame from it must hit the pre-decap peer/VNI admission drop.
before_line="$(ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo ip netns exec o3k-fabric nft list table netdev '$auth_table' | grep -F 'counter' | grep -F 'drop'")"
before="$(sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' <<<"$before_line")"
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo ip netns exec o3k-ep-a2 timeout 5 tcpdump -nn -l -i eth0 arp >'$REMOTE_TMP_ROOT/wrong-peer-endpoint.txt' 2>&1" & cap_wrong_peer=$!
sleep 1
assert_wireguard_route host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" "$FABRIC_V3_3H_HOST_B_IP"
capture_wireguard_underlay host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" \
    "$FABRIC_V3_3H_HOST_B_IP" fabric-v3-wrong-peer-underlay.txt
ssh_host host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" \
    "sudo ip netns exec o3k-fabric python3 '$REMOTE_TMP_ROOT/fabric-v3-vxlan-inject.py' '$FABRIC_V3_3H_HOST_C_IP' '$FABRIC_V3_3H_HOST_B_IP' 101 02:00:00:00:b1:01 10.0.0.30"
finish_wireguard_underlay_capture host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" fabric-v3-wrong-peer-underlay.txt
wait "$cap_wrong_peer" || true
after_line="$(ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo ip netns exec o3k-fabric nft list table netdev '$auth_table' | grep -F 'counter' | grep -F 'drop'")"
after="$(sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' <<<"$after_line")"
((after > before))
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "grep -q '0 packets captured' '$REMOTE_TMP_ROOT/wrong-peer-endpoint.txt'"
capture_remote_file A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "$REMOTE_TMP_ROOT/wrong-peer-endpoint.txt" isolation/wrong-peer-endpoint.txt
echo "fabric-v3-three-host-gate: nonparticipant-peer-vni-rejected counter=$before->$after"

GATE_PHASE=realm_scoped_dhcp_broadcast
GATE_CLASSIFICATION=PROVIDER_CONFORMANCE_DEFECT
# Realm-scoped DHCP-like broadcasts.
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" "sudo ip netns exec o3k-ep-a2 timeout 8 tcpdump -n -l -i eth0 'udp port 67 or 68' >'$REMOTE_TMP_ROOT/dhcp-broadcast-a2.txt' 2>&1" & cap_a=$!
sleep 1
ssh_host A1 "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo ip netns exec o3k-ep-a1 python3 '$REMOTE_TMP_ROOT/fabric-v3-dhcp-discover.py' eth0"
wait "$cap_a" || true
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo grep -q '0.0.0.0.*255.255.255.255.*67' '$REMOTE_TMP_ROOT/dhcp-broadcast-a2.txt'"
capture_remote_file A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "$REMOTE_TMP_ROOT/dhcp-broadcast-a2.txt" dhcp/dhcp-broadcast-a2.txt
echo 'fabric-v3-three-host-gate: dhcp-discover-broadcast=passed'

GATE_PHASE=restart_reconcile
GATE_CLASSIFICATION=PROVIDER_CONFORMANCE_DEFECT
# Reconcile after deleting the host-b WireGuard device.
ssh_host host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" 'sudo ip netns exec o3k-fabric ip link del o3k-wg'
apply_host host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" host-a "$FABRIC_V3_3H_HOST_A_IP" "$AK" host-c "$FABRIC_V3_3H_HOST_C_IP" "$CK"
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" 'sudo ip netns exec o3k-ep-a2 ping -c 3 -W 2 10.0.0.10 >/dev/null'

echo 'fabric-v3-three-host-gate: nested-three-host-packet-path=passed'
echo 'fabric-v3-three-host-gate: nested-realm-broadcast=passed'
echo 'fabric-v3-three-host-gate: nested-restart-reconcile=passed'

GATE_PHASE=provider_cleanup
GATE_CLASSIFICATION=CLEANUP_DEFECT
    for spec in "host-a $FABRIC_V3_3H_HOST_A_IP $FABRIC_V3_3H_KEY_A" \
        "host-b $FABRIC_V3_3H_HOST_B_IP $FABRIC_V3_3H_KEY_B" \
        "host-c $FABRIC_V3_3H_HOST_C_IP $FABRIC_V3_3H_KEY_C"; do
        read -r host ip key <<<"$spec"
        ssh_host "$host" "$ip" "$key" \
            "for n in o3k-ep-a1 o3k-ep-a2 o3k-ep-b1 o3k-ep-b2; do sudo ip netns del \"\$n\" 2>/dev/null || true; done"
    done
    ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo '$REMOTE_HELPER' --root '$RUN_ROOT' --mode remove --host-id host-a --transport-ip '$FABRIC_V3_3H_HOST_A_IP' --peer 'host-b,$FABRIC_V3_3H_HOST_B_IP,$FABRIC_V3_3H_HOST_B_IP:65001,$BK' --peer 'host-c,$FABRIC_V3_3H_HOST_C_IP,$FABRIC_V3_3H_HOST_C_IP:65001,$CK' " \
        >"$EVIDENCE_DIR/remove-host-a.txt"
    ssh_host host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
        "sudo '$REMOTE_HELPER' --root '$RUN_ROOT' --mode remove --host-id host-b --transport-ip '$FABRIC_V3_3H_HOST_B_IP' --peer 'host-a,$FABRIC_V3_3H_HOST_A_IP,$FABRIC_V3_3H_HOST_A_IP:65001,$AK' --peer 'host-c,$FABRIC_V3_3H_HOST_C_IP,$FABRIC_V3_3H_HOST_C_IP:65001,$CK' " \
        >"$EVIDENCE_DIR/remove-host-b.txt"
    ssh_host host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" \
        "sudo '$REMOTE_HELPER' --root '$RUN_ROOT' --mode remove --host-id host-c --transport-ip '$FABRIC_V3_3H_HOST_C_IP' --peer 'host-a,$FABRIC_V3_3H_HOST_A_IP,$FABRIC_V3_3H_HOST_A_IP:65001,$AK' --peer 'host-b,$FABRIC_V3_3H_HOST_B_IP,$FABRIC_V3_3H_HOST_B_IP:65001,$BK' " \
        >"$EVIDENCE_DIR/remove-host-c.txt"
    foreign_canary_after="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo ip -j -d link show dev '$FOREIGN_CANARY' | python3 -c 'import json,sys; x=json.load(sys.stdin)[0]; print(json.dumps({\"ifname\":x.get(\"ifname\"),\"flags\":x.get(\"flags\"),\"mtu\":x.get(\"mtu\"),\"address\":x.get(\"address\"),\"broadcast\":x.get(\"broadcast\"),\"kind\":x.get(\"linkinfo\",{}).get(\"info_kind\")},sort_keys=True))'")"
printf '%s\n' "$foreign_canary_after" >"$EVIDENCE_DIR/foreign-state-after-provider-remove.json"
[[ "$foreign_canary_after" == "$foreign_canary_before" ]]
ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo ip link del '$FOREIGN_CANARY'"
if ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo ip -j -d link show dev '$FOREIGN_CANARY'" >/dev/null 2>&1; then
    echo "CLEANUP_DEFECT: run-owned foreign-state canary remained: $FOREIGN_CANARY" >&2
    exit 1
fi
FOREIGN_CANARY_CREATED=0
GATE_PHASE=evidence_finalize
GATE_CLASSIFICATION=HARNESS_GAP
python3 - "$EVIDENCE_DIR/result.json" "$FABRIC_V3_3H_RUN_ID" \
    "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_HOST_C_IP" <<'PYPASS'
import json,pathlib,sys
path,run,*hosts=sys.argv[1:]
pathlib.Path(path).write_text(json.dumps({
    "artifact_type":"fabric-v3-provider-gate",
    "run_id":run,
    "status":"passed",
    "classification":None,
    "hosts":dict(zip(("host-a","host-b","host-c"),hosts)),
    "provider_remove_observed_hosts":["host-a","host-b","host-c"],
    "foreign_canary_unchanged_before_harness_cleanup":True,
    "foreign_canary_removed_after_harness_cleanup":True,
},sort_keys=True,indent=2)+"\n")
PYPASS
GATE_PHASE=complete
GATE_CLASSIFICATION=NONE
echo 'fabric-v3-three-host-gate: provider-cleanup-and-foreign-canary=passed'
