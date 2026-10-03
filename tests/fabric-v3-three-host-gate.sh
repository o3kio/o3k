#!/usr/bin/env bash
set -Eeuo pipefail

# Disposable nested three-host Fabric v3 gate. This is evidence tooling only;
# it does not create or modify canonical O3K state. The provider helper builds
# the accepted fixture and the commands below attach disposable endpoint
# namespaces to the provider-owned realm bridges.

: "${FABRIC_V3_3H_HELPER_BIN:?set FABRIC_V3_3H_HELPER_BIN to the built helper}"
: "${FABRIC_V3_3H_HOST_A_IP:?set host-a address}"
: "${FABRIC_V3_3H_HOST_B_IP:?set host-b address}"
: "${FABRIC_V3_3H_HOST_C_IP:?set host-c address}"
: "${FABRIC_V3_3H_KEY_A:?set host-a ssh key}"
: "${FABRIC_V3_3H_KEY_B:?set host-b ssh key}"
: "${FABRIC_V3_3H_KEY_C:?set host-c ssh key}"

RUN_ROOT="${FABRIC_V3_3H_REMOTE_ROOT:-/tmp/o3k-fabric-v3-three-host}"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
REMOTE_USER="${FABRIC_V3_3H_REMOTE_USER:-o3k}"

ssh_host() {
    local host="$1" ip="$2" key="$3"
    shift 3
    sudo ssh "${SSH_OPTS[@]}" -i "$key" "$REMOTE_USER@$ip" "$@"
}

copy_helper() {
    for spec in "host-a $FABRIC_V3_3H_HOST_A_IP $FABRIC_V3_3H_KEY_A" \
        "host-b $FABRIC_V3_3H_HOST_B_IP $FABRIC_V3_3H_KEY_B" \
        "host-c $FABRIC_V3_3H_HOST_C_IP $FABRIC_V3_3H_KEY_C"; do
        read -r host ip key <<<"$spec"
        sudo scp "${SSH_OPTS[@]}" -i "$key" "$FABRIC_V3_3H_HELPER_BIN" \
            "$REMOTE_USER@$ip:/tmp/fabric-regression-3host-helper" >/dev/null
        ssh_host "$host" "$ip" "$key" \
            'sudo chmod 755 /tmp/fabric-regression-3host-helper'
    done
}

apply_host() {
    local host="$1" ip="$2" key="$3" p1h="$4" p1ip="$5" p1k="$6" p2h="$7" p2ip="$8" p2k="$9"
    ssh_host "$host" "$ip" "$key" \
        "sudo /tmp/fabric-regression-3host-helper --root '$RUN_ROOT' --mode apply --host-id '$host' --transport-ip '$ip' --peer '$p1h,$p1ip,$p1ip:65001,$p1k' --peer '$p2h,$p2ip,$p2ip:65001,$p2k'"
}

attach_endpoint() {
    local ip="$1" key="$2" name="$3" bridge="$4" addr="$5" mac="$6"
    ssh_host "endpoint-$name" "$ip" "$key" \
        "sudo ip netns del o3k-ep-$name 2>/dev/null || true; sudo ip netns add o3k-ep-$name; sudo ip link add o3k-v-$name type veth peer name eth0; sudo ip link set eth0 netns o3k-ep-$name; sudo ip link set o3k-v-$name master '$bridge'; sudo ip link set o3k-v-$name up; sudo ip netns exec o3k-ep-$name ip link set lo up; sudo ip netns exec o3k-ep-$name ip link set eth0 address '$mac'; sudo ip netns exec o3k-ep-$name ip addr add '$addr/24' dev eth0; sudo ip netns exec o3k-ep-$name ip link set eth0 up; sudo ip netns exec o3k-ep-$name sysctl -qw net.ipv4.conf.all.rp_filter=0"
}

copy_helper
AK="$(cat /tmp/fabric-v3-host-a.pub)"
BK="$(cat /tmp/fabric-v3-host-b.pub)"
CK="$(cat /tmp/fabric-v3-host-c.pub)"
ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    'sudo ip link add f3-foreign-can type bridge 2>/dev/null || true; sudo ip link set f3-foreign-can up'
apply_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" host-b "$FABRIC_V3_3H_HOST_B_IP" "$BK" host-c "$FABRIC_V3_3H_HOST_C_IP" "$CK"
apply_host host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" host-a "$FABRIC_V3_3H_HOST_A_IP" "$AK" host-c "$FABRIC_V3_3H_HOST_C_IP" "$CK"
apply_host host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" host-a "$FABRIC_V3_3H_HOST_A_IP" "$AK" host-b "$FABRIC_V3_3H_HOST_B_IP" "$BK"

attach_endpoint "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" a1 o3k-b-a1000000 10.0.0.10 02:00:00:00:a1:01
attach_endpoint "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" a2 o3k-b-a1000000 10.0.0.20 02:00:00:00:a1:02
attach_endpoint "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" b1 o3k-b-b1000000 10.0.0.10 02:00:00:00:b1:01
attach_endpoint "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" b2 o3k-b-b1000000 10.0.0.20 02:00:00:00:b1:02

ssh_host A1 "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" 'sudo ip netns exec o3k-ep-a1 ping -c 3 -W 2 10.0.0.20 >/dev/null && sudo ip netns exec o3k-ep-a1 ip neigh show 10.0.0.20'
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" 'sudo ip netns exec o3k-ep-a2 ping -c 3 -W 2 10.0.0.10 >/dev/null && sudo ip netns exec o3k-ep-a2 ip neigh show 10.0.0.10'
ssh_host B1 "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" 'sudo ip netns exec o3k-ep-b1 ping -c 3 -W 2 10.0.0.20 >/dev/null && sudo ip netns exec o3k-ep-b1 ip neigh show 10.0.0.20'
ssh_host B2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" 'sudo ip netns exec o3k-ep-b2 ping -c 3 -W 2 10.0.0.10 >/dev/null && sudo ip netns exec o3k-ep-b2 ip neigh show 10.0.0.10'

# Realm-scoped DHCP-like broadcasts.
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" "sudo ip netns exec o3k-ep-a2 timeout 8 tcpdump -n -l -i eth0 'udp port 67 or 68' >/tmp/fabric-v3-dhcp-a2.txt 2>&1" & cap_a=$!
sleep 1
ssh_host A1 "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" 'sudo ip netns exec o3k-ep-a1 python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1); s.sendto(b\"DHCP-DISCOVER-A\",(\"10.0.0.255\",67))"'
wait "$cap_a" || true
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" 'sudo grep -q "10.0.0.10.*10.0.0.255.*67" /tmp/fabric-v3-dhcp-a2.txt'

# Reconcile after deleting the host-b WireGuard device.
ssh_host host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" 'sudo ip netns exec o3k-fabric ip link del o3k-wg'
apply_host host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" host-a "$FABRIC_V3_3H_HOST_A_IP" "$AK" host-c "$FABRIC_V3_3H_HOST_C_IP" "$CK"
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" 'sudo ip netns exec o3k-ep-a2 ping -c 3 -W 2 10.0.0.10 >/dev/null'

echo 'fabric-v3-three-host-gate: nested-three-host-packet-path=passed'
echo 'fabric-v3-three-host-gate: nested-realm-broadcast=passed'
echo 'fabric-v3-three-host-gate: nested-restart-reconcile=passed'

if [[ "${FABRIC_V3_3H_KEEP:-0}" != 1 ]]; then
    for spec in "host-a $FABRIC_V3_3H_HOST_A_IP $FABRIC_V3_3H_KEY_A" \
        "host-b $FABRIC_V3_3H_HOST_B_IP $FABRIC_V3_3H_KEY_B" \
        "host-c $FABRIC_V3_3H_HOST_C_IP $FABRIC_V3_3H_KEY_C"; do
        read -r host ip key <<<"$spec"
        ssh_host "$host" "$ip" "$key" 'for n in o3k-ep-a1 o3k-ep-a2 o3k-ep-b1 o3k-ep-b2; do sudo ip netns del "$n" 2>/dev/null || true; done'
    done
    ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        'sudo /tmp/fabric-regression-3host-helper --root /tmp/o3k-fabric-v3-three-host --mode remove --host-id host-a --transport-ip 192.168.122.118 --peer host-b,192.168.122.134,192.168.122.134:65001,'"$BK"' --peer host-c,192.168.122.196,192.168.122.196:65001,'"$CK" >/dev/null
    ssh_host host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
        'sudo /tmp/fabric-regression-3host-helper --root /tmp/o3k-fabric-v3-three-host --mode remove --host-id host-b --transport-ip 192.168.122.134 --peer host-a,192.168.122.118,192.168.122.118:65001,'"$AK"' --peer host-c,192.168.122.196,192.168.122.196:65001,'"$CK" >/dev/null
    ssh_host host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" \
        'sudo /tmp/fabric-regression-3host-helper --root /tmp/o3k-fabric-v3-three-host --mode remove --host-id host-c --transport-ip 192.168.122.196 --peer host-a,192.168.122.118,192.168.122.118:65001,'"$AK"' --peer host-b,192.168.122.134,192.168.122.134:65001,'"$BK" >/dev/null
    ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        'sudo ip link show f3-foreign-can >/dev/null'
    echo 'fabric-v3-three-host-gate: provider-cleanup-and-foreign-canary=passed'
fi
