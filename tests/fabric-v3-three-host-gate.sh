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
FOREIGN_CANARY="f3c${BASHPID}"
HOST_A_PUBLIC_KEY_FILE="${FABRIC_V3_3H_HOST_A_PUBLIC_KEY_FILE:-/tmp/fabric-v3-host-a.pub}"
HOST_B_PUBLIC_KEY_FILE="${FABRIC_V3_3H_HOST_B_PUBLIC_KEY_FILE:-/tmp/fabric-v3-host-b.pub}"
HOST_C_PUBLIC_KEY_FILE="${FABRIC_V3_3H_HOST_C_PUBLIC_KEY_FILE:-/tmp/fabric-v3-host-c.pub}"

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
    sudo scp "${SSH_OPTS[@]}" -i "$FABRIC_V3_3H_KEY_A" \
        "$PWD/tests/fabric-v3-dhcp-discover.py" \
        "$REMOTE_USER@$FABRIC_V3_3H_HOST_A_IP:/tmp/fabric-v3-dhcp-discover.py" >/dev/null
    ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        'sudo chmod 755 /tmp/fabric-v3-dhcp-discover.py'
    sudo scp "${SSH_OPTS[@]}" -i "$FABRIC_V3_3H_KEY_A" \
        "$PWD/tests/fabric-v3-vxlan-inject.py" \
        "$REMOTE_USER@$FABRIC_V3_3H_HOST_A_IP:/tmp/fabric-v3-vxlan-inject.py" >/dev/null
    sudo scp "${SSH_OPTS[@]}" -i "$FABRIC_V3_3H_KEY_C" \
        "$PWD/tests/fabric-v3-vxlan-inject.py" \
        "$REMOTE_USER@$FABRIC_V3_3H_HOST_C_IP:/tmp/fabric-v3-vxlan-inject.py" >/dev/null
    ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        'sudo chmod 755 /tmp/fabric-v3-vxlan-inject.py'
    ssh_host host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" \
        'sudo chmod 755 /tmp/fabric-v3-vxlan-inject.py'
}

apply_host() {
    local host="$1" ip="$2" key="$3" p1h="$4" p1ip="$5" p1k="$6" p2h="$7" p2ip="$8" p2k="$9"
    ssh_host "$host" "$ip" "$key" \
        "sudo /tmp/fabric-regression-3host-helper --root '$RUN_ROOT' --mode apply --host-id '$host' --transport-ip '$ip' --peer '$p1h,$p1ip,$p1ip:65001,$p1k' --peer '$p2h,$p2ip,$p2ip:65001,$p2k'"
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
    local host="$1" ip="$2" key="$3" peer_underlay="$4" output="$5" dev
    dev="$(ssh_host "$host" "$ip" "$key" \
        "ip -4 route get '$peer_underlay' | awk '{print \$3}'")"
    [[ "$dev" =~ ^[[:alnum:]_.-]+$ ]]
    ssh_host "$host" "$ip" "$key" \
        "sudo rm -f '/tmp/$output' '/tmp/$output.pid'; sudo sh -c 'tcpdump -G 15 -W 1 -nn -l -i $dev \"udp port 4789 or udp port 65001\" > /tmp/$output 2>&1 < /dev/null & echo \$! > /tmp/$output.pid'; for attempt in \$(seq 1 40); do sudo grep -q 'listening on' '/tmp/$output' && exit 0; sleep 0.05; done; exit 1"
    CAPTURE_DEV="$dev"
}

finish_wireguard_underlay_capture() {
    local host="$1" ip="$2" key="$3" output="$4"
    ssh_host "$host" "$ip" "$key" \
        "pid=\$(sudo cat '/tmp/$output.pid'); sudo kill -INT \"\$pid\" 2>/dev/null || true; for attempt in \$(seq 1 40); do sudo kill -0 \"\$pid\" 2>/dev/null || break; sleep 0.05; done; set -e; sudo cat '/tmp/$output'; sudo grep -q '65001' '/tmp/$output'; ! sudo grep -Eq '\\.4789: UDP' '/tmp/$output'"
    echo "fabric-v3-three-host-gate: negative-probe-encrypted-underlay host=$host interface=$CAPTURE_DEV passed"
}

copy_helper
AK="$(cat "$HOST_A_PUBLIC_KEY_FILE")"
BK="$(cat "$HOST_B_PUBLIC_KEY_FILE")"
CK="$(cat "$HOST_C_PUBLIC_KEY_FILE")"
existing_host_a_links="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" 'sudo ip -o link show')"
if grep -Eq "^[0-9]+: ${FOREIGN_CANARY}:" <<<"$existing_host_a_links"; then
    echo "fabric-v3-three-host-gate: foreign canary name collision: $FOREIGN_CANARY" >&2
    exit 1
fi
ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo ip link add '$FOREIGN_CANARY' type bridge && sudo ip link set '$FOREIGN_CANARY' up"
foreign_canary_before="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo ip -j -d link show dev '$FOREIGN_CANARY' | python3 -c 'import json,sys; x=json.load(sys.stdin)[0]; print(json.dumps({\"ifname\":x.get(\"ifname\"),\"flags\":x.get(\"flags\"),\"mtu\":x.get(\"mtu\"),\"address\":x.get(\"address\"),\"broadcast\":x.get(\"broadcast\"),\"kind\":x.get(\"linkinfo\",{}).get(\"info_kind\")},sort_keys=True))'")"
apply_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" host-b "$FABRIC_V3_3H_HOST_B_IP" "$BK" host-c "$FABRIC_V3_3H_HOST_C_IP" "$CK"
apply_host host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" host-a "$FABRIC_V3_3H_HOST_A_IP" "$AK" host-c "$FABRIC_V3_3H_HOST_C_IP" "$CK"
apply_host host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" host-a "$FABRIC_V3_3H_HOST_A_IP" "$AK" host-b "$FABRIC_V3_3H_HOST_B_IP" "$BK"

attach_endpoint "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" a1 o3k-b-a1000000 10.0.0.10 02:00:00:00:a1:01
attach_endpoint "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" a2 o3k-b-a1000000 10.0.0.20 02:00:00:00:a1:02
attach_endpoint "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" b1 o3k-b-b1000000 10.0.0.10 02:00:00:00:b1:01
attach_endpoint "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" b2 o3k-b-b1000000 10.0.0.20 02:00:00:00:b1:02

# Capture WireGuard transport packets on host-a's physical/nested underlay
# while the tenant ping traverses the overlay. The decoded capture must show
# only host transport addresses and UDP/65001, never tenant source addresses.
underlay_dev="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "ip -4 route get '$FABRIC_V3_3H_HOST_B_IP' | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p'")"
[[ -n "$underlay_dev" ]]
ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "sudo timeout 12 tcpdump -nn -l -i '$underlay_dev' 'udp port 65001' -c 4 >/tmp/fabric-v3-underlay-capture.txt 2>&1" & cap_underlay=$!
sleep 1

ssh_host A1 "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" 'sudo ip netns exec o3k-ep-a1 ping -c 3 -W 2 10.0.0.20 >/dev/null && sudo ip netns exec o3k-ep-a1 ip neigh show 10.0.0.20'
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" 'sudo ip netns exec o3k-ep-a2 ping -c 3 -W 2 10.0.0.10 >/dev/null && sudo ip netns exec o3k-ep-a2 ip neigh show 10.0.0.10'
ssh_host B1 "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" 'sudo ip netns exec o3k-ep-b1 ping -c 3 -W 2 10.0.0.20 >/dev/null && sudo ip netns exec o3k-ep-b1 ip neigh show 10.0.0.20'
ssh_host B2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" 'sudo ip netns exec o3k-ep-b2 ping -c 3 -W 2 10.0.0.10 >/dev/null && sudo ip netns exec o3k-ep-b2 ip neigh show 10.0.0.10'
wait "$cap_underlay" || true
ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    'grep -q "4 packets captured" /tmp/fabric-v3-underlay-capture.txt; ! grep -q "10\\.0\\.0\\." /tmp/fabric-v3-underlay-capture.txt; grep -q "192\\.168\\.122" /tmp/fabric-v3-underlay-capture.txt'
echo "fabric-v3-three-host-gate: underlay-wireguard-only=passed interface=$underlay_dev"

# Near-boundary traffic must cross at the derived tenant MTU. The next byte
# must produce an explicit local MTU error rather than a silent fabric drop.
ssh_host A1 "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    'sudo ip netns exec o3k-ep-a1 ping -c 3 -W 2 -M do -s 1362 10.0.0.20 >/dev/null; if sudo ip netns exec o3k-ep-a1 ping -c 1 -W 2 -M do -s 1363 10.0.0.20 >/tmp/fabric-v3-mtu-oversize.txt 2>&1; then exit 41; fi; grep -Eq "message too long|Frag needed|mtu=1390" /tmp/fabric-v3-mtu-oversize.txt'
echo 'fabric-v3-three-host-gate: tenant-mtu-boundary=passed'

# Build a tiny static endpoint guest and attach it to the actual provider TAP.
# This makes the probes cross the same TAP ingress used by a QEMU guest rather
# than treating writes to an unattached TAP as guest traffic.
qemu_root="$(mktemp -d /tmp/fabric-v3-qemu-initrd.XXXXXX)"
mkdir -p "$qemu_root/bin" "$qemu_root/dev" "$qemu_root/proc" "$qemu_root/sys"
gcc -static -O2 "$PWD/tests/fabric-v3-spoof-guest.c" -o "$qemu_root/spoof"
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
(cd "$qemu_root" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1 > "$qemu_root.cpio.gz")
sudo scp "${SSH_OPTS[@]}" -i "$FABRIC_V3_3H_KEY_A" "$qemu_root.cpio.gz" \
    "$REMOTE_USER@$FABRIC_V3_3H_HOST_A_IP:/tmp/fabric-v3-initrd.cpio.gz" >/dev/null

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
        "sudo timeout 15 qemu-system-x86_64 -machine accel=kvm -cpu host -m 128 -kernel /boot/vmlinuz-\$(uname -r) -initrd /tmp/fabric-v3-initrd.cpio.gz -append 'console=ttyS0 rdinit=/init mode=$mode' -display none -serial file:/tmp/fabric-v3-qemu-guest-$mode.log -monitor none -no-reboot -netdev tap,id=n1,ifname=$tap,script=no,downscript=no -device virtio-net-pci,netdev=n1; rc=\$?; if [ \"\$rc\" -eq 0 ] || [ \"\$rc\" -eq 124 ]; then exit 0; else exit \"\$rc\"; fi"
    ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo grep -q 'sent guest probe $mode' /tmp/fabric-v3-qemu-guest-$mode.log"
    after_line="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo nft list table bridge '$table' | grep -F '$rule' | grep -F 'iifname \"$tap\"' | head -1")"
    after="$(sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' <<<"$after_line")"
    ((after > before))
    echo "fabric-v3-three-host-gate: antispoof-$mode=passed counter=$before->$after"
done

# Identical addresses in Realm A and Realm B must stay on their own L2 island.
ssh_host B2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    'sudo ip netns exec o3k-ep-b2 timeout 5 tcpdump -n -l -i eth0 arp >/tmp/fabric-v3-cross-realm.txt 2>&1' & cap_overlap=$!
sleep 1
ssh_host A1 "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    'sudo ip netns exec o3k-ep-a1 ping -c 2 -W 2 10.0.0.20 >/dev/null'
wait "$cap_overlap" || true
ssh_host B2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    'grep -q "0 packets captured" /tmp/fabric-v3-cross-realm.txt'
echo 'fabric-v3-three-host-gate: overlapping-realm-isolation=passed'

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
    'sudo ip netns exec o3k-fabric timeout 5 tcpdump -nn -l -i o3k-wg "udp dst port 4789" >/tmp/fabric-v3-unknown-vni-wg.txt 2>&1' & cap_unknown_wg=$!
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    'sudo ip netns exec o3k-ep-a2 timeout 5 tcpdump -nn -l -i eth0 arp >/tmp/fabric-v3-unknown-vni-endpoint.txt 2>&1' & cap_unknown_ep=$!
sleep 1
assert_wireguard_route host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" "$FABRIC_V3_3H_HOST_B_IP"
capture_wireguard_underlay host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    "$FABRIC_V3_3H_HOST_B_IP" fabric-v3-unknown-vni-underlay.txt
ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    'sudo ip netns exec o3k-fabric python3 /tmp/fabric-v3-vxlan-inject.py 192.168.122.118 192.168.122.134 999 02:00:00:00:a1:01 10.0.0.10'
finish_wireguard_underlay_capture host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" fabric-v3-unknown-vni-underlay.txt
wait "$cap_unknown_wg" || true
wait "$cap_unknown_ep" || true
after_unknown_line="$(ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo ip netns exec o3k-fabric nft list table netdev '$auth_table' | grep -F 'counter' | grep -F 'drop'")"
after_unknown="$(sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' <<<"$after_unknown_line")"
((after_unknown > before_unknown))
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    'grep -q "vni 999" /tmp/fabric-v3-unknown-vni-wg.txt && grep -q "0 packets captured" /tmp/fabric-v3-unknown-vni-endpoint.txt'
echo "fabric-v3-three-host-gate: unknown-vni-dropped-before-vxlan counter=$before_unknown->$after_unknown"

# Host C is authenticated and enrolled, but it is not a Realm A participant.
# A Realm A VNI frame from it must hit the pre-decap peer/VNI admission drop.
before_line="$(ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo ip netns exec o3k-fabric nft list table netdev '$auth_table' | grep -F 'counter' | grep -F 'drop'")"
before="$(sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' <<<"$before_line")"
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    'sudo ip netns exec o3k-ep-a2 timeout 5 tcpdump -nn -l -i eth0 arp >/tmp/fabric-v3-wrong-peer-endpoint.txt 2>&1' & cap_wrong_peer=$!
sleep 1
assert_wireguard_route host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" "$FABRIC_V3_3H_HOST_B_IP"
capture_wireguard_underlay host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" \
    "$FABRIC_V3_3H_HOST_B_IP" fabric-v3-wrong-peer-underlay.txt
ssh_host host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" \
    'sudo ip netns exec o3k-fabric python3 /tmp/fabric-v3-vxlan-inject.py 192.168.122.196 192.168.122.134 101 02:00:00:00:b1:01 10.0.0.30'
finish_wireguard_underlay_capture host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" fabric-v3-wrong-peer-underlay.txt
wait "$cap_wrong_peer" || true
after_line="$(ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    "sudo ip netns exec o3k-fabric nft list table netdev '$auth_table' | grep -F 'counter' | grep -F 'drop'")"
after="$(sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' <<<"$after_line")"
((after > before))
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    'grep -q "0 packets captured" /tmp/fabric-v3-wrong-peer-endpoint.txt'
echo "fabric-v3-three-host-gate: nonparticipant-peer-vni-rejected counter=$before->$after"

# Realm-scoped DHCP-like broadcasts.
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" "sudo ip netns exec o3k-ep-a2 timeout 8 tcpdump -n -l -i eth0 'udp port 67 or 68' >/tmp/fabric-v3-dhcp-a2.txt 2>&1" & cap_a=$!
sleep 1
ssh_host A1 "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
    'sudo ip netns exec o3k-ep-a1 python3 /tmp/fabric-v3-dhcp-discover.py eth0'
wait "$cap_a" || true
ssh_host A2 "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
    'sudo grep -q "0.0.0.0.*255.255.255.255.*67" /tmp/fabric-v3-dhcp-a2.txt'
echo 'fabric-v3-three-host-gate: dhcp-discover-broadcast=passed'

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
        "sudo /tmp/fabric-regression-3host-helper --root '$RUN_ROOT' --mode remove --host-id host-a --transport-ip 192.168.122.118 --peer host-b,192.168.122.134,192.168.122.134:65001,$BK --peer host-c,192.168.122.196,192.168.122.196:65001,$CK" >/dev/null
    ssh_host host-b "$FABRIC_V3_3H_HOST_B_IP" "$FABRIC_V3_3H_KEY_B" \
        "sudo /tmp/fabric-regression-3host-helper --root '$RUN_ROOT' --mode remove --host-id host-b --transport-ip 192.168.122.134 --peer host-a,192.168.122.118,192.168.122.118:65001,$AK --peer host-c,192.168.122.196,192.168.122.196:65001,$CK" >/dev/null
    ssh_host host-c "$FABRIC_V3_3H_HOST_C_IP" "$FABRIC_V3_3H_KEY_C" \
        "sudo /tmp/fabric-regression-3host-helper --root '$RUN_ROOT' --mode remove --host-id host-c --transport-ip 192.168.122.196 --peer host-a,192.168.122.118,192.168.122.118:65001,$AK --peer host-b,192.168.122.134,192.168.122.134:65001,$BK" >/dev/null
    foreign_canary_after="$(ssh_host host-a "$FABRIC_V3_3H_HOST_A_IP" "$FABRIC_V3_3H_KEY_A" \
        "sudo ip -j -d link show dev '$FOREIGN_CANARY' | python3 -c 'import json,sys; x=json.load(sys.stdin)[0]; print(json.dumps({\"ifname\":x.get(\"ifname\"),\"flags\":x.get(\"flags\"),\"mtu\":x.get(\"mtu\"),\"address\":x.get(\"address\"),\"broadcast\":x.get(\"broadcast\"),\"kind\":x.get(\"linkinfo\",{}).get(\"info_kind\")},sort_keys=True))'")"
    [[ "$foreign_canary_after" == "$foreign_canary_before" ]]
    echo 'fabric-v3-three-host-gate: provider-cleanup-and-foreign-canary=passed'
fi
