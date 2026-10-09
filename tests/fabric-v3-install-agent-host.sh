#!/usr/bin/env bash
# Harness-side installation for one Fabric v3 nested compute guest.
# Discover the effective QEMU credentials from a short-lived libvirt QEMU
# process, then grant only that group access to this run's compute storage.
set -Eeuo pipefail

host="$1"; octet="$2"; run="$3"; stage="$4"
[[ "$host" =~ ^[abc]$ && "$octet" =~ ^(20[1-3]|21[1-3]|22[1-9]|23[0-9])$ ]] || { echo "invalid host identity" >&2; exit 2; }
[[ "$run" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || { echo "invalid run id" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
[[ -d "$stage" && ! -L "$stage" ]] || { echo "invalid staging directory" >&2; exit 2; }

base="/var/lib/o3k-fabric-v3/$run"
tls="/etc/o3k-fabric-v3/$run/tls"
[[ ! -e "$base" && ! -L "$base" ]] || { echo "run storage collision: $base" >&2; exit 1; }
[[ ! -e "/etc/o3k-fabric-v3/$run" && ! -L "/etc/o3k-fabric-v3/$run" ]] \
  || { echo "run credential collision: /etc/o3k-fabric-v3/$run" >&2; exit 1; }
probe="o3k-qemu-identity-${run}-${host}"
probe_xml="/run/$probe.xml"
probe_pid=""
probe_created=0
cleanup() {
  set +e
  if (( probe_created )); then
    virsh -c qemu:///system destroy "$probe" >/dev/null 2>&1
  fi
  rm -f -- "$probe_xml"
}
trap cleanup EXIT

virsh -c qemu:///system dominfo "$probe" >/dev/null 2>&1 && { echo "QEMU identity probe collision" >&2; exit 1; }
cat >"$probe_xml" <<EOF
<domain type='kvm'><name>$probe</name><memory unit='MiB'>256</memory><vcpu>1</vcpu>
  <os><type arch='x86_64' machine='q35'>hvm</type></os>
  <features><acpi/><apic/></features><cpu mode='host-passthrough' check='none'/>
  <devices><emulator>/usr/bin/qemu-system-x86_64</emulator>
    <controller type='pci' model='pcie-root'/></devices></domain>
EOF
virsh -c qemu:///system create "$probe_xml" >/dev/null
probe_created=1
for _ in $(seq 1 50); do
  probe_pid="$(ps -ww -eo pid=,args= | awk -v n="$probe" 'index($0,"-name guest=" n ",") {print $1}')"
  [[ -n "$probe_pid" ]] && break
  sleep 0.1
done
[[ -n "$probe_pid" && "$probe_pid" != *$'\n'* ]] || { echo "cannot identify probe QEMU process" >&2; exit 1; }
status="/proc/$probe_pid/status"
qemu_uid="$(awk '/^Uid:/{print $3}' "$status")"
qemu_gid="$(awk '/^Gid:/{print $3}' "$status")"
[[ "$qemu_uid" =~ ^[0-9]+$ && "$qemu_gid" =~ ^[0-9]+$ ]] || { echo "cannot resolve QEMU credentials" >&2; exit 1; }
qemu_user="$(getent passwd "$qemu_uid" | cut -d: -f1)"
qemu_group="$(getent group "$qemu_gid" | cut -d: -f1)"
[[ -n "$qemu_user" && -n "$qemu_group" ]] || { echo "QEMU UID/GID missing from NSS" >&2; exit 1; }

virsh -c qemu:///system destroy "$probe" >/dev/null
rm -f -- "$probe_xml"
trap - EXIT

install -d -m 0700 "$base" "$base/network" "$base/network/fabric-provider" \
  "$base/compute" "$base/compute/tls" "$tls"
printf 'o3k-fabric-v3-run-v1\nrun=%s\nhost=%s\n' "$run" "$host" >"$base/.o3k-fabric-v3-owned"
chmod 0600 "$base/.o3k-fabric-v3-owned"
# Ancestors are traversable by the QEMU group; private network keys and agent
# credentials retain root-only access. The compute tree is setgid so overlays
# inherit the discovered QEMU group.
chown "root:$qemu_gid" "$base" "$base/compute"
chmod 0710 "$base"
chmod 2710 "$base/compute"

install -m 0755 "$stage/o3k-network" /usr/local/bin/o3k-network
install -d -m 0755 /usr/local/libexec
install -m 0755 "$stage/o3k-compute" /usr/local/libexec/o3k-compute-real
cat >/usr/local/bin/o3k-compute <<'EOF'
#!/bin/sh
# Let run-owned qcow2 overlays inherit the QEMU group with controlled access.
umask 0007
exec /usr/local/libexec/o3k-compute-real "$@"
EOF
chmod 0755 /usr/local/bin/o3k-compute
install -m 0644 "$stage/ca.pem" "$tls/ca.pem"
install -m 0644 "$stage/network-agent-$host.pem" "$tls/network-agent.pem"
install -m 0600 "$stage/network-agent-$host-key.pem" "$tls/network-agent-key.pem"
install -m 0644 "$stage/compute-agent-$host.pem" "$base/compute/tls/agent.pem"
install -m 0600 "$stage/compute-agent-$host-key.pem" "$base/compute/tls/agent-key.pem"
install -m 0644 "$stage/ca.pem" "$base/compute/tls/ca.pem"
install -m 0644 "$stage/controller-network.pem" "$tls/controller-network.pem"
install -m 0600 "$stage/controller-network-key.pem" "$tls/controller-network-key.pem"
printf '%s\n' "compute-agent-$host" >"$base/compute/agent-id"
chmod 0600 "$base/compute/agent-id"
if [[ ! -e "$base/network/fabric-provider/wireguard-private.key" ]]; then
  (umask 077; wg genkey >"$base/network/fabric-provider/wireguard-private.key")
fi
chmod 0600 "$base/network/fabric-provider/wireguard-private.key"
wg pubkey <"$base/network/fabric-provider/wireguard-private.key" \
  >"$base/network/fabric-provider/wireguard-public.key"
chmod 0600 "$base/network/fabric-provider/wireguard-public.key"
if ! pgrep -x o3k-network >/dev/null; then
  nohup env \
    O3K_NETWORK_AGENT_ID="network-agent-$host" \
    O3K_NETWORK_AGENT_EPOCH="network-epoch-$host-1" \
    O3K_NETWORK_CONTROLLER_ID="controller-$run" \
    O3K_NETWORK_CONTROLLER_EPOCH="controller-epoch-1" \
    O3K_NETWORK_FENCING_TOKEN=1 \
    O3K_NETWORK_ROOT="$base/network/executor" \
    O3K_NETWORK_BRIDGE=o3k-br0 \
    O3K_NETWORK_UPLINK=mgmt0 \
    O3K_NETWORK_BRIDGE_UPLINK=none \
    O3K_NETWORK_OWNERSHIP_ROOT="$base/network/ownership" \
    O3K_NETWORK_DHCP_ROOT="$base/network/dhcp" \
    O3K_NETWORK_DNSMASQ=/usr/sbin/dnsmasq \
    O3K_NETWORK_FABRIC_ROOT="$base/network/fabric" \
    O3K_NETWORK_TAP_USER="$qemu_user" \
    O3K_NETWORK_TAP_GROUP="$qemu_group" \
    O3K_NETWORK_LISTEN=0.0.0.0:50061 \
    O3K_NETWORK_TLS_CERTIFICATE="$tls/network-agent.pem" \
    O3K_NETWORK_TLS_CERT="$tls/network-agent.pem" \
    O3K_NETWORK_TLS_KEY="$tls/network-agent-key.pem" \
    O3K_NETWORK_TLS_CLIENT_CA="$tls/ca.pem" \
    RUST_LOG=info \
    /usr/local/bin/o3k-network >"$base/network/agent.log" 2>&1 </dev/null &
  echo $! >"$base/network/agent.pid"
fi

echo "QEMU execution identity discovered: $qemu_user:$qemu_group (uid=$qemu_uid gid=$qemu_gid)"
echo "run-owned compute storage prepared: $base/compute (group=$qemu_group, mode=2710)"
