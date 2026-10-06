#!/usr/bin/env bash
set -Eeuo pipefail

# Supported-HTTP Fabric v3 three-host nested campaign. This script is test
# harness only and refuses to run against a different product source tree.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRODUCT_SHA=ba23a65e312ae8755673e2af131937760b4fb248
PRODUCT_TREE=b7a71360fac7e6cf8ba931018e5b4f9ff40a055c
BASE_IMAGE="${O3K_FABRIC_V3_BASE_IMAGE:-/var/lib/libvirt/images/noble-server-cloudimg-amd64.img}"
CIRROS_URL=https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img
CIRROS_SHA=7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b
RUN_ID="${O3K_FABRIC_V3_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
PREFIX="o3k-fabric-v3-${RUN_ID}"
EVIDENCE_ROOT="${O3K_FABRIC_V3_EVIDENCE_ROOT:-/var/tmp}"
EVIDENCE="$EVIDENCE_ROOT/fabric-v3-minimal-three-host-$RUN_ID"
IMAGE_STORE="${O3K_FABRIC_V3_IMAGE_STORE:-/var/lib/libvirt/images}"
NETWORK="${O3K_FABRIC_V3_LIBVIRT_NETWORK:-default}"
SSH_USER=o3k
SSH_PORT=22
API_PORT="${O3K_FABRIC_V3_API_PORT:-18081}"
CONTROL_PORT="${O3K_FABRIC_V3_CONTROL_PORT:-50051}"
PROJECT_ID=eba29e2d-53de-461d-ae91-ede7402713cb
FABRIC_DOMAIN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
SSH_KEY="$EVIDENCE/management/campaign_ed25519"
KNOWN_HOSTS="$EVIDENCE/management/known_hosts"
TLS_DIR="$EVIDENCE/management/tls"
STAGE="$EVIDENCE/environment/stage"
BASE=""
TOKEN=""
O3KD_PID=""
CAMPAIGN_FAILURE=""
CLASSIFICATION=""
FRESH_DOMAINS=()
SERVER_IDS=()
PORT_IDS=()
NETWORK_ID=""
SUBNET_ID=""
IMAGE_ID=""
declare -A MGMT_IP=() MGMT_OCTET=()
HOSTS=(a b c)

fail() {
  CAMPAIGN_FAILURE="$*"
  CLASSIFICATION="${2:-HARNESS_GAP}"
  echo "FIRST FAILURE [$CLASSIFICATION]: ${CAMPAIGN_FAILURE%%|*}" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || fail "required command missing: $1"; }
ssh_opts=(-i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" -o ConnectTimeout=8)
# The destination is local shell data; ssh intentionally expands remote command arguments client-side.
# shellcheck disable=SC2029
ssh_vm() { local address="$1"; shift; ssh "${ssh_opts[@]}" "$SSH_USER@$address" "$@"; }
scp_vm() { local address="$1"; shift; scp -i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" "$@" "$SSH_USER@$address:"; }
api() { curl --silent --show-error --fail-with-body --max-time 30 -H "x-auth-token: $TOKEN" "$@"; }
field() { python3 -c 'import json,sys
v=json.load(sys.stdin)
for k in sys.argv[1].split("."): v=v[int(k)] if isinstance(v,list) else v[k]
print(v)' "$1"; }
url_port() { local port="$1"; python3 - "$port" <<'PY'
import socket,sys
s=socket.socket(); s.bind(("0.0.0.0", int(sys.argv[1]))); s.close()
PY
}
find_free_port() {
  local preferred="$1" port
  for port in $(seq "$preferred" "$((preferred + 100))"); do
    if url_port "$port" >/dev/null 2>&1; then printf '%s\n' "$port"; return 0; fi
  done
  return 1
}

if [[ -z "${O3K_FABRIC_V3_API_PORT:-}" ]]; then
  API_PORT="$(find_free_port "$API_PORT")" || fail "no free API port in configured range" "ENVIRONMENT_GAP"
fi
if [[ -z "${O3K_FABRIC_V3_CONTROL_PORT:-}" ]]; then
  CONTROL_PORT="$(find_free_port "$CONTROL_PORT")" || fail "no free compute-control port in configured range" "ENVIRONMENT_GAP"
fi

[[ ! -e "$EVIDENCE" && ! -L "$EVIDENCE" ]] || fail "evidence path already exists: $EVIDENCE" "HARNESS_GAP"
mkdir -p "$EVIDENCE"/{environment,management,api,canonical,plans,attachments,compute-a,compute-b,compute-c,arp,icmp,tcp,udp,wireguard,vxlan,restart,compute-agent-restart,endpoint-removal,teardown}
chmod 0700 "$EVIDENCE"
[[ ! -e "$EVIDENCE/.o3k-fabric-v3-owned" ]] || fail "evidence path collision"
printf 'o3k-fabric-v3-campaign-v1\nrun=%s\nprefix=%s\n' "$RUN_ID" "$PREFIX" >"$EVIDENCE/.o3k-fabric-v3-owned"
chmod 0600 "$EVIDENCE/.o3k-fabric-v3-owned"
git -C "$ROOT_DIR" rev-parse HEAD >"$EVIDENCE/environment/harness_sha.txt"
git -C "$ROOT_DIR" rev-parse 'HEAD^{tree}' >"$EVIDENCE/environment/harness_tree.txt"
cp "$ROOT_DIR/tests/fabric-v3-o3k-three-host-campaign.sh" "$EVIDENCE/environment/campaign-driver.sh"
cp "$ROOT_DIR/tests/fabric-v3-install-agent-host.sh" "$EVIDENCE/environment/install-agent-host.sh"
sha256sum "$ROOT_DIR/tests/fabric-v3-o3k-three-host-campaign.sh" >"$EVIDENCE/environment/driver.sha256"

cleanup_on_success() {
  local rc=$?
  if (( rc == 0 )) && [[ "${CAMPAIGN_TEARDOWN_PASS:-0}" == 1 ]]; then
    # Teardown is API-led; guests are deleted only if their exact run prefix
    # and UUID markers still match the inventory recorded by this process.
    for domain in "${FRESH_DOMAINS[@]}"; do
      [[ "$domain" == "$PREFIX-compute-"[abc] ]] || continue
      xml="$(virsh -c qemu:///system dumpxml "$domain" 2>/dev/null || true)"
      expected_uuid="$(awk -F '\t' -v n="$domain" '$2==n{print $5}' "$EVIDENCE/environment/inventory.tsv")"
      actual_uuid="$(virsh -c qemu:///system domuuid "$domain" 2>/dev/null || true)"
      if [[ -n "$expected_uuid" && "$actual_uuid" == "$expected_uuid" ]] \
        && grep -Fq "<name>$domain</name>" <<<"$xml" \
        && grep -Fq "$PREFIX" <<<"$xml"; then
        virsh -c qemu:///system destroy "$domain" >/dev/null 2>&1 || true
        virsh -c qemu:///system undefine "$domain" --remove-all-storage >/dev/null 2>&1 || true
      fi
    done
  fi
  if [[ -n "$O3KD_PID" ]]; then kill -TERM "$O3KD_PID" 2>/dev/null || true; wait "$O3KD_PID" 2>/dev/null || true; fi
  if [[ -f "$EVIDENCE/.o3k-fabric-v3-owned" ]] && grep -Fqx "run=$RUN_ID" "$EVIDENCE/.o3k-fabric-v3-owned"; then
    date -u +%FT%TZ >"$EVIDENCE/ended_at_utc.txt"
    if [[ ! -f "$EVIDENCE/result.json" ]]; then
      python3 - "$EVIDENCE/result.json" "$RUN_ID" "$PRODUCT_SHA" "$PRODUCT_TREE" "$CAMPAIGN_FAILURE" "$CLASSIFICATION" <<'PY'
import json,sys
path,run,product,tree,failure,classification=sys.argv[1:]
json.dump({"result":"FAIL","run_id":run,"product_sha":product,"product_tree":tree,"first_failure":failure,"classification":classification or "HARNESS_GAP"},open(path,"w"),sort_keys=True,indent=2)
print(file=open(path,"a"))
PY
    fi
    tar --exclude="$(basename "$EVIDENCE")/management/campaign_ed25519" \
      --exclude="$(basename "$EVIDENCE")/management/tls/certs" \
      --exclude="$(basename "$EVIDENCE")/environment/stage" \
      --exclude="$(basename "$EVIDENCE")/controller-data" \
      -C "$EVIDENCE_ROOT" -czf "$EVIDENCE.tar.gz" "$(basename "$EVIDENCE")"
    sha256sum "$EVIDENCE.tar.gz" >"$EVIDENCE.tar.gz.sha256"
    echo "EVIDENCE_ARCHIVE=$EVIDENCE.tar.gz"
    cat "$EVIDENCE.tar.gz.sha256"
  fi
}
trap cleanup_on_success EXIT

if ! command -v cargo >/dev/null 2>&1; then
  cargo_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
  if [[ -n "$cargo_home" && -x "$cargo_home/.cargo/bin/cargo" ]]; then
    PATH="$cargo_home/.cargo/bin:$PATH"
    export PATH
  fi
fi
for tool in cargo curl openssl python3 virsh virt-install qemu-img genisoimage ssh ssh-keygen ssh-keyscan scp ip wg sha256sum tar timeout bridge hostnamectl; do need "$tool"; done
[[ $EUID -eq 0 ]] || fail "campaign must run as root to provision nested libvirt guests" "ENVIRONMENT_GAP"
[[ -c /dev/kvm ]] || fail "/dev/kvm unavailable" "ENVIRONMENT_GAP"
[[ -r "$BASE_IMAGE" ]] || fail "base image unreadable: $BASE_IMAGE" "ENVIRONMENT_GAP"
[[ "$(git -C "$ROOT_DIR" rev-parse "$PRODUCT_SHA^{tree}")" == "$PRODUCT_TREE" ]] || fail "frozen product source tree mismatch" "HARNESS_GAP"
[[ -z "$(git -C "$ROOT_DIR" diff --name-only "$PRODUCT_SHA" -- bins crates Cargo.toml Cargo.lock)" ]] || fail "product source differs from frozen candidate" "PRODUCT_DEFECT"
url_port "$API_PORT" || fail "API port is occupied: $API_PORT" "ENVIRONMENT_GAP"
url_port "$CONTROL_PORT" || fail "compute control port is occupied: $CONTROL_PORT" "ENVIRONMENT_GAP"
git -C "$ROOT_DIR" rev-parse HEAD >"$EVIDENCE/environment/harness_sha.txt"
git -C "$ROOT_DIR" rev-parse 'HEAD^{tree}' >"$EVIDENCE/environment/harness_tree.txt"
git -C "$ROOT_DIR" rev-parse "$PRODUCT_SHA" >"$EVIDENCE/environment/product_sha.txt"
git -C "$ROOT_DIR" rev-parse "$PRODUCT_SHA^{tree}" >"$EVIDENCE/environment/product_tree.txt"
hostnamectl >"$EVIDENCE/environment/physical-host.txt" 2>&1 || hostname >"$EVIDENCE/environment/physical-host.txt"
date -u +%FT%TZ >"$EVIDENCE/started_at_utc.txt"
sha256sum "$BASE_IMAGE" >"$EVIDENCE/environment/base-image.sha256"
[[ "$(awk '{print $1}' "$EVIDENCE/environment/base-image.sha256")" == 612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354 ]] || fail "base image checksum mismatch" "ENVIRONMENT_GAP"

echo "Building frozen binaries from $PRODUCT_SHA"
 CARGO_TARGET_DIR="$ROOT_DIR/target" cargo build --release --all-features -p o3kd -p o3k-compute-bin -p o3k-network-bin >"$EVIDENCE/environment/build.log" 2>&1 || fail "frozen product binaries failed to build" "HARNESS_GAP"
for binary in o3kd o3k-compute-bin o3k-network-bin; do
  [[ -x "$ROOT_DIR/target/release/$binary" ]] || fail "missing frozen binary $binary" "HARNESS_GAP"
  sha256sum "$ROOT_DIR/target/release/$binary" >>"$EVIDENCE/environment/runtime-assets.sha256"
done

echo "Running accepted QEMU storage preflight"
O3K_QEMU_PREFLIGHT_RUN_ID="$RUN_ID" bash "$ROOT_DIR/tests/fabric-v3-qemu-storage-preflight.sh" >"$EVIDENCE/environment/qemu-storage-preflight.txt" 2>&1 || fail "QEMU storage preflight failed" "ENVIRONMENT_GAP"

virsh -c qemu:///system net-info "$NETWORK" >"$EVIDENCE/environment/libvirt-network.txt" 2>&1 || fail "libvirt management network unavailable" "ENVIRONMENT_GAP"
virsh -c qemu:///system list --all --name | sed '/^$/d' | sort >"$EVIDENCE/environment/libvirt-domains-before.txt"
net_active="$(awk -F': *' '/^Active:/{print $2}' "$EVIDENCE/environment/libvirt-network.txt")"
[[ "$net_active" == yes ]] || fail "libvirt management network is inactive" "ENVIRONMENT_GAP"
BRIDGE="$(virsh -c qemu:///system net-dumpxml "$NETWORK" | sed -n "s/.*bridge name='\([^']*\)'.*/\1/p" | head -1)"
[[ -n "$BRIDGE" ]] || fail "cannot identify management bridge" "ENVIRONMENT_GAP"
HOST_MGMT_IP="$(ip -4 -o addr show dev "$BRIDGE" | awk '{split($4,a,"/"); print a[1]; exit}')"
[[ -n "$HOST_MGMT_IP" ]] || fail "management bridge lacks IPv4 address" "ENVIRONMENT_GAP"
BASE="http://$HOST_MGMT_IP:$API_PORT"

umask 077
ssh-keygen -q -t ed25519 -N '' -C "$PREFIX" -f "$SSH_KEY"
ssh-keygen -lf "$SSH_KEY.pub" >"$EVIDENCE/management/ssh-key-fingerprint.txt"
cp "$SSH_KEY.pub" "$EVIDENCE/management/ssh-authorized-key.pub"
chmod 0600 "$SSH_KEY"; chmod 0644 "$SSH_KEY.pub"
: >"$KNOWN_HOSTS"; chmod 0600 "$KNOWN_HOSTS"

gateway="$(virsh -c qemu:///system net-dumpxml "$NETWORK" | sed -n "s/.*ip address='\([0-9.]*\)'.*/\1/p" | head -1)"
[[ -n "$gateway" ]] || fail "cannot identify management gateway" "ENVIRONMENT_GAP"
available_octets=()
for octet in $(seq 221 239); do
  address="192.168.122.$octet"
  ip neigh show dev "$BRIDGE" | grep -Fq "$address" && continue
  virsh -c qemu:///system net-dhcp-leases "$NETWORK" | grep -Fq "$address" && continue
  timeout 2 bash -c "</dev/tcp/$address/$SSH_PORT" >/dev/null 2>&1 && continue
  available_octets+=("$octet")
  ((${#available_octets[@]} == 3)) && break
done
((${#available_octets[@]} == 3)) || fail "fewer than three unused management addresses in 192.168.122.221-239" "ENVIRONMENT_GAP"
for index in 0 1 2; do
  host="${HOSTS[$index]}"
  octet="${available_octets[$index]}"
  address="192.168.122.$octet"
  MGMT_OCTET[$host]="$octet"
  MGMT_IP[$host]="$address"
done
printf 'compute-a=%s\ncompute-b=%s\ncompute-c=%s\n' "${MGMT_IP[a]}" "${MGMT_IP[b]}" "${MGMT_IP[c]}" >"$EVIDENCE/environment/management-addresses.txt"

for host in a b c; do
  octet="${MGMT_OCTET[$host]}"; domain="$PREFIX-compute-$host"; address="${MGMT_IP[$host]}"
  if virsh -c qemu:///system dominfo "$domain" >/dev/null 2>&1; then fail "fresh domain name collision: $domain" "ENVIRONMENT_GAP"; fi
  disk="$IMAGE_STORE/$PREFIX-compute-$host.qcow2"; seed="$IMAGE_STORE/$PREFIX-compute-$host-seed.iso"; ws="$EVIDENCE/environment/seed-$host"
  [[ ! -e "$disk" && ! -e "$seed" ]] || fail "fresh guest disk/seed collision for $host" "ENVIRONMENT_GAP"
  mkdir -m 0700 "$ws"
  mac="52:54:00:fa:32:$(printf '%02x' "$((octet-210))")"
  cat >"$ws/user-data" <<EOF
#cloud-config
hostname: compute-$host
users:
  - name: $SSH_USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    groups: [sudo, kvm]
    ssh_authorized_keys:
      - $(cat "$SSH_KEY.pub")
disable_root: true
ssh_pwauth: false
package_update: true
packages:
  - qemu-kvm
  - libvirt-daemon-system
  - libvirt-clients
  - qemu-utils
  - wireguard-tools
  - dnsmasq
  - nftables
  - curl
runcmd:
  - [systemctl, enable, --now, libvirtd]
  - [usermod, -aG, libvirt,kvm, o3k]
EOF
  cat >"$ws/network-config" <<EOF
version: 2
ethernets:
  mgmt0:
    match: {macaddress: "$mac"}
    set-name: mgmt0
    addresses: ["$address/24"]
    routes: [{to: default, via: "$gateway"}]
    nameservers: {addresses: ["$gateway", "1.1.1.1"]}
EOF
  printf 'instance-id: %s\nlocal-hostname: compute-%s\n' "$domain" "$host" >"$ws/meta-data"
  genisoimage -quiet -output "$seed" -volid cidata -joliet -rock "$ws/user-data" "$ws/meta-data" "$ws/network-config" || fail "seed ISO creation failed for $host" "HARNESS_GAP"
  qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$disk" 16G || fail "overlay creation failed for $host" "ENVIRONMENT_GAP"
  chgrp kvm "$disk" "$seed"; chmod 0640 "$disk" "$seed"
  virt-install --connect qemu:///system --name "$domain" --uuid "$(python3 -c 'import uuid; print(uuid.uuid4())')" --import --ram 4096 --vcpus 2 --cpu host-passthrough --disk "path=$disk,format=qcow2,bus=virtio" --disk "path=$seed,device=cdrom" --network "network=$NETWORK,model=virtio,mac=$mac" --os-variant ubuntu24.04 --graphics none --noautoconsole --quiet || fail "libvirt failed to create fresh compute guest $host" "ENVIRONMENT_GAP"
  FRESH_DOMAINS+=("$domain")
  printf '%s\t%s\t%s\t%s\t%s\n' "compute-$host" "$domain" "$address" "$mac" "$(virsh -c qemu:///system domuuid "$domain")" >>"$EVIDENCE/environment/inventory.tsv"
done

for host in a b c; do
  address="${MGMT_IP[$host]}"; domain="$PREFIX-compute-$host"
  ready=0
  for _ in $(seq 1 240); do
    if timeout 4 bash -c "</dev/tcp/$address/$SSH_PORT" >/dev/null 2>&1; then
      ssh-keyscan -T 3 -H "$address" >>"$KNOWN_HOSTS" 2>/dev/null || true
      if ssh_vm "$address" true >/dev/null 2>&1; then ready=1; break; fi
    fi
    virsh -c qemu:///system domstate "$domain" | grep -qi running || fail "guest $host is not running" "ENVIRONMENT_GAP"
    sleep 5
  done
  (( ready == 1 )) || fail "authenticated SSH readiness timed out for compute-$host" "ENVIRONMENT_GAP"
  packages_ready=0
  for _ in $(seq 1 240); do
    if ssh_vm "$address" 'command -v virsh >/dev/null && command -v wg >/dev/null && command -v bridge >/dev/null && command -v nft >/dev/null && sudo systemctl is-active --quiet libvirtd' >/dev/null 2>&1; then
      packages_ready=1
      break
    fi
    sleep 5
  done
  (( packages_ready == 1 )) || fail "guest $host did not finish installing the required nested compute tools" "ENVIRONMENT_GAP"
  # The remote $PRETTY_NAME expansion is required for guest OS identification.
  # shellcheck disable=SC2016
  ssh_vm "$address" 'printf "boot_id="; cat /proc/sys/kernel/random/boot_id; printf "kernel="; uname -r; printf "os="; . /etc/os-release; echo "$PRETTY_NAME"; ip -j link; ip -j route; bridge -j link; bridge -j fdb; (wg show || true); (sudo nft list ruleset || true); (sudo find /var/lib/o3k-fabric-v3 -maxdepth 5 -type f -print 2>/dev/null || true); sudo virsh list --all --name' >"$EVIDENCE/environment/baseline-compute-$host.txt" || fail "baseline collection failed for compute-$host" "ENVIRONMENT_GAP"
  echo "compute-$host management PASS $address domain=$domain"
done
ssh-keygen -lf "$KNOWN_HOSTS" >"$EVIDENCE/management/known-hosts-fingerprints.txt"

install -d -m 0700 "$TLS_DIR" "$STAGE"
extra_ids=(--agent-id compute-agent-a --extra-agent-id compute-agent-b --extra-agent-id compute-agent-c --extra-agent-id network-agent-a --extra-agent-id network-agent-b --extra-agent-id network-agent-c --extra-agent-id controller-network)
bash "$ROOT_DIR/packaging/bootstrap-certs.sh" --output-dir "$TLS_DIR/certs" --server-name o3k-control-plane "${extra_ids[@]}" >"$EVIDENCE/management/cert-generation.txt" 2>&1 || fail "campaign TLS identity generation failed" "HARNESS_GAP"
cp "$ROOT_DIR/target/release/o3k-network-bin" "$STAGE/o3k-network"
cp "$ROOT_DIR/target/release/o3k-compute-bin" "$STAGE/o3k-compute"
cp "$ROOT_DIR/tests/fabric-v3-install-agent-host.sh" "$STAGE/install-agent-host.sh"
cp "$TLS_DIR/certs/ca.pem" "$STAGE/ca.pem"
for host in a b c; do
  cp "$TLS_DIR/certs/server.pem" "$STAGE/network-agent-$host.pem"
  cp "$TLS_DIR/certs/server-key.pem" "$STAGE/network-agent-$host-key.pem"
  if [[ "$host" == a ]]; then
    compute_cert_dir="$TLS_DIR/certs"
  else
    compute_cert_dir="$TLS_DIR/certs/agents/compute-agent-$host"
  fi
  cp "$compute_cert_dir/agent.pem" "$STAGE/compute-agent-$host.pem"
  cp "$compute_cert_dir/agent-key.pem" "$STAGE/compute-agent-$host-key.pem"
done
cp "$TLS_DIR/certs/agents/controller-network/agent.pem" "$STAGE/controller-network.pem"
cp "$TLS_DIR/certs/agents/controller-network/agent-key.pem" "$STAGE/controller-network-key.pem"

for host in a b c; do
  octet="${MGMT_OCTET[$host]}"; address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo install -d -o o3k -g o3k -m 0700 /tmp/$RUN_ID-stage"
  scp -i "$SSH_KEY" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" "$STAGE"/* "$SSH_USER@$address:/tmp/$RUN_ID-stage/"
  ssh_vm "$address" "sudo bash /tmp/$RUN_ID-stage/install-agent-host.sh $host $octet $RUN_ID /tmp/$RUN_ID-stage" >"$EVIDENCE/management/install-$host.log" 2>&1 || fail "network agent installation failed on compute-$host" "ENVIRONMENT_GAP"
  case "$host" in a) health_port=19101;; b) health_port=19102;; c) health_port=19103;; esac
  ssh_vm "$address" "sudo install -m 0755 /tmp/$RUN_ID-stage/o3k-compute /usr/local/bin/o3k-compute-bin; sudo install -d -m 0700 /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls; sudo install -m 0644 /tmp/$RUN_ID-stage/compute-agent-$host.pem /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls/agent.pem; sudo install -m 0600 /tmp/$RUN_ID-stage/compute-agent-$host-key.pem /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls/agent-key.pem; sudo install -m 0644 /tmp/$RUN_ID-stage/ca.pem /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls/ca.pem; sudo chown -R root:root /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls; sudo bash -c 'umask 077; printf compute-agent-$host > /var/lib/o3k-fabric-v3/$RUN_ID/compute/agent-id'; sudo nohup env O3K_COMPUTE_DATA_DIR=/var/lib/o3k-fabric-v3/$RUN_ID/compute O3K_COMPUTE_CONTROL_ENDPOINT=https://$HOST_MGMT_IP:$CONTROL_PORT O3K_COMPUTE_SERVER_NAME=o3k-control-plane O3K_COMPUTE_HOST_LABEL=host-$host O3K_COMPUTE_TLS_DIR=/var/lib/o3k-fabric-v3/$RUN_ID/compute/tls O3K_COMPUTE_HEALTH_ADDR=0.0.0.0:$health_port O3K_COMPUTE_MAX_DISK_GB=30 O3K_COMPUTE_NETWORK_EXTERNAL=1 O3K_COMPUTE_NETWORK_ROOT=/var/lib/o3k-fabric-v3/$RUN_ID/network/ownership O3K_COMPUTE_BRIDGE_NAME=o3k-br0 O3K_COMPUTE_DHCP_BINARY=/usr/sbin/dnsmasq O3K_COMPUTE_FABRIC_HOST_ID=host-$host O3K_COMPUTE_FABRIC_STATE_ROOT=/var/lib/o3k-fabric-v3/$RUN_ID/network/fabric RUST_LOG=info /usr/local/bin/o3k-compute-bin >/var/lib/o3k-fabric-v3/$RUN_ID/compute/agent.log 2>&1 </dev/null & echo \$! | sudo tee /var/lib/o3k-fabric-v3/$RUN_ID/compute/agent.pid >/dev/null"
done

for host in a b c; do
  address="${MGMT_IP[$host]}"; ready=0
  case "$host" in a) health_port=19101;; b) health_port=19102;; c) health_port=19103;; esac
  for _ in $(seq 1 60); do
    if ssh_vm "$address" "sudo curl -fsS http://127.0.0.1:$health_port/readyz" >/dev/null 2>&1; then ready=1; break; fi
    sleep 2
  done
  (( ready == 1 )) || fail "compute agent health failed on host-$host" "ENVIRONMENT_GAP"
  ssh_vm "$address" "sudo ip -j -d link show dev mgmt0; sudo wg show; sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric-provider/wireguard-public.key" >"$EVIDENCE/management/compute-$host.txt" || fail "host-$host runtime observation failed" "ENVIRONMENT_GAP"
done

WG_A="$(ssh_vm "${MGMT_IP[a]}" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric-provider/wireguard-public.key")"
WG_B="$(ssh_vm "${MGMT_IP[b]}" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric-provider/wireguard-public.key")"
WG_C="$(ssh_vm "${MGMT_IP[c]}" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric-provider/wireguard-public.key")"
cat >"$EVIDENCE/environment/fabric-identities.json" <<JSON
[
 {"host_id":"host-a","agent_id":"network-agent-a","public_key":"$WG_A","underlay_endpoint":"${MGMT_IP[a]}:65001","fabric_transport_ip":"100.64.3.1","provider_version":"wireguard-v1","fabric_generation":1,"underlay_mtu":1500,"fabric_mtu":1440,"administrative_state":"enabled"},
 {"host_id":"host-b","agent_id":"network-agent-b","public_key":"$WG_B","underlay_endpoint":"${MGMT_IP[b]}:65001","fabric_transport_ip":"100.64.3.2","provider_version":"wireguard-v1","fabric_generation":1,"underlay_mtu":1500,"fabric_mtu":1440,"administrative_state":"enabled"},
 {"host_id":"host-c","agent_id":"network-agent-c","public_key":"$WG_C","underlay_endpoint":"${MGMT_IP[c]}:65001","fabric_transport_ip":"100.64.3.3","provider_version":"wireguard-v1","fabric_generation":1,"underlay_mtu":1500,"fabric_mtu":1440,"administrative_state":"enabled"}
]
JSON
DIRECTORY="$(python3 "${MGMT_IP[a]}" "${MGMT_IP[b]}" "${MGMT_IP[c]}" <<'PY'
import json,sys
print(json.dumps([{"host_id":f"host-{x}","agent_id":f"network-agent-{x}","agent_epoch":f"network-epoch-{x}-1","endpoint":f"https://{ip}:50061","tls_server_name":"o3k-control-plane"} for x,ip in zip("abc",sys.argv[1:])],separators=(",",":")))
PY
)"
AUTHORIZED=""
for host in a b c; do
  if [[ "$host" == a ]]; then
    compute_cert="$TLS_DIR/certs/agent.pem"
  else
    compute_cert="$TLS_DIR/certs/agents/compute-agent-$host/agent.pem"
  fi
  fp="$(openssl x509 -in "$compute_cert" -outform DER | sha256sum | awk '{print $1}')"
  [[ -z "$AUTHORIZED" ]] || AUTHORIZED+=,
  AUTHORIZED+="compute-agent-$host=$fp"
done
SIGNING_KEY="$(openssl rand -hex 48)"
FABRIC_HOST_IDENTITIES="$(cat "$EVIDENCE/environment/fabric-identities.json")"
install -d -m 0700 "$EVIDENCE/controller-data"
export O3K_PROVIDER=agent O3K_DATA_DIR="$EVIDENCE/controller-data" O3K_CONTROLLER_ID="controller-$RUN_ID" O3K_CONTROLLER_EPOCH="controller-epoch-1" O3K_BOOTSTRAP_PASSWORD="campaign-$RUN_ID" O3K_TOKEN_SIGNING_KEY="$SIGNING_KEY"
export O3K_FABRIC_DOMAIN_ID="$FABRIC_DOMAIN_ID" O3K_FABRIC_HOST_IDENTITIES="$FABRIC_HOST_IDENTITIES" O3K_NETWORK_AGENT_DIRECTORY="$DIRECTORY"
export O3K_NETWORK_AGENT_CA="$TLS_DIR/certs/ca.pem" O3K_NETWORK_AGENT_CLIENT_CERT="$TLS_DIR/certs/agents/controller-network/agent.pem" O3K_NETWORK_AGENT_CLIENT_KEY="$TLS_DIR/certs/agents/controller-network/agent-key.pem"
export O3K_COMPUTE_CONTROL_ADDR="0.0.0.0:$CONTROL_PORT" O3K_COMPUTE_SERVER_CERTIFICATE="$TLS_DIR/certs/server.pem" O3K_COMPUTE_SERVER_PRIVATE_KEY="$TLS_DIR/certs/server-key.pem" O3K_COMPUTE_CLIENT_CA="$TLS_DIR/certs/ca.pem" O3K_COMPUTE_AUTHORIZED_AGENTS="$AUTHORIZED"
"$ROOT_DIR/target/release/o3kd" --listen-addr "$HOST_MGMT_IP:$API_PORT" --data-dir "$EVIDENCE/controller-data" --log-filter info >"$EVIDENCE/management/o3kd.log" 2>&1 &
O3KD_PID=$!
for _ in $(seq 1 120); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; kill -0 "$O3KD_PID" 2>/dev/null || fail "o3kd exited during startup" "ENVIRONMENT_GAP"; sleep 1; done
curl -fsS "$BASE/readyz" >"$EVIDENCE/management/o3kd-ready.json" || fail "o3kd failed readiness" "ENVIRONMENT_GAP"

curl -fsS -X POST "$BASE/v3/auth/tokens" -H 'content-type: application/json' -D "$EVIDENCE/api/auth.headers" -o "$EVIDENCE/api/auth.body" --data "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"admin\",\"password\":\"campaign-$RUN_ID\"}}},\"scope\":{\"project\":{\"name\":\"admin\"}}}}" || fail "supported HTTP authentication failed" "SUPPORTED_API_GAP"
TOKEN="$(awk 'tolower($1)=="x-subject-token:"{print $2}' "$EVIDENCE/api/auth.headers" | tr -d '\r')"
[[ -n "$TOKEN" ]] || fail "authentication returned no token" "SUPPORTED_API_GAP"
python3 - "$EVIDENCE/api/auth.headers" <<'PY'
import pathlib,re,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text(errors="replace")
p.write_text(re.sub(r'(?im)^(x-subject-token:\s*).+$',r'\1[REDACTED]',s))
PY

curl --fail --silent --show-error --max-time 30 -X POST "$BASE/v2/images" -H "x-auth-token: $TOKEN" -H 'content-type: application/json' -d "{\"name\":\"$PREFIX-cirros\",\"disk_format\":\"qcow2\",\"container_format\":\"bare\",\"visibility\":\"private\"}" >"$EVIDENCE/api/image-create.response.json" || fail "supported image create failed" "SUPPORTED_API_GAP"
IMAGE_ID="$(field id <"$EVIDENCE/api/image-create.response.json")"
image_file="${O3K_FABRIC_V3_CIRROS_IMAGE:-$EVIDENCE/environment/cirros-0.6.3-x86_64-disk.img}"
if [[ ! -f "$image_file" ]]; then curl --fail --location --silent --show-error "$CIRROS_URL" -o "$image_file" || fail "CirrOS download failed" "ENVIRONMENT_GAP"; fi
printf '%s  %s\n' "$CIRROS_SHA" "$image_file" | sha256sum --check --status || fail "CirrOS checksum mismatch" "ENVIRONMENT_GAP"
sha256sum "$image_file" >"$EVIDENCE/environment/cirros.sha256"
curl --fail --silent --show-error --max-time 120 -X PUT "$BASE/v2/images/$IMAGE_ID/file" -H "x-auth-token: $TOKEN" -H 'content-type: application/octet-stream' --data-binary "@$image_file" >"$EVIDENCE/api/image-upload.response.txt" || fail "supported image upload failed" "SUPPORTED_API_GAP"

curl --fail --silent --show-error -X POST "$BASE/v2.0/networks" -H "x-auth-token: $TOKEN" -H 'content-type: application/json' -d "{\"network\":{\"name\":\"$PREFIX-network\"}}" >"$EVIDENCE/api/network-create.response.json" || fail "supported network create failed" "SUPPORTED_API_GAP"
NETWORK_ID="$(field network.id <"$EVIDENCE/api/network-create.response.json")"
curl --fail --silent --show-error -X POST "$BASE/v2.0/subnets" -H "x-auth-token: $TOKEN" -H 'content-type: application/json' -d "{\"subnet\":{\"name\":\"$PREFIX-subnet\",\"network_id\":\"$NETWORK_ID\",\"cidr\":\"10.77.0.0/24\"}}" >"$EVIDENCE/api/subnet-create.response.json" || fail "supported subnet create failed" "SUPPORTED_API_GAP"
SUBNET_ID="$(field subnet.id <"$EVIDENCE/api/subnet-create.response.json")"
FLAVOR_ID="$(api "$BASE/v2.1/$PROJECT_ID/flavors" | python3 -c 'import json,sys; print(json.load(sys.stdin)["flavors"][0]["id"])')"
[[ -n "$FLAVOR_ID" ]] || fail "supported flavor listing returned no flavor" "SUPPORTED_API_GAP"

create_server() {
  local host="$1" port_id response server_id status request
  port_id="$(api -X POST "$BASE/v2.0/ports" -H 'content-type: application/json' -d "{\"port\":{\"name\":\"$PREFIX-port-$host\",\"network_id\":\"$NETWORK_ID\"}}" | tee "$EVIDENCE/api/port-$host.response.json" | field port.id)"
  PORT_IDS+=("$port_id")
  request="$EVIDENCE/api/server-$host.create.json"
  python3 - "$request" "$PREFIX" "$host" "$IMAGE_ID" "$FLAVOR_ID" "$port_id" <<'PY'
import json,sys
path,prefix,host,image,flavor,port=sys.argv[1:]
json.dump({"server":{"name":f"{prefix}-server-{host}","image":{"id":image},"flavor":{"id":flavor},"networks":[{"uuid":port}],"config_drive":False}},open(path,"w"),sort_keys=True)
PY
  # Storage was preflighted before guests/server creation. Record a second
  # read-only proof immediately before each public server create.
  bash "$ROOT_DIR/tests/fabric-v3-qemu-storage-preflight.sh" >"$EVIDENCE/environment/qemu-storage-preflight-server-$host.txt" 2>&1 || fail "QEMU storage preflight failed before server $host" "ENVIRONMENT_GAP"
  response="$(curl --silent --show-error --max-time 60 -X POST "$BASE/v2.1/$PROJECT_ID/servers" -H "x-auth-token: $TOKEN" -H 'content-type: application/json' -H "x-openstack-request-id: $PREFIX-server-$host" --data-binary "@$request")"
  printf '%s\n' "$response" >"$EVIDENCE/api/server-$host.create.response.json"
  server_id="$(printf '%s' "$response" | field server.id 2>/dev/null || true)"
  [[ -n "$server_id" ]] || fail "server $host create was rejected: $response" "SUPPORTED_API_GAP"
  SERVER_IDS+=("$server_id")
  for _ in $(seq 1 240); do
    status="$(api "$BASE/v2.1/$PROJECT_ID/servers/$server_id" | tee "$EVIDENCE/api/server-$host.current.json" | field server.status)"
    [[ "$status" == ACTIVE ]] && break
    [[ "$status" == ERROR ]] && fail "server $host entered ERROR" "ATTACHMENT_DEFECT"
    sleep 2
  done
  [[ "$status" == ACTIVE ]] || fail "server $host did not reach ACTIVE (last=$status)" "ATTACHMENT_DEFECT"
  echo "server $host ACTIVE id=$server_id"
  local response_host expected_host address domain="" tap ownership tap_mac guest_mac current_mac bridge
  expected_host="compute-agent-$host"
  response_host="$(api "$BASE/v2.1/$PROJECT_ID/servers/$server_id" | tee "$EVIDENCE/api/server-$host-placement.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["server"].get("OS-EXT-SRV-ATTR:host", ""))')"
  [[ "$response_host" == "$expected_host" ]] || fail "server $host placed on $response_host, expected $expected_host" "DISPATCH_DEFECT"
  address="${MGMT_IP[$host]}"
  for _ in $(seq 1 60); do
    domain="$(ssh_vm "$address" "sudo virsh -c qemu:///system list --all --name | while read -r n; do [ -n \"\$n\" ] || continue; x=\$(sudo virsh -c qemu:///system dumpxml \"\$n\" 2>/dev/null || true); if printf '%s' \"\$x\" | grep -Fq 'server_id=\"$server_id\"' && printf '%s' \"\$x\" | grep -Fq 'managed_by=\"o3k-compute\"'; then printf '%s\\n' \"\$n\"; fi; done" | head -1)"
    [[ -n "$domain" ]] && break
    sleep 1
  done
  [[ -n "$domain" ]] || fail "server $host ACTIVE but no matching owned VM domain found on $expected_host" "PRODUCT_DEFECT"
  printf '%s\n' "$domain" >"$EVIDENCE/compute-$host/domain.txt"
  ssh_vm "$address" "sudo virsh -c qemu:///system dumpxml '$domain'" >"$EVIDENCE/compute-$host/domain.xml"
  ssh_vm "$address" "sudo virsh -c qemu:///system domstate '$domain'" >"$EVIDENCE/compute-$host/domain-state.txt"
  [[ "$(tr -d '\r' <"$EVIDENCE/compute-$host/domain-state.txt")" == running ]] || fail "server $host domain is not running" "PRODUCT_DEFECT"
  tap="$(python3 - "$EVIDENCE/compute-$host/domain.xml" <<'PY'
import sys,xml.etree.ElementTree as E
r=E.parse(sys.argv[1]).getroot()
for i in r.findall('./devices/interface'):
 t=i.find('target')
 if t is not None and t.get('dev','').startswith('o3ktap-'): print(t.get('dev')); break
PY
)"
  [[ -n "$tap" ]] || fail "server $host domain XML has no Fabric TAP" "ATTACHMENT_DEFECT"
  ssh_vm "$address" "sudo ip -j -d link show dev '$tap'" >"$EVIDENCE/attachments/server-$host-live-tap.json" || fail "real Fabric TAP disappeared for $host" "ATTACHMENT_DEFECT"
  ownership="/var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json"
  ssh_vm "$address" "sudo cat '$ownership'" >"$EVIDENCE/attachments/server-$host-provider-ownership.json" || fail "Fabric ownership observation failed for $host" "OWNERSHIP_DEFECT"
  tap_mac="$(python3 - "$EVIDENCE/attachments/server-$host-provider-ownership.json" "$port_id" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); taps=x.get("realm",{}).get("endpoint_taps",{})
assert sys.argv[2] in taps
assert sys.argv[2] not in x.get("realm",{}).get("pending_endpoint_taps",{})
print(taps[sys.argv[2]]["mac"])
PY
)" || fail "durable committed TAP ownership was absent for $host" "OWNERSHIP_DEFECT"
  guest_mac="$(field port.mac_address <"$EVIDENCE/api/port-$host.response.json")"
  python3 - "$EVIDENCE/attachments/server-$host-live-tap.json" "$tap" "$tap_mac" "$EVIDENCE/attachments/server-$host-provider-ownership.json" "$server_id" "$host" <<'PY' || fail "live TAP identity/type/owner/bridge attestation failed for $host" "ATTACHMENT_DEFECT"
import json,sys
x=json.load(open(sys.argv[1])); name,mac=sys.argv[2:4]
assert len(x)==1 and x[0].get('ifname')==name and x[0].get('address','').lower()==mac.lower()
i=x[0]['linkinfo']; assert i.get('info_kind')=='tun' and i.get('info_data',{}).get('type')=='tap'
o=json.load(open(sys.argv[4])); plan=o['plan']; assert plan['local_host']=='host-'+sys.argv[6]
assert plan['directory']['directory_generation']==o['directory_generation']
tap=o['realm']['endpoint_taps']; assert sys.argv[5] in tap and sys.argv[5] not in o['realm']['pending_endpoint_taps']
assert x[0].get('master')==o['realm']['bridge']
PY
  bridge="$(python3 - "$EVIDENCE/attachments/server-$host-live-tap.json" <<'PY'
import json,sys; print(json.load(open(sys.argv[1]))[0].get('master',''))
PY
)"
  current_mac="$(python3 - "$EVIDENCE/attachments/server-$host-live-tap.json" <<'PY'
import json,sys; print(json.load(open(sys.argv[1]))[0].get('address',''))
PY
)"
  [[ "$current_mac" != "$guest_mac" ]] || fail "provider TAP and canonical guest MAC unexpectedly match" "SECURITY_DEFECT"
  printf 'provider_tap_mac=%s\ncanonical_guest_mac=%s\n' "$current_mac" "$guest_mac" >"$EVIDENCE/attachments/server-$host-mac-separation.txt"
  # The accepted compute attachment resolver ran during API create. Its PASS is
  # evidenced by successful VM realization; preserve the live observation too.
  echo "REAL-HOST FABRIC TAP ATTESTATION: PASS" >"$EVIDENCE/attachments/server-$host-attestation.txt"
  echo "tap=$tap info_kind=tun info_data.type=tap master=$bridge" >>"$EVIDENCE/attachments/server-$host-attestation.txt"
}

create_server a
create_server b
create_server c

console_command() {
  local host="$1" command="$2" label="$3" address="${MGMT_IP[$1]}" domain
  domain="$(cat "$EVIDENCE/compute-$host/domain.txt")"
  python3 - "$SSH_KEY" "$KNOWN_HOSTS" "$SSH_USER" "$address" "$domain" "$command" "$EVIDENCE/$label" <<'PY'
import pexpect,sys
key,known,user,address,domain,command,output=sys.argv[1:]
args=["-i",key,"-o","BatchMode=yes","-o","IdentitiesOnly=yes","-o","StrictHostKeyChecking=yes", "-o",f"UserKnownHostsFile={known}",f"{user}@{address}",f"sudo virsh -c qemu:///system console --force --safe {domain}"]
p=pexpect.spawn("ssh",args,encoding="utf-8",timeout=45)
p.logfile=open(output,"w",encoding="utf-8")
try:
    i=p.expect([r"(?i)login:",r"(?m)[^\r\n]*[#$] ?$",pexpect.EOF])
    if i==0:
        p.sendline("cirros")
        p.expect(r"(?i)password:")
        p.sendline("gocubsgo")
        p.expect(r"(?m)[^\r\n]*[#$] ?$")
    elif i==2:
        raise RuntimeError("serial console ended before shell readiness")
    p.sendline(command+"; rc=$?; echo __O3K_RC_$rc__")
    p.expect(r"__O3K_RC_([0-9]+)__")
    rc=int(p.match.group(1))
    p.send("\x1d")
    p.expect(pexpect.EOF,timeout=8)
    if rc:
        raise SystemExit(rc)
finally:
    if p.isalive(): p.close(force=True)
PY
  local rc=$?
  (( rc == 0 )) || fail "guest $host command failed ($label)" "DATAPLANE_DEFECT"
}

wait_guest_shell() {
  local host="$1" output="compute-$1/guest-serial-login.txt"
  console_command "$host" 'echo GUEST_SHELL_READY' "$output" || return 1
  grep -Fq GUEST_SHELL_READY "$EVIDENCE/$output"
}
for host in a b c; do wait_guest_shell "$host" || fail "guest $host serial boot/login proof failed" "ENVIRONMENT_GAP"; done

declare -A TENANT_IP=() TENANT_MAC=()
for host in a b c; do
  TENANT_IP[$host]="$(field port.fixed_ips.0.ip_address <"$EVIDENCE/api/port-$host.response.json")"
  TENANT_MAC[$host]="$(field port.mac_address <"$EVIDENCE/api/port-$host.response.json")"
done
printf 'server,host,tenant_ip,guest_mac\n' >"$EVIDENCE/canonical/endpoints.csv"
for host in a b c; do printf '%s,host-%s,%s,%s\n' "$host" "$host" "${TENANT_IP[$host]}" "${TENANT_MAC[$host]}" >>"$EVIDENCE/canonical/endpoints.csv"; done

# Cold neighbor resolution and the six required tenant-address ICMP flows.
for pair in a:b b:a a:c c:a b:c c:b; do
  from="${pair%%:*}"; to="${pair##*:}"
  console_command "$from" "ping -c 1 -W 4 ${TENANT_IP[$to]}" "icmp/$from-to-$to.txt" || fail "ICMP $from->$to failed" "DATAPLANE_DEFECT"
  console_command "$from" "ip neigh show ${TENANT_IP[$to]}" "arp/$from-to-$to.txt" || fail "ARP observation $from->$to failed" "DATAPLANE_DEFECT"
  grep -Fqi "${TENANT_MAC[$to]}" "$EVIDENCE/arp/$from-to-$to.txt" || fail "ARP $from->$to resolved to wrong MAC" "DATAPLANE_DEFECT"
done

# Bounded TCP and UDP listeners run inside B/C CirrOS guests; sender commands
# originate inside A over tenant addresses.
console_command b 'rm -f /tmp/o3k-tcp-data; nohup busybox nc -l -p 18081 >/tmp/o3k-tcp-data 2>&1 </dev/null &' tcp-listener.txt || fail "TCP listener setup failed" "DATAPLANE_DEFECT"
sleep 1
console_command a "echo o3k-tcp-$RUN_ID | busybox nc -w 5 ${TENANT_IP[b]} 18081" tcp/sender.txt || fail "TCP A->B failed" "DATAPLANE_DEFECT"
console_command b 'grep -F o3k-tcp- /tmp/o3k-tcp-data' tcp/receiver.txt || fail "TCP payload did not arrive at B" "DATAPLANE_DEFECT"
console_command c 'rm -f /tmp/o3k-udp-data; nohup busybox nc -u -l -p 18082 >/tmp/o3k-udp-data 2>&1 </dev/null &' udp-listener.txt || fail "UDP listener setup failed" "DATAPLANE_DEFECT"
sleep 1
console_command a "echo o3k-udp-$RUN_ID | busybox nc -u -w 3 ${TENANT_IP[c]} 18082" udp/sender.txt || fail "UDP A->C failed" "DATAPLANE_DEFECT"
console_command c 'sleep 1; grep -F o3k-udp- /tmp/o3k-udp-data' udp/receiver.txt || fail "UDP payload did not arrive at C" "DATAPLANE_DEFECT"

for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo ip -j -d link; sudo bridge -j link; sudo bridge -j fdb; sudo wg show; sudo nft list ruleset" >"$EVIDENCE/$([ "$host" = a ] && echo compute-a || ([ "$host" = b ] && echo compute-b || echo compute-c))/runtime-state.txt" || fail "runtime evidence failed for host-$host" "ENVIRONMENT_GAP"
done

for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json" >"$EVIDENCE/plans/host-$host-ownership.json" || fail "Fabric ownership snapshot failed on $host" "OWNERSHIP_DEFECT"
  ssh_vm "$address" 'sudo wg show all transfer; sudo ip -d -j link' >"$EVIDENCE/wireguard/host-$host-before-traffic.txt" || fail "WireGuard/VXLAN snapshot failed on $host" "ENVIRONMENT_GAP"
done

# Confirm HER converged to every remote participant in each durable current
# provider plan. Runtime link/FDB/WireGuard records above are retained beside it.
python3 - "$EVIDENCE/plans" <<'PY' || fail "HER participant convergence failed" "DATAPLANE_DEFECT"
import glob,json,sys
files=glob.glob(sys.argv[1]+"/host-*-ownership.json")
assert len(files)==3
for path in files:
    x=json.load(open(path)); hosts={e["selected_host"] for e in x["plan"]["directory"]["entries"]}
    assert hosts=={"host-a","host-b","host-c"}, (path,hosts)
PY

for host in a b c; do
  domain="$(cat "$EVIDENCE/compute-$host/domain.txt")"
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo virsh -c qemu:///system domiflist '$domain'" >"$EVIDENCE/compute-$host/interfaces.txt"
done

# WireGuard counters must grow over the real tenant packet tests. Private keys
# never enter the evidence bundle.
for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" 'sudo wg show all transfer' >"$EVIDENCE/wireguard/host-$host-after-traffic.txt" || fail "WireGuard counters unavailable on $host" "DATAPLANE_DEFECT"
done
python3 - "$EVIDENCE/wireguard" <<'PY' || fail "WireGuard traffic counters did not grow" "DATAPLANE_DEFECT"
import glob,sys
for before in glob.glob(sys.argv[1]+"/host-*-before-traffic.txt"):
    host=before.rsplit("/",1)[-1].split("-")[1]
    after=sys.argv[1]+f"/host-{host}-after-traffic.txt"
    old=sum(int(x.split()[2])+int(x.split()[3]) for x in open(before) if len(x.split())>=4 and x.split()[2].isdigit() and x.split()[3].isdigit())
    new=sum(int(x.split()[2])+int(x.split()[3]) for x in open(after) if len(x.split())>=4 and x.split()[2].isdigit() and x.split()[3].isdigit())
    assert new>old, (host,old,new)
PY

python3 - "$EVIDENCE/plans" "$EVIDENCE/wireguard" <<'PY' || fail "VXLAN VNI/link realization did not match Fabric plan" "DATAPLANE_DEFECT"
import glob,json,sys
vnis=set()
for path in glob.glob(sys.argv[1]+"/host-*-ownership.json"):
    host=path.rsplit("/",1)[-1].split("-")[1]
    plan=json.load(open(path)); expected=plan["plan"]["encapsulation"]["provider_segment_id"]
    vnis.add(expected)
    observation=open(sys.argv[2]+f"/host-{host}-before-traffic.txt").read()
    links=json.loads(observation[observation.index("["):])
    assert any(i.get("linkinfo",{}).get("info_kind")=="vxlan" and int(i.get("linkinfo",{}).get("info_data",{}).get("id",-1))==expected for i in links), (host,expected)
assert len(vnis)==1, vnis
PY

# Controller restart while A/B/C are alive. No tenant/API mutation wakes
# reconciliation; all six tenant flows are rerun after agents reconnect.
kill -TERM "$O3KD_PID"; wait "$O3KD_PID" 2>/dev/null || true; O3KD_PID=""
"$ROOT_DIR/target/release/o3kd" --listen-addr "$HOST_MGMT_IP:$API_PORT" --data-dir "$EVIDENCE/controller-data" --log-filter info >"$EVIDENCE/restart/o3kd.log" 2>&1 & O3KD_PID=$!
for _ in $(seq 1 120); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; kill -0 "$O3KD_PID" 2>/dev/null || fail "controller restart failed" "DURABLE_RECONCILIATION_GAP"; sleep 1; done
curl -fsS "$BASE/readyz" >"$EVIDENCE/restart/ready.json" || fail "controller did not become ready after restart" "DURABLE_RECONCILIATION_GAP"
for pair in a:b b:a a:c c:a b:c c:b; do
  from="${pair%%:*}"; to="${pair##*:}"
  console_command "$from" "ping -c 1 -W 4 ${TENANT_IP[$to]}" "restart/$from-to-$to.txt" || fail "post-controller-restart ICMP $from->$to failed" "DURABLE_RECONCILIATION_GAP"
done
api "$BASE/v2.1/$PROJECT_ID/servers" >"$EVIDENCE/restart/servers.json" || fail "API unavailable after controller restart" "DURABLE_RECONCILIATION_GAP"
for host in a b c; do grep -Fq "$PREFIX-server-$host" "$EVIDENCE/restart/servers.json" || fail "server $host missing after controller recovery" "DURABLE_RECONCILIATION_GAP"; done

# Remove C only through the supported API and prove HER/local endpoint
# withdrawal, then exercise A/B before final API teardown.
curl --fail --silent --show-error --max-time 60 -X DELETE "$BASE/v2.1/$PROJECT_ID/servers/${SERVER_IDS[2]}" -H "x-auth-token: $TOKEN" >"$EVIDENCE/endpoint-removal/server-c-delete.txt" || fail "supported server C deletion failed" "CLEANUP_DEFECT"
for _ in $(seq 1 120); do
  if ! curl -fsS "$BASE/v2.1/$PROJECT_ID/servers/${SERVER_IDS[2]}" -H "x-auth-token: $TOKEN" >"$EVIDENCE/endpoint-removal/server-c-final.json" 2>/dev/null; then break; fi
  sleep 1
done
for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json" >"$EVIDENCE/endpoint-removal/host-$host-ownership.json" || fail "post-C-removal state unavailable on $host" "OWNERSHIP_DEFECT"
done
python3 - "$EVIDENCE/endpoint-removal" "${PORT_IDS[2]}" <<'PY' || fail "C endpoint/HER did not withdraw" "CLEANUP_DEFECT"
import glob,json,sys
for path in glob.glob(sys.argv[1]+"/host-*-ownership.json"):
    x=json.load(open(path)); assert sys.argv[2] not in x.get("realm",{}).get("endpoint_taps",{}), path
    hosts={e["selected_host"] for e in x.get("plan",{}).get("directory",{}).get("entries",[])}
    assert hosts=={"host-a","host-b"}, (path,hosts)
PY
console_command a "ping -c 1 -W 4 ${TENANT_IP[b]}" endpoint-removal/a-to-b.txt || fail "A/B failed after C removal" "DATAPLANE_DEFECT"
console_command b "ping -c 1 -W 4 ${TENANT_IP[a]}" endpoint-removal/b-to-a.txt || fail "B/A failed after C removal" "DATAPLANE_DEFECT"

# Supported API teardown; provider state is never manually repaired/deleted.
for index in 1 0; do
  id="${SERVER_IDS[$index]}"
  curl --fail --silent --show-error --max-time 60 -X DELETE "$BASE/v2.1/$PROJECT_ID/servers/$id" -H "x-auth-token: $TOKEN" >"$EVIDENCE/teardown/server-${id}.delete.txt" || fail "supported server delete failed: $id" "CLEANUP_DEFECT"
done
for _ in $(seq 1 120); do
  left=0
  for id in "${SERVER_IDS[@]}"; do if curl -sS -o /dev/null "$BASE/v2.1/$PROJECT_ID/servers/$id" -H "x-auth-token: $TOKEN"; then left=1; fi; done
  (( left == 0 )) && break; sleep 1
done
for id in "${PORT_IDS[@]}"; do curl --fail --silent --show-error --max-time 30 -X DELETE "$BASE/v2.0/ports/$id" -H "x-auth-token: $TOKEN" >"$EVIDENCE/teardown/port-$id.delete.txt" || fail "supported port delete failed: $id" "CLEANUP_DEFECT"; done
curl --fail --silent --show-error --max-time 30 -X DELETE "$BASE/v2.0/subnets/$SUBNET_ID" -H "x-auth-token: $TOKEN" >"$EVIDENCE/teardown/subnet-delete.txt" || fail "supported subnet delete failed" "CLEANUP_DEFECT"
curl --fail --silent --show-error --max-time 30 -X DELETE "$BASE/v2.0/networks/$NETWORK_ID" -H "x-auth-token: $TOKEN" >"$EVIDENCE/teardown/network-delete.txt" || fail "supported network delete failed" "CLEANUP_DEFECT"
curl --fail --silent --show-error --max-time 30 -X DELETE "$BASE/v2/images/$IMAGE_ID" -H "x-auth-token: $TOKEN" >"$EVIDENCE/teardown/image-delete.txt" || fail "supported image delete failed" "CLEANUP_DEFECT"
for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" 'sudo virsh -c qemu:///system list --all --name' >"$EVIDENCE/teardown/host-$host-domains.txt"
  for server_host in a b c; do
    domain="$(cat "$EVIDENCE/compute-$server_host/domain.txt")"
    if grep -Fxq "$domain" "$EVIDENCE/teardown/host-$host-domains.txt"; then
      fail "server domain $domain leaked on host-$host" "CLEANUP_DEFECT"
    fi
  done
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json 2>/dev/null || true" >"$EVIDENCE/teardown/host-$host-ownership.json"
done
python3 - "$EVIDENCE/teardown" <<'PY' || fail "run-owned endpoint TAP/HER state leaked after teardown" "CLEANUP_DEFECT"
import glob,json,sys
for path in glob.glob(sys.argv[1]+"/host-*-ownership.json"):
  if not open(path).read().strip(): continue
    x=json.load(open(path)); assert not x.get("realm",{}).get("endpoint_taps",{}), path
PY
# Remove only the three exact fresh compute guests after proving their API
# resources and server domains are gone. Then compare the physical libvirt
# inventory to the pre-run inventory to detect any foreign-domain mutation.
for domain in "${FRESH_DOMAINS[@]}"; do
  expected_uuid="$(awk -F '\t' -v n="$domain" '$2==n{print $5}' "$EVIDENCE/environment/inventory.tsv")"
  xml="$(virsh -c qemu:///system dumpxml "$domain" 2>/dev/null || true)"
  actual_uuid="$(virsh -c qemu:///system domuuid "$domain" 2>/dev/null || true)"
  if [[ -z "$expected_uuid" || "$actual_uuid" != "$expected_uuid" ]] \
    || ! grep -Fq "<name>$domain</name>" <<<"$xml" \
    || ! grep -Fq "$PREFIX" <<<"$xml"; then
    fail "fresh compute guest ownership could not be re-proven for $domain" "OWNERSHIP_DEFECT"
  fi
  virsh -c qemu:///system destroy "$domain" >/dev/null 2>&1 || true
  virsh -c qemu:///system undefine "$domain" --remove-all-storage >/dev/null \
    || fail "could not remove owned fresh compute guest $domain" "CLEANUP_DEFECT"
done
virsh -c qemu:///system list --all --name | sed '/^$/d' | sort >"$EVIDENCE/teardown/libvirt-domains-after.txt"
diff -u "$EVIDENCE/environment/libvirt-domains-before.txt" "$EVIDENCE/teardown/libvirt-domains-after.txt" >"$EVIDENCE/teardown/libvirt-domains.diff" \
  || fail "foreign libvirt domain inventory changed during campaign" "OWNERSHIP_DEFECT"
git -C "$ROOT_DIR" rev-parse HEAD >"$EVIDENCE/environment/harness_sha.txt"
git -C "$ROOT_DIR" rev-parse 'HEAD^{tree}' >"$EVIDENCE/environment/harness_tree.txt"
sha256sum "$ROOT_DIR/tests/fabric-v3-o3k-three-host-campaign.sh" >"$EVIDENCE/environment/driver.sha256"
CAMPAIGN_TEARDOWN_PASS=1

cat >"$EVIDENCE/result.json" <<JSON
{"result":"PASS","run_id":"$RUN_ID","product_sha":"$PRODUCT_SHA","product_tree":"$PRODUCT_TREE","harness_sha":"$(git -C "$ROOT_DIR" rev-parse HEAD)","fabric_domain_id":"$FABRIC_DOMAIN_ID","servers":["${SERVER_IDS[0]}","${SERVER_IDS[1]}","${SERVER_IDS[2]}"],"teardown":"PASS"}
JSON
echo "FABRIC V3 O3K MINIMAL THREE-HOST MILESTONE: PASS"
