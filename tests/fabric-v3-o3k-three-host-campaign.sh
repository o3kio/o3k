#!/usr/bin/env bash
set -Eeuo pipefail

# Supported-HTTP Fabric v3 three-host nested campaign. This script is test
# harness only and refuses to run against a different product source tree.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRODUCT_SHA=fa51ef1fb1affc8f35553a1072ca5c434da8bf4b
PRODUCT_TREE=e27ea22b3a473a5300bfaf320c79892a5d07d142
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
declare -A MGMT_IP=() MGMT_OCTET=() MGMT_MAC=() REALM_BRIDGE=() GUEST_IPV6=()
HOSTS=(a b c)
LAST_GUEST_CHANNEL_ERROR=0

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
declare -A reserved_addresses=() defined_macs=()
for address_file in "$EVIDENCE_ROOT"/fabric-v3-minimal-three-host-*/environment/management-addresses.txt; do
  [[ -f "$address_file" ]] || continue
  while IFS='=' read -r _ address; do
    [[ "$address" =~ ^192\.168\.122\.[0-9]+$ ]] && reserved_addresses[$address]=1
  done <"$address_file"
done
while IFS= read -r domain; do
  [[ -n "$domain" ]] || continue
  while IFS= read -r mac; do
    [[ "$mac" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] && defined_macs["${mac,,}"]=1
  done < <(virsh -c qemu:///system domiflist "$domain" 2>/dev/null | awk 'NR > 2 {print tolower($5)}')
done < <(virsh -c qemu:///system list --all --name)
available_octets=()
for octet in $(seq 100 250); do
  address="192.168.122.$octet"
  mac="52:54:00:fa:$(printf '%02x' "$((octet / 256))"):$(printf '%02x' "$((octet % 256))")"
  [[ -n "${reserved_addresses[$address]:-}" ]] && continue
  [[ -n "${defined_macs[$mac]:-}" ]] && continue
  ip neigh show dev "$BRIDGE" | grep -Fq "$address" && continue
  virsh -c qemu:///system net-dhcp-leases "$NETWORK" | grep -Fq "$address" && continue
  timeout 2 bash -c "</dev/tcp/$address/$SSH_PORT" >/dev/null 2>&1 && continue
  available_octets+=("$octet")
  ((${#available_octets[@]} == 3)) && break
done
((${#available_octets[@]} == 3)) || fail "fewer than three unused management addresses in 192.168.122.100-250" "ENVIRONMENT_GAP"
for index in 0 1 2; do
  host="${HOSTS[$index]}"
  octet="${available_octets[$index]}"
  address="192.168.122.$octet"
  MGMT_OCTET[$host]="$octet"
  MGMT_IP[$host]="$address"
  MGMT_MAC[$host]="52:54:00:fa:$(printf '%02x' "$((octet / 256))"):$(printf '%02x' "$((octet % 256))")"
done
printf 'compute-a=%s\ncompute-b=%s\ncompute-c=%s\n' "${MGMT_IP[a]}" "${MGMT_IP[b]}" "${MGMT_IP[c]}" >"$EVIDENCE/environment/management-addresses.txt"
printf 'compute-a=%s\ncompute-b=%s\ncompute-c=%s\n' "${MGMT_MAC[a]}" "${MGMT_MAC[b]}" "${MGMT_MAC[c]}" >"$EVIDENCE/environment/management-macs.txt"

for host in a b c; do
  octet="${MGMT_OCTET[$host]}"; domain="$PREFIX-compute-$host"; address="${MGMT_IP[$host]}"
  ram_mib=4096; vcpus=2
  # The public create API has no per-host placement selector. Give host A one
  # extra schedulable vCPU so the supported scheduler's deterministic free-
  # inventory ranking selects A first; after A's allocation, equal B/C
  # capacity and provider-ID order select B, then C. The live capability
  # preflight below verifies this assumption before tenant creation.
  [[ "$host" != a ]] || vcpus=3
  if virsh -c qemu:///system dominfo "$domain" >/dev/null 2>&1; then fail "fresh domain name collision: $domain" "ENVIRONMENT_GAP"; fi
  disk="$IMAGE_STORE/$PREFIX-compute-$host.qcow2"; seed="$IMAGE_STORE/$PREFIX-compute-$host-seed.iso"; ws="$EVIDENCE/environment/seed-$host"
  [[ ! -e "$disk" && ! -e "$seed" ]] || fail "fresh guest disk/seed collision for $host" "ENVIRONMENT_GAP"
  mkdir -m 0700 "$ws"
  mac="${MGMT_MAC[$host]}"
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
  - [usermod, -aG, "libvirt,kvm", o3k]
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
  virt-install --connect qemu:///system --name "$domain" --uuid "$(python3 -c 'import uuid; print(uuid.uuid4())')" --import --ram "$ram_mib" --vcpus "$vcpus" --cpu host-passthrough --disk "path=$disk,format=qcow2,bus=virtio" --disk "path=$seed,device=cdrom" --network "network=$NETWORK,model=virtio,mac=$mac" --os-variant ubuntu24.04 --graphics none --noautoconsole --quiet || fail "libvirt failed to create fresh compute guest $host" "ENVIRONMENT_GAP"
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
    # Ubuntu may run libvirtd on demand through systemd sockets and let the
    # daemon exit while idle. Exercise the actual qemu:///system API instead
    # of requiring the monolithic service process to remain active.
    if ssh_vm "$address" 'command -v virsh >/dev/null && command -v wg >/dev/null && command -v bridge >/dev/null && command -v nft >/dev/null && test -c /dev/kvm && sudo virsh -c qemu:///system list --all >/dev/null 2>&1' >/dev/null 2>&1; then
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
  ssh_vm "$address" "sudo install -m 0755 /tmp/$RUN_ID-stage/o3k-compute /usr/local/bin/o3k-compute-bin; sudo install -d -m 0700 /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls; sudo install -m 0644 /tmp/$RUN_ID-stage/compute-agent-$host.pem /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls/agent.pem; sudo install -m 0600 /tmp/$RUN_ID-stage/compute-agent-$host-key.pem /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls/agent-key.pem; sudo install -m 0644 /tmp/$RUN_ID-stage/ca.pem /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls/ca.pem; sudo chown -R root:root /var/lib/o3k-fabric-v3/$RUN_ID/compute/tls; sudo bash -c 'umask 077; printf compute-agent-$host > /var/lib/o3k-fabric-v3/$RUN_ID/compute/agent-id'; sudo bash -c 'nohup env O3K_COMPUTE_DATA_DIR=/var/lib/o3k-fabric-v3/$RUN_ID/compute O3K_COMPUTE_CONTROL_ENDPOINT=https://$HOST_MGMT_IP:$CONTROL_PORT O3K_COMPUTE_SERVER_NAME=o3k-control-plane O3K_COMPUTE_HOST_LABEL=host-$host O3K_COMPUTE_TLS_DIR=/var/lib/o3k-fabric-v3/$RUN_ID/compute/tls O3K_COMPUTE_HEALTH_ADDR=0.0.0.0:$health_port O3K_COMPUTE_MAX_DISK_GB=30 O3K_COMPUTE_NETWORK_EXTERNAL=1 O3K_COMPUTE_NETWORK_ROOT=/var/lib/o3k-fabric-v3/$RUN_ID/network/ownership O3K_COMPUTE_BRIDGE_NAME=o3k-br0 O3K_COMPUTE_DHCP_BINARY=/usr/sbin/dnsmasq O3K_COMPUTE_FABRIC_HOST_ID=host-$host O3K_COMPUTE_FABRIC_STATE_ROOT=/var/lib/o3k-fabric-v3/$RUN_ID/network/fabric RUST_LOG=info /usr/local/bin/o3k-compute-bin >/var/lib/o3k-fabric-v3/$RUN_ID/compute/agent.log 2>&1 </dev/null & echo \$! >/var/lib/o3k-fabric-v3/$RUN_ID/compute/agent.pid'"
done

for host in a b c; do
  address="${MGMT_IP[$host]}"; ready=0
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
DIRECTORY="$(python3 - "${MGMT_IP[a]}" "${MGMT_IP[b]}" "${MGMT_IP[c]}" <<'PY'
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

# Compute /readyz includes the authenticated controller registration state, so
# defer this check until o3kd is listening and ready. Checking it before the
# controller starts would make a healthy agent report 503 by design.
for host in a b c; do
  address="${MGMT_IP[$host]}"; ready=0
  case "$host" in a) health_port=19101;; b) health_port=19102;; c) health_port=19103;; esac
  for _ in $(seq 1 60); do
    if ssh_vm "$address" "sudo curl -fsS http://127.0.0.1:$health_port/readyz" >/dev/null 2>&1; then ready=1; break; fi
    sleep 2
  done
  (( ready == 1 )) || fail "compute agent did not register with the ready controller on host-$host" "HARNESS_GAP"
  ssh_vm "$address" "sudo curl -fsS http://127.0.0.1:$health_port/readyz" \
    >"$EVIDENCE/management/compute-$host-ready.json" \
    || fail "could not capture registered compute capacity for host-$host" "HARNESS_GAP"
done
python3 - "$EVIDENCE/management" <<'PY' || fail "live compute capacities do not produce deterministic A/B/C scheduler order" "HARNESS_GAP"
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
capacity={}
for host in "abc":
    body=json.loads((root/f"compute-{host}-ready.json").read_text())
    assert body["agent_id"]==f"compute-agent-{host}", body
    c=body["capabilities"]
    capacity[host]=sum(int(c[k]) for k in ("max_vcpus","max_memory_mib","max_disk_gb"))
assert capacity["a"]==capacity["b"]+1 and capacity["b"]==capacity["c"], capacity
print(json.dumps({"scheduler_capacity_score":capacity},sort_keys=True))
PY

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
  local response_host expected_host address domain="" tap ownership tap_mac guest_mac current_mac bridge realm_id
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
  ownership="/var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json"
  ssh_vm "$address" "sudo cat '$ownership'" >"$EVIDENCE/attachments/server-$host-provider-ownership.json" || fail "Fabric ownership observation failed for $host" "OWNERSHIP_DEFECT"
  guest_mac="$(field port.mac_address <"$EVIDENCE/api/port-$host.response.json")"
  tap_contract="$(python3 - "$EVIDENCE/compute-$host/domain.xml" "$EVIDENCE/attachments/server-$host-provider-ownership.json" "$port_id" "$guest_mac" <<'PY'
import json,sys,xml.etree.ElementTree as ET
domain=ET.parse(sys.argv[1]).getroot()
ownership=json.load(open(sys.argv[2])); endpoint,guest_mac=sys.argv[3:]
matches=[(rid,r) for rid,r in ownership.get('realms',{}).items() if endpoint in r.get('endpoint_taps',{})]
assert len(matches)==1, matches
realm_id,realm=matches[0]
record=realm['endpoint_taps'][endpoint]
assert endpoint not in realm.get('pending_endpoint_taps',{})
tap=record['interface']; assert tap
interfaces=[]
for interface in domain.findall('./devices/interface'):
    target=interface.find('target')
    if target is not None and target.get('dev')==tap: interfaces.append(interface)
assert len(interfaces)==1, (tap,len(interfaces))
mac=interfaces[0].find('mac').get('address','').lower()
assert mac==guest_mac.lower(), (mac,guest_mac)
print('\t'.join((tap,record['mac'],realm_id,realm['bridge'],mac)))
PY
)" || fail "domain TAP target or durable provider ownership did not match" "ATTACHMENT_DEFECT"
  IFS=$'\t' read -r tap tap_mac realm_id bridge guest_domain_mac <<<"$tap_contract"
  REALM_BRIDGE[$host]="$bridge"
  ssh_vm "$address" "sudo ip -j -d link show dev '$tap'" >"$EVIDENCE/attachments/server-$host-live-tap.json" || fail "real Fabric TAP disappeared for $host" "ATTACHMENT_DEFECT"
  ssh_vm "$address" "sudo cat '/var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/plans/$realm_id.json'" >"$EVIDENCE/attachments/server-$host-fabric-plan.json" || fail "current Fabric plan observation failed for $host" "ATTACHMENT_DEFECT"
  ssh_vm "$address" "sudo cat '/var/lib/o3k-fabric-v3/$RUN_ID/network/executor/accepted-network-plans.json'" >"$EVIDENCE/attachments/server-$host-execution-plans.json" || fail "network execution plan observation failed for $host" "ATTACHMENT_DEFECT"
  python3 - "$EVIDENCE/attachments/server-$host-live-tap.json" "$tap" "$tap_mac" "$bridge" "$EVIDENCE/attachments/server-$host-provider-ownership.json" "$EVIDENCE/attachments/server-$host-fabric-plan.json" "$EVIDENCE/attachments/server-$host-execution-plans.json" "$port_id" "$guest_mac" "$expected_host" "$realm_id" <<'PY' || fail "live TAP, plan, or committed ownership attestation failed for $host" "ATTACHMENT_DEFECT"
import json,sys
live=json.load(open(sys.argv[1])); name,provider_mac,bridge=sys.argv[2:5]
ownership=json.load(open(sys.argv[5])); plan=json.load(open(sys.argv[6])); accepted=json.load(open(sys.argv[7]))
endpoint,guest_mac,agent,realm_id=sys.argv[8:]
realms=ownership.get('realms',{}); assert realm_id in realms
realm=realms[realm_id]; record=realm.get('endpoint_taps',{}).get(endpoint)
assert record and endpoint not in realm.get('pending_endpoint_taps',{})
assert record.get('interface')==name and record.get('mac','').lower()==provider_mac.lower()
assert len(live)==1 and live[0].get('ifname')==name and int(live[0].get('ifindex',0))>0
assert live[0].get('address','').lower()==provider_mac.lower()
linkinfo=live[0].get('linkinfo',{}); assert linkinfo.get('info_kind')=='tun' and linkinfo.get('info_data',{}).get('type')=='tap'
assert live[0].get('master')==bridge==realm.get('bridge')
assert plan.get('realm_id')==realm_id and plan.get('local_host')=='host-'+agent[-1]
assert plan.get('directory_generation')==realm.get('directory_generation')
entries=[e for e in plan.get('directory',{}).get('entries',[]) if e.get('endpoint_id')==endpoint]
assert len(entries)==1 and entries[0].get('selected_host')=='host-'+agent[-1]
assert entries[0].get('mac','').lower()==guest_mac.lower()
success=[]
for item in accepted.get('plans',[]):
    command=item.get('plan',{}); fabric=command.get('fabric',{})
    intents=command.get('intents',[])
    has_endpoint=any('EndpointAttachment' in intent and intent['EndpointAttachment'].get('endpoint_id')==endpoint for intent in intents)
    if item.get('status')=='Succeeded' and item.get('target',{}).get('agent_id')=='network-agent-'+agent[-1] and fabric.get('realm_id')==realm_id and has_endpoint:
        success.append(item)
assert success, 'no succeeded endpoint apply plan for target agent'
assert live[0].get('address','').lower()!=guest_mac.lower()
PY
  bridge="$(python3 - "$EVIDENCE/attachments/server-$host-live-tap.json" <<'PY'
import json,sys; print(json.load(open(sys.argv[1]))[0].get('master',''))
PY
)"
  current_mac="$(python3 - "$EVIDENCE/attachments/server-$host-live-tap.json" <<'PY'
import json,sys; print(json.load(open(sys.argv[1]))[0].get('address',''))
PY
)"
  [[ "$current_mac" == "$tap_mac" && "$current_mac" != "$guest_mac" && "$guest_domain_mac" == "$guest_mac" ]] || fail "provider TAP and canonical guest MAC identities were not preserved" "SECURITY_DEFECT"
  printf 'provider_tap_mac=%s\ncanonical_guest_mac=%s\n' "$current_mac" "$guest_mac" >"$EVIDENCE/attachments/server-$host-mac-separation.txt"
  # The accepted compute attachment resolver ran during API create. Its PASS is
  # evidenced by successful VM realization; preserve the live observation too.
  echo "REAL-HOST FABRIC TAP ATTESTATION: PASS" >"$EVIDENCE/attachments/server-$host-attestation.txt"
  echo "tap=$tap info_kind=tun info_data.type=tap master=$bridge" >>"$EVIDENCE/attachments/server-$host-attestation.txt"
}

create_server a
create_server b
create_server c

guest_boot_proof() {
  local host="$1" address="${MGMT_IP[$1]}" domain xml serial_path serial_dir
  domain="$(cat "$EVIDENCE/compute-$host/domain.txt")"
  xml="$EVIDENCE/compute-$host/domain.xml"
  serial_path="$(python3 - "$xml" "$RUN_ID" <<'PY'
import sys,xml.etree.ElementTree as ET
root=ET.parse(sys.argv[1]).getroot(); run=sys.argv[2]
devices=root.find('devices'); matches=[]
for node in devices.findall('serial') if devices is not None else []:
    source=node.find('source')
    path=source.get('path','') if source is not None else ''
    if node.get('type')=='file' and path.startswith(f'/var/lib/o3k-fabric-v3/{run}/compute/console/'):
        matches.append(path)
assert len(matches)==1, matches
print(matches[0])
PY
)" || return 1
  serial_dir="/var/lib/o3k-fabric-v3/$RUN_ID/compute/console/"
  [[ "$serial_path" == "$serial_dir"* && "$serial_path" != *$'\n'* ]] || return 1
  for _ in $(seq 1 240); do
    if ssh_vm "$address" "sudo test -f '$serial_path' && sudo cat '$serial_path'" >"$EVIDENCE/compute-$host/serial.log" 2>/dev/null; then
      if grep -Eqi "CirrOS.*login:|login as 'cirros' user|cirros login:" "$EVIDENCE/compute-$host/serial.log"; then
        printf 'domain=%s\nserial_file=%s\nboot_login_prompt=PASS\n' "$domain" "$serial_path" >"$EVIDENCE/compute-$host/guest-serial-login.txt"
        return 0
      fi
    fi
    sleep 2
  done
  return 1
}

mac_link_local() {
  python3 - "$1" <<'PY'
import sys
b=bytes.fromhex(sys.argv[1].replace(':',''))
assert len(b)==6
b=bytes([b[0]^2,b[1],b[2],0xff,0xfe,b[3],b[4],b[5]])
print('fe80::'+':'.join(f'{int.from_bytes(b[i:i+2],"big"):x}' for i in range(0,8,2)))
PY
}

for host in a b c; do
  guest_boot_proof "$host" || fail "guest $host file-backed serial did not prove boot/login readiness" "ENVIRONMENT_GAP"
done

declare -A TENANT_IP=() TENANT_MAC=()
for host in a b c; do
  TENANT_IP[$host]="$(field port.fixed_ips.0.ip_address <"$EVIDENCE/api/port-$host.response.json")"
  TENANT_MAC[$host]="$(field port.mac_address <"$EVIDENCE/api/port-$host.response.json")"
  GUEST_IPV6[$host]="$(mac_link_local "${TENANT_MAC[$host]}")"
done
printf 'server,host,tenant_ip,guest_mac\n' >"$EVIDENCE/canonical/endpoints.csv"
for host in a b c; do printf '%s,host-%s,%s,%s\n' "$host" "$host" "${TENANT_IP[$host]}" "${TENANT_MAC[$host]}" >>"$EVIDENCE/canonical/endpoints.csv"; done

guest_tunnel_command() {
  local host="$1" command="$2" label="$3" address="${MGMT_IP[$1]}" bridge="${REALM_BRIDGE[$1]}" ipv6="${GUEST_IPV6[$1]}"
  local port tunnel_pid known_alias keyscan_file rc
  LAST_GUEST_CHANNEL_ERROR=0
  port="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
  known_alias="o3k-guest-$host"
  tunnel_log="$EVIDENCE/compute-$host/guest-ssh-tunnel.log"
  ssh "${ssh_opts[@]}" -o ExitOnForwardFailure=yes -N -L "127.0.0.1:$port:[$ipv6%$bridge]:22" "$SSH_USER@$address" >"$tunnel_log" 2>&1 &
  tunnel_pid=$!
  cleanup_tunnel() { kill "$tunnel_pid" 2>/dev/null || true; wait "$tunnel_pid" 2>/dev/null || true; }
  for _ in $(seq 1 40); do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/$port" >/dev/null 2>&1; then break; fi
    if ! kill -0 "$tunnel_pid" 2>/dev/null; then cat "$tunnel_log" >&2; cleanup_tunnel; LAST_GUEST_CHANNEL_ERROR=1; return 1; fi
    sleep 0.25
  done
  if ! timeout 2 bash -c "</dev/tcp/127.0.0.1/$port" >/dev/null 2>&1; then cleanup_tunnel; LAST_GUEST_CHANNEL_ERROR=1; return 1; fi
  keyscan_file="$EVIDENCE/compute-$host/guest-keyscan.tmp"
  ssh-keyscan -T 4 -p "$port" 127.0.0.1 2>/dev/null >"$keyscan_file" || { cleanup_tunnel; LAST_GUEST_CHANNEL_ERROR=1; return 1; }
  if ! python3 - "$keyscan_file" "$KNOWN_HOSTS" "$known_alias" "$port" <<'PY'
import sys
src,dst,alias,port=sys.argv[1:]
lines=[]
for line in open(src):
    fields=line.split()
    if len(fields)>=3: lines.append(f'{alias} {fields[1]} {fields[2]}\n')
assert lines
with open(dst,'a') as out: out.writelines(lines)
PY
  then cleanup_tunnel; LAST_GUEST_CHANNEL_ERROR=1; return 1; fi
  rm -f "$keyscan_file"
  python3 - "$KNOWN_HOSTS" "$SSH_KEY" "$known_alias" "$port" "$command" "$EVIDENCE/$label" <<'PY'
import pexpect,sys
known,key,alias,port,command,output=sys.argv[1:]
wrapped=f'{command}; rc=$?; printf "\\n__O3K_RC_%s__\\n" "$rc"'
args=['-tt','-i',key,'-p',port,'-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o',f'HostKeyAlias={alias}','-o',f'UserKnownHostsFile={known}','-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no',f'cirros@127.0.0.1',wrapped]
p=pexpect.spawn('ssh',args,encoding='utf-8',timeout=45)
with open(output,'w',encoding='utf-8') as f:
    p.logfile_read=f
    try:
        for _ in range(3):
            i=p.expect([r"(?i)password:",r'__O3K_RC_([0-9]+)__',pexpect.EOF])
            if i==0:
                p.sendline('gocubsgo')
                continue
            if i==1:
                rc=int(p.match.group(1)); p.expect(pexpect.EOF,timeout=8)
                if rc: raise SystemExit(rc)
                break
            raise RuntimeError('guest SSH closed before command completed')
        else: raise RuntimeError('guest SSH authentication prompt repeated')
    except (pexpect.EOF,pexpect.TIMEOUT,OSError) as exc:
        f.write(f'\nGUEST_CHANNEL_ERROR: {type(exc).__name__}\n')
        raise SystemExit(254)
    finally:
        if p.isalive(): p.close(force=True)
PY
  rc=$?
  cleanup_tunnel
  if (( rc == 254 )); then LAST_GUEST_CHANNEL_ERROR=1; fi
  return "$rc"
}

console_command() { guest_tunnel_command "$@"; }
guest_failure_class() {
  local phase_class="$1"
  if (( LAST_GUEST_CHANNEL_ERROR )); then printf 'HARNESS_GAP\n'; else printf '%s\n' "$phase_class"; fi
}

# Cold neighbor resolution and the six required tenant-address ICMP flows.
for pair in a:b b:a a:c c:a b:c c:b; do
  from="${pair%%:*}"; to="${pair##*:}"
  console_command "$from" "ping -c 1 -W 4 ${TENANT_IP[$to]}" "icmp/$from-to-$to.txt" || fail "ICMP $from->$to failed" "$(guest_failure_class DATAPLANE_DEFECT)"
  console_command "$from" "ip neigh show ${TENANT_IP[$to]}" "arp/$from-to-$to.txt" || fail "ARP observation $from->$to failed" "$(guest_failure_class DATAPLANE_DEFECT)"
  grep -Fqi "${TENANT_MAC[$to]}" "$EVIDENCE/arp/$from-to-$to.txt" || fail "ARP $from->$to resolved to wrong MAC" "DATAPLANE_DEFECT"
done

# Bounded TCP and UDP listeners run inside B/C CirrOS guests; sender commands
# originate inside A over tenant addresses.
console_command b 'rm -f /tmp/o3k-tcp-data; nohup busybox nc -l -p 18081 >/tmp/o3k-tcp-data 2>&1 </dev/null &' tcp-listener.txt || fail "TCP listener setup failed" "$(guest_failure_class DATAPLANE_DEFECT)"
sleep 1
console_command a "echo o3k-tcp-$RUN_ID | busybox nc -w 5 ${TENANT_IP[b]} 18081" tcp/sender.txt || fail "TCP A->B failed" "$(guest_failure_class DATAPLANE_DEFECT)"
console_command b 'grep -F o3k-tcp- /tmp/o3k-tcp-data' tcp/receiver.txt || fail "TCP payload did not arrive at B" "$(guest_failure_class DATAPLANE_DEFECT)"
console_command c 'rm -f /tmp/o3k-udp-data; nohup busybox nc -u -l -p 18082 >/tmp/o3k-udp-data 2>&1 </dev/null &' udp-listener.txt || fail "UDP listener setup failed" "$(guest_failure_class DATAPLANE_DEFECT)"
sleep 1
console_command a "echo o3k-udp-$RUN_ID | busybox nc -u -w 3 ${TENANT_IP[c]} 18082" udp/sender.txt || fail "UDP A->C failed" "$(guest_failure_class DATAPLANE_DEFECT)"
console_command c 'sleep 1; grep -F o3k-udp- /tmp/o3k-udp-data' udp/receiver.txt || fail "UDP payload did not arrive at C" "$(guest_failure_class DATAPLANE_DEFECT)"

for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo ip -j -d link; sudo bridge -j link; sudo bridge -j fdb; sudo wg show; sudo nft list ruleset" >"$EVIDENCE/$([ "$host" = a ] && echo compute-a || ([ "$host" = b ] && echo compute-b || echo compute-c))/runtime-state.txt" || fail "runtime evidence failed for host-$host" "ENVIRONMENT_GAP"
done

for host in a b c; do
  address="${MGMT_IP[$host]}"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/ownership.json" >"$EVIDENCE/plans/host-$host-ownership.json" || fail "Fabric ownership snapshot failed on $host" "OWNERSHIP_DEFECT"
  realm_id="$(python3 - "$EVIDENCE/plans/host-$host-ownership.json" "${PORT_IDS[@]}" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); endpoints=set(sys.argv[2:])
matches=[rid for rid,r in x.get('realms',{}).items() if endpoints.intersection(r.get('endpoint_taps',{}))]
assert len(matches)==1, matches
print(matches[0])
PY
)" || fail "current Realm ownership could not be resolved on $host" "OWNERSHIP_DEFECT"
  echo "$realm_id" >"$EVIDENCE/plans/host-$host-realm-id.txt"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/plans/$realm_id.json" >"$EVIDENCE/plans/host-$host-fabric-plan.json" || fail "current Fabric plan snapshot failed on $host" "OWNERSHIP_DEFECT"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/executor/accepted-network-plans.json" >"$EVIDENCE/plans/host-$host-execution-plans.json" || fail "network execution plan snapshot failed on $host" "OWNERSHIP_DEFECT"
  ssh_vm "$address" 'sudo wg show all transfer; sudo ip -d -j link' >"$EVIDENCE/wireguard/host-$host-before-traffic.txt" || fail "WireGuard/VXLAN snapshot failed on $host" "ENVIRONMENT_GAP"
done

# Confirm HER converged to every remote participant in each durable current
# provider plan. Runtime link/FDB/WireGuard records above are retained beside it.
python3 - "$EVIDENCE/plans" <<'PY' || fail "HER participant convergence failed" "DATAPLANE_DEFECT"
import glob,json,sys
files=glob.glob(sys.argv[1]+"/host-*-fabric-plan.json")
assert len(files)==3
for path in files:
    x=json.load(open(path)); hosts={e["selected_host"] for e in x["directory"]["entries"]}
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
for path in glob.glob(sys.argv[1]+"/host-*-fabric-plan.json"):
    host=path.rsplit("/",1)[-1].split("-")[1]
    plan=json.load(open(path)); expected=plan["encapsulation"]["provider_segment_id"]
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
  console_command "$from" "ping -c 1 -W 4 ${TENANT_IP[$to]}" "restart/$from-to-$to.txt" || fail "post-controller-restart ICMP $from->$to failed" "$(guest_failure_class DURABLE_RECONCILIATION_GAP)"
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
  realm_id="$(python3 - "$EVIDENCE/endpoint-removal/host-$host-ownership.json" "${PORT_IDS[0]}" "${PORT_IDS[1]}" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); endpoints=set(sys.argv[2:])
matches=[rid for rid,r in x.get('realms',{}).items() if endpoints.intersection(r.get('endpoint_taps',{}))]
assert len(matches)==1, matches
print(matches[0])
PY
)" || fail "A/B Realm ownership could not be resolved on $host" "OWNERSHIP_DEFECT"
  ssh_vm "$address" "sudo cat /var/lib/o3k-fabric-v3/$RUN_ID/network/fabric/plans/$realm_id.json" >"$EVIDENCE/endpoint-removal/host-$host-fabric-plan.json" || fail "post-C-removal Fabric plan unavailable on $host" "OWNERSHIP_DEFECT"
done
python3 - "$EVIDENCE/endpoint-removal" "${PORT_IDS[2]}" <<'PY' || fail "C endpoint/HER did not withdraw" "CLEANUP_DEFECT"
import glob,json,sys
for path in glob.glob(sys.argv[1]+"/host-*-ownership.json"):
    x=json.load(open(path)); assert all(sys.argv[2] not in r.get("endpoint_taps",{}) for r in x.get("realms",{}).values()), path
    host=path.rsplit("/",1)[-1].split("-")[1]
    plan=json.load(open(sys.argv[1]+f"/host-{host}-fabric-plan.json"))
    hosts={e["selected_host"] for e in plan.get("directory",{}).get("entries",[])}
    assert hosts=={"host-a","host-b"}, (path,hosts)
PY
console_command a "ping -c 1 -W 4 ${TENANT_IP[b]}" endpoint-removal/a-to-b.txt || fail "A/B failed after C removal" "$(guest_failure_class DATAPLANE_DEFECT)"
console_command b "ping -c 1 -W 4 ${TENANT_IP[a]}" endpoint-removal/b-to-a.txt || fail "B/A failed after C removal" "$(guest_failure_class DATAPLANE_DEFECT)"

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
    x=json.load(open(path))
    assert all(not r.get("endpoint_taps",{}) and not r.get("pending_endpoint_taps",{}) for r in x.get("realms",{}).values()), path
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
