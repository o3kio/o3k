#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EA_CONFIG_FILE="${EA_CONFIG_FILE:-$ROOT_DIR/tests/ea-qualification/ea-config.env}"
[[ -f "$EA_CONFIG_FILE" && ! -L "$EA_CONFIG_FILE" ]] || {
  echo "qualification config is missing or unsafe: $EA_CONFIG_FILE" >&2
  exit 1
}
# shellcheck source=tests/ea-qualification/ea-config.env
source "$EA_CONFIG_FILE"
STATE="$EA_POOL_ROOT/.ea-owned"
KNOWN_HOSTS="$EA_POOL_ROOT/known_hosts"
SSH_KEY="$EA_POOL_ROOT/compute_id_ed25519"

validate_config() {
  local variable value
  for variable in EA_RUN_ID EA_NETWORK EA_NETWORK_BRIDGE EA_POOL EA_DOMAIN_PREFIX; do
    value="${!variable}"
    [[ "$value" =~ ^[A-Za-z0-9_.-]{1,64}$ && "$value" != *..* ]] || {
      echo "invalid qualification config value: $variable" >&2
      exit 2
    }
  done
  for variable in EA_NETWORK_UUID EA_POOL_UUID; do
    value="${!variable}"
    [[ "$value" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || {
      echo "invalid qualification config value: $variable" >&2
      exit 2
    }
  done
  [[ "$EA_NETWORK_BRIDGE" =~ ^[A-Za-z0-9_-]{1,15}$ ]] || {
    echo "invalid qualification bridge name" >&2; exit 2;
  }
  [[ "$EA_IMAGE_ROOT" =~ ^/[A-Za-z0-9_./-]+$ \
    && "$EA_POOL_ROOT" =~ ^/[A-Za-z0-9_./-]+$ \
    && "$EA_BASE_IMAGE" =~ ^/[A-Za-z0-9_./-]+$ ]] || {
    echo "qualification paths may contain only absolute path-safe characters" >&2; exit 2;
  }
  for value in "$EA_IMAGE_ROOT" "$EA_POOL_ROOT" "$EA_BASE_IMAGE"; do
    [[ "$value" != *'/../'* && "$value" != */.. && "$value" != *'/./'* && "$value" != */. ]] || {
      echo "qualification paths must not contain dot components" >&2; exit 2;
    }
  done
  [[ "$EA_BASE_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid pinned Ubuntu image checksum" >&2; exit 2;
  }
  [[ "$EA_HOSTS" == 1 || "$EA_HOSTS" == 3 ]] || {
    echo "EA_HOSTS must be 1 or 3" >&2; exit 2;
  }
  python3 - "$EA_NETWORK_CIDR" "$EA_NETWORK_GATEWAY" "$EA_DHCP_START" "$EA_DHCP_END" <<'PY'
import ipaddress
import sys

try:
    network = ipaddress.ip_network(sys.argv[1], strict=True)
    addresses = [ipaddress.ip_address(value) for value in sys.argv[2:]]
except ValueError as error:
    raise SystemExit(f"invalid qualification network config: {error}")
if not isinstance(network, ipaddress.IPv4Network) or any(
    not isinstance(address, ipaddress.IPv4Address) for address in addresses
):
    raise SystemExit("qualification network and addresses must use IPv4")
if network.prefixlen != 24:
    raise SystemExit("qualification network must use the supported /24 prefix")
if any(address not in network for address in addresses):
    raise SystemExit("gateway and DHCP range must be inside the campaign subnet")
if addresses[0] >= addresses[1] or addresses[1] > addresses[2] or len(set(addresses)) != len(addresses):
    raise SystemExit("gateway and DHCP range must be distinct and ordered")
PY
  [[ "$EA_POOL_ROOT" == "$EA_IMAGE_ROOT"/* ]] || {
    echo "qualification pool must be inside its campaign image root" >&2; exit 2;
  }
}
validate_config

usage() {
  echo "usage: $0 inventory|provision [HOST_COUNT: 1|3]|ssh HOST COMMAND...|cleanup" >&2
  exit 2
}

owned() {
  [[ -f "$STATE" && ! -L "$STATE" ]] \
    && [[ "$(head -n 1 "$STATE")" == "o3k-ea-qualification-owned-v1" ]] \
    && grep -Fxq "run=$EA_RUN_ID" "$STATE" \
    && grep -Fxq "network=$EA_NETWORK" "$STATE" \
    && grep -Fxq "network_uuid=$EA_NETWORK_UUID" "$STATE" \
    && grep -Fxq "pool=$EA_POOL" "$STATE" \
    && grep -Fxq "pool_uuid=$EA_POOL_UUID" "$STATE"
}

verify_ids() {
  [[ "$(virsh net-uuid "$EA_NETWORK" 2>/dev/null || true)" == "$EA_NETWORK_UUID" ]] \
    && [[ "$(virsh pool-uuid "$EA_POOL" 2>/dev/null || true)" == "$EA_POOL_UUID" ]]
}

verify_cleanup_ids() {
  local names
  names="$(virsh net-list --all --name)" || {
    echo "refusing cleanup: cannot inspect libvirt networks" >&2; return 1;
  }
  if grep -Fxq "$EA_NETWORK" <<<"$names"; then
    [[ "$(virsh net-uuid "$EA_NETWORK")" == "$EA_NETWORK_UUID" ]] || {
      echo "refusing cleanup: campaign network name has a different UUID" >&2; return 1;
    }
  fi
  names="$(virsh pool-list --all --name)" || {
    echo "refusing cleanup: cannot inspect libvirt storage pools" >&2; return 1;
  }
  if grep -Fxq "$EA_POOL" <<<"$names"; then
    [[ "$(virsh pool-uuid "$EA_POOL")" == "$EA_POOL_UUID" ]] || {
      echo "refusing cleanup: campaign pool name has a different UUID" >&2; return 1;
    }
  fi
}

verify_base_image() {
  [[ -f "$EA_BASE_IMAGE" && ! -L "$EA_BASE_IMAGE" ]] || {
    echo "pinned Ubuntu base image is missing or not a regular file: $EA_BASE_IMAGE" >&2
    exit 1
  }
  [[ "$(sha256sum "$EA_BASE_IMAGE" | awk '{print $1}')" == "$EA_BASE_SHA256" ]] || {
    echo "pinned Ubuntu base image checksum mismatch" >&2
    exit 1
  }
}

inventory() {
  echo "EA run=$EA_RUN_ID network=$EA_NETWORK pool=$EA_POOL"
  virsh net-info "$EA_NETWORK" 2>&1 || true
  virsh pool-info "$EA_POOL" 2>&1 || true
  virsh list --all --name | grep -F "$EA_DOMAIN_PREFIX" || true
  df -h "$EA_IMAGE_ROOT"
  sha256sum "$EA_BASE_IMAGE"
  [[ ! -f "$STATE" ]] || { echo "ownership marker present: $STATE"; sed -n '/^host_[abc]=/p' "$STATE"; }
}

define_network_and_pool() {
  mkdir -p "$EA_POOL_ROOT"
  [[ "$(realpath -m "$EA_POOL_ROOT")" == "$EA_IMAGE_ROOT/$EA_RUN_ID" ]] || {
    echo "campaign pool path escapes the configured image root" >&2
    exit 1
  }
  if virsh net-info "$EA_NETWORK" >/dev/null 2>&1; then
    [[ "$(virsh net-uuid "$EA_NETWORK")" == "$EA_NETWORK_UUID" ]] || {
      echo "refusing existing network with a different UUID: $EA_NETWORK" >&2; exit 1;
    }
  else
    local network_xml
    network_xml="$(mktemp)"
    cat >"$network_xml" <<XML
<network>
  <name>$EA_NETWORK</name>
  <uuid>$EA_NETWORK_UUID</uuid>
  <forward mode='nat'/>
  <bridge name='$EA_NETWORK_BRIDGE'/>
  <ip address='$EA_NETWORK_GATEWAY' netmask='255.255.255.0'>
    <dhcp><range start='$EA_DHCP_START' end='$EA_DHCP_END'/></dhcp>
  </ip>
</network>
XML
    virsh net-define "$network_xml"
    rm -f -- "$network_xml"
    virsh net-start "$EA_NETWORK"
    virsh net-autostart "$EA_NETWORK"
  fi
  if virsh pool-info "$EA_POOL" >/dev/null 2>&1; then
    [[ "$(virsh pool-uuid "$EA_POOL")" == "$EA_POOL_UUID" ]] || {
      echo "refusing existing storage pool with a different UUID: $EA_POOL" >&2; exit 1;
    }
  else
    local pool_xml
    pool_xml="$(mktemp)"
    cat >"$pool_xml" <<XML
<pool type='dir'>
  <name>$EA_POOL</name>
  <uuid>$EA_POOL_UUID</uuid>
  <target><path>$EA_POOL_ROOT</path></target>
</pool>
XML
    virsh pool-define "$pool_xml"
    rm -f -- "$pool_xml"
    virsh pool-start "$EA_POOL"
    virsh pool-autostart "$EA_POOL"
  fi
  verify_ids || { echo "network or pool UUID mismatch" >&2; exit 1; }
}

host_letter() {
  case "$1" in a|b|c) printf '%s' "$1" ;; *) echo "invalid host name" >&2; return 2 ;; esac
}

lookup_ip() {
  local domain="$1" mac=""
  mac="$(virsh domiflist "$domain" | awk 'NR>2 && $2!="" {print $5; exit}')"
  [[ -n "$mac" ]] || return 1
  for _ in $(seq 1 240); do
    local ip
    ip="$(virsh net-dhcp-leases "$EA_NETWORK" | awk -v m="$mac" 'tolower($3)==tolower(m) && $4=="ipv4" {sub(/\/24$/, "", $5); print $5; exit}')"
    [[ -n "$ip" ]] && { printf '%s' "$ip"; return 0; }
    sleep 5
  done
  echo "no DHCP lease appeared for $domain" >&2
  return 1
}

ssh_guest() {
  local letter domain ip
  letter="$(host_letter "$1")"
  domain="${EA_DOMAIN_PREFIX}${letter}"
  shift
  ip="$(lookup_ip "$domain")"
  ssh -i "$SSH_KEY" \
    -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$KNOWN_HOSTS" -o HostKeyAlias="$domain" \
    "ubuntu@$ip" "$@"
}

provision() {
  local requested_hosts="${1:-$EA_HOSTS}"
  [[ "$requested_hosts" == 1 || "$requested_hosts" == 3 ]] || {
    echo "provision host count must be 1 or 3" >&2; exit 2;
  }
  local hosts=(a)
  [[ "$requested_hosts" == 1 ]] || hosts=(a b c)
  verify_base_image
  for tool in virsh virt-install qemu-img virt-customize genisoimage ssh ssh-keygen uuidgen; do
    command -v "$tool" >/dev/null || { echo "required host tool is missing: $tool" >&2; exit 1; }
  done
  [[ -c /dev/kvm ]] || { echo "/dev/kvm is unavailable" >&2; exit 1; }
  [[ ! -e "$STATE" ]] || { echo "campaign marker already exists; use inventory or cleanup first" >&2; exit 1; }
  for letter in a b c; do
    local domain disk seed hostkey ip user_pub
    domain="${EA_DOMAIN_PREFIX}${letter}"
    disk="$EA_POOL_ROOT/${domain}.qcow2"
    seed="$EA_POOL_ROOT/${domain}-seed.iso"
    hostkey="$EA_POOL_ROOT/.${domain}-hostkey"
    [[ ! -e "$disk" && ! -e "$seed" && ! -e "$hostkey" ]] || {
      echo "refusing preexisting campaign file for $domain" >&2; exit 1;
    }
    if virsh dominfo "$domain" >/dev/null 2>&1; then
      echo "refusing preexisting domain $domain" >&2; exit 1;
    fi
  done
  [[ ! -d "$EA_POOL_ROOT" || -z "$(find "$EA_POOL_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo "refusing nonempty campaign directory without its ownership marker" >&2; exit 1;
  }
  local -A host_uuids=()
  for letter in a b c; do
    local uuid
    uuid="$(uuidgen)"
    [[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || {
      echo "uuidgen returned an invalid domain UUID" >&2; exit 1;
    }
    host_uuids[$letter]="$uuid"
  done
  # qemu's confined worker account must be able to traverse the pool path;
  # private credentials and evidence stay in separate 0700/0600 files.
  install -d -m 0755 "$EA_POOL_ROOT"
  chmod 0755 "$EA_POOL_ROOT"
  local state_contents
  umask 077
  state_contents="$(cat <<EOF
o3k-ea-qualification-owned-v1
run=$EA_RUN_ID
network=$EA_NETWORK
network_uuid=$EA_NETWORK_UUID
pool=$EA_POOL
pool_uuid=$EA_POOL_UUID
EOF
  )"
  for letter in a b c; do
    local domain disk seed uuid
    domain="${EA_DOMAIN_PREFIX}${letter}"
    disk="$EA_POOL_ROOT/${domain}.qcow2"
    seed="$EA_POOL_ROOT/${domain}-seed.iso"
    uuid="${host_uuids[$letter]}"
    state_contents+=$'\n'"host_${letter}=${domain}|${uuid}|${disk}|${seed}"
  done
  printf '%s\n' "$state_contents" >"$STATE"
  chmod 0600 "$STATE"

  # Persist campaign ownership before the first libvirt network/pool mutation.
  define_network_and_pool
  install -d -m 0700 "$EA_POOL_ROOT/credentials"
  [[ ! -e "$SSH_KEY" ]] || { echo "refusing preexisting SSH client key" >&2; exit 1; }
  ssh-keygen -q -t ed25519 -N '' -C "$EA_RUN_ID operator" -f "$SSH_KEY"
  chmod 0600 "$SSH_KEY"
  user_pub="$(cat "$SSH_KEY.pub")"
  : >"$KNOWN_HOSTS"
  chmod 0600 "$KNOWN_HOSTS"
  for letter in "${hosts[@]}"; do
    local domain disk seed hostkey hostpub hostcfg userdata metadata uuid ram_mb
    domain="${EA_DOMAIN_PREFIX}${letter}"
    disk="$EA_POOL_ROOT/${domain}.qcow2"
    seed="$EA_POOL_ROOT/${domain}-seed.iso"
    hostkey="$EA_POOL_ROOT/.${domain}-hostkey"
    hostpub="$hostkey.pub"
    hostcfg="$EA_POOL_ROOT/.${domain}-cloud.cfg"
    uuid="$(sed -n "s/^host_${letter}=//p" "$STATE" | cut -d'|' -f2)"
    ram_mb=6144
    [[ "$letter" != a ]] || ram_mb=8192

    # Exact intended identities were persisted before the first VM mutation.
    qemu-img create -q -f qcow2 -F qcow2 -b "$EA_BASE_IMAGE" "$disk" 20G
    ssh-keygen -q -t ed25519 -N '' -C "$domain" -f "$hostkey"
    # cloud-init normally deletes pre-existing host keys on first boot. Preserve
    # the injected per-guest key so strict known_hosts pinning remains valid.
    printf 'ssh_deletekeys: false\n' >"$hostcfg"
    sudo virt-customize -a "$disk" \
      --upload "$hostkey:/etc/ssh/ssh_host_ed25519_key" \
      --upload "$hostcfg:/etc/cloud/cloud.cfg.d/99-o3k-preserve-hostkey.cfg" \
      --run-command 'chown root:root /etc/ssh/ssh_host_ed25519_key /etc/cloud/cloud.cfg.d/99-o3k-preserve-hostkey.cfg && chmod 0600 /etc/ssh/ssh_host_ed25519_key && chmod 0644 /etc/cloud/cloud.cfg.d/99-o3k-preserve-hostkey.cfg'
    sudo chown "$(id -u):$(id -g)" "$disk"
    printf '%s %s\n' "$domain" "$(awk '{print $1, $2}' "$hostpub")" >>"$KNOWN_HOSTS"
    rm -f -- "$hostkey" "$hostpub" "$hostcfg"

    userdata="$EA_POOL_ROOT/${domain}-user-data"
    metadata="$EA_POOL_ROOT/${domain}-meta-data"
    cat >"$userdata" <<EOF
#cloud-config
hostname: $domain
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    groups: [sudo, kvm]
    lock_passwd: true
    ssh_authorized_keys:
      - $user_pub
disable_root: true
ssh_pwauth: false
EOF
    printf 'instance-id: %s\nlocal-hostname: %s\n' "$domain" "$domain" >"$metadata"
    # NoCloud requires these exact filenames at the ISO root. The earlier
    # guest-prefixed names silently fell back to DataSourceNone and skipped
    # user creation/authorized_keys, so verify this as a real login below.
    genisoimage -quiet -output "$seed" -volid cidata -joliet -rock \
      -graft-points "user-data=$userdata" "meta-data=$metadata"
    rm -f -- "$userdata" "$metadata"
    virt-install --connect qemu:///system --name "$domain" --uuid "$uuid" --import \
      --ram "$ram_mb" --vcpus 4 --disk "path=$disk,format=qcow2,bus=virtio" \
      --disk "path=$seed,device=cdrom" --network "network=$EA_NETWORK,model=virtio" \
      --os-variant ubuntu24.04 --cpu host-passthrough --graphics none --noautoconsole --quiet
    ip="$(lookup_ip "$domain")"
    for _ in $(seq 1 120); do
      if ssh_guest "$letter" 'test -c /dev/kvm && test -r /dev/kvm && id -nG | tr " " "\n" | grep -Fxq kvm'; then
        break
      fi
      sleep 5
    done
    ssh_guest "$letter" 'test -c /dev/kvm && test -r /dev/kvm && id -nG | tr " " "\n" | grep -Fxq kvm' || {
      echo "nested KVM or SSH identity check failed for $domain ($ip)" >&2; exit 1;
    }
    printf 'host=%s\tip=%s\tuuid=%s\tvcpus=4\tram_mb=%s\tnested_kvm=verified\n' \
      "$domain" "$ip" "$uuid" "$ram_mb" >>"$EA_POOL_ROOT/inventory.tsv"
  done
  echo "$requested_hosts nested Ubuntu 24.04 host(s) provisioned on $EA_NETWORK with pinned SSH host keys."
}

cleanup() {
  owned || { echo "refusing cleanup: campaign ownership marker is missing or mismatched" >&2; exit 1; }
  verify_cleanup_ids || { echo "refusing cleanup: network/pool ownership mismatch" >&2; exit 1; }
  for letter in a b c; do
    local record domain expected_uuid disk seed current_uuid sources
    record="$(sed -n "s/^host_${letter}=//p" "$STATE")"
    [[ -n "$record" ]] || { echo "incomplete ownership record for host $letter" >&2; exit 1; }
    IFS='|' read -r domain expected_uuid disk seed <<<"$record"
    [[ "$domain" == "${EA_DOMAIN_PREFIX}${letter}" \
      && "$disk" == "$EA_POOL_ROOT/$domain.qcow2" \
      && "$seed" == "$EA_POOL_ROOT/$domain-seed.iso" ]] || {
      echo "ownership record path/name mismatch for host $letter" >&2; exit 1;
    }
    if virsh dominfo "$domain" >/dev/null 2>&1; then
      current_uuid="$(virsh domuuid "$domain")"
      [[ "$current_uuid" == "$expected_uuid" && "$(virsh domname "$expected_uuid")" == "$domain" ]] || {
        echo "refusing domain UUID mismatch for $domain" >&2; exit 1;
      }
      sources="$(virsh domblklist "$domain" --details | awk 'NR>2 && $4!="" {print $4}')"
      if ! grep -Fxq "$disk" <<<"$sources" || ! grep -Fxq "$seed" <<<"$sources"; then
        echo "refusing cleanup: $domain storage mapping differs from ownership record" >&2; exit 1;
      fi
    fi
  done
  for letter in a b c; do
    local record domain expected_uuid disk seed
    record="$(sed -n "s/^host_${letter}=//p" "$STATE")"
    IFS='|' read -r domain expected_uuid disk seed <<<"$record"
    if virsh dominfo "$domain" >/dev/null 2>&1; then
      virsh destroy "$domain" >/dev/null 2>&1 || true
      virsh undefine "$domain" >/dev/null
    fi
    [[ ! -e "$disk" ]] || rm -- "$disk"
    [[ ! -e "$seed" ]] || rm -- "$seed"
    [[ ! -e "$EA_POOL_ROOT/.$domain-hostkey" ]] || rm -f -- "$EA_POOL_ROOT/.$domain-hostkey" "$EA_POOL_ROOT/.$domain-hostkey.pub"
  done
  rm -f -- "$STATE" "$SSH_KEY" "$SSH_KEY.pub" "$KNOWN_HOSTS"
  echo "Only recorded EA domains and their recorded campaign disks/seeds were removed; pool/network and evidence remain."
}

case "${1:-}" in
  inventory) inventory ;;
  provision) shift; provision "${1:-$EA_HOSTS}" ;;
  ssh) shift; [[ $# -ge 2 ]] || usage; ssh_guest "$@" ;;
  cleanup) cleanup ;;
  *) usage ;;
esac
