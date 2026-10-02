#!/usr/bin/env bash
# PP.5 Small Edge campaign: provision N fresh nested-KVM libvirt hosts.
#
# This is the first installation step of a multi-host Small Edge campaign. It
# provisions real QEMU/KVM guests (2 vCPU / 2 GiB / 10 GiB, host-passthrough CPU
# so nested KVM works), boots each one, proves /dev/kvm is present and usable
# inside it, and records per-host evidence. Nothing here touches O3K Rust code
# and no `cargo` command is ever run (the shared target dir is owned by another
# build).
#
# Ownership model: every domain, disk and seed ISO this run creates carries the
# exact prefix `o3k-pp5-<RUN_ID>-`. Teardown removes nothing that is not ours;
# it verifies an ownership marker written by this script before deleting.
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CAMPAIGN_DIR="$REPO_ROOT/tests/pp5-small-edge-campaign"
RUNS_ROOT="$CAMPAIGN_DIR/runs"
IMGS_DIR="${O3K_PP5_IMAGES_DIR:-/var/lib/libvirt/images}"
BASE_IMG="${O3K_PP5_BASE_IMAGE:-/var/lib/libvirt/images/noble-server-cloudimg-amd64.img}"
BASE_SHA="612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354"
NETWORK="${O3K_PP5_NETWORK:-default}"
USER_NAME=o3k
DISK_GB="${O3K_PP5_DISK_GB:-10}"
VCPUS="${O3K_PP5_VCPUS:-2}"
RAM_MB="${O3K_PP5_RAM_MB:-2048}"
# Under full 5-guest parallel boot on this shared host the guests take 10-20
# minutes to come up (CPU/IO contention), so the budgets are deliberately
# generous; per-host detection still finishes as soon as ARP shows the guest.
SSH_WAIT_ATTEMPTS="${O3K_PP5_SSH_WAIT_ATTEMPTS:-600}"   # * 5s -> ~50 min total budget
BOOT_WAIT_ATTEMPTS="${O3K_PP5_BOOT_WAIT_ATTEMPTS:-600}"  # * 5s -> ~50 min to get an IP

HOST_COUNT="${O3K_PP5_HOST_COUNT:-${1:-5}}"
[[ "$HOST_COUNT" =~ ^[0-9]+$ ]] && ((HOST_COUNT >= 1 && HOST_COUNT <= 26)) \
  || { echo "provision-hosts: host count must be an integer in [1,26]" >&2; exit 2; }

RUN_ID="${O3K_PP5_RUN_ID:-$(date -u +%m%d%H%M%S)-$$}"
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] \
  || { echo "provision-hosts: invalid RUN_ID '$RUN_ID'" >&2; exit 2; }

PREFIX="o3k-pp5-$RUN_ID"
EVID="$RUNS_ROOT/$RUN_ID"
START_TS="$(date -u +%FT%TZ)"

fail() { echo "provision-hosts failed: $1" >&2; exit 1; }

# --- preflight ---------------------------------------------------------------
command -v virsh >/dev/null 2>&1 || fail "virsh is unavailable"
command -v virt-install >/dev/null 2>&1 || fail "virt-install is unavailable"
command -v qemu-img >/dev/null 2>&1 || fail "qemu-img is unavailable"
command -v genisoimage >/dev/null 2>&1 || fail "genisoimage is unavailable (cloud-localds absent on this host)"
command -v ssh >/dev/null 2>&1 || fail "ssh is unavailable"
command -v ssh-keygen >/dev/null 2>&1 || fail "ssh-keygen is unavailable"
command -v python3 >/dev/null 2>&1 || fail "python3 is unavailable (needed for evidence JSON)"
command -v openssl >/dev/null 2>&1 || fail "openssl is unavailable"
[ -e /dev/kvm ] || fail "/dev/kvm is missing on this host"
[ -c /dev/kvm ] || fail "/dev/kvm is not a character device"

[ -f "$BASE_IMG" ] || fail "base image not found: $BASE_IMG (treat as read-only input; never modify/delete)"
actual_sha="$(sha256sum "$BASE_IMG" | awk '{print $1}')"
[ "$actual_sha" == "$BASE_SHA" ] \
  || fail "base image sha mismatch: expected $BASE_SHA got $actual_sha"

virsh -c qemu:///system net-info "$NETWORK" >/dev/null 2>&1 || fail "libvirt network '$NETWORK' is unavailable"
# libvirt 10.0.0 net-info reports readiness under `Active:`, not `State:`.
net_state="$(virsh -c qemu:///system net-info "$NETWORK" 2>/dev/null | awk -F': *' '/^Active:/{print $2}')"
[ "$net_state" == "yes" ] || fail "libvirt network '$NETWORK' is not active (active=$net_state)"
gateway="$(virsh -c qemu:///system net-dumpxml "$NETWORK" \
  | grep -oE "address='[0-9.]+'" | head -1 | tr -d "address='")"
[ -n "$gateway" ] || fail "could not determine gateway for network '$NETWORK'"
BRIDGE="$(virsh -c qemu:///system net-dumpxml "$NETWORK" \
  | grep -oE "bridge name='[^']+'" | head -1 | sed "s/bridge name='//;s/'//")"
[ -n "$BRIDGE" ] || fail "could not determine bridge for network '$NETWORK'"

# Fail closed if a previous run was never torn down: our exact prefix must not
# already own any domain, disk or seed.
existing="$(virsh -c qemu:///system list --all --name | grep -F -e "$PREFIX-" || true)"
[ -z "$existing" ] || fail "prefix collision: domain(s) already exist for $PREFIX (run not torn down?): $existing"
for glob in "$IMGS_DIR/$PREFIX-"*.qcow2 "$IMGS_DIR/$PREFIX-"*-seed.iso; do
  [ -e "$glob" ] || continue
  fail "prefix collision: leftover volume '$glob' for $PREFIX (run not torn down?)"
done
[ -e "$EVID" ] && fail "evidence dir already exists: $EVID"
[ -e "$RUNS_ROOT" ] && [ ! -d "$RUNS_ROOT" ] && fail "runs root is not a directory: $RUNS_ROOT"

umask 077
mkdir -p "$EVID/keys"
printf 'o3k-pp5-owned-v1\nprefix=%s\nrun=%s\nstarted=%s\nhost_count=%s\n' \
  "$PREFIX" "$RUN_ID" "$START_TS" "$HOST_COUNT" >"$EVID/.o3k-pp5-owned"
chmod 0600 "$EVID/.o3k-pp5-owned"

# --- per-host helpers --------------------------------------------------------
host_letter() { # 1 -> a, 2 -> b, ...
  local idx="$1" oct
  oct="$(printf '%03o' "$((96 + idx))")"   # 097, 098, ...
  printf '%b' "\\$oct"                      # '\097' -> 'a'
}

create_disk() { # $1 disk path
  qemu-img create -f qcow2 -b "$BASE_IMG" -F qcow2 "$1" "${DISK_GB}G" >/dev/null
}

make_seed() { # $1 hostname, $2 key pub, $3 seed source workspace, $4 output ISO path
  local hostname="$1" pub="$2" ws="$3" out="$4"
  mkdir -p "$ws"
  cat >"$ws/user-data" <<EOF
#cloud-config
hostname: $hostname
users:
  - name: $USER_NAME
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    groups: [sudo, kvm]
    ssh_authorized_keys:
      - $pub
disable_root: true
ssh_pwauth: false
EOF
  printf 'instance-id: %s\nlocal-hostname: %s\n' "$hostname" "$hostname" >"$ws/meta-data"
  genisoimage -output "$out" -volid cidata -joliet -rock \
    "$ws/user-data" "$ws/meta-data" >/dev/null 2>&1 || return 1
  [ -s "$out" ]
}

wait_for_ip() { # $1 domain name; prints IP once the guest is live on the network
  local name="$1" mac="" ip
  # Primary source is the libvirt lease table; fallback is the host ARP/neigh
  # table at the interface MAC, which is ground truth that the guest is up and
  # has an address on $BRIDGE (libvirt lease reporting can lag under multi-boot).
  mac="$(virsh -c qemu:///system domiflist "$name" 2>/dev/null | awk 'NR>2{print $5; exit}')"
  for _ in $(seq 1 "$BOOT_WAIT_ATTEMPTS"); do
    ip="$(virsh -c qemu:///system domifaddr "$name" --source lease 2>/dev/null \
      | awk '$2=="ipv4"{split($3,a,"/"); print a[1]; exit}')"
    if [ -z "$ip" ] && [ -n "$mac" ] && [ -n "$BRIDGE" ]; then
      # `ip neigh show dev <bridge>` prints `IP lladdr MAC STATE` (the `dev`
      # column is dropped), so match the MAC anywhere in the line instead of a
      # fixed field — the field position differs and caused a silent miss.
      ip="$(ip neigh show dev "$BRIDGE" 2>/dev/null \
        | awk -v m="$mac" 'tolower($0) ~ tolower(m){print $1; exit}')"
    fi
    [ -n "$ip" ] && { printf '%s' "$ip"; return 0; }
    sleep 5
  done
  return 1
}

wait_ssh() { # $1 ip, $2 key; returns once `true` succeeds over SSH
  local ip="$1" key="$2"
  for _ in $(seq 1 "$SSH_WAIT_ATTEMPTS"); do
    ssh -i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -o BatchMode=yes "$USER_NAME@$ip" true 2>/dev/null && return 0
    sleep 5
  done
  return 1
}

ssh_vm() { # $1 ip, $2 key, rest -> remote command
  local ip="$1" key="$2"; shift 2
  ssh -i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 -o BatchMode=yes "$USER_NAME@$ip" "$@"
}

# --- phase 1: create artifacts and define/start every domain -----------------
# All VMs are started up front so they boot in parallel (the dominant cost is
# guest boot time; per-host DHCP/SSH waiting happens in phase 2).
: >"$EVID/inventory.txt"
declare -a PASS=() FAIL=()
declare -a HOST_LETTERS=()

for idx in $(seq 1 "$HOST_COUNT"); do
  letter="$(host_letter "$idx")"
  name="$PREFIX-host-$letter"
  disk="$IMGS_DIR/$PREFIX-host-$letter.qcow2"
  seed="$IMGS_DIR/$PREFIX-host-$letter-seed.iso"
  key="$EVID/keys/host-$letter/id_ed25519"
  ws="$EVID/keys/host-$letter/seed"
  echo "===[$idx/$HOST_COUNT] define/start $name ==="

  if ! create_disk "$disk"; then FAIL+=("$name"); echo "  disk creation failed" >&2; continue; fi
  mkdir -p "$(dirname "$key")"
  if ! ssh-keygen -t ed25519 -f "$key" -N '' -C "$name" >/dev/null 2>&1; then
    FAIL+=("$name"); echo "  ssh key generation failed" >&2; continue
  fi
  if ! make_seed "$name" "$(cat "$key.pub")" "$ws" "$seed"; then
    FAIL+=("$name"); echo "  seed ISO failed" >&2; continue
  fi

  if ! virt-install --connect qemu:///system --name "$name" --import \
      --ram "$RAM_MB" --vcpus "$VCPUS" \
      --disk "path=$disk,format=qcow2,device=disk,bus=virtio" \
      --disk "path=$seed,device=cdrom" \
      --network "network=$NETWORK,model=virtio" \
      --os-variant ubuntu24.04 --cpu host-passthrough \
      --graphics none --noautoconsole --quiet >/dev/null 2>&1; then
    FAIL+=("$name"); echo "  virt-install failed" >&2; continue
  fi
  HOST_LETTERS+=("$letter")
done

# --- phase 2: wait for DHCP + SSH, then assert KVM in each started host ------
for letter in "${HOST_LETTERS[@]}"; do
  name="$PREFIX-host-$letter"
  disk="$IMGS_DIR/$PREFIX-host-$letter.qcow2"
  seed="$IMGS_DIR/$PREFIX-host-$letter-seed.iso"
  key="$EVID/keys/host-$letter/id_ed25519"
  h_start="$(date +%s)"
  echo "--- waiting on $name ---"

  uuid="$(virsh -c qemu:///system domuuid "$name" 2>/dev/null || printf unknown)"
  ip="$(wait_for_ip "$name")" || { FAIL+=("$name"); echo "  no DHCP lease / IP within budget" >&2; continue; }
  if ! wait_ssh "$ip" "$key"; then
    FAIL+=("$name"); echo "  SSH did not become reachable at $ip within budget" >&2; continue
  fi

  # Prove KVM is present and usable inside the guest, then record host facts.
  # Single round-trip: assert /dev/kvm is a readable char device AND the CPU
  # exposes vmx/svm (host-passthrough), and print the host facts. The remote
  # script exits non-zero if the KVM assertion fails, so this is authoritative.
  facts="$(set +e; ssh_vm "$ip" "$key" '
    if [ -e /dev/kvm ] && [ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] \
       && grep -Eqi "vmx|svm" /proc/cpuinfo; then
      printf "kvm=1\n"
    else
      printf "kvm=0\n"; exit 1
    fi
    printf "nproc=%s\n" "$(nproc)"
    awk "/^MemTotal:/{printf \"mem_mb_total=%d\\n\", \$2/1024; exit}" /proc/meminfo
    printf "kernel=%s\n" "$(uname -r)"
  ' 2>/dev/null)" || { FAIL+=("$name"); echo "  /dev/kvm not present/usable inside guest" >&2; continue; }
  kvm_ok="$(printf '%s\n' "$facts" | sed -n 's/^kvm=//p' | head -1)"
  nproc_v="$(printf '%s\n' "$facts" | sed -n 's/^nproc=//p' | head -1)"
  mem_mb_v="$(printf '%s\n' "$facts" | sed -n 's/^mem_mb_total=//p' | head -1)"
  mem_v="${mem_mb_v} MiB total"
  kernel_v="$(printf '%s\n' "$facts" | sed -n 's/^kernel=//p' | head -1)"
  h_end="$(date +%s)"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$ip" "$uuid" "$kvm_ok" "$nproc_v" "$mem_mb_v" "$kernel_v" \
    "$((h_end - h_start))" >>"$EVID/host-facts.tsv"

  PASS+=("$name")
  {
    printf 'domain\t%s\t%s\n' "$name" "$uuid"
    printf 'ip\t%s\t%s\n' "$name" "$ip"
    printf 'disk\t%s\t%s\n' "$name" "$disk"
    printf 'seed\t%s\t%s\n' "$name" "$seed"
    printf 'key\t%s\t%s\n' "$name" "$key"
  } >>"$EVID/inventory.txt"
  echo "  OK: ip=$ip kvm=$kvm_ok nproc=$nproc_v mem=$mem_v kernel=$kernel_v wait=$((h_end-h_start))s"
done

# --- evidence ----------------------------------------------------------------
python3 - "$EVID/evidence.json" "$PREFIX" "$RUN_ID" "$HOST_COUNT" \
  "$START_TS" "$(date -u +%FT%TZ)" "$gateway" "$NETWORK" \
  "$EVID/host-facts.tsv" "${#PASS[@]}" "${#FAIL[@]}" <<'PY'
import json, sys
path, prefix, run, hc, start, finish, gw, net, facts_tsv, np, nf = sys.argv[1:]
hosts = []
try:
    with open(facts_tsv, encoding="utf-8") as f:
        for line in f:
            name, ip, uuid, kvm, nproc, mem, kernel, wait = line.rstrip("\n").split("\t")
            hosts.append({
                "name": name, "ip": ip, "uuid": uuid,
                "kvm_usable": kvm == "1", "nproc": int(nproc),
                "mem_mb_total": int(mem), "kernel": kernel,
                "wait_seconds": int(wait),
            })
except FileNotFoundError:
    pass
with open(path, "w", encoding="utf-8") as f:
    json.dump({
        "artifact_type": "pp5-small-edge-provision",
        "run": run, "prefix": prefix, "host_count": int(hc),
        "network": net, "gateway": gw,
        "started_at": start, "finished_at": finish,
        "passed": int(np), "failed": int(nf),
        "outcome": "PASS" if int(nf) == 0 else "FAIL",
        "hosts": hosts,
    }, f, indent=2, sort_keys=True)
    f.write("\n")
PY

echo "=== provision completed: ${#PASS[@]}/$HOST_COUNT hosts OK, ${#FAIL[@]} failed, prefix=$PREFIX run=$RUN_ID ==="
echo "inventory: $EVID/inventory.txt  evidence: $EVID/evidence.json"
if (( ${#FAIL[@]} > 0 )); then
  echo "FAILED HOSTS: ${FAIL[*]}" >&2
  echo "run teardown to reclaim everything owned by prefix $PREFIX:" >&2
  echo "  O3K_PP5_RUN_ID=$RUN_ID bash $CAMPAIGN_DIR/teardown-hosts.sh" >&2
  exit 1
fi
exit 0
