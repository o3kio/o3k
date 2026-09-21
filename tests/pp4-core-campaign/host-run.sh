#!/usr/bin/env bash
# PP.4 Core public-artifact campaign driver: fresh nested KVM, Araf skipped.
set -Eeuo pipefail
DISTRO=ubuntu
if [ "$#" -ge 1 ]; then DISTRO="$1"; fi
EVID=target/pp4-core-$(date -u +%Y%m%dT%H%M%SZ)-$DISTRO
if [ "$#" -ge 2 ]; then EVID="$2"; fi
VERSION="${O3K_PP4_VERSION-v0.4.0-rc.22}"
EXPECTED_SHA="${O3K_PP4_SOURCE_SHA-02c2852f5498d2632baff6b1ee49ed12a24d4bd8}"
WORK="${O3K_PP4_WORK-$(mktemp -d /tmp/o3k-pp4-core.XXXXXX)}"
SSH_PORT="${O3K_PP4_SSH_PORT-2392}"
mkdir -p "$EVID" "$WORK"
SSH_KEY="$WORK/id_ed25519"; DISK="$WORK/$DISTRO.qcow2"; SEED="$WORK/seed"
SEED_ISO="$WORK/seed.iso"; PIDFILE="$WORK/qemu.pid"
case "$DISTRO" in
  ubuntu) BASE="${O3K_UBUNTU_IMAGE-/root/noble-server-cloudimg-amd64.img}"; VM_NAME=pp4-core-ubuntu ;;
  debian)
    BASE="${O3K_DEBIAN_IMAGE-$WORK/debian-12-genericcloud-amd64.qcow2}"; VM_NAME=pp4-core-debian
    if [ ! -f "$BASE" ]; then curl -fsSL --retry 3 -o "$BASE" https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2; fi ;;
  *) echo 'usage: host-run.sh ubuntu|debian [evidence-dir]' >&2; exit 2 ;;
esac
[ -f "$BASE" ] || { echo "missing base image: $BASE" >&2; exit 2; }
ssh-keygen -t ed25519 -f "$SSH_KEY" -N '' -C pp4-core >/dev/null
qemu-img create -f qcow2 -b "$BASE" -F qcow2 "$DISK" 24G >/dev/null
mkdir -p "$SEED"
cat >"$SEED/user-data" <<EOF
#cloud-config
hostname: $VM_NAME
users:
  - name: tester
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "$SSH_KEY.pub")
package_update: true
package_upgrade: false
packages:
  - curl
  - ca-certificates
runcmd:
  - echo 'tester ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/tester
  - chmod 0440 /etc/sudoers.d/tester
EOF
printf 'instance-id: %s\nlocal-hostname: %s\n' "$VM_NAME" "$VM_NAME" >"$SEED/meta-data"
genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock "$SEED/user-data" "$SEED/meta-data" >/dev/null
# shellcheck disable=SC2086
qemu-system-x86_64 -name "$VM_NAME" -machine type=q35,accel=kvm -cpu host -smp 2 -m 6144 \
  -drive file="$DISK",if=virtio,format=qcow2 -drive file="$SEED_ISO",if=virtio,media=cdrom \
  -netdev user,id=net0,hostfwd=tcp::$SSH_PORT-:22 -device virtio-net-pci,netdev=net0 \
  -display none -daemonize -pidfile "$PIDFILE"
ssh_vm() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p "$SSH_PORT" tester@127.0.0.1 "$@"; }
cleanup() {
  if [[ "${O3K_PP4_KEEP_VM-0}" == 1 ]]; then
    echo "PP4 debug VM retained: work=$WORK ssh_port=$SSH_PORT key=$SSH_KEY pidfile=$PIDFILE" >&2
    return 0
  fi
  set +e
  if [ -f "$PIDFILE" ]; then
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
  fi
  sleep 2
  rm -rf "$SEED" "$SEED_ISO" "$DISK" "$PIDFILE" "$SSH_KEY" "$SSH_KEY.pub"
  rmdir "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
for _attempt in $(seq 1 120); do ssh_vm true 2>/dev/null && break; sleep 3; done
ssh_vm true || { echo 'SSH did not come up' >&2; exit 1; }
ssh_vm 'sudo timeout 900 cloud-init status --wait' || true
ssh_vm 'test -e /dev/kvm'
echo "PP4 VM ready: $DISTRO /dev/kvm"
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$SSH_PORT" \
  "$(dirname "$0")/native_client.py" "$(dirname "$0")/in-vm-native-smoke.sh" \
  "$(dirname "$0")/verify_manifest.py" tester@127.0.0.1:/home/tester/
ssh_vm 'chmod 0755 /home/tester/in-vm-native-smoke.sh /home/tester/native_client.py'
ssh_vm "curl -sfL https://github.com/o3kio/o3k/releases/download/$VERSION/install.sh | sudo env O3K_SKIP_ARAF=1 sh -" 2>&1 | tee "$EVID/install-output.log"
ssh_vm "sudo python3 /home/tester/verify_manifest.py '$VERSION' '$EXPECTED_SHA'"
ssh_vm 'mkdir -p /home/tester/pp4-evidence'
set +e
ssh_vm 'bash /home/tester/in-vm-native-smoke.sh /home/tester/pp4-evidence /home/tester/native_client.py > /home/tester/native-smoke.log 2>&1'
smoke_status=$?
set -e
set +e
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$SSH_PORT" \
  tester@127.0.0.1:/home/tester/native-smoke.log "$EVID/native-smoke.log" >/dev/null 2>&1
log_copy_status=$?
if (( log_copy_status != 0 )); then
  # Preserve a diagnostic even when the guest SSH service drops during a
  # provider action; this keeps a harness failure distinct from product
  # evidence and lets the outer campaign report the actual transport state.
  printf 'native log unavailable (scp status=%s, smoke status=%s)\n' "$log_copy_status" "$smoke_status" >"$EVID/native-smoke.log"
fi
set -e
cat "$EVID/native-smoke.log"
# Preserve the in-guest evidence directory on failure too, so a harness or
# product failure is diagnosed from the recorded observations rather than a
# two-line stdout tail.
set +e
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$SSH_PORT" -r \
  tester@127.0.0.1:/home/tester/pp4-evidence/. "$EVID/" >/dev/null 2>&1
set -e
((smoke_status == 0)) || exit "$smoke_status"
printf 'release=%s\nsource_sha=%s\ndistro=%s\ncampaign_status=PASS\n' "$VERSION" "$EXPECTED_SHA" "$DISTRO" >"$EVID/campaign.env"
echo "PP4 CORE CAMPAIGN PASS: $DISTRO"
