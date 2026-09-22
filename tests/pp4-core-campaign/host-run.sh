#!/usr/bin/env bash
# PP.4 Core public-artifact campaign driver: fresh nested KVM, Araf skipped.
set -Eeuo pipefail
DISTRO=ubuntu
if [ "$#" -ge 1 ]; then DISTRO="$1"; fi
EVID=target/pp4-core-$(date -u +%Y%m%dT%H%M%SZ)-$DISTRO
if [ "$#" -ge 2 ]; then EVID="$2"; fi
VERSION="${O3K_PP4_VERSION-}"
EXPECTED_SHA="${O3K_PP4_SOURCE_SHA-}"
[[ "$VERSION" =~ ^v0\.4\.0-rc\.[0-9]+$ ]] || {
  echo 'O3K_PP4_VERSION is required and must be an immutable v0.4.0-rc.N tag' >&2; exit 2;
}
[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'O3K_PP4_SOURCE_SHA is required and must be a 40-character lowercase SHA' >&2; exit 2;
}
HARNESS_SHA="${O3K_PP4_HARNESS_SHA-$(git rev-parse HEAD 2>/dev/null || printf unknown)}"
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
  - jq
  - docker.io
runcmd:
  - echo 'tester ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/tester
  - chmod 0440 /etc/sudoers.d/tester
  - systemctl enable --now docker
EOF
printf 'instance-id: %s\nlocal-hostname: %s\n' "$VM_NAME" "$VM_NAME" >"$SEED/meta-data"
genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock "$SEED/user-data" "$SEED/meta-data" >/dev/null
# A serial console log is captured so a guest that fails to come back after the
# campaign reboot can be diagnosed instead of guessed at.
# shellcheck disable=SC2086
qemu-system-x86_64 -name "$VM_NAME" -machine type=q35,accel=kvm -cpu host -smp 2 -m 6144 \
  -drive file="$DISK",if=virtio,format=qcow2 -drive file="$SEED_ISO",if=virtio,media=cdrom \
  -netdev user,id=net0,hostfwd=tcp::$SSH_PORT-:22 -device virtio-net-pci,netdev=net0 \
  -display none -serial "file:$WORK/console.log" -daemonize -pidfile "$PIDFILE"
ssh_vm() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p "$SSH_PORT" tester@127.0.0.1 "$@"; }
# Protected evidence backup. An external wipe of target/ already destroyed one
# campaign's raw evidence, so every run copies its evidence out of the mutable
# checkout before teardown. The copy is staged inside the backup root and moved
# into place with an atomic rename, so a half-written backup is never visible,
# and an earlier run's backup is never overwritten.
BACKUP_ROOT="${O3K_PP4_EVIDENCE_BACKUP-$HOME/pp4-evidence-backup}"
BACKED_UP=0
backup_evidence() {
  (( BACKED_UP == 0 )) || return 0
  [[ -d "$EVID" ]] || return 0
  [[ -n "$(ls -A "$EVID" 2>/dev/null)" ]] || return 0
  mkdir -p "$BACKUP_ROOT"
  local name staging
  name="$(basename "$EVID")"
  [[ -e "$BACKUP_ROOT/$name" ]] && name="$name.$(date -u +%Y%m%dT%H%M%SZ)"
  staging="$(mktemp -d "$BACKUP_ROOT/.incoming.XXXXXX")" || return 0
  if cp -a "$EVID/." "$staging/" 2>/dev/null; then
    printf 'release=%s\nsource_sha=%s\nharness_sha=%s\ndistro=%s\ncampaign_status=%s\nevidence_dir=%s\nbacked_up_at=%s\n' \
      "$VERSION" "$EXPECTED_SHA" "$HARNESS_SHA" "$DISTRO" "${CAMPAIGN_STATUS:-incomplete}" \
      "$EVID" "$(date -u +%FT%TZ)" >"$staging/evidence-identity.txt" 2>/dev/null || true
    if mv -T "$staging" "$BACKUP_ROOT/$name" 2>/dev/null; then
      BACKED_UP=1
      echo "PP4 evidence backed up: $BACKUP_ROOT/$name" >&2
      return 0
    fi
  fi
  rm -rf "$staging"
  echo 'PP4 evidence backup failed; raw evidence left in the checkout' >&2
}
cleanup() {
  if [[ -f "$WORK/console.log" && -d "$EVID" ]]; then
    cp -f -- "$WORK/console.log" "$EVID/guest-console.log" 2>/dev/null || true
  fi
  backup_evidence
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
  "$(dirname "$0")/in-vm-core-acceptance.sh" "$(dirname "$0")/horizon-witness.sh" \
  "$(dirname "$0")/in-vm-core-post.sh" "$(dirname "$0")/generate_core_manifest.py" \
  "$(dirname "$0")/verify_manifest.py" tester@127.0.0.1:/home/tester/
ssh_vm 'chmod 0755 /home/tester/in-vm-native-smoke.sh /home/tester/in-vm-core-acceptance.sh /home/tester/in-vm-core-post.sh /home/tester/native_client.py /home/tester/horizon-witness.sh /home/tester/generate_core_manifest.py'
ssh_vm "curl -sfL https://github.com/o3kio/o3k/releases/download/$VERSION/install.sh | sudo env O3K_SKIP_ARAF=1 sh -" 2>&1 | tee "$EVID/install-output.log"
ssh_vm "sudo python3 /home/tester/verify_manifest.py '$VERSION' '$EXPECTED_SHA'"
ssh_vm 'mkdir -p /home/tester/pp4-evidence'
set +e
ssh_vm "O3K_PP4_VERSION='$VERSION' O3K_PP4_SOURCE_SHA='$EXPECTED_SHA' O3K_PP4_HARNESS_SHA='$HARNESS_SHA' bash /home/tester/in-vm-core-acceptance.sh /home/tester/pp4-evidence /home/tester/native_client.py '$DISTRO' > /home/tester/core-acceptance.log 2>&1"
smoke_status=$?
set -e
if (( smoke_status == 0 )); then
  # The reboot is performed by the host driver so a dropped SSH session is
  # expected and cannot be confused with a product failure.  `sudo reboot`
  # returns immediately while sshd lingers for a few seconds, so the guest must
  # be observed going down AND coming back with a different boot id: otherwise
  # the gate is vacuous and the delayed shutdown kills the post-reboot phases.
  ssh_vm 'cat /proc/sys/kernel/random/boot_id' >"$EVID/boot-id-before-reboot.txt" 2>/dev/null || smoke_status=1
  ssh_vm 'sudo reboot' >/dev/null 2>&1 || true
  went_down=0
  for _attempt in $(seq 1 60); do
    if ! ssh_vm true 2>/dev/null; then went_down=1; break; fi
    sleep 2
  done
  (( went_down == 1 )) || { echo 'guest never became unreachable during the reboot' >&2; smoke_status=1; }
  came_back=0
  for _attempt in $(seq 1 120); do
    if ssh_vm true 2>/dev/null; then came_back=1; break; fi
    sleep 3
  done
  (( came_back == 1 )) || { echo 'SSH did not return after the host reboot' >&2; smoke_status=1; }
  if (( smoke_status == 0 )); then
    ssh_vm 'cat /proc/sys/kernel/random/boot_id' >"$EVID/boot-id-after-reboot.txt" 2>/dev/null || smoke_status=1
  fi
  if (( smoke_status == 0 )); then
    if cmp -s "$EVID/boot-id-before-reboot.txt" "$EVID/boot-id-after-reboot.txt"; then
      echo 'host reboot not proven: guest boot id is unchanged' >&2
      smoke_status=1
    else
      echo 'host reboot verified: guest boot id changed'
    fi
  fi
  if (( smoke_status == 0 )); then
    set +e
    ssh_vm "O3K_PP4_VERSION='$VERSION' O3K_PP4_SOURCE_SHA='$EXPECTED_SHA' O3K_PP4_HARNESS_SHA='$HARNESS_SHA' bash /home/tester/in-vm-core-post.sh /home/tester/pp4-evidence /home/tester/native_client.py '$DISTRO' >> /home/tester/core-acceptance.log 2>&1"
    smoke_status=$?
    set -e
  fi
fi
set +e
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$SSH_PORT" \
  tester@127.0.0.1:/home/tester/core-acceptance.log "$EVID/core-acceptance.log" >/dev/null 2>&1
log_copy_status=$?
if (( log_copy_status != 0 )); then
  # Preserve a diagnostic even when the guest SSH service drops during a
  # provider action; this keeps a harness failure distinct from product
  # evidence and lets the outer campaign report the actual transport state.
  printf 'core acceptance log unavailable (scp status=%s, status=%s)\n' "$log_copy_status" "$smoke_status" >"$EVID/core-acceptance.log"
fi
set -e
cat "$EVID/core-acceptance.log"
# Preserve the in-guest evidence directory on failure too, so a harness or
# product failure is diagnosed from the recorded observations rather than a
# two-line stdout tail.
set +e
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$SSH_PORT" -r \
  tester@127.0.0.1:/home/tester/pp4-evidence/. "$EVID/" >/dev/null 2>&1
set -e
((smoke_status == 0)) || { CAMPAIGN_STATUS=FAILED; exit "$smoke_status"; }
CAMPAIGN_STATUS=PASS
printf 'release=%s\nsource_sha=%s\nharness_sha=%s\ndistro=%s\ncampaign_status=PASS\n' "$VERSION" "$EXPECTED_SHA" "$HARNESS_SHA" "$DISTRO" >"$EVID/campaign.env"
# Back up before the teardown trap tears the run down, so a later wipe of the
# checkout cannot take the only copy of a passed campaign with it.
backup_evidence
echo "PP4 CORE CAMPAIGN PASS: $DISTRO"
