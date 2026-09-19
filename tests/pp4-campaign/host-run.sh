#!/usr/bin/env bash
# PP.4 campaign — HOST runner (o3kio/o3k#973).
#
# Provisions a fresh nested-KVM VM (no repo, no bundle) and drives:
#   phase1a (in-vm): foreign canaries -> exact public one-liner -> success
#                    output + T0-T3/T5 stamps -> canonical state -> guest boot
#                    proof -> curl OIDC verify
#   browser (host):  Chromium INSIDE the VM (demo CA imported into its NSS
#                    profile) driven by Playwright over CDP from the host:
#                    tenant journey (login -> scope -> catalog -> capacity ->
#                    images/networks/servers -> create pp4-native -> operation
#                    -> action -> delete -> logout) + operator journey.
#                    Emits PP4-TIMESTAMPS T4 + PP4-NATIVE id.
#   phase1b (in-vm): cross-interface scenarios A-D (openstack CLI <-> Araf
#                    native BFF on identical canonical IDs), OpenTofu smoke,
#                    secret scans, optional Horizon witness (O3K_PP4_HORIZON=1)
#   reboot:          host reboot recovery gate (new boot_id)
#   browser relogin: post-reboot OIDC/session recovery
#   phase2 (in-vm):  convergence rerun, failure/recovery matrix, interrupted
#                    deployment, uninstall/reinstall, purge/reinstall,
#                    foreign canaries, final scans
#
# Usage: bash host-run.sh <ubuntu|debian> <evidence-dir>
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
DISTRO="${1:?usage: host-run.sh <ubuntu|debian> [evidence-dir]}"
EVID="${2:-$REPO/target/pp4-campaign/$DISTRO}"
VERSION="${O3K_CAMPAIGN_VERSION:?set O3K_CAMPAIGN_VERSION (e.g. v0.4.0-rc.6)}"
SOURCE_SHA="${O3K_CAMPAIGN_SOURCE_SHA:-$(git -C "$REPO" rev-parse HEAD)}"
WORK="$REPO/target/pp4-campaign/vms"
SSH_KEY="$WORK/id_ed25519"
mkdir -p "$WORK" "$EVID"
EVID_FINAL="$EVID/evidence-final"
mkdir -p "$EVID_FINAL"

case "$DISTRO" in
  ubuntu) SSH_PORT="${O3K_CAMPAIGN_SSH_PORT:-2322}"; CDP_PORT="${O3K_CAMPAIGN_CDP_PORT:-9223}" ;;
  debian) SSH_PORT="${O3K_CAMPAIGN_SSH_PORT:-2324}"; CDP_PORT="${O3K_CAMPAIGN_CDP_PORT:-9225}" ;;
  *) echo "unsupported distro: $DISTRO" >&2; exit 2 ;;
esac
VM_NAME="pp4-${DISTRO}"
VM_EVID="/home/tester/pp4-evidence"
VM_SCRIPTS="/home/tester/pp4-campaign"
VM_BROWSER="/home/tester/pp4-browser"
CHROME_CACHE="$HOME/.cache/ms-playwright/chromium_headless_shell-1243"

[ -f "$SSH_KEY" ] || ssh-keygen -t ed25519 -f "$SSH_KEY" -N '' -C "pp4" >/dev/null
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 -o ServerAliveInterval=15 -p "$SSH_PORT")
SCP_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P "$SSH_PORT")

log() { echo "[$(date -u +%H:%M:%SZ)] $*"; }

cleanup() {
  log "cleanup"
  [ -n "${CDP_FWD_PID:-}" ] && kill "$CDP_FWD_PID" 2>/dev/null || true
  if [ -f "$WORK/${VM_NAME}.pid" ]; then
    kill "$(cat "$WORK/${VM_NAME}.pid")" 2>/dev/null || true
  fi
  sleep 3
  rm -f "$WORK/${VM_NAME}.qcow2" "$WORK/${VM_NAME}-seed.iso" "$WORK/${VM_NAME}.pid"
  rm -rf "$WORK/seed-${VM_NAME}"
  log "cleanup done"
}
trap cleanup EXIT

case "$DISTRO" in
  ubuntu)
    BASE="/root/noble-server-cloudimg-amd64.img"
    if [ ! -f "$BASE" ]; then
      curl -L --retry 3 -o "$BASE" https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
    fi
    ;;
  debian)
    BASE="$WORK/debian-12-genericcloud-amd64.qcow2"
    if [ ! -f "$BASE" ]; then
      curl -L --retry 3 -o "$BASE" https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2
    fi
    ;;
esac

# ---- provision the fresh VM ----------------------------------------------------
DISK="$WORK/${VM_NAME}.qcow2"
SEED_DIR="$WORK/seed-${VM_NAME}"
SEED_ISO="$WORK/${VM_NAME}-seed.iso"
rm -f "$DISK" "$SEED_ISO"
qemu-img create -f qcow2 -b "$BASE" -F qcow2 "$DISK" 20G
mkdir -p "$SEED_DIR"
cat > "$SEED_DIR/user-data" <<EOF
#cloud-config
hostname: ${VM_NAME}
users:
  - name: tester
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "${SSH_KEY}.pub")
ssh_pwauth: false
package_update: true
package_upgrade: false
packages:
  - curl
  - ca-certificates
runcmd:
  - echo "tester ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/tester
  - chmod 0440 /etc/sudoers.d/tester
EOF
printf 'instance-id: %s-%s\nlocal-hostname: %s\n' "$VM_NAME" "$(date +%s)" "$VM_NAME" > "$SEED_DIR/meta-data"
genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock \
  "$SEED_DIR/user-data" "$SEED_DIR/meta-data" >/dev/null

qemu-system-x86_64 \
  -name "$VM_NAME" \
  -machine type=q35,accel=kvm \
  -cpu host \
  -smp 2 \
  -m 6144 \
  -drive file="$DISK",if=virtio,format=qcow2 \
  -drive file="$SEED_ISO",if=virtio,media=cdrom \
  -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
  -device virtio-net-pci,netdev=net0 \
  -display none -daemonize -pidfile "$WORK/${VM_NAME}.pid"
log "VM ${VM_NAME} launched"

ssh_vm() { ssh "${SSH_OPTS[@]}" tester@localhost "$@"; }

for i in $(seq 1 90); do
  if ssh_vm true 2>/dev/null; then log "SSH up"; break; fi
  sleep 5
done
ssh_vm true || { echo "SSH never came up" >&2; exit 1; }
ssh_vm 'sudo timeout 600 cloud-init status --wait' 2>/dev/null || true
log "nested KVM inside VM: $(ssh_vm 'ls /dev/kvm >/dev/null 2>&1 && echo present || echo ABSENT')"
BOOT_ID_BEFORE="$(ssh_vm 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)"
[ -n "$BOOT_ID_BEFORE" ] || { echo "could not read pre-reboot boot_id" >&2; exit 1; }
printf '%s\n' "$BOOT_ID_BEFORE" > "$EVID_FINAL/boot-id-before.txt"

# ---- stage scripts + chromium into the VM ---------------------------------------
ssh_vm "mkdir -p $VM_SCRIPTS $VM_EVID $VM_BROWSER /home/tester/pp4-tofu"
scp "${SCP_OPTS[@]}" "$SCRIPT_DIR"/in-vm-*.sh tester@localhost:"$VM_SCRIPTS/" >/dev/null
scp "${SCP_OPTS[@]}" -r "$SCRIPT_DIR/tofu" tester@localhost:/home/tester/pp4-tofu/project >/dev/null 2>&1 || true
# OpenTofu 1.12.6 (pinned + digest-verified; supplemental IaC witness)
TOOLING="$REPO/target/pp4-campaign/tooling"
mkdir -p "$TOOLING"
TOFU_TGZ="$TOOLING/tofu_1.12.6_linux_amd64.tar.gz"
if [ ! -f "$TOFU_TGZ" ]; then
  curl -fL --retry 3 -o "$TOFU_TGZ" https://github.com/opentofu/opentofu/releases/download/v1.12.6/tofu_1.12.6_linux_amd64.tar.gz
fi
echo '50a6106fa4de523d09c87af85f3db1dd47535fc005727fdca6852146476b88ec  tofu_1.12.6_linux_amd64.tar.gz' \
  | (cd "$TOOLING" && sha256sum -c - >/dev/null) || { echo "tofu archive digest mismatch" >&2; exit 1; }
scp "${SCP_OPTS[@]}" "$TOFU_TGZ" tester@localhost:/home/tester/pp4-tofu/tofu.tgz >/dev/null
ssh_vm "cd /home/tester/pp4-tofu && tar xzf tofu.tgz && chmod +x tofu && rm -f tofu.tgz"
if [ -d "$CHROME_CACHE" ] && [ ! -f "$WORK/chrome-headless-shell.tgz" ]; then
  tar -C "$CHROME_CACHE" -czf "$WORK/chrome-headless-shell.tgz" .
fi
[ -f "$WORK/chrome-headless-shell.tgz" ] || { echo "missing chromium cache at $CHROME_CACHE" >&2; exit 1; }
scp "${SCP_OPTS[@]}" "$WORK/chrome-headless-shell.tgz" tester@localhost:"$VM_BROWSER/chrome.tgz" >/dev/null
ssh_vm "cd $VM_BROWSER && tar xzf chrome.tgz && mv chrome-headless-shell-linux64 chrome 2>/dev/null || true"

# ---- phase 1a: canaries -> one-liner -> core asserts ------------------------------
log "phase1a: one-liner install ($VERSION)"
ssh_vm "sudo rm -f $VM_EVID/phase1a-done"
ssh_vm "sudo nohup env O3K_CAMPAIGN_VERSION=$VERSION bash $VM_SCRIPTS/in-vm-phase1a.sh $DISTRO $VM_EVID $SOURCE_SHA \
  >$VM_EVID/phase1a-console.log 2>&1 </dev/null &"
P1A_MARKER=""
for i in $(seq 1 240); do
  sleep 10
  P1A_MARKER="$(ssh_vm "sudo cat $VM_EVID/phase1a-done 2>/dev/null" 2>/dev/null || true)"
  [ -n "$P1A_MARKER" ] && break
done
log "phase1a poll: ${P1A_MARKER:-<none>}"
scp "${SCP_OPTS[@]}" -r tester@localhost:"$VM_EVID/." "$EVID_FINAL/" 2>/dev/null || true
if ! grep -Fq 'PHASE1A-COMPLETE status=passed' <<<"$P1A_MARKER"; then
  echo "phase1a failed: ${P1A_MARKER:-no marker}" >&2
  ssh_vm 'sudo tail -100 /var/log/o3k/*.log 2>/dev/null; sudo journalctl -u o3kd --no-pager -n 60; sudo docker ps -a; sudo docker compose -p o3k-araf-demo logs --tail 60 2>/dev/null' >"$EVID_FINAL/phase1a-diagnostics.log" 2>&1 || true
  exit 1
fi
log "phase1a complete"

# ---- browser e2e (host playwright -> in-VM chromium over CDP) ---------------------
log "browser: starting in-VM chromium"
ssh_vm "sudo rm -f $VM_EVID/browser-ready"
ssh_vm "sudo nohup bash $VM_SCRIPTS/in-vm-browser.sh $VM_BROWSER $VM_EVID \
  >$VM_EVID/browser-console.log 2>&1 </dev/null &"
for i in $(seq 1 60); do
  sleep 5
  [ "$(ssh_vm "sudo cat $VM_EVID/browser-ready 2>/dev/null" 2>/dev/null || true)" = "ready" ] && break
done
[ "$(ssh_vm "sudo cat $VM_EVID/browser-ready 2>/dev/null" 2>/dev/null || true)" = "ready" ] \
  || { echo "in-VM chromium did not start; see browser-console.log" >&2; exit 1; }
ssh -N -L "$CDP_PORT:127.0.0.1:9223" "${SSH_OPTS[@]}" tester@localhost &
CDP_FWD_PID=$!
for i in $(seq 1 30); do curl -sf "http://127.0.0.1:$CDP_PORT/json/version" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "http://127.0.0.1:$CDP_PORT/json/version" >/dev/null || { echo "CDP forward failed" >&2; exit 1; }

log "browser: installing host test deps"
if [ ! -d "$REPO/tests/pp4-browser-e2e/node_modules" ]; then
  (cd "$REPO/tests/pp4-browser-e2e" && npm ci --no-audit --no-fund)
fi
ALICE_PW="$(ssh_vm 'sudo awk -F": " "/^password:/{print \$2}" /var/lib/o3k/araf-demo/credentials.txt' 2>/dev/null || true)"
[ -n "$ALICE_PW" ] || { echo "could not read demo credentials file" >&2; exit 1; }
mkdir -p "$EVID_FINAL/browser"

log "browser: tenant + operator journeys"
set +e
(cd "$REPO/tests/pp4-browser-e2e" && \
  CDP_URL="http://127.0.0.1:$CDP_PORT" \
  PP4_ALICE_USER=alice PP4_ALICE_PASSWORD="$ALICE_PW" \
  PP4_EVIDENCE_DIR="$EVID_FINAL/browser" \
  npx playwright test --no-deps specs/tenant.spec.ts) \
  2>&1 | tee "$EVID_FINAL/05-browser-e2e.log"
BROWSER_RC=$?
(cd "$REPO/tests/pp4-browser-e2e" && \
  CDP_URL="http://127.0.0.1:$CDP_PORT" \
  PP4_ALICE_USER=alice PP4_ALICE_PASSWORD="$ALICE_PW" \
  PP4_EVIDENCE_DIR="$EVID_FINAL/browser" \
  npx playwright test --no-deps specs/operator.spec.ts) \
  2>&1 | tee -a "$EVID_FINAL/05-browser-e2e.log"
OPERATOR_RC=$?
set -e
[ "$OPERATOR_RC" -eq 0 ] || BROWSER_RC=$OPERATOR_RC
T4="$(grep -oE 'PP4-TIMESTAMPS T4=[0-9]+' "$EVID_FINAL/05-browser-e2e.log" | head -1 | cut -d= -f2 || true)"
[ -n "$T4" ] && printf 'T4=%s\n' "$T4" >> "$EVID_FINAL/03-timestamps.env"
grep -oE 'PP4-NATIVE id=[a-f0-9-]+' "$EVID_FINAL/05-browser-e2e.log" | head -1 | sed 's/PP4-NATIVE id=//' \
  > "$EVID_FINAL/05-browser-ids.env" || true
if [ "$BROWSER_RC" -ne 0 ]; then
  scp "${SCP_OPTS[@]}" -r tester@localhost:"$VM_EVID/." "$EVID_FINAL/" 2>/dev/null || true
  echo "browser e2e FAILED (rc $BROWSER_RC)" >&2; exit 1
fi
grep -q 'PP4-TENANT-OK' "$EVID_FINAL/05-browser-e2e.log" || { echo "tenant journey missing PP4-TENANT-OK" >&2; exit 1; }
grep -q 'PP4-OPERATOR-OK' "$EVID_FINAL/05-browser-e2e.log" || { echo "operator journey missing PP4-OPERATOR-OK" >&2; exit 1; }
log "browser e2e complete (T4=$T4)"

# push host-side browser ids into the VM evidence for phase1b
scp "${SCP_OPTS[@]}" "$EVID_FINAL/05-browser-ids.env" "$EVID_FINAL/03-timestamps.env" tester@localhost:"$VM_EVID/" >/dev/null 2>&1 || true

# ---- phase 1b: cross-interface scenarios, tofu smoke, scans, horizon ------------
log "phase1b: cross-interface + supplemental evidence"
ssh_vm "sudo rm -f $VM_EVID/phase1b-done"
HORIZON_ENV=""
[ "${O3K_PP4_HORIZON:-0}" = 1 ] && HORIZON_ENV="O3K_PP4_HORIZON=1"
ssh_vm "sudo nohup env O3K_CAMPAIGN_VERSION=$VERSION $HORIZON_ENV bash $VM_SCRIPTS/in-vm-phase1b.sh $DISTRO $VM_EVID $SOURCE_SHA \
  >$VM_EVID/phase1b-console.log 2>&1 </dev/null &"
P1B_MARKER=""
for i in $(seq 1 240); do
  sleep 10
  P1B_MARKER="$(ssh_vm "sudo cat $VM_EVID/phase1b-done 2>/dev/null" 2>/dev/null || true)"
  [ -n "$P1B_MARKER" ] && break
done
log "phase1b poll: ${P1B_MARKER:-<none>}"
scp "${SCP_OPTS[@]}" -r tester@localhost:"$VM_EVID/." "$EVID_FINAL/" 2>/dev/null || true
if ! grep -Fq 'PHASE1B-COMPLETE status=passed' <<<"$P1B_MARKER"; then
  echo "phase1b failed: ${P1B_MARKER:-no marker}" >&2
  ssh_vm 'sudo tail -60 /var/log/o3k/*.log 2>/dev/null; sudo docker ps -a' >"$EVID_FINAL/phase1b-diagnostics.log" 2>&1 || true
  exit 1
fi
log "phase1b complete"

# ---- host reboot ------------------------------------------------------------------
log "rebooting the VM (host reboot recovery gate)"
ssh_vm 'sudo reboot' 2>/dev/null || true
WENT_DOWN=0
for i in $(seq 1 24); do
  if ! ssh_vm true 2>/dev/null && ! ssh_vm true 2>/dev/null; then WENT_DOWN=1; break; fi
  sleep 5
done
[ "$WENT_DOWN" = 1 ] || { echo "VM never went down" >&2; exit 1; }
SSH_BACK=0
BOOT_ID_AFTER=""
for i in $(seq 1 180); do
  BOOT_ID_AFTER="$(ssh_vm 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)"
  if [ -n "$BOOT_ID_AFTER" ] && [ "$BOOT_ID_AFTER" != "$BOOT_ID_BEFORE" ]; then SSH_BACK=1; break; fi
  sleep 5
done
[ "$SSH_BACK" = 1 ] || { echo "VM never came back with a new boot_id" >&2; exit 1; }
printf '%s\n' "$BOOT_ID_AFTER" > "$EVID_FINAL/boot-id-after.txt"
log "VM back after reboot (boot_id changed)"

# ---- browser relogin (post-reboot recovery) ----------------------------------------
log "browser: post-reboot relogin"
ssh_vm "sudo rm -f $VM_EVID/browser-ready"
ssh_vm "sudo nohup bash $VM_SCRIPTS/in-vm-browser.sh $VM_BROWSER $VM_EVID \
  >$VM_EVID/browser-console.log 2>&1 </dev/null &"
for i in $(seq 1 60); do
  sleep 5
  [ "$(ssh_vm "sudo cat $VM_EVID/browser-ready 2>/dev/null" 2>/dev/null || true)" = "ready" ] && break
done
set +e
(cd "$REPO/tests/pp4-browser-e2e" && \
  CDP_URL="http://127.0.0.1:$CDP_PORT" \
  PP4_ALICE_USER=alice PP4_ALICE_PASSWORD="$ALICE_PW" \
  PP4_EVIDENCE_DIR="$EVID_FINAL/browser-relogin" \
  npx playwright test --no-deps specs/relogin.spec.ts) 2>&1 | tee "$EVID_FINAL/23-browser-relogin.log"
RELOGIN_RC=$?
set -e
[ "$RELOGIN_RC" -eq 0 ] && grep -q 'PP4-RELOGIN-OK' "$EVID_FINAL/23-browser-relogin.log" \
  || { echo "post-reboot browser relogin FAILED" >&2; exit 1; }
log "browser relogin OK"

# ---- phase 2: recovery, convergence, failure matrix, cleanup -----------------------
log "phase2: convergence + failure/recovery + cleanup"
ssh_vm "sudo rm -f $VM_EVID/phase2-done"
ssh_vm "sudo nohup env O3K_CAMPAIGN_VERSION=$VERSION bash $VM_SCRIPTS/in-vm-phase2.sh $DISTRO $VM_EVID $SOURCE_SHA \
  >$VM_EVID/phase2-console.log 2>&1 </dev/null &"
P2_MARKER=""
for i in $(seq 1 360); do
  sleep 10
  P2_MARKER="$(ssh_vm "sudo cat $VM_EVID/phase2-done 2>/dev/null" 2>/dev/null || true)"
  [ -n "$P2_MARKER" ] && break
done
log "phase2 poll: ${P2_MARKER:-<none>}"
scp "${SCP_OPTS[@]}" -r tester@localhost:"$VM_EVID/." "$EVID_FINAL/" 2>/dev/null || true
if ! grep -Fq 'PHASE2-COMPLETE status=passed' <<<"$P2_MARKER"; then
  echo "phase2 failed: ${P2_MARKER:-no marker}" >&2
  ssh_vm 'sudo tail -60 /var/log/o3k/*.log 2>/dev/null; sudo docker ps -a; sudo journalctl -u o3kd --no-pager -n 60' >"$EVID_FINAL/phase2-diagnostics.log" 2>&1 || true
  exit 1
fi
log "phase2 complete"

# ---- durable manifest ----------------------------------------------------------------
log "assembling durable manifest"
python3 "$SCRIPT_DIR/make-manifest.py" "$DISTRO" "$EVID_FINAL" "$VERSION" "$SOURCE_SHA" \
  | tee "$EVID_FINAL/99-manifest.json" >/dev/null
log "PP4 campaign COMPLETE: $EVID_FINAL"
