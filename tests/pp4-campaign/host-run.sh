#!/usr/bin/env bash
# PP.4 campaign — HOST runner (o3kio/o3k#973).
#
# Provisions a fresh nested-KVM VM (no repo, no bundle) and drives:
#   phase1a (in-vm): foreign canaries -> exact public one-liner -> success
#                    output + T0-T3/T5 stamps -> canonical state -> guest boot
#                    proof -> curl OIDC verify
#   ui target (host):  creates `pp4-ui-target` through the UNMODIFIED OpenStack
#                    CLI inside the VM (a canonical native resource the console
#                    lists) so the tenant journey has a real resource to delete
#   browser (host):  Chromium INSIDE the VM (demo CA imported into its NSS
#                    profile) driven by Playwright over CDP from the host:
#                    tenant journey (login -> scope -> catalog -> capacity ->
#                    images/networks/servers by canonical id -> console VM
#                    create fails truthfully -> console delete of the
#                    CLI-created server -> logout) + operator journey.
#                    Emits PP4-TIMESTAMPS T4 + PP4-GAP lines + PP4-UI-DELETE id.
#   phase1b (in-vm): cross-interface scenarios A-D (openstack CLI <-> Araf
#                    native BFF on identical canonical IDs), classified-gap
#                    probes, OpenTofu smoke, secret scans, optional Horizon
#                    witness (O3K_PP4_HORIZON=1)
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
# Absolute from here on: the browser specs run with tests/pp4-browser-e2e as
# their working directory, so relative evidence paths would resolve wrongly.
EVID="$(cd "$EVID" && pwd)"
EVID_FINAL="$EVID/evidence-final"
# A previous run's files must not survive into this campaign's manifest: the
# manifest hashes every file in this directory, so stale evidence from an
# earlier (failed) run would be recorded as if this run produced it.
rm -rf "$EVID_FINAL"
mkdir -p "$EVID_FINAL"
# The installer timestamp ledger is authoritative for T0..T3/T5, while later
# demo reinstall/purge steps are allowed to rewrite files in the VM evidence
# directory.  Keep an immutable host-side copy for final manifest assembly.
TIMESTAMP_SNAPSHOT="$EVID/pp4-install-timestamps.snapshot"

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
  if [ "${O3K_PP4_KEEP_VM:-0}" = 1 ]; then
    log "O3K_PP4_KEEP_VM=1: leaving the VM running for harness iteration (SSH port $SSH_PORT)"
    return 0
  fi
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
    BASE_URL="https://cloud-images.ubuntu.com/noble/20260911/noble-server-cloudimg-amd64.img"
    BASE_DIGEST_ALG="sha256"
    BASE_DIGEST="612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354"
    if [ ! -f "$BASE" ]; then
      curl -fL --retry 3 -o "$BASE" "$BASE_URL"
    fi
    ;;
  debian)
    BASE="$WORK/debian-12-genericcloud-amd64.qcow2"
    BASE_URL="https://cloud.debian.org/images/cloud/bookworm/20260909-2596/debian-12-genericcloud-amd64-20260909-2596.qcow2"
    BASE_DIGEST_ALG="sha512"
    BASE_DIGEST="08fea112563461f251f3c95a5c5cf8cb25eb60f74cec03e85a97ff91d3efef3059d35837598bbb476008f20db6d3bdc7143c5f2f2a9a6da394a0acc601fd5986"
    if [ ! -f "$BASE" ]; then
      curl -fL --retry 3 -o "$BASE" "$BASE_URL"
    fi
    ;;
esac

printf '%s\n' \
  "distro=$DISTRO" \
  "url=$BASE_URL" \
  "digest_algorithm=$BASE_DIGEST_ALG" \
  "digest=$BASE_DIGEST" > "$EVID_FINAL/00-base-image.txt"
if ! printf '%s  %s\n' "$BASE_DIGEST" "$BASE" | "${BASE_DIGEST_ALG}sum" -c - >/dev/null; then
  echo "base image digest mismatch for $BASE_URL" >&2
  exit 1
fi

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
scp "${SCP_OPTS[@]}" -r "$SCRIPT_DIR/tofu" tester@localhost:/home/tester/pp4-tofu/project >/dev/null \
  || { echo "could not stage OpenTofu project" >&2; exit 1; }
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
ssh_vm "mkdir -p $VM_BROWSER"
scp "${SCP_OPTS[@]}" "$WORK/chrome-headless-shell.tgz" tester@localhost:"$VM_BROWSER/chrome.tgz" >/dev/null \
  || { echo "could not stage chromium cache" >&2; exit 1; }
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
# The phase script writes the installer ledger as root.  On a failed installer
# run it may not exist, so collect diagnostics before attempting the staged
# timestamp copy; this keeps the failure evidence actionable instead of
# masking it with a secondary `cp: cannot stat` error.
if ssh_vm "sudo test -f $VM_EVID/03-timestamps.env"; then
  ssh_vm "sudo cp $VM_EVID/03-timestamps.env $VM_SCRIPTS/03-timestamps.env && sudo chmod 0644 $VM_SCRIPTS/03-timestamps.env"
  # The root-owned ledger is unreadable to the tester account during recursive
  # scp.  Temporarily remove only that staged path, pull the rest fail-closed,
  # then restore it for the browser/phase1b handoff below.
  ssh_vm "sudo rm -f $VM_EVID/03-timestamps.env"
  scp "${SCP_OPTS[@]}" -r tester@localhost:"$VM_EVID/." "$EVID_FINAL/" \
    || { echo "could not pull phase1a evidence" >&2; exit 1; }
  scp "${SCP_OPTS[@]}" tester@localhost:"$VM_SCRIPTS/03-timestamps.env" "$EVID_FINAL/03-timestamps.env" >/dev/null
  ssh_vm "sudo cp $VM_SCRIPTS/03-timestamps.env $VM_EVID/03-timestamps.env && sudo chown root:root $VM_EVID/03-timestamps.env && rm -f $VM_SCRIPTS/03-timestamps.env"
else
  ssh_vm "sudo tar -C '$VM_EVID' -cf - ." | tar -xf - -C "$EVID_FINAL" \
    || { echo "could not pull failed phase1a evidence" >&2; exit 1; }
fi
if ! grep -Fq 'PHASE1A-COMPLETE status=passed' <<<"$P1A_MARKER"; then
  echo "phase1a failed: ${P1A_MARKER:-no marker}" >&2
  ssh_vm 'sudo tail -100 /var/log/o3k/*.log 2>/dev/null; sudo journalctl -u o3kd --no-pager -n 60; sudo docker ps -a; sudo docker compose -p o3k-araf-demo logs --tail 60 2>/dev/null' >"$EVID_FINAL/phase1a-diagnostics.log" 2>&1 || true
  exit 1
fi
# Snapshot the validated installer ledger before browser/phase2 evidence can
# overwrite the mutable VM-side copy.
cp "$EVID_FINAL/03-timestamps.env" "$TIMESTAMP_SNAPSHOT"
log "phase1a complete"

# ---- console-ui target + TestLab ids (unmodified OpenStack CLI inside the VM) -----
# The only real UI mutation this pinned tuple supports is the advertised delete
# action on an EXISTING canonical resource: the pinned Araf SPA cannot submit
# any create form (the create schemas O3K serves declare JSON Schema 2020-12
# while the pinned schema-runtime compiles with draft-07 Ajv; the upstream fix,
# Araf PR #118, is not in this release tuple). The harness therefore creates the
# delete target itself through the UNMODIFIED OpenStack CLI: a CLI-created
# server is a canonical native resource (same uuid) and appears in the console.
# Every id is resolved inside the VM and every lookup fails closed.
vm_openstack_id_by_name() { # TYPE(image|network|flavor) NAME
  local type="$1" name="$2"
  ssh_vm "sudo bash -c 'set -e; . /etc/o3k/admin-openrc; openstack ${type} list -f json'" 2>/dev/null \
    | python3 -c 'import json,sys
items = json.load(sys.stdin)
for item in items:
    if item.get("Name") == sys.argv[1]:
        print(item["ID"])
        break' "$name" || true
}
PP4_ADMIN_PROJECT_ID="eba29e2d-53de-461d-ae91-ede7402713cb"
# The pinned demo tuple advertises no flavor collection, so the console create
# form can only work with the canonical flavor id the installer recorded in the
# root-owned VM ledger. The demo image and network exist ONLY through the
# compatibility APIs (the native image/network inventories are empty), so their
# canonical ids come from the unmodified OpenStack CLI inside the VM. All are
# mandatory: an empty value would let the journey silently degrade.
PP4_FLAVOR_ID="$(ssh_vm 'sudo cat /etc/o3k/testlab-flavor-id' 2>/dev/null | tr -d '[:space:]')"
[ -n "$PP4_FLAVOR_ID" ] || { echo "could not read /etc/o3k/testlab-flavor-id in the VM" >&2; exit 1; }
PP4_IMAGE_ID="$(vm_openstack_id_by_name image cirros-0.6.3)"
[ -n "$PP4_IMAGE_ID" ] || { echo "could not resolve the cirros image id via the VM OpenStack CLI" >&2; exit 1; }
PP4_NETWORK_ID="$(vm_openstack_id_by_name network testlab-network)"
[ -n "$PP4_NETWORK_ID" ] || { echo "could not resolve the testlab-network id via the VM OpenStack CLI" >&2; exit 1; }
[ -n "$PP4_ADMIN_PROJECT_ID" ] || { echo "PP4_ADMIN_PROJECT_ID is empty" >&2; exit 1; }
# `openstack server create --flavor` takes the flavor id the CLI reports.
UI_TARGET_FLAVOR_ID="$(vm_openstack_id_by_name flavor testlab-flavor)"
[ -n "$UI_TARGET_FLAVOR_ID" ] || { echo "could not resolve the testlab-flavor id via the VM OpenStack CLI" >&2; exit 1; }
log "ui target: creating pp4-ui-target through the unmodified OpenStack CLI"
ssh_vm "sudo bash -c 'set -e; . /etc/o3k/admin-openrc; openstack server create --wait --image ${PP4_IMAGE_ID} --flavor ${UI_TARGET_FLAVOR_ID} --nic net-id=${PP4_NETWORK_ID} --config-drive true --key-name testlab-keypair pp4-ui-target'" \
  > "$EVID_FINAL/04b-ui-target-create.log" 2>&1 \
  || { echo "could not create pp4-ui-target through the VM OpenStack CLI (see 04b-ui-target-create.log)" >&2; exit 1; }
PP4_UI_TARGET_ID="$(ssh_vm 'sudo bash -c ". /etc/o3k/admin-openrc; openstack server show pp4-ui-target -c id -f value"' 2>/dev/null | tr -d '[:space:]')"
[ -n "$PP4_UI_TARGET_ID" ] || { echo "pp4-ui-target has no canonical id (openstack server show pp4-ui-target)" >&2; exit 1; }
log "ui target: pp4-ui-target id=$PP4_UI_TARGET_ID"
export PP4_FLAVOR_ID PP4_ADMIN_PROJECT_ID PP4_IMAGE_ID PP4_NETWORK_ID PP4_UI_TARGET_ID

# ---- browser e2e (host playwright -> in-VM chromium over CDP) ---------------------
log "browser: starting in-VM chromium"
# The in-VM chromium validates TLS against the VM trust store, so the demo CA
# must be installed as a system trust anchor before the journey runs (an NSS
# import into the browser profile is not consulted by chrome-headless-shell).
# Without this every page load fails with ERR_CERT_AUTHORITY_INVALID.
install_vm_demo_ca() {
  ssh_vm 'sudo install -m 0644 /var/lib/o3k/araf-demo/tls/ca.crt \
      /usr/local/share/ca-certificates/o3k-demo-ca.crt && sudo update-ca-certificates >/dev/null' \
    || { echo "could not install the demo CA into the VM trust store" >&2; exit 1; }
}
install_vm_demo_ca
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
# Deployment-side production-tuple evidence (phase1a) that the browser suite
# re-checks server-side, so a fixture-mode deployment cannot pass on the DOM alone.
PP4_DEPLOYMENT_ENV_FILE="$EVID_FINAL/10-araf-production-tuple.txt"
[ -f "$PP4_DEPLOYMENT_ENV_FILE" ] || { echo "missing $PP4_DEPLOYMENT_ENV_FILE from phase1a" >&2; exit 1; }
export PP4_DEPLOYMENT_ENV_FILE
mkdir -p "$EVID_FINAL/browser"

log "browser: tenant + operator journeys"
set +e
(cd "$REPO/tests/pp4-browser-e2e" && \
  CDP_URL="http://127.0.0.1:$CDP_PORT" \
  TENANT_URL="https://tenant.o3k.demo" OPERATOR_URL="https://operator.o3k.demo" \
  PP4_ALICE_USER=alice PP4_ALICE_PASSWORD="$ALICE_PW" \
  PP4_FLAVOR_ID="$PP4_FLAVOR_ID" PP4_ADMIN_PROJECT_ID="$PP4_ADMIN_PROJECT_ID" \
  PP4_IMAGE_ID="$PP4_IMAGE_ID" PP4_NETWORK_ID="$PP4_NETWORK_ID" \
  PP4_UI_TARGET_ID="$PP4_UI_TARGET_ID" \
  PP4_DEPLOYMENT_ENV_FILE="$PP4_DEPLOYMENT_ENV_FILE" \
  PP4_EVIDENCE_DIR="$EVID_FINAL/browser" \
  npx playwright test --no-deps specs/tenant.spec.ts) \
  2>&1 | tee "$EVID_FINAL/05-browser-e2e.log"
BROWSER_RC=$?
(cd "$REPO/tests/pp4-browser-e2e" && \
  CDP_URL="http://127.0.0.1:$CDP_PORT" \
  TENANT_URL="https://tenant.o3k.demo" OPERATOR_URL="https://operator.o3k.demo" \
  PP4_ALICE_USER=alice PP4_ALICE_PASSWORD="$ALICE_PW" \
  PP4_FLAVOR_ID="$PP4_FLAVOR_ID" PP4_ADMIN_PROJECT_ID="$PP4_ADMIN_PROJECT_ID" \
  PP4_IMAGE_ID="$PP4_IMAGE_ID" PP4_NETWORK_ID="$PP4_NETWORK_ID" \
  PP4_UI_TARGET_ID="$PP4_UI_TARGET_ID" \
  PP4_DEPLOYMENT_ENV_FILE="$PP4_DEPLOYMENT_ENV_FILE" \
  PP4_EVIDENCE_DIR="$EVID_FINAL/browser" \
  npx playwright test --no-deps specs/operator.spec.ts) \
  2>&1 | tee -a "$EVID_FINAL/05-browser-e2e.log"
OPERATOR_RC=$?
set -e
[ "$OPERATOR_RC" -eq 0 ] || BROWSER_RC=$OPERATOR_RC
# A UI fallback means the mutation was NOT performed through the browser
# journey, so the campaign's real-browser claim does not hold: fail loudly and
# keep the fallback logs for diagnosis.
if grep -q 'PP4-UI-FALLBACK' "$EVID_FINAL/05-browser-e2e.log"; then
  grep -oE 'PP4-UI-FALLBACK [a-z-]+' "$EVID_FINAL/05-browser-e2e.log" | sort -u >&2
  echo "browser journey used a UI fallback: the real-browser claim is not met (see 05-browser-e2e.log)" >&2
  exit 1
fi
T4="$(grep -oE 'PP4-TIMESTAMPS T4=[0-9]+' "$EVID_FINAL/05-browser-e2e.log" | head -1 | cut -d= -f2 || true)"
[ -n "$T4" ] || { echo "browser phase produced no PP4-TIMESTAMPS T4 marker" >&2; exit 1; }
printf 'T4=%s\n' "$T4" >> "$EVID_FINAL/03-timestamps.env"
# The tenant journey's only real UI mutation on this pinned tuple is the delete
# of the CLI-created server through its advertised action; phase1b proves the
# cross-interface absence from this id. No console CREATE is claimed: the pinned
# SPA cannot compile the 2020-12 create schemas O3K serves.
UI_DELETE_ID="$(grep -oE 'PP4-UI-DELETE id=[a-f0-9-]+' "$EVID_FINAL/05-browser-e2e.log" | head -1 | cut -d= -f2 || true)"
[ -n "$UI_DELETE_ID" ] || { echo "browser journey produced no PP4-UI-DELETE id" >&2; exit 1; }
[ "$UI_DELETE_ID" = "$PP4_UI_TARGET_ID" ] \
  || { echo "the console deleted $UI_DELETE_ID, not the harness target $PP4_UI_TARGET_ID" >&2; exit 1; }
printf 'PP4_UI_DELETE_ID=%s\n' "$UI_DELETE_ID" > "$EVID_FINAL/05-browser-ids.env"
if [ "$BROWSER_RC" -ne 0 ]; then
  scp "${SCP_OPTS[@]}" -r tester@localhost:"$VM_EVID/." "$EVID_FINAL/" \
    || { echo "could not pull browser-failure evidence" >&2; exit 1; }
  echo "browser e2e FAILED (rc $BROWSER_RC)" >&2; exit 1
fi
grep -q 'PP4-TENANT-OK' "$EVID_FINAL/05-browser-e2e.log" || { echo "tenant journey missing PP4-TENANT-OK" >&2; exit 1; }
grep -q 'PP4-OPERATOR-OK' "$EVID_FINAL/05-browser-e2e.log" || { echo "operator journey missing PP4-OPERATOR-OK" >&2; exit 1; }
log "browser e2e complete (T4=$T4)"

# push host-side browser ids + log into the VM evidence for phase1b.  Keep the
# installer-owned timestamp ledger in place; replacing it with the host-side
# T4-only file would destroy T0..T3/T5 before the durable manifest is built.
# (05-browser-e2e.log is a SEC1 scan target inside the VM; 05-browser-ids.env
# carries the browser-created resource id for the cross-interface deletion
# check). The in-VM evidence dir is root-owned (the phase scripts run as root),
# so the files are copied into the tester-owned staging dir first and moved
# into place with sudo.
scp "${SCP_OPTS[@]}" "$EVID_FINAL/05-browser-ids.env" \
  "$EVID_FINAL/05-browser-e2e.log" tester@localhost:"$VM_SCRIPTS/" >/dev/null 2>&1 \
  || { echo "could not push browser evidence into the VM" >&2; exit 1; }
ssh_vm "sudo mv -f $VM_SCRIPTS/05-browser-ids.env $VM_SCRIPTS/05-browser-e2e.log $VM_EVID/ && sudo sh -c 'printf \"T4=%s\\n\" \"$T4\" >> \"$VM_EVID/03-timestamps.env\"' && sudo chown root:root $VM_EVID/05-browser-ids.env $VM_EVID/03-timestamps.env $VM_EVID/05-browser-e2e.log" \
  || { echo "could not install browser evidence into the VM evidence dir" >&2; exit 1; }

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
# Phase1b writes a few diagnostic traces as root (notably the OpenTofu
# compatibility trace).  Stream the directory through sudo tar so evidence
# transfer does not depend on an unprivileged tester being able to read every
# file, while retaining the fail-closed transfer check.
ssh_vm "sudo tar -C '$VM_EVID' -cf - ." \
  | tar -xf - -C "$EVID_FINAL" \
  || { echo "could not pull phase1b evidence" >&2; exit 1; }
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

# ---- post-reboot readiness gate -----------------------------------------------------
# The demo stack restarts with the host (restart: unless-stopped) and the IdP
# needs ~a minute: a login attempt before the stack is ready answers 401
# (truthfully, the upstream IdP is not there yet). Wait for readiness first.
log "waiting for the demo stack to become ready after the reboot"
# The demo stack (Keycloak + two BFFs + four nginx containers) restarts with
# the host; the measured recovery window is recorded as evidence. Sharing the
# host with a second campaign VM pushed recovery beyond 8 minutes, so the
# bound is 20.
STACK_READY=0
STACK_WAIT_START="$(date +%s)"
STACK_READY_AT=""
for i in $(seq 1 240); do
  if ssh_vm 'sudo -n curl -sf --cacert /var/lib/o3k/araf-demo/tls/ca.crt https://idp.o3k.demo/demo-healthz >/dev/null 2>&1 \
      && curl -sf http://127.0.0.1:8080/readyz >/dev/null 2>&1 \
      && curl -sf http://127.0.0.1:8081/readyz >/dev/null 2>&1 \
      && curl -sf http://127.0.0.1:18080/readyz >/dev/null 2>&1' 2>/dev/null; then
    STACK_READY=1
    STACK_READY_AT="$(date +%s)"
    break
  fi
  if [ $((i % 12)) -eq 0 ]; then
    printf -- '--- %s (elapsed %ss)\n' "$(date -u +%H:%M:%SZ)" "$(( $(date +%s) - STACK_WAIT_START ))" \
      >>"$EVID_FINAL/23b-post-reboot-stack-timeline.txt"
    ssh_vm 'sudo docker ps -a --format "{{.Names}} {{.Status}}"' \
      >>"$EVID_FINAL/23b-post-reboot-stack-timeline.txt" 2>&1 || true
  fi
  sleep 5
done
if [ "$STACK_READY" = 1 ]; then
  printf 'demo_stack_recovery_seconds=%s\n' "$((STACK_READY_AT - STACK_WAIT_START))" \
    > "$EVID_FINAL/23c-post-reboot-recovery.txt"
  log "demo stack ready after the reboot in $((STACK_READY_AT - STACK_WAIT_START))s (O3K + IdP + both BFFs)"
else
  ssh_vm 'sudo docker ps -a --format "{{.Names}} {{.Status}}"; sudo docker logs o3k-araf-demo-idp-1 2>&1 | tail -20' \
    >"$EVID_FINAL/23b-post-reboot-stack-timeout.txt" 2>&1 || true
  echo "the demo stack did not become ready within 20 minutes of the reboot" >&2
  exit 1
fi

# ---- browser relogin (post-reboot recovery) ----------------------------------------
log "browser: post-reboot relogin"
# The VM reboot killed the SSH port-forward, so the CDP tunnel must be
# re-established (and verified) before the relogin journey runs.
if [ -n "${CDP_FWD_PID:-}" ]; then kill "$CDP_FWD_PID" 2>/dev/null || true; CDP_FWD_PID=""; fi
install_vm_demo_ca
ssh_vm "sudo rm -f $VM_EVID/browser-ready"
ssh_vm "sudo nohup bash $VM_SCRIPTS/in-vm-browser.sh $VM_BROWSER $VM_EVID \
  >$VM_EVID/browser-console.log 2>&1 </dev/null &"
for i in $(seq 1 60); do
  sleep 5
  [ "$(ssh_vm "sudo cat $VM_EVID/browser-ready 2>/dev/null" 2>/dev/null || true)" = "ready" ] && break
done
[ "$(ssh_vm "sudo cat $VM_EVID/browser-ready 2>/dev/null" 2>/dev/null || true)" = "ready" ] \
  || { echo "in-VM chromium did not restart after the reboot; see browser-console.log" >&2; exit 1; }
ssh -N -L "$CDP_PORT:127.0.0.1:9223" "${SSH_OPTS[@]}" tester@localhost &
CDP_FWD_PID=$!
for i in $(seq 1 30); do curl -sf "http://127.0.0.1:$CDP_PORT/json/version" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "http://127.0.0.1:$CDP_PORT/json/version" >/dev/null \
  || { echo "CDP forward did not come back after the reboot" >&2; exit 1; }
set +e
(cd "$REPO/tests/pp4-browser-e2e" && \
  CDP_URL="http://127.0.0.1:$CDP_PORT" \
  TENANT_URL="https://tenant.o3k.demo" OPERATOR_URL="https://operator.o3k.demo" \
  PP4_ALICE_USER=alice PP4_ALICE_PASSWORD="$ALICE_PW" \
  PP4_FLAVOR_ID="$PP4_FLAVOR_ID" PP4_ADMIN_PROJECT_ID="$PP4_ADMIN_PROJECT_ID" \
  PP4_IMAGE_ID="$PP4_IMAGE_ID" PP4_NETWORK_ID="$PP4_NETWORK_ID" \
  PP4_UI_TARGET_ID="$PP4_UI_TARGET_ID" \
  PP4_DEPLOYMENT_ENV_FILE="$PP4_DEPLOYMENT_ENV_FILE" \
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
# Phase2 also emits root-owned ledgers/traces.  Use the same privileged tar
# stream as phase1b so the final recovery evidence is complete and transfer is
# still fail-closed on either SSH or extraction failure.
ssh_vm "sudo tar -C '$VM_EVID' -cf - ." \
  | tar -xf - -C "$EVID_FINAL" \
  || { echo "could not pull phase2 evidence" >&2; exit 1; }
if ! grep -Fq 'PHASE2-COMPLETE status=passed' <<<"$P2_MARKER"; then
  echo "phase2 failed: ${P2_MARKER:-no marker}" >&2
  ssh_vm 'sudo tail -60 /var/log/o3k/*.log 2>/dev/null; sudo docker ps -a; sudo journalctl -u o3kd --no-pager -n 60' >"$EVID_FINAL/phase2-diagnostics.log" 2>&1 || true
  exit 1
fi
log "phase2 complete"

# Restore the installer ledger and add the browser timestamp.  This is done
# after the final VM evidence copy because the convergence/purge matrix may
# replace 03-timestamps.env with a phase-local file.
cp "$TIMESTAMP_SNAPSHOT" "$EVID_FINAL/03-timestamps.env"
printf 'T4=%s\n' "$T4" >> "$EVID_FINAL/03-timestamps.env"

# The phase2 evidence copy is authoritative for the final VM-side evidence and
# can replace the phase1b identity ledger.  Re-attach the host-created browser
# target only after that copy, so all three canonical IDs survive into the
# durable manifest.
printf 'pp4-ui-target %s\n' "$PP4_UI_TARGET_ID" >> "$EVID_FINAL/14-scenarioA-identity.txt"

# ---- durable manifest ----------------------------------------------------------------
log "assembling durable manifest"
# A non-PASS manifest is written to disk (as evidence) and fails the campaign:
# the manifest only reports PASS when the numbered evidence supports it.
if ! python3 "$SCRIPT_DIR/make-manifest.py" "$DISTRO" "$EVID_FINAL" "$VERSION" "$SOURCE_SHA" \
     > "$EVID_FINAL/99-manifest.json"; then
  echo "durable manifest is not PASS: see $EVID_FINAL/99-manifest.json (failures on stderr)" >&2
  exit 1
fi
python3 - "$EVID_FINAL/99-manifest.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"[pp4] manifest result={doc['result']} cases={len(doc['test_cases'])}")
PY
log "PP4 campaign COMPLETE: $EVID_FINAL"
