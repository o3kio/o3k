#!/usr/bin/env bash
# Verify libvirt's actual QEMU identity can access a run-owned backing image
# and overlay, then prove libvirt can start a domain using that overlay.
# This is harness code; it does not modify product state.
set -Eeuo pipefail

BASE_IMAGE="${O3K_QEMU_PREFLIGHT_BASE_IMAGE:-/var/lib/libvirt/images/noble-server-cloudimg-amd64.img}"
RUN_ID="${O3K_QEMU_PREFLIGHT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || { echo "invalid run id" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
command -v virsh >/dev/null
command -v qemu-img >/dev/null
command -v setpriv >/dev/null
[[ -r "$BASE_IMAGE" ]] || { echo "base image is not readable: $BASE_IMAGE" >&2; exit 1; }

PREFIX="o3k-qemu-access-$RUN_ID"
IDENTITY_DOMAIN="$PREFIX-identity"
DISK_DOMAIN="$PREFIX-disk"
ROOT="/var/lib/libvirt/images/$PREFIX"
MARKER="$ROOT/.o3k-qemu-preflight-owned"
identity_xml="/run/$PREFIX-identity.xml"
disk_xml="/run/$PREFIX-disk.xml"
identity_pid=""
identity_created=0
disk_created=0
root_created=0
uid=""
gid=""
groups=""

fail() { echo "QEMU storage preflight: $*" >&2; exit 1; }
cleanup() {
  set +e
  if (( disk_created )); then
    virsh -c qemu:///system destroy "$DISK_DOMAIN" >/dev/null 2>&1
    virsh -c qemu:///system undefine "$DISK_DOMAIN" >/dev/null 2>&1
  fi
  if (( identity_created )); then
    virsh -c qemu:///system destroy "$IDENTITY_DOMAIN" >/dev/null 2>&1
    virsh -c qemu:///system undefine "$IDENTITY_DOMAIN" >/dev/null 2>&1
  fi
  rm -f -- "$identity_xml" "$disk_xml"
  if (( root_created )) && [[ -f "$MARKER" && ! -L "$MARKER" ]] \
    && grep -Fqx "run=$RUN_ID" "$MARKER"; then
    rm -f -- "$ROOT/overlay.qcow2" "$MARKER"
    rmdir -- "$ROOT" 2>/dev/null || true
  fi
}
trap cleanup EXIT

virsh -c qemu:///system dominfo "$IDENTITY_DOMAIN" >/dev/null 2>&1 && fail "identity domain collision"
virsh -c qemu:///system dominfo "$DISK_DOMAIN" >/dev/null 2>&1 && fail "disk domain collision"
[[ ! -e "$identity_xml" && ! -L "$identity_xml" ]] || fail "identity XML path collision"
[[ ! -e "$disk_xml" && ! -L "$disk_xml" ]] || fail "disk XML path collision"
[[ ! -e "$ROOT" ]] || fail "storage path collision: $ROOT"
mkdir -m 0711 -- "$ROOT"
root_created=1
printf 'o3k-qemu-preflight-v1\nrun=%s\nprefix=%s\n' "$RUN_ID" "$PREFIX" >"$MARKER"
chmod 0600 "$MARKER"

# Start a run-scoped diskless domain first and read the real QEMU process's
# credentials. This avoids assumptions about qemu.conf defaults or UID/GID.
cat >"$identity_xml" <<EOF
<domain type='kvm'>
  <name>$IDENTITY_DOMAIN</name><memory unit='MiB'>256</memory><vcpu>1</vcpu>
  <os><type arch='x86_64' machine='q35'>hvm</type></os>
  <features><acpi/><apic/></features><cpu mode='host-passthrough' check='none'/>
  <devices><emulator>/usr/bin/qemu-system-x86_64</emulator>
    <controller type='pci' model='pcie-root'/></devices>
</domain>
EOF
virsh -c qemu:///system create "$identity_xml" >/dev/null || fail "could not start identity probe domain"
identity_created=1
for _ in $(seq 1 50); do
  identity_pid="$(ps -ww -eo pid=,args= | awk -v n="$IDENTITY_DOMAIN" 'index($0,"-name guest=" n ",") {print $1}')"
  [[ -n "$identity_pid" ]] && break
  sleep 0.1
done
[[ -n "$identity_pid" ]] || fail "could not identify QEMU process for probe domain"
[[ "$identity_pid" != *$'\n'* ]] || fail "multiple QEMU processes match probe domain"
status="/proc/$identity_pid/status"
[[ -r "$status" ]] || fail "QEMU process exited during identity inspection"
uid="$(awk '/^Uid:/{print $3}' "$status")"
gid="$(awk '/^Gid:/{print $3}' "$status")"
groups="$(awk '/^Groups:/{for(i=2;i<=NF;i++) printf "%s%s", (i==2?"":","), $i}' "$status")"
[[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || fail "could not read QEMU effective UID/GID"
user_name="$(getent passwd "$uid" | cut -d: -f1)"
group_name="$(getent group "$gid" | cut -d: -f1)"
[[ -n "$user_name" && -n "$group_name" ]] || fail "QEMU UID/GID do not resolve through NSS"

# The root is run-owned and grants traversal only; files remain limited to the
# QEMU identity. The base image is a shared read-only input.
chown "$uid:$gid" "$ROOT"
chmod 0710 "$ROOT"
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$ROOT/overlay.qcow2" 1G >/dev/null
chown "$uid:$gid" "$ROOT/overlay.qcow2"
chmod 0600 "$ROOT/overlay.qcow2"

as_qemu() {
  if [[ -n "$groups" ]]; then
    setpriv --reuid "$uid" --regid "$gid" --groups "$groups" -- "$@"
  else
    setpriv --reuid "$uid" --regid "$gid" --clear-groups -- "$@"
  fi
}

as_qemu python3 - "$BASE_IMAGE" "$ROOT/overlay.qcow2" "$ROOT" <<'PY'
import os, sys
base, overlay, root = sys.argv[1:]
parts = []
path = os.path.abspath(root)
while path != os.path.dirname(path):
    parts.append(path)
    path = os.path.dirname(path)
parts.reverse()
for parent in parts:
    if not os.access(parent, os.X_OK):
        raise SystemExit(f"not traversable: {parent}")
if not os.access(base, os.R_OK):
    raise SystemExit(f"backing image not readable: {base}")
if not (os.access(overlay, os.R_OK) and os.access(overlay, os.W_OK)):
    raise SystemExit(f"overlay not readable/writable: {overlay}")
with open(overlay, "r+b") as f:
    f.seek(0, os.SEEK_END)
    f.flush()
PY

cat >"$disk_xml" <<EOF
<domain type='kvm'>
  <name>$DISK_DOMAIN</name><memory unit='MiB'>512</memory><vcpu>1</vcpu>
  <os><type arch='x86_64' machine='q35'>hvm</type></os>
  <features><acpi/><apic/></features><cpu mode='host-passthrough' check='none'/>
  <devices><emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'><driver name='qemu' type='qcow2'/>
      <source file='$ROOT/overlay.qcow2'/><target dev='vda' bus='virtio'/></disk>
    <controller type='pci' model='pcie-root'/></devices>
</domain>
EOF
virsh -c qemu:///system create "$disk_xml" >/dev/null || fail "libvirt/QEMU could not open run-owned overlay"
disk_created=1
state="$(virsh -c qemu:///system domstate "$DISK_DOMAIN" 2>/dev/null | tr -d '\r')"
[[ "$state" == running ]] || fail "disk probe domain did not remain running (state=$state)"

printf 'QEMU_IDENTITY uid=%s gid=%s user=%s group=%s supplementary_groups=%s\n' \
  "$uid" "$gid" "$user_name" "$group_name" "${groups:-none}"
printf 'RUN_ID=%s\n' "$RUN_ID"
printf 'PARENT_TRAVERSAL PASS\nBACKING_IMAGE_READ PASS\nOVERLAY_READ_WRITE PASS\nLIBVIRT_STORAGE_ACCESS PASS\n'
