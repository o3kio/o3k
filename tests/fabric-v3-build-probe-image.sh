#!/usr/bin/env bash
set -Eeuo pipefail

# Build a deterministic acceptance guest from the pinned CirrOS 0.6.3 image.
# CirrOS keeps its root filesystem in the initramfs, so the recipe explicitly
# injects the campaign key and Dropbear policy there. No tenant IPv4 address
# or route is written into the image.

BASE_IMAGE="${1:?usage: $0 CIRROS_BASE_IMAGE PROBE_PUBLIC_KEY OUTPUT_IMAGE EVIDENCE_DIR}"
PROBE_PUBLIC_KEY="${2:?missing acceptance public key}"
OUTPUT_IMAGE="${3:?missing output image}"
EVIDENCE_DIR="${4:?missing evidence directory}"
EXPECTED_BASE_SHA=7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b
MAX_PUBLIC_UPLOAD_BYTES=$((64 * 1024 * 1024))
SOURCE_DATE_EPOCH=1727395200

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
for tool in qemu-img guestfish virt-ls lsinitramfs gzip cpio sha256sum chroot; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
[[ -r "$BASE_IMAGE" && -r "$PROBE_PUBLIC_KEY" ]] || { echo "base image or public key unreadable" >&2; exit 2; }
[[ ! -e "$OUTPUT_IMAGE" && ! -L "$OUTPUT_IMAGE" ]] || { echo "probe output already exists: $OUTPUT_IMAGE" >&2; exit 2; }
[[ -d "$EVIDENCE_DIR" ]] || { echo "evidence directory missing" >&2; exit 2; }
printf '%s  %s\n' "$EXPECTED_BASE_SHA" "$BASE_IMAGE" | sha256sum --check --status \
  || { echo "pinned CirrOS image checksum mismatch" >&2; exit 1; }
grep -Eq '^ssh-ed25519 [A-Za-z0-9+/=]+( .*)?$' "$PROBE_PUBLIC_KEY" \
  || { echo "acceptance key must be one Ed25519 public key" >&2; exit 1; }

WORK_DIR="$(mktemp -d "$EVIDENCE_DIR/.probe-recipe.XXXXXX")"
cleanup() { rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT
mkdir -m 0700 "$WORK_DIR/rootfs"

qemu-img convert -c -O qcow2 "$BASE_IMAGE" "$OUTPUT_IMAGE" \
  >"$EVIDENCE_DIR/probe-image-convert.log" 2>&1
INITRD_NAME="$(virt-ls -a "$OUTPUT_IMAGE" -m /dev/sda1 /boot \
  | awk '/^initrd\.img-[[:alnum:]._-]+$/ { print; exit }')"
[[ -n "$INITRD_NAME" ]] || { echo "pinned CirrOS initramfs not found" >&2; exit 1; }
INITRD_IN="$WORK_DIR/initrd.img"
guestfish --ro -a "$OUTPUT_IMAGE" <<EOF >"$EVIDENCE_DIR/probe-image-extract.log"
run
mount-ro /dev/sda1 /
download /boot/$INITRD_NAME $INITRD_IN
EOF

(
  cd "$WORK_DIR/rootfs"
  gzip -dc "$INITRD_IN" | cpio --extract --make-directories --preserve-modification-time --no-absolute-filenames \
    >"$EVIDENCE_DIR/probe-image-unpack.log" 2>&1
)

[[ -x "$WORK_DIR/rootfs/usr/sbin/dropbear" ]] || { echo "CirrOS Dropbear binary missing" >&2; exit 1; }
[[ -x "$WORK_DIR/rootfs/sbin/ip" && -x "$WORK_DIR/rootfs/bin/ping" && -x "$WORK_DIR/rootfs/usr/bin/nc" ]] \
  || { echo "CirrOS networking test tools missing" >&2; exit 1; }
grep -q '^cirros:x:1000:1000:' "$WORK_DIR/rootfs/etc/passwd" \
  || { echo "expected acceptance account cirros (uid 1000) missing" >&2; exit 1; }
[[ -L "$WORK_DIR/rootfs/etc/rc3.d/S40-network" \
   && -L "$WORK_DIR/rootfs/etc/rc3.d/S50-dropbear" \
   && -e "$WORK_DIR/rootfs/etc/rc3.d/S45-cirros-net-ds" ]] \
  || { echo "expected CirrOS network data-source and Dropbear boot entries missing" >&2; exit 1; }
# CirrOS can wait for metadata in S45-cirros-net-ds. Start the existing
# Dropbear service after S40 network setup and before that optional lookup so
# host-local IPv6 link-local control does not depend on a metadata endpoint.
mv "$WORK_DIR/rootfs/etc/rc3.d/S50-dropbear" "$WORK_DIR/rootfs/etc/rc3.d/S42-dropbear"
[[ -L "$WORK_DIR/rootfs/etc/rc3.d/S42-dropbear" \
   && ! -e "$WORK_DIR/rootfs/etc/rc3.d/S50-dropbear" ]] \
  || { echo "could not position Dropbear before the CirrOS metadata probe" >&2; exit 1; }

install -d -o 1000 -g 1000 -m 0700 "$WORK_DIR/rootfs/home/cirros/.ssh"
install -o 1000 -g 1000 -m 0600 "$PROBE_PUBLIC_KEY" "$WORK_DIR/rootfs/home/cirros/.ssh/authorized_keys"
install -d -m 0755 "$WORK_DIR/rootfs/etc/default"
cat >"$WORK_DIR/rootfs/etc/default/dropbear" <<'EOF'
# Acceptance-only policy: key authentication, non-root user, IPv6 listener.
DROPBEAR_ARGS="-s -w -p [::]:22"
EOF
chmod 0644 "$WORK_DIR/rootfs/etc/default/dropbear"

# Normalize initramfs mtimes and archive order. cpio's --reproducible also
# zeros inode/device metadata. The per-campaign authorized key is intentionally
# part of the image; the final image checksum is recorded for every run.
find "$WORK_DIR/rootfs" -depth -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(
  cd "$WORK_DIR/rootfs"
  find . -print0 | LC_ALL=C sort -z \
    | cpio --null --create --format=newc --owner=0:0 --reproducible \
    | gzip -n -9 >"$WORK_DIR/initrd.probe.img"
)
guestfish --rw -a "$OUTPUT_IMAGE" <<EOF >"$EVIDENCE_DIR/probe-image-install.log"
run
mount /dev/sda1 /
upload $WORK_DIR/initrd.probe.img /boot/$INITRD_NAME
sync
EOF

# Validate the generated archive and the exact policy/key material before it
# enters the supported image API. Image service upload limit is 64 MiB.
gzip -dc "$WORK_DIR/initrd.probe.img" | cpio --list --quiet >"$EVIDENCE_DIR/probe-image-files.txt"
grep -Fxq 'etc/default/dropbear' "$EVIDENCE_DIR/probe-image-files.txt"
grep -Fxq 'home/cirros/.ssh/authorized_keys' "$EVIDENCE_DIR/probe-image-files.txt"
grep -Fxq 'usr/sbin/dropbear' "$EVIDENCE_DIR/probe-image-files.txt"
[[ "$(stat -c %s "$OUTPUT_IMAGE")" -lt "$MAX_PUBLIC_UPLOAD_BYTES" ]] \
  || { echo "probe image exceeds supported 64 MiB public image upload limit" >&2; exit 1; }

{
  qemu-img --version | head -1
  guestfish --version
  virt-ls --version
  cpio --version | head -1
  gzip --version | head -1
  chroot "$WORK_DIR/rootfs" /usr/sbin/dropbear -V
  printf 'source=https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img\n'
  printf 'source_sha256=%s\n' "$EXPECTED_BASE_SHA"
  printf 'source_date_epoch=%s\n' "$SOURCE_DATE_EPOCH"
  printf 'dropbear_start_order=S42-after-S40-network-before-S45-cirros-net-ds\n'
  printf 'max_public_upload_bytes=%s\n' "$MAX_PUBLIC_UPLOAD_BYTES"
  stat -c 'probe_image_bytes=%s' "$OUTPUT_IMAGE"
  sha256sum "$BASE_IMAGE" "$OUTPUT_IMAGE" "$PROBE_PUBLIC_KEY"
} >"$EVIDENCE_DIR/probe-image-toolchain-and-sha256.txt"
