#!/usr/bin/env bash
set -Eeuo pipefail

# Build the Fabric acceptance workload image from the pinned host Ubuntu cloud
# image. No packages are installed from a moving repository during the build.
# The recipe configures only an acceptance account, SSH and the interface name;
# tenant addresses and routes remain DHCP/kernel generated.

BASE_IMAGE="${1:?usage: $0 BASE_IMAGE PROBE_PUBLIC_KEY OUTPUT_IMAGE EVIDENCE_DIR}"
PROBE_PUBLIC_KEY="${2:?missing acceptance public key}"
OUTPUT_IMAGE="${3:?missing output image}"
EVIDENCE_DIR="${4:?missing evidence directory}"
EXPECTED_BASE_SHA=612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
for tool in qemu-img virt-customize virt-inspector sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
[[ -r "$BASE_IMAGE" && -r "$PROBE_PUBLIC_KEY" ]] || { echo "base image or public key unreadable" >&2; exit 2; }
[[ ! -e "$OUTPUT_IMAGE" && ! -L "$OUTPUT_IMAGE" ]] || { echo "probe output already exists: $OUTPUT_IMAGE" >&2; exit 2; }
[[ -d "$EVIDENCE_DIR" ]] || { echo "evidence directory missing" >&2; exit 2; }
printf '%s  %s\n' "$EXPECTED_BASE_SHA" "$BASE_IMAGE" | sha256sum --check --status \
  || { echo "pinned probe base image checksum mismatch" >&2; exit 1; }

RECIPE_DIR="$(mktemp -d "$EVIDENCE_DIR/.probe-recipe.XXXXXX")"
cleanup() {
  local item
  for item in "$RECIPE_DIR/sshd.conf" "$RECIPE_DIR/cloud-init.cfg"; do
    [[ ! -e "$item" ]] || rm -f -- "$item"
  done
  rmdir -- "$RECIPE_DIR"
}
trap cleanup EXIT

cat >"$RECIPE_DIR/sshd.conf" <<'EOF'
AddressFamily any
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers ubuntu
EOF
cat >"$RECIPE_DIR/cloud-init.cfg" <<'EOF'
ssh_deletekeys: true
ssh_genkeytypes: [ed25519]
EOF

qemu-img convert -c -O qcow2 "$BASE_IMAGE" "$OUTPUT_IMAGE" \
  >"$EVIDENCE_DIR/probe-image-convert.log" 2>&1
virt-customize -a "$OUTPUT_IMAGE" \
  --run-command 'useradd --create-home --shell /bin/bash --groups sudo ubuntu && passwd --lock ubuntu' \
  --ssh-inject "ubuntu:file:$PROBE_PUBLIC_KEY" \
  --upload "$RECIPE_DIR/sshd.conf:/etc/ssh/sshd_config.d/60-o3k-fabric-probe.conf" \
  --upload "$RECIPE_DIR/cloud-init.cfg:/etc/cloud/cloud.cfg.d/99-o3k-fabric-probe.cfg" \
  --run-command 'chmod 0644 /etc/ssh/sshd_config.d/60-o3k-fabric-probe.conf /etc/cloud/cloud.cfg.d/99-o3k-fabric-probe.cfg' \
  --run-command 'systemctl enable ssh' \
  --run-command 'printf "%s\\n" "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash net.ifnames=0 biosdevname=0\"" >/etc/default/grub.d/99-o3k-fabric-probe.cfg && update-grub' \
  --run-command 'cloud-init clean --logs --machine-id' \
  >"$EVIDENCE_DIR/probe-image-build.log" 2>&1

virt-inspector -a "$OUTPUT_IMAGE" >"$EVIDENCE_DIR/probe-image-inspector.xml"
python3 - "$EVIDENCE_DIR/probe-image-inspector.xml" "$EVIDENCE_DIR/probe-image-packages.json" <<'PY'
import json,sys,xml.etree.ElementTree as ET
root=ET.parse(sys.argv[1]).getroot()
required={"cloud-init","iproute2","iputils-ping","netcat-openbsd","openssh-server"}
found={}
for app in root.findall(".//application"):
    name=app.findtext("name")
    if name in required:
        epoch=app.findtext("epoch")
        version=app.findtext("version") or ""
        release=app.findtext("release") or ""
        found[name]="".join((epoch+":" if epoch and epoch!="0" else "",version,"-"+release if release else ""))
missing=required-set(found)
if missing:
    raise SystemExit("probe base lacks required packages: "+", ".join(sorted(missing)))
json.dump(found,open(sys.argv[2],"w"),sort_keys=True,indent=2)
print(file=open(sys.argv[2],"a"))
PY

virt-customize -a "$OUTPUT_IMAGE" --run-command \
  'test -x /usr/sbin/sshd && install -d -m 0755 /run/sshd && ssh-keygen -q -t ed25519 -N "" -f /tmp/o3k-probe-validation-key && sshd -T -h /tmp/o3k-probe-validation-key | grep -q "^addressfamily any$" && sshd -T -h /tmp/o3k-probe-validation-key | grep -q "^pubkeyauthentication yes$" && sshd -T -h /tmp/o3k-probe-validation-key | grep -q "^passwordauthentication no$" && test -x /usr/bin/ip && test -x /usr/bin/ping && test -x /usr/bin/nc && grep -E "^[[:space:]]*linux[[:space:]].*net.ifnames=0.*biosdevname=0" /boot/grub/grub.cfg && rm -f /tmp/o3k-probe-validation-key /tmp/o3k-probe-validation-key.pub' \
  >"$EVIDENCE_DIR/probe-image-validation.log" 2>&1

{
  qemu-img --version | head -1
  virt-customize --version
  virt-inspector --version
  ssh -V 2>&1 | head -1
  printf 'guest openssh-server: %s\n' "$(python3 -c 'import json; print(json.load(open("'"$EVIDENCE_DIR"'/probe-image-packages.json"))["openssh-server"])')"
  sha256sum "$BASE_IMAGE" "$OUTPUT_IMAGE" "$PROBE_PUBLIC_KEY"
} >"$EVIDENCE_DIR/probe-image-toolchain-and-sha256.txt"
