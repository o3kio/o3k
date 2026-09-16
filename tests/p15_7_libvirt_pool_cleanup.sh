#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-libvirt-pool.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
BIN_DIR="$WORK_DIR/bin"
STATE_DIR="$WORK_DIR/libvirt-state"
IMAGE_ROOT="$WORK_DIR/libvirt-images"
RUNNER_TEMP="$WORK_DIR/runner-temp"
mkdir -p "$BIN_DIR" "$STATE_DIR" "$IMAGE_ROOT" "$RUNNER_TEMP"

cat >"$BIN_DIR/virsh" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$1" == -c && "$2" == qemu:///system ]] || exit 90
shift 2
command="$1"
shift
case "$command" in
  pool-list)
    if [[ -f "$P15_7_FAKE_POOL_PRESENT" ]]; then
      cat "$P15_7_FAKE_POOL_NAME"
    fi
    ;;
  pool-define)
    cp -- "$1" "$P15_7_FAKE_POOL_XML"
    python3 - "$P15_7_FAKE_POOL_XML" >"$P15_7_FAKE_POOL_NAME" <<'PY'
import sys
import xml.etree.ElementTree as ET
print(ET.parse(sys.argv[1]).getroot().findtext("name"))
PY
    : >"$P15_7_FAKE_POOL_PRESENT"
    printf 'define\n' >>"$P15_7_FAKE_POOL_ACTIONS"
    ;;
  pool-dumpxml)
    cat "$P15_7_FAKE_POOL_XML"
    ;;
  pool-info)
    printf 'Name: %s\nState: %s\n' "$(cat "$P15_7_FAKE_POOL_NAME")" "$(cat "$P15_7_FAKE_POOL_STATE")"
    ;;
  pool-start)
    printf 'running\n' >"$P15_7_FAKE_POOL_STATE"
    printf 'start\n' >>"$P15_7_FAKE_POOL_ACTIONS"
    ;;
  pool-destroy)
    printf 'inactive\n' >"$P15_7_FAKE_POOL_STATE"
    printf 'destroy\n' >>"$P15_7_FAKE_POOL_ACTIONS"
    ;;
  pool-undefine)
    rm -f -- "$P15_7_FAKE_POOL_PRESENT"
    printf 'undefine\n' >>"$P15_7_FAKE_POOL_ACTIONS"
    ;;
  *) exit 91 ;;
esac
SH
chmod +x "$BIN_DIR/virsh"
export PATH="$BIN_DIR:$PATH"
export P15_7_FAKE_POOL_PRESENT="$STATE_DIR/present"
export P15_7_FAKE_POOL_NAME="$STATE_DIR/name"
export P15_7_FAKE_POOL_XML="$STATE_DIR/pool.xml"
export P15_7_FAKE_POOL_STATE="$STATE_DIR/state"
export P15_7_FAKE_POOL_ACTIONS="$STATE_DIR/actions"
export O3K_P15_7_LIBVIRT_IMAGE_ROOT="$IMAGE_ROOT"

pool_path="$IMAGE_ROOT/o3k-p15-7-12345"
bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" assert-absent 12345 "$pool_path"
bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" define 12345 "$pool_path"
grep -Fqx 'o3k-p15-7-journey-owned=12345' <(python3 -c 'import sys,xml.etree.ElementTree as e; print(e.parse(sys.argv[1]).getroot().findtext("description"))' "$P15_7_FAKE_POOL_XML")
bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" cleanup 12345 "$pool_path"
[[ ! -e "$P15_7_FAKE_POOL_PRESENT" ]]
grep -Fqx destroy "$P15_7_FAKE_POOL_ACTIONS"
grep -Fqx undefine "$P15_7_FAKE_POOL_ACTIONS"

# The prior failed diagnostic used this legacy filename. Its run marker plus
# exact pool name and target path authorize removing only that stale pool.
stale_run=35083047252
stale_image="$RUNNER_TEMP/cirros-0.6.3-p15-7-diagnostic-${stale_run}.abcdef"
stale_pool="o3k-p15-7-${stale_run}"
stale_path="$IMAGE_ROOT/$stale_pool"
touch "$stale_image"
printf 'o3k-disposable-image-v1\nrun=%s\nphase=generic\n' "$stale_run" >"$stale_image.o3k-owned"
cat >"$P15_7_FAKE_POOL_XML" <<XML
<pool type="dir">
  <name>${stale_pool}</name>
  <uuid>11111111-1111-4111-8111-111111111111</uuid>
  <capacity>0</capacity>
  <allocation>0</allocation>
  <available>0</available>
  <target><path>${stale_path}</path></target>
</pool>
XML
printf '%s\n' "$stale_pool" >"$P15_7_FAKE_POOL_NAME"
: >"$P15_7_FAKE_POOL_PRESENT"
printf 'running\n' >"$P15_7_FAKE_POOL_STATE"
: >"$P15_7_FAKE_POOL_ACTIONS"
bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" cleanup-stale-diagnostic-images "$RUNNER_TEMP"
[[ ! -e "$stale_image" && ! -e "$stale_image.o3k-owned" && ! -e "$P15_7_FAKE_POOL_PRESENT" ]]

# A matching name with a different target is foreign or ambiguous. Refuse to
# undefine it and retain the diagnostic image ownership record for review.
foreign_image="$RUNNER_TEMP/cirros-0.6.3-x86_64-disk.img.p15-7-diagnostic-7654321.abcdef"
foreign_run=7654321
foreign_pool="o3k-p15-7-${foreign_run}"
touch "$foreign_image"
printf 'o3k-disposable-image-v1\nrun=%s\nphase=generic\n' "$foreign_run" >"$foreign_image.o3k-owned"
cat >"$P15_7_FAKE_POOL_XML" <<XML
<pool type="dir">
  <name>${foreign_pool}</name>
  <target><path>${IMAGE_ROOT}/foreign</path></target>
</pool>
XML
printf '%s\n' "$foreign_pool" >"$P15_7_FAKE_POOL_NAME"
: >"$P15_7_FAKE_POOL_PRESENT"
printf 'running\n' >"$P15_7_FAKE_POOL_STATE"
: >"$P15_7_FAKE_POOL_ACTIONS"
if bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" cleanup-stale-diagnostic-images "$RUNNER_TEMP" 2>/dev/null; then
  echo "stale cleanup accepted a pool with a foreign target path" >&2
  exit 1
fi
[[ -e "$foreign_image" && -e "$foreign_image.o3k-owned" && -e "$P15_7_FAKE_POOL_PRESENT" ]]
if grep -Fq destroy "$P15_7_FAKE_POOL_ACTIONS"; then
  echo "stale cleanup destroyed an ambiguous pool" >&2
  exit 1
fi

echo "P15.7 libvirt pool ownership cleanup tests passed"
