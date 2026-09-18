#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-libvirt-pool.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
BIN_DIR="$WORK_DIR/bin"
STATE_DIR="$WORK_DIR/libvirt-states"
DOMAIN_DIR="$WORK_DIR/libvirt-domains"
IMAGE_ROOT="$WORK_DIR/libvirt-images"
RUNNER_TEMP="$WORK_DIR/runner-temp"
mkdir -p "$BIN_DIR" "$STATE_DIR" "$DOMAIN_DIR" "$IMAGE_ROOT" "$RUNNER_TEMP"

# Fake libvirt backed by directory state: one `name|path|state|autostart`
# file and one per-pool XML per pool, plus per-domain XML for the
# domain-attachment scan.
cat >"$BIN_DIR/virsh" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$1" == -c && "$2" == qemu:///system ]] || exit 90
shift 2
command="$1"
shift
case "$command" in
  pool-list)
    if [[ "${1:-}" == --details ]]; then
      for f in "$P15_7_FAKE_POOL_STATE_DIR"/*.pool; do
        [[ -e "$f" ]] || continue
        IFS='|' read -r n p st auto <"$f"
        printf ' %-20s %-10s %-10s %s\n' "$n" "$st" "${auto:-no}" "$p"
      done
      exit 0
    fi
    for f in "$P15_7_FAKE_POOL_STATE_DIR"/*.pool; do
      [[ -e "$f" ]] || continue
      name="${f##*/}"; name="${name%.pool}"
      printf '%s\n' "$name"
    done
    ;;
  pool-dumpxml)
    [[ -e "$P15_7_FAKE_POOL_STATE_DIR/$1.xml" ]] || { echo "pool not found" >&2; exit 1; }
    cat "$P15_7_FAKE_POOL_STATE_DIR/$1.xml"
    ;;
  pool-info)
    [[ -e "$P15_7_FAKE_POOL_STATE_DIR/$1.pool" ]] || { echo "pool not found" >&2; exit 1; }
    IFS='|' read -r n p st auto <"$P15_7_FAKE_POOL_STATE_DIR/$1.pool"
    printf 'Name: %s\nState: %s\nAutostart: %s\n' "$n" "$st" "${auto:-no}"
    ;;
  pool-define)
    python3 - "$1" "$P15_7_FAKE_POOL_STATE_DIR" <<'PY'
import shutil, sys
import xml.etree.ElementTree as ET
xmlfile, state_dir = sys.argv[1:]
pool = ET.parse(xmlfile).getroot()
name = pool.findtext("name")
path = pool.findtext("target/path")
with open(state_dir + "/" + name + ".pool", "w", encoding="utf-8") as f:
    f.write(name + "|" + path + "|inactive|no\n")
shutil.copyfile(xmlfile, state_dir + "/" + name + ".xml")
PY
    printf 'define %s\n' "$(python3 - "$1" <<'PY'
import sys
import xml.etree.ElementTree as ET
print(ET.parse(sys.argv[1]).getroot().findtext("name"))
PY
)" >>"$P15_7_FAKE_POOL_ACTIONS"
    ;;
  pool-start)
    [[ -e "$P15_7_FAKE_POOL_STATE_DIR/$1.pool" ]] || exit 1
    IFS='|' read -r n p st auto <"$P15_7_FAKE_POOL_STATE_DIR/$1.pool"
    printf '%s|%s|running|%s\n' "$n" "$p" "${auto:-no}" >"$P15_7_FAKE_POOL_STATE_DIR/$1.pool"
    printf 'start %s\n' "$1" >>"$P15_7_FAKE_POOL_ACTIONS"
    ;;
  pool-destroy)
    [[ -e "$P15_7_FAKE_POOL_STATE_DIR/$1.pool" ]] || exit 1
    IFS='|' read -r n p st auto <"$P15_7_FAKE_POOL_STATE_DIR/$1.pool"
    printf '%s|%s|inactive|%s\n' "$n" "$p" "${auto:-no}" >"$P15_7_FAKE_POOL_STATE_DIR/$1.pool"
    printf 'destroy %s\n' "$1" >>"$P15_7_FAKE_POOL_ACTIONS"
    ;;
  pool-undefine)
    rm -f -- "$P15_7_FAKE_POOL_STATE_DIR/$1.pool" "$P15_7_FAKE_POOL_STATE_DIR/$1.xml"
    printf 'undefine %s\n' "$1" >>"$P15_7_FAKE_POOL_ACTIONS"
    ;;
  list)
    for f in "$P15_7_FAKE_DOMAIN_STATE_DIR"/*.xml; do
      [[ -e "$f" ]] || continue
      name="${f##*/}"; name="${name%.xml}"
      printf '%s\n' "$name"
    done
    ;;
  dumpxml)
    [[ "$1" == --all ]] && exit 0
    [[ -e "$P15_7_FAKE_DOMAIN_STATE_DIR/$1.xml" ]] || { echo "domain not found" >&2; exit 1; }
    cat "$P15_7_FAKE_DOMAIN_STATE_DIR/$1.xml"
    ;;
  domblklist)
    [[ -e "$P15_7_FAKE_DOMAIN_STATE_DIR/$1.blk" ]] && cat "$P15_7_FAKE_DOMAIN_STATE_DIR/$1.blk"
    ;;
  *) exit 91 ;;
esac
SH
chmod +x "$BIN_DIR/virsh"
export PATH="$BIN_DIR:$PATH"
export P15_7_FAKE_POOL_STATE_DIR="$STATE_DIR"
export P15_7_FAKE_DOMAIN_STATE_DIR="$DOMAIN_DIR"
export P15_7_FAKE_POOL_ACTIONS="$STATE_DIR/actions"
export O3K_P15_7_LIBVIRT_IMAGE_ROOT="$IMAGE_ROOT"

reset_state() {
  set +e
  rm -rf -- "$STATE_DIR"/*.pool "$STATE_DIR"/*.xml "$DOMAIN_DIR"/* 2>/dev/null
  set -e
  : >"$P15_7_FAKE_POOL_ACTIONS"
}

make_pool() {
  local name="$1" path="$2" state="$3"
  printf '%s|%s|%s|no\n' "$name" "$path" "$state" >"$STATE_DIR/$name.pool"
  cat >"$STATE_DIR/$name.xml" <<XML
<pool type="dir">
  <name>${name}</name>
  <target><path>${path}</path></target>
</pool>
XML
}

make_marker() {
  local path="$1" run="$2" pool="$3"
  mkdir -p "$path"
  printf 'o3k-p15-7-pool-owned-v1\nrun=%s\npool=%s\npath=%s\nsource_sha=unknown\n' \
    "$run" "$pool" "$path" >"$path/.o3k-p15-7-pool-owned"
}

pool_present() {
  [[ -f "$STATE_DIR/$1.pool" ]]
}

sweep() {
  set +e
  SWEEP_OUT="$(bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" cleanup-stale-pools 2>&1)"
  SWEEP_RC=$?
  set -e
}

# --- existing single-run lifecycle: assert-absent/define/cleanup ----------
pool_path="$IMAGE_ROOT/o3k-p15-7-12345"
mkdir -p "$pool_path"
bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" assert-absent 12345 "$pool_path"
bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" define 12345 "$pool_path"
python3 - "$STATE_DIR/o3k-p15-7-12345.xml" "$pool_path" <<'PY'
import sys
import xml.etree.ElementTree as ET

pool = ET.parse(sys.argv[1]).getroot()
assert pool.findtext("name") == "o3k-p15-7-12345"
assert pool.get("type") == "dir"
assert pool.findtext("target/path") == sys.argv[2]
assert pool.find("description") is None
PY
# define now writes the durable pool ownership marker.
marker_file="$pool_path/.o3k-p15-7-pool-owned"
marker_lines="$(cat "$marker_file")"
[[ -f "$marker_file" && ! -L "$marker_file" ]]
grep -Fqx 'o3k-p15-7-pool-owned-v1' <<<"$marker_lines"
grep -Fqx 'run=12345' <<<"$marker_lines"
grep -Fqx 'pool=o3k-p15-7-12345' <<<"$marker_lines"
grep -Fqx "path=$pool_path" <<<"$marker_lines"
grep -Eq '^source_sha=(unknown|[0-9a-fA-F]{40})$' <<<"$marker_lines"
bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" cleanup 12345 "$pool_path"
! pool_present o3k-p15-7-12345
[[ ! -e "$marker_file" ]]
grep -Fqx 'destroy o3k-p15-7-12345' "$P15_7_FAKE_POOL_ACTIONS"
grep -Fqx 'undefine o3k-p15-7-12345' "$P15_7_FAKE_POOL_ACTIONS"

# --- existing stale-diagnostic-image path --------------------------------
# The prior failed diagnostic used this legacy filename. Its run marker plus
# exact pool name and target path authorize removing only that stale pool.
reset_state
stale_run=35083047252
stale_image="$RUNNER_TEMP/cirros-0.6.3-p15-7-diagnostic-${stale_run}.abcdef"
stale_pool="o3k-p15-7-${stale_run}"
stale_path="$IMAGE_ROOT/$stale_pool"
mkdir -p "$stale_path"
touch "$stale_image"
printf 'o3k-disposable-image-v1\nrun=%s\nphase=generic\n' "$stale_run" >"$stale_image.o3k-owned"
make_pool "$stale_pool" "$stale_path" running
bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" cleanup-stale-diagnostic-images "$RUNNER_TEMP"
[[ ! -e "$stale_image" && ! -e "$stale_image.o3k-owned" && ! -e "$STATE_DIR/$stale_pool.pool" ]]

# A matching name with a different target is foreign or ambiguous. Refuse to
# undefine it and retain the diagnostic image ownership record for review.
reset_state
foreign_image="$RUNNER_TEMP/cirros-0.6.3-x86_64-disk.img.p15-7-diagnostic-7654321.abcdef"
foreign_run=7654321
foreign_pool="o3k-p15-7-${foreign_run}"
touch "$foreign_image"
printf 'o3k-disposable-image-v1\nrun=%s\nphase=generic\n' "$foreign_run" >"$foreign_image.o3k-owned"
make_pool "$foreign_pool" "$IMAGE_ROOT/foreign" running
if bash "$ROOT_DIR/scripts/p15-7-libvirt-storage-pool.sh" cleanup-stale-diagnostic-images "$RUNNER_TEMP" 2>/dev/null; then
  echo "stale cleanup accepted a pool with a foreign target path" >&2
  exit 1
fi
[[ -e "$foreign_image" && -e "$foreign_image.o3k-owned" && -e "$STATE_DIR/$foreign_pool.pool" ]]
if grep -Fq "destroy $foreign_pool" "$P15_7_FAKE_POOL_ACTIONS"; then
  echo "stale cleanup destroyed an ambiguous pool" >&2
  exit 1
fi

# --- cleanup-stale-pools sweep -------------------------------------------

# marker-backed stale pool (inactive) -> reaped
reset_state
p1="o3k-p15-7-101"; p1path="$IMAGE_ROOT/$p1"; make_pool "$p1" "$p1path" inactive
make_marker "$p1path" 101 "$p1"
sweep
[[ "$SWEEP_RC" == 0 ]]
grep -Fq "REAPED $p1" <<<"$SWEEP_OUT"
! pool_present "$p1"
[[ ! -e "$p1path/.o3k-p15-7-pool-owned" ]]

# marker-backed active+autostart pool -> reaped (destroy + undefine)
reset_state
p2="o3k-p15-7-202"; p2path="$IMAGE_ROOT/$p2"; make_pool "$p2" "$p2path" running
make_marker "$p2path" 202 "$p2"
sweep
[[ "$SWEEP_RC" == 0 ]]
grep -Fq "REAPED $p2" <<<"$SWEEP_OUT"
! pool_present "$p2"
grep -Fq "destroy $p2" "$P15_7_FAKE_POOL_ACTIONS"
grep -Fq "undefine $p2" "$P15_7_FAKE_POOL_ACTIONS"

# second cleanup-stale-pools run -> no-op success (idempotent)
sweep
[[ "$SWEEP_RC" == 0 ]]
! grep -Fq "REAPED" <<<"$SWEEP_OUT"

# post-sweep, the fake pool store no longer holds the marker-backed owned
# pools that were just reaped.
for leftover in "$STATE_DIR"/*.pool; do
  [[ -e "$leftover" ]] || continue
  lname="${leftover##*/}"; lname="${lname%.pool}"
  if [[ "$lname" =~ ^o3k-p15-7-[0-9]+$ ]]; then
    echo "owned pool $lname survived the sweep" >&2
    exit 1
  fi
done

# pool with wrong/foreign target path -> preserved, reported AMBIGUOUS
reset_state
p3="o3k-p15-7-303"; p3path="$IMAGE_ROOT/$p3"; make_pool "$p3" "$IMAGE_ROOT/foreign-dir/$p3" running
make_marker "$p3path" 303 "$p3"
sweep
[[ "$SWEEP_RC" == 0 ]]
grep -Fq "AMBIGUOUS $p3" <<<"$SWEEP_OUT"
pool_present "$p3"

# pool with marker whose run= does not match pool name -> preserved
reset_state
p4="o3k-p15-7-404"; p4path="$IMAGE_ROOT/$p4"; make_pool "$p4" "$p4path" running
make_marker "$p4path" 99999 "$p4"
sweep
[[ "$SWEEP_RC" == 0 ]]
grep -Fq "AMBIGUOUS $p4" <<<"$SWEEP_OUT"
pool_present "$p4"
! grep -Fq "destroy $p4" "$P15_7_FAKE_POOL_ACTIONS"

# pool with marker whose path= does not match live target -> preserved
reset_state
p5="o3k-p15-7-505"; p5path="$IMAGE_ROOT/$p5"; make_pool "$p5" "$p5path" running
make_marker "$p5path" 505 "$p5"
printf 'o3k-p15-7-pool-owned-v1\nrun=505\npool=%s\npath=%s\nsource_sha=unknown\n' \
  "$p5" "$IMAGE_ROOT/somewhere-else" >"$p5path/.o3k-p15-7-pool-owned"
sweep
[[ "$SWEEP_RC" == 0 ]]
grep -Fq "AMBIGUOUS $p5" <<<"$SWEEP_OUT"
pool_present "$p5"

# conforming pool with NO marker -> preserved (ambiguous)
reset_state
p6="o3k-p15-7-606"; p6path="$IMAGE_ROOT/$p6"; make_pool "$p6" "$p6path" running
sweep
[[ "$SWEEP_RC" == 0 ]]
grep -Fq "AMBIGUOUS $p6" <<<"$SWEEP_OUT"
pool_present "$p6"

# marker with garbage content -> preserved
reset_state
p7="o3k-p15-7-707"; p7path="$IMAGE_ROOT/$p7"; make_pool "$p7" "$p7path" running
mkdir -p "$p7path"
printf 'not a valid marker\ngarbage here\n' >"$p7path/.o3k-p15-7-pool-owned"
sweep
[[ "$SWEEP_RC" == 0 ]]
grep -Fq "AMBIGUOUS $p7" <<<"$SWEEP_OUT"
pool_present "$p7"

# foreign pools (journey-owned and unrelated) are untouched
reset_state
jpool="o3k-p15-7-journey-12345"; jpath="$IMAGE_ROOT/not-the-journey-pool"
np="o3k-nettest"
make_pool "$jpool" "$jpath" running
make_pool "$np" "$IMAGE_ROOT/nettest" running
sweep
[[ "$SWEEP_RC" == 0 ]]
pool_present "$jpool"
pool_present "$np"
! grep -Fq "destroy $jpool" "$P15_7_FAKE_POOL_ACTIONS"
! grep -Fq "destroy $np" "$P15_7_FAKE_POOL_ACTIONS"
! grep -Fq "AMBIGUOUS $jpool" <<<"$SWEEP_OUT"
! grep -Fq "AMBIGUOUS $np" <<<"$SWEEP_OUT"

# pool referenced in a domain dumpxml (disk source under pool path) -> preserved
reset_state
p8="o3k-p15-7-808"; p8path="$IMAGE_ROOT/$p8"; make_pool "$p8" "$p8path" running
make_marker "$p8path" 808 "$p8"
cat >"$DOMAIN_DIR/vm1.xml" <<XML
<domain type="kvm">
  <name>vm1</name>
  <devices>
    <disk type="file" device="disk">
      <source file="${p8path}/guest.qcow2"/>
    </disk>
  </devices>
</domain>
XML
sweep
[[ "$SWEEP_RC" == 0 ]]
grep -Fq "AMBIGUOUS $p8" <<<"$SWEEP_OUT"
pool_present "$p8"
! grep -Fq "destroy $p8" "$P15_7_FAKE_POOL_ACTIONS"

echo "P15.7 libvirt pool ownership cleanup tests passed"
