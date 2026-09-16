#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${O3K_P15_7_LIBVIRT_IMAGE_ROOT:-/var/lib/libvirt/images}"
VIRSH=(virsh -c qemu:///system)
POOL_XML_TMP=""
trap '[[ -z "${POOL_XML_TMP:-}" ]] || rm -f -- "$POOL_XML_TMP"' EXIT

die() {
  echo "P15.7 libvirt pool cleanup blocked: $*" >&2
  exit 1
}

valid_run_id() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]
}

expected_pool_path() {
  local run_id="$1" path="$2"
  valid_run_id "$run_id" || die "run id is unsafe"
  [[ "$ROOT" == /* && "$ROOT" != *..* && -d "$ROOT" && ! -L "$ROOT" ]] \
    || die "libvirt image root is unsafe"
  [[ "$path" == "$ROOT/o3k-p15-7-$run_id" && "$path" != *..* ]] \
    || die "pool path is not the exact run-owned image directory"
}

pool_listing() {
  "${VIRSH[@]}" pool-list --all --name
}

pool_present() {
  local listing="$1" name="$2"
  grep -Fxq -- "$name" <<<"$listing"
}

pool_xml_matches() {
  local name="$1" path="$2" run_id="$3" description_policy="$4" xml
  xml="$("${VIRSH[@]}" pool-dumpxml "$name")" || return 1
  python3 -c '
import sys
import xml.etree.ElementTree as ET

name, path, run_id, description_policy = sys.argv[1:]
try:
    pool = ET.fromstring(sys.stdin.read())
except ET.ParseError:
    raise SystemExit(1)
description = pool.findtext("description", "")
expected_description = f"o3k-p15-7-journey-owned={run_id}"
valid = (
    pool.tag == "pool"
    and pool.get("type") == "dir"
    and pool.findtext("name") == name
    and pool.findtext("target/path") == path
)
if description_policy == "required":
    valid = valid and description == expected_description
elif description_policy == "legacy-or-owned":
    valid = valid and description in ("", expected_description)
else:
    valid = False
raise SystemExit(0 if valid else 1)
' "$name" "$path" "$run_id" "$description_policy" <<<"$xml"
}

remove_pool() {
  local name="$1" path="$2" run_id="$3" description_policy="$4" listing state
  listing="$(pool_listing)" || die "cannot inspect libvirt storage pools"
  if ! pool_present "$listing" "$name"; then
    return 0
  fi
  pool_xml_matches "$name" "$path" "$run_id" "$description_policy" \
    || die "pool identity does not match its run-owned path and marker"
  state="$("${VIRSH[@]}" pool-info "$name" | sed -n 's/^State:[[:space:]]*//p')" \
    || die "cannot inspect run-owned pool state"
  case "$state" in
    running|active) "${VIRSH[@]}" pool-destroy "$name" || die "cannot stop run-owned pool" ;;
    inactive) ;;
    *) die "run-owned pool state is ambiguous" ;;
  esac
  "${VIRSH[@]}" pool-undefine "$name" || die "cannot undefine run-owned pool"
  listing="$(pool_listing)" || die "cannot verify libvirt storage pool cleanup"
  ! pool_present "$listing" "$name" || die "run-owned pool remains after undefine"
}

define_pool() {
  local run_id="$1" path="$2" name listing
  expected_pool_path "$run_id" "$path"
  name="o3k-p15-7-$run_id"
  listing="$(pool_listing)" || die "cannot inspect libvirt storage pools"
  ! pool_present "$listing" "$name" || die "run-owned libvirt pool already exists"
  POOL_XML_TMP="$(mktemp "${TMPDIR:-/tmp}/o3k-p15-7-pool.XXXXXX")" \
    || die "cannot create temporary pool definition"
  python3 - "$name" "$path" "$run_id" >"$POOL_XML_TMP" <<'PY'
import sys
import xml.etree.ElementTree as ET

name, path, run_id = sys.argv[1:]
pool = ET.Element("pool", {"type": "dir"})
ET.SubElement(pool, "name").text = name
ET.SubElement(pool, "description").text = f"o3k-p15-7-journey-owned={run_id}"
target = ET.SubElement(pool, "target")
ET.SubElement(target, "path").text = path
ET.indent(pool, space="  ")
ET.ElementTree(pool).write(sys.stdout.buffer, encoding="utf-8", xml_declaration=True)
PY
  "${VIRSH[@]}" pool-define "$POOL_XML_TMP" || die "cannot define run-owned libvirt pool"
  pool_xml_matches "$name" "$path" "$run_id" required \
    || die "defined libvirt pool failed its ownership check"
  "${VIRSH[@]}" pool-start "$name" || die "cannot start run-owned libvirt pool"
  rm -f -- "$POOL_XML_TMP"
  POOL_XML_TMP=""
}

assert_pool_absent() {
  local run_id="$1" path="$2" name listing
  expected_pool_path "$run_id" "$path"
  name="o3k-p15-7-$run_id"
  listing="$(pool_listing)" || die "cannot inspect libvirt storage pools"
  ! pool_present "$listing" "$name" || die "run-owned libvirt pool already exists"
}

cleanup_owned_pool() {
  local run_id="$1" path="$2"
  expected_pool_path "$run_id" "$path"
  remove_pool "o3k-p15-7-$run_id" "$path" "$run_id" required
}

cleanup_stale_diagnostic_images() {
  local temp_root="$1" marker image base run_id pool_path
  [[ "$temp_root" == /* && "$temp_root" != *..* && -d "$temp_root" && ! -L "$temp_root" ]] \
    || die "runner temp path is unsafe"
  temp_root="$(realpath -e -- "$temp_root")"
  shopt -s nullglob
  local -a markers=(
    "$temp_root"/cirros-0.6.3-p15-7-diagnostic-*.o3k-owned
    "$temp_root"/cirros-0.6.3-x86_64-disk.img.p15-7-diagnostic-*.o3k-owned
  )
  for marker in "${markers[@]}"; do
    image="${marker%.o3k-owned}"
    [[ -f "$marker" && ! -L "$marker" ]] || die "diagnostic image marker is not a regular file"
    [[ ! -L "$image" ]] || die "diagnostic image path is unsafe"
    if [[ -e "$image" && ! -f "$image" ]]; then
      die "diagnostic image path is not a regular file"
    fi
    run_id="$(python3 - "$marker" <<'PY'
import pathlib, re, sys
lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
runs = [line[4:] for line in lines if line.startswith("run=")]
if lines.count("o3k-disposable-image-v1") != 1 or lines.count("phase=generic") != 1:
    raise SystemExit("invalid image ownership marker")
if len(runs) != 1 or not re.fullmatch(r"[0-9]+", runs[0]):
    raise SystemExit("invalid image ownership run")
print(runs[0])
PY
)" || die "diagnostic image ownership marker is invalid"
    base="${image##*/}"
    case "$base" in
      "cirros-0.6.3-p15-7-diagnostic-${run_id}."*|\
      "cirros-0.6.3-x86_64-disk.img.p15-7-diagnostic-${run_id}."*) ;;
      *) die "diagnostic image filename does not match its ownership run" ;;
    esac
    pool_path="$ROOT/o3k-p15-7-$run_id"
    remove_pool "o3k-p15-7-$run_id" "$pool_path" "$run_id" legacy-or-owned
    rm -f -- "$image" "$marker"
    echo "P15.7 stale diagnostic image cleaned: run=$run_id"
  done
}

case "${1:-}" in
  define)
    [[ $# == 3 ]] || die "usage: $0 define RUN_ID STORAGE_ROOT"
    define_pool "$2" "$3"
    ;;
  assert-absent)
    [[ $# == 3 ]] || die "usage: $0 assert-absent RUN_ID STORAGE_ROOT"
    assert_pool_absent "$2" "$3"
    ;;
  cleanup)
    [[ $# == 3 ]] || die "usage: $0 cleanup RUN_ID STORAGE_ROOT"
    cleanup_owned_pool "$2" "$3"
    ;;
  cleanup-stale-diagnostic-images)
    [[ $# == 2 ]] || die "usage: $0 cleanup-stale-diagnostic-images RUNNER_TEMP"
    cleanup_stale_diagnostic_images "$2"
    ;;
  *) die "unknown command" ;;
esac
