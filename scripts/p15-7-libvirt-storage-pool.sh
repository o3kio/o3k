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
  local name="$1" path="$2" xml
  xml="$("${VIRSH[@]}" pool-dumpxml "$name")" || return 1
  # Use the documented pool identity fields; descriptions are not part of the
  # storage-pool XML contract and are not a durable ownership marker.
  python3 -c '
import sys
import xml.etree.ElementTree as ET

name, path = sys.argv[1:]
try:
    pool = ET.fromstring(sys.stdin.read())
except ET.ParseError:
    raise SystemExit(1)
valid = (
    pool.tag == "pool"
    and pool.get("type") == "dir"
    and pool.findtext("name") == name
    and pool.findtext("target/path") == path
)
raise SystemExit(0 if valid else 1)
' "$name" "$path" <<<"$xml"
}

# Resolve the durable source-sha recorded in the pool ownership marker. A
# protected run always supplies a 40-hex commit via GITHUB_SHA (GitHub Actions
# exports it for every step); O3K_P15_7_SOURCE_SHA is the journey's explicit
# override. Only when BOTH are unset (local/dev runs) is the literal string
# "unknown" used. A set but non-hex value is refused — never guessed.
pool_source_sha() {
  local sha="${O3K_P15_7_SOURCE_SHA:-${GITHUB_SHA:-}}"
  if [[ -z "$sha" ]]; then
    printf 'unknown\n'
    return 0
  fi
  [[ "$sha" =~ ^[0-9a-fA-F]{40}$ ]] || die "source sha is not 40-hex"
  printf '%s\n' "$sha"
}

# Atomically publish the durable pool ownership marker into the pool's exact
# target directory. The marker is the only durable record that authorizes the
# stale-pool sweep, so:
#   - the temporary file is created INSIDE the pool directory (same
#     filesystem) and the canonical marker appears only via an atomic
#     same-directory rename of fully-written, content-validated bytes;
#   - a `.tmp.*` temporary marker is never ownership evidence and must never
#     authorize destructive cleanup;
#   - libvirt creates the run-owned pool directory root-owned (0711), so a
#     passwordless-sudo path performs the identical in-directory write +
#     rename as the unprivileged fast path. Fail closed if neither works.
write_pool_marker() {
  local path="$1" run_id="$2" name="$3" sha tmp marker content
  expected_pool_path "$run_id" "$path"
  [[ "$name" == "o3k-p15-7-$run_id" ]] \
    || die "pool name is not the exact run-owned name"
  [[ -d "$path" && ! -L "$path" ]] \
    || die "pool target path is not an owned directory"
  sha="$(pool_source_sha)"
  marker="$path/.o3k-p15-7-pool-owned"
  content="$(printf 'o3k-p15-7-pool-owned-v1\nrun=%s\npool=%s\npath=%s\nsource_sha=%s\n' \
    "$run_id" "$name" "$path" "$sha")" \
    || die "cannot compose pool ownership marker content"

  # Unprivileged fast path: temp inside the pool dir, validate, atomic rename.
  if tmp="$(mktemp "$path/.o3k-p15-7-pool-owned.tmp.XXXXXX" 2>/dev/null)"; then
    if printf '%s' "$content" >"$tmp" \
      && chmod 0644 "$tmp" \
      && [[ "$(cat -- "$tmp")" == "$content" ]] \
      && mv -f -- "$tmp" "$marker"; then
      return 0
    fi
    rm -f -- "$tmp" 2>/dev/null || true
  fi

  # Privileged path (root-owned 0711 pool dir): the temp file is still created
  # inside the pool directory and published by the same atomic rename, as the
  # runner user via passwordless sudo. The canonical marker is never written
  # directly.
  printf '%s' "$content" | sudo -n sh -c '
    umask 022
    t="$(mktemp "$1/.o3k-p15-7-pool-owned.tmp.XXXXXX")" || exit 1
    cat >"$t" || { rm -f -- "$t"; exit 1; }
    chmod 0644 "$t" || { rm -f -- "$t"; exit 1; }
    [ "$(cat -- "$t")" = "$2" ] || { rm -f -- "$t"; exit 1; }
    mv -f -- "$t" "$3" || { rm -f -- "$t"; exit 1; }
  ' -- "$path" "$content" "$marker" || die "cannot record pool ownership marker"
}

# Sweep-only non-fatal path conformance (the sweep reports AMBIGUOUS instead
# of dying on a foreign/mismatched target, so it cannot reuse expected_pool_path
# which is a hard validator).
pool_path_conforms() {
  local run_id="$1" path="$2"
  [[ "$ROOT" == /* && "$ROOT" != *..* && -d "$ROOT" && ! -L "$ROOT" ]] || return 1
  [[ "$path" == "$ROOT/o3k-p15-7-$run_id" && "$path" != *..* ]] || return 1
}

# Extract the target path (and structurally confirm type=dir + name) from live
# pool XML. Exit 0 with the path on stdout; exit 1 if the XML is absent/
# unparseable/does not claim the dir type and name; exit 2 if the live
# pool-dumpxml command itself failed (infrastructure, not ambiguity).
pool_xml_path() {
  local name="$1" xml
  xml="$("${VIRSH[@]}" pool-dumpxml "$name" 2>/dev/null)" || return 2
  python3 -c '
import sys
import xml.etree.ElementTree as ET

name = sys.argv[1]
try:
    pool = ET.fromstring(sys.stdin.read())
    path = pool.findtext("target/path")
except (ET.ParseError, UnicodeError):
    raise SystemExit(1)
if (
    pool.tag == "pool"
    and pool.get("type") == "dir"
    and pool.findtext("name") == name
    and path
):
    print(path)
    raise SystemExit(0)
raise SystemExit(1)
' "$name" <<<"$xml"
}

# Validate the durable pool ownership marker: a regular file (never a
# symlink) whose magic appears exactly once and whose run/pool/path all match
# the live pool, with a 40-hex or "unknown" source_sha.
pool_marker_valid() {
  local name="$1" path="$2" run_id="$3"
  local marker="$path/.o3k-p15-7-pool-owned"
  [[ -f "$marker" && ! -L "$marker" ]] || return 1
  python3 - "$name" "$path" "$run_id" <<'PY'
import re
import sys

name, path, run_id = sys.argv[1:]
lines = open(path + "/.o3k-p15-7-pool-owned", encoding="utf-8").read().splitlines()
if lines.count("o3k-p15-7-pool-owned-v1") != 1:
    raise SystemExit(1)


def field(key):
    hits = [line[len(key) + 1:] for line in lines if line.startswith(key + "=")]
    return hits[0] if len(hits) == 1 else None


run = field("run")
pool = field("pool")
pth = field("path")
sha = field("source_sha")
if run != run_id or pool != name or pth != path:
    raise SystemExit(1)
if sha is None or (sha != "unknown" and re.fullmatch(r"[0-9a-fA-F]{40}", sha) is None):
    raise SystemExit(1)
raise SystemExit(0)
PY
}

# Return 0 if any domain's dumpxml or domblklist --details references the pool
# target path; 1 if no domain references it; 2 if a domain cannot be inspected
# (unsafe to reap, fail closed).
pool_domain_references() {
  local path="$1" dom listing xml blk
  listing="$("${VIRSH[@]}" list --all --name 2>/dev/null)" || return 2
  while IFS= read -r dom; do
    [[ -n "$dom" ]] || continue
    xml="$("${VIRSH[@]}" dumpxml "$dom" 2>/dev/null)" || return 2
    if grep -Fq -- "$path" <<<"$xml"; then
      return 0
    fi
    blk="$("${VIRSH[@]}" domblklist "$dom" --details 2>/dev/null)" || return 2
    if grep -Fq -- "$path" <<<"$blk"; then
      return 0
    fi
  done <<<"$listing"
  return 1
}

remove_pool() {
  local name="$1" path="$2" run_id="$3" listing state
  expected_pool_path "$run_id" "$path"
  [[ "$name" == "o3k-p15-7-$run_id" ]] \
    || die "pool name is not the exact run-owned name"
  listing="$(pool_listing)" || die "cannot inspect libvirt storage pools"
  if ! pool_present "$listing" "$name"; then
    return 0
  fi
  pool_xml_matches "$name" "$path" \
    || die "pool identity does not match its exact run-owned name and path"
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
  # The pool is gone; drop its ownership marker and any orphaned publication
  # temporaries too (best-effort; the root-owned pool dir may need the sudo
  # idiom). Temporaries are removed only here, after the complete ownership
  # proof for this exact pool has passed — never as standalone cleanup.
  rm -f -- "$path/.o3k-p15-7-pool-owned" "$path"/.o3k-p15-7-pool-owned.tmp.* 2>/dev/null \
    || sudo -n rm -f -- "$path/.o3k-p15-7-pool-owned" "$path"/.o3k-p15-7-pool-owned.tmp.* 2>/dev/null \
    || true
}

define_pool() {
  local run_id="$1" path="$2" name listing
  expected_pool_path "$run_id" "$path"
  name="o3k-p15-7-$run_id"
  listing="$(pool_listing)" || die "cannot inspect libvirt storage pools"
  ! pool_present "$listing" "$name" || die "run-owned libvirt pool already exists"
  POOL_XML_TMP="$(mktemp "${TMPDIR:-/tmp}/o3k-p15-7-pool.XXXXXX")" \
    || die "cannot create temporary pool definition"
  python3 - "$name" "$path" >"$POOL_XML_TMP" <<'PY'
import sys
import xml.etree.ElementTree as ET

name, path = sys.argv[1:]
pool = ET.Element("pool", {"type": "dir"})
ET.SubElement(pool, "name").text = name
target = ET.SubElement(pool, "target")
ET.SubElement(target, "path").text = path
ET.indent(pool, space="  ")
ET.ElementTree(pool).write(sys.stdout.buffer, encoding="utf-8", xml_declaration=True)
PY
  "${VIRSH[@]}" pool-define "$POOL_XML_TMP" || die "cannot define run-owned libvirt pool"
  pool_xml_matches "$name" "$path" \
    || die "defined libvirt pool failed its exact name and path check"
  "${VIRSH[@]}" pool-start "$name" || die "cannot start run-owned libvirt pool"
  rm -f -- "$POOL_XML_TMP"
  POOL_XML_TMP=""
  write_pool_marker "$path" "$run_id" "$name" \
    || die "cannot record run-owned pool ownership marker"
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
  remove_pool "o3k-p15-7-$run_id" "$path" "$run_id"
}

# Extract the numeric GitHub run id from an owned pool name
# (o3k-p15-7-<RUN_ID>). Returns 1 for any other name so the sweep treats it
# as foreign and leaves it alone.
run_id_from_pool_name() {
  local name="$1"
  if [[ "$name" =~ ^o3k-p15-7-([0-9]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

# Sweep every libvirt storage pool, reaping only pools whose ownership is
# fully proven (exact name + exact target path + structural XML + a valid
# durable marker + no live domain reference). Ambiguity is reported and the
# pool is preserved; only infrastructure failures abort the sweep.
cleanup_stale_pools() {
  local listing name run_id path rc ref_rc
  listing="$(pool_listing)" || die "cannot inspect libvirt storage pools"
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    # Condition 1: owned numeric run naming (GitHub run IDs). Pools that do
    # not match are foreign (e.g. o3k-nettest) or owned by another subsystem
    # (e.g. o3k-p15-7-journey-*, the journey's own pool) — never reap, and do
    # not classify their absent marker as ambiguity.
    if ! run_id="$(run_id_from_pool_name "$name")"; then
      continue
    fi
    # Condition 2: exact expected target path read from live pool XML.
    path="$(pool_xml_path "$name")"
    rc=$?
    if (( rc != 0 )); then
      if (( rc == 2 )); then
        die "cannot dumpxml candidate pool $name"
      fi
      echo "AMBIGUOUS $name pool_xml_invalid"
      continue
    fi
    if ! pool_path_conforms "$run_id" "$path"; then
      echo "AMBIGUOUS $name foreign_target_path"
      continue
    fi
    # Condition 3: full structural match (name / target path / type=dir).
    if ! pool_xml_matches "$name" "$path"; then
      echo "AMBIGUOUS $name pool_xml_mismatch"
      continue
    fi
    # Condition 4: valid, matching durable ownership marker.
    if ! pool_marker_valid "$name" "$path" "$run_id"; then
      echo "AMBIGUOUS $name marker_invalid_or_missing"
      continue
    fi
    # Condition 5: no live domain may reference the pool path.
    pool_domain_references "$path" \
      && { echo "AMBIGUOUS $name referenced_by_domain"; continue; } \
      || ref_rc=$?
    if [[ "${ref_rc:-0}" == 2 ]]; then
      echo "AMBIGUOUS $name domain_scan_unavailable"
      continue
    fi
    # All conditions hold: this is provably ours and unused. Reap it.
    remove_pool "$name" "$path" "$run_id"
    echo "REAPED $name"
  done <<<"$listing"
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
    remove_pool "o3k-p15-7-$run_id" "$pool_path" "$run_id"
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
  cleanup-stale-pools)
    [[ $# == 1 ]] || die "usage: $0 cleanup-stale-pools"
    cleanup_stale_pools
    ;;
  cleanup-stale-diagnostic-images)
    [[ $# == 2 ]] || die "usage: $0 cleanup-stale-diagnostic-images RUNNER_TEMP"
    cleanup_stale_diagnostic_images "$2"
    ;;
  *) die "unknown command" ;;
esac
