#!/usr/bin/env bash
set -Eeuo pipefail

# Regression for the bounded one-time legacy pool sanitation path
# (scripts/p15-7-legacy-pool-sanitation.sh). Proves: allowlisted owned-layout
# pools are reaped, foreign pools are untouched, domain-referenced pools are
# preserved, non-allowlisted owned pools are untouched, marker-carrying pools
# are refused, and a second run is idempotent.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-p15-7-legacy-sanitation.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
BIN_DIR="$WORK_DIR/bin"
STATE_DIR="$WORK_DIR/state"
IMAGE_ROOT="$WORK_DIR/images"
mkdir -p "$BIN_DIR" "$STATE_DIR" "$IMAGE_ROOT" \
  "$WORK_DIR/journey-temp/o3k-p15-7-journey-222"

cat >"$BIN_DIR/virsh" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$1" == -c && "$2" == qemu:///system ]] || exit 90
shift 2
command="$1"; shift
case "$command" in
  pool-list)
    [[ "${1:-} ${2:-}" == "--all --name" ]] || exit 91
    [[ ! -f "$P15_7_SAN_STATE/pools" ]] || cat "$P15_7_SAN_STATE/pools"
    ;;
  pool-dumpxml)
    grep -A1 "^NAME=$1\$" "$P15_7_SAN_STATE/xml" | tail -n 1 | sed 's/^XML=//'
    ;;
  list)
    [[ "${1:-} ${2:-}" == "--all --name" ]] || exit 91
    [[ ! -f "$P15_7_SAN_STATE/doms" ]] || cat "$P15_7_SAN_STATE/doms"
    ;;
  dumpxml)
    cat "$P15_7_SAN_STATE/dom-$1.xml" 2>/dev/null || true
    ;;
  pool-info)
    echo "State: $(grep "^STATE=$1:" "$P15_7_SAN_STATE/xml" | cut -d: -f2)"
    ;;
  pool-destroy)
    sed -i "s/^STATE=$1:.*/STATE=$1:inactive/" "$P15_7_SAN_STATE/xml"
    ;;
  pool-undefine)
    grep -v "^NAME=$1\$" "$P15_7_SAN_STATE/xml" >"$P15_7_SAN_STATE/xml.new"
    # Drop the XML/STATE lines belonging to the removed pool entry.
    python3 - "$P15_7_SAN_STATE/xml.new" "$1" >"$P15_7_SAN_STATE/xml.new2" <<'PY'
import sys
path, name = sys.argv[1:]
lines = open(path).read().splitlines()
out, skip_next = [], False
for line in lines:
    if skip_next:
        skip_next = False
        continue
    if line == f"NAME={name}":
        skip_next = True
        continue
    out.append(line)
print("\n".join(out))
PY
    mv "$P15_7_SAN_STATE/xml.new2" "$P15_7_SAN_STATE/xml"
    rm -f "$P15_7_SAN_STATE/xml.new"
    sed -i "/^$1\$/d" "$P15_7_SAN_STATE/pools"
    ;;
  *) exit 91 ;;
esac
SH
chmod +x "$BIN_DIR/virsh"
export PATH="$BIN_DIR:$PATH"
export P15_7_SAN_STATE="$STATE_DIR"
export O3K_P15_7_LIBVIRT_IMAGE_ROOT="$IMAGE_ROOT"

pool_xml_entry() {
  # name path state
  printf 'NAME=%s\nXML=<pool type="dir"><name>%s</name><target><path>%s</path></target></pool>\nSTATE=%s:%s\n' \
    "$1" "$1" "$2" "$1" "$3"
}

reset_state() {
  cat >"$STATE_DIR/pools" <<EOF
o3k-p15-7-111
o3k-p15-7-journey-222
o3k-p15-7-999
o3k-nettest
EOF
  {
    pool_xml_entry o3k-p15-7-111 "$IMAGE_ROOT/o3k-p15-7-111" running
    pool_xml_entry o3k-p15-7-journey-222 "$WORK_DIR/journey-temp/o3k-p15-7-journey-222" running
    pool_xml_entry o3k-p15-7-999 "$IMAGE_ROOT/o3k-p15-7-999" inactive
    pool_xml_entry o3k-nettest "$WORK_DIR/foreign" inactive
  } >"$STATE_DIR/xml"
  : >"$STATE_DIR/doms"
  rm -f "$STATE_DIR"/dom-*.xml
}

run_sanitation() {
  # The script refuses to run unless hostname is runner-2404; shadow it.
  bash -c '
    hostname() { echo runner-2404; }
    export -f hostname
    bash "$0" "$1"
  ' "$ROOT_DIR/scripts/p15-7-legacy-pool-sanitation.sh" "$1"
}

allowlist="$WORK_DIR/allowlist"
cat >"$allowlist" <<EOF
# bounded test allowlist
o3k-p15-7-111 111 $IMAGE_ROOT/o3k-p15-7-111
o3k-p15-7-journey-222 222 $WORK_DIR/journey-temp/o3k-p15-7-journey-222
EOF

# 1. Happy path: allowlisted owned-layout pools reaped; non-allowlisted owned
#    pool (999) and foreign pool untouched.
reset_state
run_sanitation "$allowlist"
[[ ! -e "$STATE_DIR/pools" ]] || ! grep -Fxq o3k-p15-7-111 "$STATE_DIR/pools" \
  || { echo "owned pool was not reaped" >&2; exit 1; }
! grep -Fxq o3k-p15-7-journey-222 "$STATE_DIR/pools" \
  || { echo "journey pool was not reaped" >&2; exit 1; }
grep -Fxq o3k-p15-7-999 "$STATE_DIR/pools" \
  || { echo "non-allowlisted owned pool was touched" >&2; exit 1; }
grep -Fxq o3k-nettest "$STATE_DIR/pools" \
  || { echo "foreign pool was touched" >&2; exit 1; }

# 2. Idempotent second run.
run_sanitation "$allowlist"

# 3. Domain disk referencing the pool path blocks the reap.
reset_state
printf 'vm1\n' >"$STATE_DIR/doms"
printf '<domain><disk><source file="%s/o3k-p15-7-111/disk.qcow2"/></disk></domain>\n' \
  "$IMAGE_ROOT" >"$STATE_DIR/dom-vm1.xml"
if run_sanitation "$allowlist" 2>/dev/null; then
  echo "sanitation succeeded despite a domain referencing the pool" >&2
  exit 1
fi
grep -Fxq o3k-p15-7-111 "$STATE_DIR/pools" \
  || { echo "domain-referenced pool was reaped" >&2; exit 1; }

# 4. Marker-carrying pool belongs to the sweep, not this path.
reset_state
mkdir -p "$IMAGE_ROOT/o3k-p15-7-111"
printf 'o3k-p15-7-pool-owned-v1\nrun=111\npool=o3k-p15-7-111\npath=%s/o3k-p15-7-111\nsource_sha=unknown\n' \
  "$IMAGE_ROOT" >"$IMAGE_ROOT/o3k-p15-7-111/.o3k-p15-7-pool-owned"
if run_sanitation "$allowlist" 2>/dev/null; then
  echo "sanitation reaped a marker-carrying pool" >&2
  exit 1
fi
grep -Fxq o3k-p15-7-111 "$STATE_DIR/pools" \
  || { echo "marker-carrying pool was reaped" >&2; exit 1; }

# 5. Wrong-host refusal is fail-closed.
reset_state
if bash "$ROOT_DIR/scripts/p15-7-legacy-pool-sanitation.sh" "$allowlist" 2>/dev/null; then
  echo "sanitation ran on a foreign host" >&2
  exit 1
fi
grep -Fxq o3k-p15-7-111 "$STATE_DIR/pools" \
  || { echo "pools modified despite wrong-host refusal" >&2; exit 1; }

echo "P15.7 legacy pool sanitation tests passed"
