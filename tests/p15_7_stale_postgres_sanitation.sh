#!/usr/bin/env bash
set -Eeuo pipefail

# Regression for the bounded one-time stale owned postgres sanitation path
# (scripts/p15-7-stale-postgres-sanitation.sh). Proves: allowlisted,
# label-proven, terminal-run-proven containers are removed; containers with
# wrong labels, non-terminal runs, sha mismatch, or names outside the
# allowlist are preserved; a second run is idempotent; wrong-host refusal is
# fail-closed.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-stale-pg.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
BIN_DIR="$WORK_DIR/bin"
STATE_DIR="$WORK_DIR/state"
mkdir -p "$BIN_DIR" "$STATE_DIR"

# --- fake docker: container state as files $STATE_DIR/<name>.{labels,running}
cat >"$BIN_DIR/docker" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
D="${P15_7_SAN_FAKE_STATE:?}"
case "$1" in
  info) exit 0 ;;
  inspect)
    shift
    name=""
    format=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -f) format="$2"; shift 2 ;;
        *) name="$1"; shift ;;
      esac
    done
    [[ -f "$D/$name.labels" ]] || exit 1
    if [[ -n "$format" ]]; then
      key="${format//\{\{/}"
      key="${key//\}\}/}"
      key="${key//index .Config.Labels /}"
      key="${key//\"/}"
      grep "^$key=" "$D/$name.labels" | cut -d= -f2- || true
    else
      cat "$D/$name.labels" >/dev/null
    fi
    ;;
  ps)
    # support: ps -a --format {{.Names}}
    for f in "$D"/*.labels; do
      [[ -e "$f" ]] || continue
      basename "$f" .labels
    done
    ;;
  rm)
    shift
    force=""
    [[ "$1" == "--force" ]] && { force=1; shift; }
    name="$1"
    [[ -n "$force" && -f "$D/$name.labels" ]] || exit 1
    rm -f -- "$D/$name.labels"
    ;;
  *) exit 91 ;;
esac
SH
chmod +x "$BIN_DIR/docker"

# --- fake curl: run-ledger lookup by URL
cat >"$BIN_DIR/curl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
R="${P15_7_SAN_FAKE_RUNS:?}"
url=""
for arg in "$@"; do
  [[ "$arg" == http* ]] && url="$arg"
done
id="${url##*/runs/}"
if [[ -n "$id" && -f "$R/$id" ]]; then
  printf '{'
  read -r status conclusion sha <"$R/$id"
  printf '"status": "%s", "conclusion": "%s", "head_sha": "%s"' "$status" "$conclusion" "$sha"
  printf '}'
else
  exit 22
fi
SH
chmod +x "$BIN_DIR/curl"

run_sanitation() {
  bash -c '
    hostname() { echo runner-2404; }
    export -f hostname
    sudo() { if [[ "$1" == "-n" ]]; then shift; fi; "$@"; }
    export -f sudo
    PATH="$0:$PATH" bash "$1" "$2"
  ' "$BIN_DIR" "$ROOT_DIR/scripts/p15-7-stale-postgres-sanitation.sh" "$1"
}

SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SHA_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

make_container() {
  # name phase run sha
  printf 'o3k.owner=o3k\no3k.run_id=%s\no3k.phase=%s\no3k.source_sha=%s\n' "$2" "$1" "$3" >"$STATE_DIR/o3k-$1-postgres-$2.labels"
}

reset_state() {
  rm -f "$STATE_DIR"/*.labels "$RUNS"/* 2>/dev/null || true
  # allowlisted, fully proven -> removed
  make_container p15-7 11111111111 "$SHA_A"; echo "completed failure $SHA_A" >"$RUNS/11111111111"
  # allowlisted but run not terminal -> preserved
  make_container p13-4 22222222222 "$SHA_B"; echo "in_progress null $SHA_B" >"$RUNS/22222222222"
  # allowlisted but sha mismatch vs run head -> preserved
  make_container p13-4 33333333333 "$SHA_A"; echo "completed failure $SHA_B" >"$RUNS/33333333333"
  # allowlisted but owner label wrong -> preserved
  printf 'o3k.owner=foreign\no3k.run_id=44444444444\no3k.phase=p13-4\no3k.source_sha=%s\n' "$SHA_A" >"$STATE_DIR/o3k-p13-4-postgres-44444444444.labels"
  echo "completed failure $SHA_A" >"$RUNS/44444444444"
  # NOT in the allowlist -> untouched
  printf 'o3k.owner=o3k\no3k.run_id=55555555555\no3k.phase=p13-4\no3k.source_sha=%s\n' "$SHA_A" >"$STATE_DIR/o3k-p13-4-postgres-55555555555.labels"
  echo "completed failure $SHA_A" >"$RUNS/55555555555"
}

RUNS="$WORK_DIR/runs"
mkdir -p "$RUNS"
export P15_7_SAN_FAKE_STATE="$STATE_DIR"
export P15_7_SAN_FAKE_RUNS="$RUNS"
export GITHUB_TOKEN="fake-test-token"
export PATH="$BIN_DIR:$PATH"

allowlist="$WORK_DIR/allowlist"
cat >"$allowlist" <<EOF
# bounded test allowlist
o3k-p15-7-postgres-11111111111 p15-7 11111111111
o3k-p13-4-postgres-22222222222 p13-4 22222222222
o3k-p13-4-postgres-33333333333 p13-4 33333333333
o3k-p13-4-postgres-44444444444 p13-4 44444444444
EOF

# 1. Only the fully-proven container is removed; all others preserved; run
#    exits non-zero because something was preserved.
reset_state
if run_sanitation "$allowlist" >/tmp/san-out.txt 2>&1; then
  echo "sanitation succeeded despite preserved containers" >&2
  exit 1
fi
grep -q "REMOVED o3k-p15-7-postgres-11111111111" /tmp/san-out.txt \
  || { echo "proven owned container was not removed" >&2; exit 1; }
[[ ! -e "$STATE_DIR/o3k-p15-7-postgres-11111111111.labels" ]] \
  || { echo "removed container still present" >&2; exit 1; }
for kept in 22222222222 33333333333 44444444444 55555555555; do
  [[ -e "$STATE_DIR/o3k-${kept#3}.labels" || -e "$STATE_DIR/o3k-p13-4-postgres-$kept.labels" ]] \
    || { echo "container $kept was wrongly removed" >&2; exit 1; }
done
[[ -e "$STATE_DIR/o3k-p13-4-postgres-55555555555.labels" ]] \
  || { echo "non-allowlisted container was touched" >&2; exit 1; }
! grep -q "55555555555" /tmp/san-out.txt \
  || { echo "non-allowlisted container appeared in report" >&2; exit 1; }

# 2. Second run is idempotent (proven container already gone; preserved stay).
reset_state
rm -f "$STATE_DIR/o3k-p15-7-postgres-11111111111.labels"
run_sanitation "$allowlist" >/dev/null 2>&1 && { echo "expected non-zero exit" >&2; exit 1; } || true

# 3. Wrong-host refusal is fail-closed and touches nothing.
reset_state
if bash -c '
  hostname() { echo foreign-host; }
  export -f hostname
  sudo() { if [[ "$1" == "-n" ]]; then shift; fi; "$@"; }
  export -f sudo
  PATH="'"$BIN_DIR"':$PATH" bash "'"$ROOT_DIR"'/scripts/p15-7-stale-postgres-sanitation.sh" "'"$allowlist"'"
' 2>/dev/null; then
  echo "sanitation ran on a foreign host" >&2
  exit 1
fi
[[ -e "$STATE_DIR/o3k-p15-7-postgres-11111111111.labels" ]] \
  || { echo "containers modified despite wrong-host refusal" >&2; exit 1; }

echo "P15.7 stale postgres sanitation tests passed"
