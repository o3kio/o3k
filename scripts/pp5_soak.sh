#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/pp5-policy.sh"

usage() {
  echo "usage: $0 --tier K-min|K-full --scale 10|20 --duration-seconds N --state-dir DIR --samples FILE --events FILE" >&2
  exit 2
}
fail() {
  printf 'PP.5 soak: classification=EVIDENCE_GAP: %s\n' "$*" >&2
  exit 2
}

tier='' scale='' duration='' state_dir='' samples='' events=''
while (($#)); do
  case "$1" in
    --tier) (($# >= 2)) || usage; tier="$2"; shift 2 ;;
    --scale) (($# >= 2)) || usage; scale="$2"; shift 2 ;;
    --duration-seconds) (($# >= 2)) || usage; duration="$2"; shift 2 ;;
    --state-dir) (($# >= 2)) || usage; state_dir="$2"; shift 2 ;;
    --samples) (($# >= 2)) || usage; samples="$2"; shift 2 ;;
    --events) (($# >= 2)) || usage; events="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[[ "$tier" == K-min && "$scale" == 10 && "$duration" == 7200 \
   || "$tier" == K-full && "$scale" == 20 && "$duration" == 43200 ]] \
  || fail 'tier, scale, and duration do not match the PP.5 contract'
[[ -n "$state_dir" && -n "$samples" && -n "$events" ]] || usage

# Do not accept caller-provided shell hooks as lifecycle, fault, or measurement
# evidence.  A repository-owned producer must own the PostgreSQL process,
# supported API churn, resource sampling, and cleanup before this lane can run.
# Exit before creating directories, truncating files, or changing TestLab state.
pp5_deferred_lane "$tier" || exit "$?"
