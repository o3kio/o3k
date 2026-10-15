#!/usr/bin/env bash
set -Eeuo pipefail

# A scale tier is deliberately unavailable until the repository has a native
# producer for the complete PP.5 runtime evidence contract.  In particular,
# the existing P15.7 journey is not sufficient: it does not observe the full
# networking, isolation, MTU, or restart contract required here.  Keep this
# entry point side-effect free so it cannot create workloads and then fail
# after producing partial or misleading acceptance artifacts.
die() {
  printf 'PP.5 scale tier: classification=EVIDENCE_GAP: %s\n' "$*" >&2
  exit 2
}

tier=""
hosts=""
while (($#)); do
  case "$1" in
    --tier)
      (($# >= 2)) || die '--tier requires a value'
      tier="$2"
      shift 2
      ;;
    --hosts)
      (($# >= 2)) || die '--hosts requires a value'
      hosts="$2"
      shift 2
      ;;
    *)
      [[ -z "$tier" ]] || die "unknown argument: $1"
      tier="$1"
      shift
      ;;
  esac
done
case "$tier" in
  S3) expected_hosts=3 ;;
  S10) expected_hosts=10 ;;
  S20) expected_hosts=20 ;;
  *) die 'usage: pp5_scale_tier.sh --tier S3|S10|S20 [--hosts COUNT]' ;;
esac
[[ -n "$hosts" ]] || hosts="$expected_hosts"
[[ "$hosts" == "$expected_hosts" ]] || die "$tier requires exactly $expected_hosts eligible hosts"

die 'native exact-release scale producer is unavailable; no TestLab or evidence state was changed'
