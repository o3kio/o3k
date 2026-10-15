#!/usr/bin/env bash

# Shared fail-closed policy boundary for PP.5 scale and soak execution.
# Keep this before any TestLab, host, or evidence mutations in every entrypoint.
# The JSON line is a disposition record on stdout, not an acceptance artifact.
# Acceptance evidence remains owned by validate_pp5_evidence.py and must never
# treat a deferred disposition as a successful result.
pp5_deferred_lane() {
  local lane="${1:-unknown}"
  case "$lane" in
    S3|S10|S20|K-min|K-full|s3-scale|s10-scale|s20-scale|k-min|k-full) ;;
    *)
      printf 'PP.5 policy: invalid deferred lane identifier\n' >&2
      return 2
      ;;
  esac
  printf '{"record_type":"o3k.pp5-lane-disposition.v1","lane":"%s","status":"DEFERRED_BY_POLICY","acceptance_result":"NOT_RUN","evidence_produced":false,"state_mutated":false}\n' \
    "$lane"
  printf 'PP.5 %s: status=DEFERRED_BY_POLICY; no campaign or evidence state was changed\n' \
    "$lane" >&2
  return 3
}
