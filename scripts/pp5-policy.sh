#!/usr/bin/env bash

# Shared fail-closed policy boundary for PP.5 scale and soak execution.
# Keep this before any TestLab, host, or evidence mutations in every entrypoint.
pp5_deferred_lane() {
  local lane="${1:-unknown}"
  printf 'PP.5 %s: status=DEFERRED_BY_POLICY; no campaign or evidence state was changed\n' \
    "$lane" >&2
  return 3
}
