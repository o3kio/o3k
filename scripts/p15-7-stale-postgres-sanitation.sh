#!/usr/bin/env bash
set -Eeuo pipefail

# Bounded, explicitly allowlisted one-time sanitation of stale OWNED O3K
# disposable PostgreSQL containers observed on runner-2404 (read-only
# inspection runs 35342436821 / 35345964079, 2026-09-18). These containers
# belong to terminal P15.7/P13.4 runs whose cleanup never executed; each
# carries a random docker veth pair that pollutes the real-host foreign-link
# digest.
#
# A container is removed only when EVERY check passes:
#   - hostname is exactly runner-2404 (refuse to run anywhere else)
#   - container name is exactly in the allowlist
#   - live docker labels prove O3K ownership: o3k.owner=o3k,
#     o3k.run_id == run id from the allowlist, o3k.phase == phase from the
#     allowlist, o3k.source_sha is a 40-hex sha
#   - the owning GitHub run is terminal (conclusion != empty, status ==
#     completed) and the container's o3k.source_sha label matches that run's
#     head_sha — two-dimensional proof, never a name prefix alone
# Anything failing any check is preserved and reported. Never touches
# containers not in the allowlist.
#
# Usage: p15-7-stale-postgres-sanitation.sh ALLOWLIST_FILE
# Allowlist: one `container-name phase run-id` triple per line; `#` comments
# and blank lines are ignored.

EXPECTED_HOST="runner-2404"
PRESERVED=0

die() {
  echo "stale postgres sanitation blocked: $*" >&2
  exit 1
}

(($# == 1)) || { echo "usage: $0 ALLOWLIST_FILE" >&2; exit 2; }
ALLOWLIST="$1"

host="$(hostname 2>/dev/null || true)"
[[ -n "$host" && "$host" == "$EXPECTED_HOST" ]] \
  || die "refusing to run on host '${host:-unknown}' (expected $EXPECTED_HOST)"
[[ -r "$ALLOWLIST" && -f "$ALLOWLIST" && ! -L "$ALLOWLIST" ]] \
  || die "allowlist is not a readable regular file"
command -v curl >/dev/null 2>&1 || die "curl is required to prove owning runs are terminal"
[[ -n "${GITHUB_TOKEN:-}" ]] || die "GITHUB_TOKEN is required to prove owning runs are terminal"
sudo -n docker info >/dev/null 2>&1 || die "cannot inspect docker"

label() {
  sudo -n docker inspect -f "{{index .Config.Labels \"$1\"}}" "$2" 2>/dev/null || true
}

run_terminal_and_sha_match() {
  local run_id="$1" expected_sha="$2" payload status conclusion head_sha
  payload="$(curl -fsS --max-time 20 \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/o3kio/o3k/actions/runs/${run_id}" 2>/dev/null || true)"
  [[ -n "$payload" ]] || return 1
  read -r status conclusion head_sha < <(python3 - "$payload" <<'PY'
import json, sys
try:
    run = json.loads(sys.argv[1])
except json.JSONDecodeError:
    raise SystemExit(0)
print(run.get("status", ""), run.get("conclusion") or "", run.get("head_sha", ""))
PY
)
  [[ "$status" == completed && -n "$conclusion" ]] || return 1
  [[ "$head_sha" == "$expected_sha" ]] || return 1
}

while IFS= read -r line; do
  [[ -n "$line" && "${line:0:1}" != "#" ]] || continue
  read -r container phase run_id extra <<<"$line"
  if [[ -n "${extra:-}" || -z "${container:-}" || -z "${phase:-}" || -z "${run_id:-}" ]]; then
    echo "PRESERVED ${container:-?} malformed_allowlist_row"
    PRESERVED=1
    continue
  fi
  [[ "$phase" =~ ^[a-z0-9-]+$ && "$run_id" =~ ^[0-9]+$ ]] \
    || { echo "PRESERVED $container invalid_identity"; PRESERVED=1; continue; }
  [[ "$container" == "o3k-${phase}-postgres-${run_id}" ]] \
    || { echo "PRESERVED $container name_not_run_owned"; PRESERVED=1; continue; }

  # Already gone — idempotent success.
  if ! sudo -n docker inspect "$container" >/dev/null 2>&1; then
    continue
  fi

  owner="$(label o3k.owner "$container")"
  run_label="$(label o3k.run_id "$container")"
  phase_label="$(label o3k.phase "$container")"
  sha_label="$(label o3k.source_sha "$container")"
  [[ "$owner" == o3k && "$run_label" == "$run_id" && "$phase_label" == "$phase" ]] \
    || { echo "PRESERVED $container ownership_labels_unproven"; PRESERVED=1; continue; }
  [[ "$sha_label" =~ ^[0-9a-fA-F]{40}$ ]] \
    || { echo "PRESERVED $container source_sha_label_invalid"; PRESERVED=1; continue; }

  if ! run_terminal_and_sha_match "$run_id" "$sha_label"; then
    echo "PRESERVED $container owning_run_not_terminal_or_sha_mismatch"
    PRESERVED=1
    continue
  fi

  sudo -n docker rm --force "$container" >/dev/null 2>&1 \
    || { echo "PRESERVED $container removal_failed"; PRESERVED=1; continue; }
  if sudo -n docker inspect "$container" >/dev/null 2>&1; then
    echo "PRESERVED $container remains_after_removal"
    PRESERVED=1
    continue
  fi
  echo "REMOVED $container"
done <"$ALLOWLIST"

(( PRESERVED == 0 )) || exit 1
echo "stale owned postgres sanitation completed"
