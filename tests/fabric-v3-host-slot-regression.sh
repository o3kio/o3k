#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The chosen management network is dynamic. Address suffixes must never become
# installer host slots; slots are stable ordinals derived from host identity.
source "$root/tests/fabric-v3-host-slot.sh"
for row in 'a 10.18.14.50 2' 'b 10.18.14.51 3' 'c 10.18.14.52 4'; do
  read -r host address expected <<<"$row"
  actual="$(fabric_v3_host_slot "$host")"
  [[ "$actual" == "$expected" ]] || {
    printf 'host %s at %s mapped to slot %s, expected %s\n' \
      "$host" "$address" "$actual" "$expected" >&2
    exit 1
  }
done
if fabric_v3_host_slot d >/dev/null 2>&1; then
  echo 'unsupported host identity unexpectedly produced a slot' >&2
  exit 1
fi
