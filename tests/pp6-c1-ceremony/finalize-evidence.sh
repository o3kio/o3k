#!/usr/bin/env bash
# Hash only retained qualification evidence. The work/ directory contains
# transient guest scratch (including private SSH material and QEMU-owned disk
# images), so it is deliberately not evidence and may be unreadable to the
# invoking user. This helper never changes ownership or permissions.
set -Eeuo pipefail

if [[ $# -ne 1 || ! -d "$1" ]]; then
  echo "usage: $0 EVIDENCE_DIR" >&2
  exit 2
fi

evidence_dir="$(cd "$1" && pwd -P)"
(
  cd "$evidence_dir"
  find . -path ./work -prune -o -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 -r sha256sum >SHA256SUMS
)
