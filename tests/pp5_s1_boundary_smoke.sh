#!/usr/bin/env bash
set -Eeuo pipefail

# One-host lower-bound smoke: the canonical bootstrap compute block only.
export O3K_P15_7_PHASE=s1-boundary
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/p15_7_scale_composition.sh"
