#!/usr/bin/env bash
set -Eeuo pipefail

# First multi-host transition: bootstrap block plus one genuine nested host.
export O3K_P15_7_PHASE=s2-boundary
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/p15_7_scale_composition.sh"
