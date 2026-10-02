#!/usr/bin/env bash
set -Eeuo pipefail

# Focused protected host-maintenance lane. The canonical journey performs the
# shared S5 prerequisite, skips #1035, and runs only the accepted maintenance leg.
export O3K_P15_7_PHASE=host-maintenance
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/p15_7_scale_composition.sh"
