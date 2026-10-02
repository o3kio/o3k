#!/usr/bin/env bash
set -Eeuo pipefail

# Focused protected S5 lane. It shares the canonical real-host journey and
# stops at post-reboot without entering crash injection or maintenance.
export O3K_P15_7_PHASE=s5-scale
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/p15_7_scale_composition.sh"
