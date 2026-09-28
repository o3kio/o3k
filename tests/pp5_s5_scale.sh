#!/usr/bin/env bash
set -Eeuo pipefail

# Focused protected S5 lane. It shares the authenticated real-host preflight
# and journey ownership boundary with PP.5, but stops at post-reboot and never
# enters crash injection or host maintenance.
export O3K_P15_7_FOCUSED_PHASE=s5
export O3K_P15_7_JOURNEY_COMMAND="${O3K_P15_7_JOURNEY_COMMAND:-bash scripts/p15-7-real-host-journey.sh}"
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/p15_7_scale_composition.sh"
