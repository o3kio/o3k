#!/usr/bin/env bash
set -Eeuo pipefail

# Focused protected #1035 lane. The canonical journey performs the shared
# S5 prerequisite and then the real crash/orphan-repair experiment.
export O3K_P15_7_PHASE=1035-crash-recovery
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/p15_7_scale_composition.sh"
