#!/usr/bin/env bash
set -Eeuo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow="$root_dir/.github/workflows/pp5-focused-lanes.yml"
grep -Fq "s5-scale" "$workflow"
grep -Fq "1035-crash-recovery" "$workflow"
grep -Fq "host-maintenance" "$workflow"
grep -Fq "tests/pp5_s5_scale.sh" "$workflow"
grep -Fq "tests/pp5_1035_crash_recovery.sh" "$workflow"
grep -Fq "tests/pp5_host_maintenance.sh" "$workflow"
grep -Fq "O3K_P15_7_1035_JOURNEY_COMMAND is required" "$root_dir/tests/pp5_1035_crash_recovery.sh"
grep -Fq "O3K_P15_7_MAINTENANCE_JOURNEY_COMMAND is required" "$root_dir/tests/pp5_host_maintenance.sh"
echo "PP.5 focused lane guards passed"
