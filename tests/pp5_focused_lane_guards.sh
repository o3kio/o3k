#!/usr/bin/env bash
set -Eeuo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow="$root_dir/.github/workflows/real-host-validation.yml"
dispatcher="$root_dir/.github/workflows/p15-7-protected-dispatch.yml"
preflight="$root_dir/.github/workflows/p15-7-protected-preflight.yml"
journey="$root_dir/scripts/p15-7-real-host-journey.sh"
test -f "$workflow"
grep -Fq 'lane:' "$workflow"
grep -Fq 'default: integrated' "$workflow"
for lane in integrated s1-boundary s2-boundary s5-scale 1035-crash-recovery host-maintenance; do
    grep -Fq -- "- $lane" "$workflow"
done
grep -Fq 'case "${PP5_LANE}" in' "$workflow"
grep -Fq 'integrated) bash tests/p15_7_scale_composition.sh' "$workflow"
grep -Fq 's5-scale) bash tests/pp5_s5_scale.sh' "$workflow"
grep -Fq 's1-boundary) bash tests/pp5_s1_boundary_smoke.sh' "$workflow"
grep -Fq 's2-boundary) bash tests/pp5_s2_boundary_smoke.sh' "$workflow"
grep -Fq '1035-crash-recovery) bash tests/pp5_1035_crash_recovery.sh' "$workflow"
grep -Fq 'host-maintenance) bash tests/pp5_host_maintenance.sh' "$workflow"
grep -Fq 'O3K_P15_7_JOURNEY_COMMAND: bash scripts/p15-7-real-host-journey.sh' "$workflow"
for protected_workflow in "$dispatcher" "$preflight"; do
    for lane in s1-boundary s2-boundary s5-scale 1035-crash-recovery host-maintenance integrated; do
        grep -Fq -- "- $lane" "$protected_workflow"
    done
    grep -Fq 'integrated|s1-boundary|s2-boundary|s5-scale|1035-crash-recovery|host-maintenance' "$protected_workflow"
done
! grep -Fq 'O3K_P15_7_1035_JOURNEY_COMMAND' "$workflow" "$root_dir/tests"/*.sh
! grep -Fq 'O3K_P15_7_MAINTENANCE_JOURNEY_COMMAND' "$workflow" "$root_dir/tests"/*.sh
test ! -e "$root_dir/.github/workflows/pp5-focused-lanes.yml"
for pair in \
    'tests/pp5_s5_scale.sh:export O3K_P15_7_PHASE=s5-scale' \
    'tests/pp5_s1_boundary_smoke.sh:export O3K_P15_7_PHASE=s1-boundary' \
    'tests/pp5_s2_boundary_smoke.sh:export O3K_P15_7_PHASE=s2-boundary' \
    'tests/pp5_1035_crash_recovery.sh:export O3K_P15_7_PHASE=1035-crash-recovery' \
    'tests/pp5_host_maintenance.sh:export O3K_P15_7_PHASE=host-maintenance'; do
    file="${pair%%:*}"; text="${pair#*:}"
    grep -Fq "$text" "$root_dir/$file"
    grep -Fq 'p15_7_scale_composition.sh' "$root_dir/$file"
done
grep -Fq 'integrated|s5-scale|1035-crash-recovery|host-maintenance|s1-boundary|s2-boundary' "$journey"
grep -Fq 'RUN_CRASH=false' "$journey"
grep -Fq 'RUN_MAINTENANCE=false' "$journey"
grep -Fq 'if [[ "${RUN_CRASH}" == true ]]' "$journey"
grep -Fq 'if [[ "${RUN_MAINTENANCE}" != true ]]' "$journey"
echo "PP.5 focused lane guards passed"
