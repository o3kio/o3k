#!/usr/bin/env bash

# Validate the small, run-owned marker written beside a workflow workload
# image. Generic diagnostic runs use the default phase; PP.5 acceptance lanes
# must pass their phase explicitly so the two TestLab epochs cannot be confused.
p15_7_verify_disposable_image_marker() {
  [[ "$#" -eq 2 || "$#" -eq 3 ]] || return 1

  local marker_path="$1"
  local expected_run="$2"
  local expected_phase=generic
  [[ "$#" -eq 2 ]] || expected_phase="$3"
  local marker_size
  local -a marker_lines=()

  [[ -n "$expected_run" ]] || return 1
  case "$expected_phase" in
    generic|pp5) ;;
    *) return 1 ;;
  esac
  [[ -f "$marker_path" && ! -L "$marker_path" ]] || return 1
  marker_size="$(wc -c <"$marker_path")" || return 1
  [[ "$marker_size" -le 256 ]] || return 1
  mapfile -t marker_lines <"$marker_path" || return 1
  [[ "${#marker_lines[@]}" -eq 3 ]] || return 1
  [[ "${marker_lines[0]}" == 'o3k-disposable-image-v1' ]] || return 1
  [[ "${marker_lines[1]}" == "run=$expected_run" ]] || return 1
  [[ "${marker_lines[2]}" == "phase=$expected_phase" ]] || return 1
}
