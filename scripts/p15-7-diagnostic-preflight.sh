#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${O3K_REAL_HOST_ARTIFACT_DIR:-$ROOT_DIR/target/p15-7-diagnostic-artifacts}"
PREFLIGHT_ARTIFACT="$ARTIFACT_DIR/p15-7-protected-preflight.json"
OUTPUT="$ARTIFACT_DIR/p15-7-diagnostic-fast-lane-preflight.json"
SOURCE_SHA="${O3K_P15_7_SOURCE_SHA:-${GITHUB_SHA:-}}"
TEMP_ROOT="${RUNNER_TEMP:-/tmp}"
LIBVIRT_IMAGE_ROOT="${O3K_P15_7_LIBVIRT_IMAGE_ROOT:-/var/lib/libvirt/images}"

[[ "$SOURCE_SHA" =~ ^[0-9a-fA-F]{40}$ ]] || {
  echo "P15.7 diagnostic preflight: exact source SHA required" >&2
  exit 2
}
mkdir -p -- "$ARTIFACT_DIR"

write_result() {
  local status="$1" reason="$2" cpus="$3" mem_kib="$4" temp_free_kib="$5" image_free_kib="$6" libvirt_cpus="$7" libvirt_mem_kib="$8"
  python3 - "$OUTPUT" "$PREFLIGHT_ARTIFACT" "$SOURCE_SHA" "$status" "$reason" \
    "$cpus" "$mem_kib" "$temp_free_kib" "$image_free_kib" "$libvirt_cpus" "$libvirt_mem_kib" <<'PY'
import json, pathlib, sys
(output, authority_path, sha, status, reason, cpus, mem_kib, temp_free_kib,
 image_free_kib, libvirt_cpus, libvirt_mem_kib) = sys.argv[1:]
try:
    authority = json.loads(pathlib.Path(authority_path).read_text(encoding="utf-8"))
    authority_status = authority.get("status", "unavailable")
    authority_reason = authority.get("reason", "unavailable")
except (OSError, json.JSONDecodeError):
    authority_status, authority_reason = "unavailable", "artifact_unavailable"
document = {
    "artifact_type": "o3k-p15-7-diagnostic-fast-lane-preflight",
    "schema_version": 1,
    "diagnostic_only": True,
    "final_completion_evidence": False,
    "redacted": True,
    "tested_source_sha": sha.lower(),
    "status": status,
    "reason": reason,
    "authority_preflight": {"status": authority_status, "reason": authority_reason},
    "multi_vm_capacity": {
        "status": "passed" if status == "passed" else ("not_run" if reason == "authority_preflight_failed" else "failed"),
        "minimum_cpu_count": 4,
        "minimum_available_memory_kib": 6144000,
        "minimum_free_disk_kib": 20971520,
        "minimum_libvirt_cpu_count": 4,
        "minimum_libvirt_memory_kib": 6144000,
        "cpu_count": int(cpus) if cpus.isdigit() else None,
        "available_memory_kib": int(mem_kib) if mem_kib.isdigit() else None,
        "runner_temp_free_kib": int(temp_free_kib) if temp_free_kib.isdigit() else None,
        "libvirt_image_free_kib": int(image_free_kib) if image_free_kib.isdigit() else None,
        "libvirt_cpu_count": int(libvirt_cpus) if libvirt_cpus.isdigit() else None,
        "libvirt_memory_kib": int(libvirt_mem_kib) if libvirt_mem_kib.isdigit() else None,
    },
}
pathlib.Path(output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  chmod 0644 -- "$OUTPUT"
}

if ! O3K_REAL_HOST_ARTIFACT_DIR="$ARTIFACT_DIR" \
  O3K_P15_7_SOURCE_SHA="$SOURCE_SHA" \
  O3K_P15_7_JOURNEY_SCRIPT="$ROOT_DIR/scripts/p15-7-real-host-journey.sh" \
  O3K_P15_7_AUTHORITY_MODE=testlab-keycloak \
  O3K_P15_7_KEYCLOAK_AUTHORITY_SCRIPT="$ROOT_DIR/scripts/p15-7-keycloak-authority.sh" \
  bash "$ROOT_DIR/scripts/p15-7-protected-preflight.sh"; then
  write_result blocked authority_preflight_failed "" "" "" "" "" ""
  exit 1
fi

cpus="$(nproc 2>/dev/null || true)"
mem_kib="$(awk '/MemAvailable:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)"
temp_free_kib="$(df -Pk "$TEMP_ROOT" 2>/dev/null | awk 'NR==2 {print $4}')"
image_free_kib="$(df -Pk "$LIBVIRT_IMAGE_ROOT" 2>/dev/null | awk 'NR==2 {print $4}')"
nodeinfo="$(virsh -c qemu:///system nodeinfo 2>/dev/null || true)"
libvirt_cpus="$(awk -F: '/CPU\(s\):/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' <<<"$nodeinfo")"
libvirt_mem_kib="$(awk -F: '/Memory size:/ {gsub(/[[:space:]KiB]/, "", $2); gsub(/[[:space:]]/, "", $2); print $2; exit}' <<<"$nodeinfo")"

reason=ready
[[ "$cpus" =~ ^[0-9]+$ && "$cpus" -ge 4 ]] || reason=multi_vm_capacity_insufficient_cpu
[[ "$mem_kib" =~ ^[0-9]+$ && "$mem_kib" -ge 6144000 ]] || reason=multi_vm_capacity_insufficient_memory
[[ "$temp_free_kib" =~ ^[0-9]+$ && "$temp_free_kib" -ge 20971520 ]] || reason=multi_vm_capacity_insufficient_disk
[[ "$image_free_kib" =~ ^[0-9]+$ && "$image_free_kib" -ge 20971520 ]] || reason=multi_vm_libvirt_disk_capacity_unavailable
[[ "$libvirt_cpus" =~ ^[0-9]+$ && "$libvirt_cpus" -ge 4 ]] || reason=multi_vm_libvirt_cpu_capacity_unavailable
[[ "$libvirt_mem_kib" =~ ^[0-9]+$ && "$libvirt_mem_kib" -ge 6144000 ]] || reason=multi_vm_libvirt_memory_capacity_unavailable

if [[ "$reason" == ready ]]; then
  write_result passed ready "$cpus" "$mem_kib" "$temp_free_kib" "$image_free_kib" "$libvirt_cpus" "$libvirt_mem_kib"
  echo "P15.7 diagnostic authority/capacity preflight: PASS"
else
  write_result failed "$reason" "$cpus" "$mem_kib" "$temp_free_kib" "$image_free_kib" "$libvirt_cpus" "$libvirt_mem_kib"
  echo "P15.7 diagnostic authority/capacity preflight: FAIL ($reason)" >&2
  exit 1
fi
