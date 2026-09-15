#!/usr/bin/env bash
set -Eeuo pipefail

# Cheap, fail-closed protected-run preflight. It runs after immutable checkout
# and before any image, database, P13, or VM work. The protected exchange
# command must write an authority envelope to O3K_P15_7_AUTHORITY_OUTPUT_FILE.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${O3K_REAL_HOST_ARTIFACT_DIR:-$ROOT_DIR/target/real-host-workflow-artifacts}"
ARTIFACT="${O3K_P15_7_PREFLIGHT_ARTIFACT:-$ARTIFACT_DIR/p15-7-protected-preflight.json}"
RUN_ID="${GITHUB_RUN_ID:-local-$$}"
SOURCE_SHA="${O3K_P15_7_SOURCE_SHA:-${GITHUB_SHA:-}}"
JOURNEY="${O3K_P15_7_JOURNEY_SCRIPT:-$ROOT_DIR/scripts/p15-7-real-host-journey.sh}"
MIN_TTL="${O3K_P15_7_MIN_TOKEN_TTL_SECONDS:-1800}"
EXCHANGE="${O3K_P15_7_OPERATOR_EXCHANGE_COMMAND:-}"
TEMP_ROOT="${RUNNER_TEMP:-/tmp}"
LIBVIRT_IMAGE_ROOT="${O3K_P15_7_LIBVIRT_IMAGE_ROOT:-/var/lib/libvirt/images}"
PREFLIGHT_SUCCESS=false

cleanup_preflight() {
  rm -f -- "${EXCHANGE_OUTPUT:-}" "${EXCHANGE_OUTPUT:-}.stdout" "${EXCHANGE_OUTPUT:-}.stderr"
  if [[ "$PREFLIGHT_SUCCESS" != true ]]; then
    rm -f -- "${TOKEN_FILE:-}" "${TOKEN_MARKER:-}"
  fi
}

[[ "$ARTIFACT_DIR" == /* && "$ARTIFACT_DIR" != *..* && ! -L "$ARTIFACT_DIR" ]] || blocked artifact_dir_unsafe
mkdir -p -- "$ARTIFACT_DIR"
chmod 0755 -- "$ARTIFACT_DIR"

write_artifact() {
  local status="$1" reason="$2" authority="$3" ttl="$4" capacity="$5"
  python3 - "$ARTIFACT" "$status" "$reason" "$authority" "$ttl" "$capacity" "$SOURCE_SHA" <<'PY'
import json, os, sys, time
path, status, reason, authority, ttl, capacity, sha = sys.argv[1:]
doc = {
    "artifact_type": "o3k-p15-7-protected-preflight",
    "schema_version": 1,
    "status": status,
    "reason": reason,
    "redacted": True,
    "tested_source_sha": sha if len(sha) == 40 else "",
    "system_operator_authority": authority,
    "token_ttl": ttl,
    "multi_vm_capacity": capacity,
    "finished_at": int(time.time()),
}
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as stream:
    json.dump(doc, stream, indent=2, sort_keys=True)
    stream.write("\n")
os.replace(tmp, path)
PY
  chmod 0644 -- "$ARTIFACT"
}

blocked() {
  local reason="$1"
  rm -f -- "${TOKEN_FILE:-}" "${TOKEN_MARKER:-}" "${EXCHANGE_OUTPUT:-}"
  write_artifact blocked "$reason" blocked blocked blocked
  echo "P15_7_PROTECTED_PREFLIGHT: BLOCKED ($reason)" >&2
  exit 2
}

[[ "$SOURCE_SHA" =~ ^[0-9a-fA-F]{40}$ ]] || blocked exact_source_sha_required
[[ "$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || true)" == "$SOURCE_SHA" ]] || blocked source_checkout_mismatch
[[ -f "$JOURNEY" && ! -L "$JOURNEY" ]] || blocked journey_driver_missing
grep -Fq 'o3k init' "$JOURNEY" || blocked journey_driver_contract_missing
grep -Fq 'o3k-p15-7-journey-owned-v1' "$JOURNEY" || blocked journey_ownership_contract_missing
[[ "$MIN_TTL" =~ ^[1-9][0-9]*$ ]] || blocked invalid_minimum_token_ttl

for command in python3 curl virsh docker nproc awk stat df realpath; do
  command -v "$command" >/dev/null 2>&1 || blocked "missing_command:$command"
done
[[ "$TEMP_ROOT" == /* && -d "$TEMP_ROOT" && ! -L "$TEMP_ROOT" && "$TEMP_ROOT" != *..* ]] || blocked runner_temp_unsafe
TEMP_ROOT="$(realpath -e -- "$TEMP_ROOT")"
[[ "$LIBVIRT_IMAGE_ROOT" == /* && -d "$LIBVIRT_IMAGE_ROOT" && ! -L "$LIBVIRT_IMAGE_ROOT" && "$LIBVIRT_IMAGE_ROOT" != *..* ]] \
  || blocked libvirt_image_root_unavailable
LIBVIRT_IMAGE_ROOT="$(realpath -e -- "$LIBVIRT_IMAGE_ROOT")"
TOKEN_FILE="${TEMP_ROOT%/}/o3k-p15-7-operator-${RUN_ID}.token"
TOKEN_MARKER="${TOKEN_FILE}.o3k-owned"
EXCHANGE_OUTPUT="${TEMP_ROOT%/}/o3k-p15-7-authority-${RUN_ID}.json"
trap cleanup_preflight EXIT
[[ -e "${O3K_REAL_HOST_KVM_PATH:-/dev/kvm}" ]] || blocked kvm_unavailable
[[ ! -L "${O3K_REAL_HOST_KVM_PATH:-/dev/kvm}" ]] || blocked kvm_path_is_symlink
virsh -c qemu:///system uri >/dev/null 2>&1 || blocked libvirt_unavailable
docker info >/dev/null 2>&1 || blocked docker_unavailable

# Reserve capacity for two independent 2-vCPU/2-GiB guests and their control
# plane. These are minimums, not a substitute for the journey's real checks.
cpus="$(nproc)"
mem_kib="$(awk '/MemAvailable:/ {print $2; exit}' /proc/meminfo)"
free_kib="$(df -Pk "$TEMP_ROOT" | awk 'NR==2 {print $4}')"
libvirt_free_kib="$(df -Pk "$LIBVIRT_IMAGE_ROOT" 2>/dev/null | awk 'NR==2 {print $4}')"
nodeinfo="$(virsh -c qemu:///system nodeinfo 2>/dev/null || true)"
libvirt_cpus="$(awk -F: '/CPU\(s\):/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' <<<"$nodeinfo")"
libvirt_mem_kib="$(awk -F: '/Memory size:/ {gsub(/[[:space:]]KiB/, "", $2); gsub(/[[:space:]]/, "", $2); print $2; exit}' <<<"$nodeinfo")"
[[ "$cpus" =~ ^[0-9]+$ && "$cpus" -ge 4 ]] || blocked multi_vm_capacity_insufficient_cpu
[[ "$mem_kib" =~ ^[0-9]+$ && "$mem_kib" -ge 6144000 ]] || blocked multi_vm_capacity_insufficient_memory
[[ "$free_kib" =~ ^[0-9]+$ && "$free_kib" -ge 20971520 ]] || blocked multi_vm_capacity_insufficient_disk
[[ "$libvirt_free_kib" =~ ^[0-9]+$ && "$libvirt_free_kib" -ge 20971520 ]] || blocked multi_vm_libvirt_disk_capacity_unavailable
[[ "$libvirt_cpus" =~ ^[0-9]+$ && "$libvirt_cpus" -ge 4 ]] || blocked multi_vm_libvirt_cpu_capacity_unavailable
[[ "$libvirt_mem_kib" =~ ^[0-9]+$ && "$libvirt_mem_kib" -ge 6144000 ]] || blocked multi_vm_libvirt_memory_capacity_unavailable

# O3K federation is configured by the protected deployment, not invented by
# this repository. The exchange command must use that trust and return the
# canonical O3K authority; no password/project token is accepted here.
issuer="${O3K_P15_7_OIDC_ISSUER:-}"
audience="${O3K_P15_7_OIDC_AUDIENCE:-}"
discovery="${O3K_P15_7_OIDC_DISCOVERY_URL:-}"
[[ "$issuer" =~ ^https://[^[:space:]]+$ ]] || blocked oidc_issuer_missing_or_invalid
[[ "$audience" =~ ^[^[:space:]]+$ ]] || blocked oidc_audience_missing_or_invalid
[[ "$discovery" =~ ^https://[^[:space:]]+$ ]] || blocked oidc_discovery_missing_or_invalid
[[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]] \
  || blocked oidc_workflow_identity_unavailable
curl --fail --silent --show-error --connect-timeout 5 --max-time 15 \
  --proto '=https' --tlsv1.2 "$discovery" -o /dev/null \
  || blocked oidc_discovery_unreachable
[[ -n "$EXCHANGE" ]] || blocked system_operator_authority_unavailable

umask 077
rm -f -- "$TOKEN_FILE" "$TOKEN_MARKER" "$EXCHANGE_OUTPUT"
touch -- "$EXCHANGE_OUTPUT"
chmod 0600 -- "$EXCHANGE_OUTPUT"
export O3K_P15_7_AUTHORITY_OUTPUT_FILE="$EXCHANGE_OUTPUT"
# Suppress both streams so a helper cannot leak an OIDC or native token.
if ! bash -lc "$EXCHANGE" >"$EXCHANGE_OUTPUT.stdout" 2>"$EXCHANGE_OUTPUT.stderr"; then
  rm -f -- "$EXCHANGE_OUTPUT.stdout" "$EXCHANGE_OUTPUT.stderr"
  blocked operator_authority_exchange_failed
fi
rm -f -- "$EXCHANGE_OUTPUT.stdout" "$EXCHANGE_OUTPUT.stderr"
[[ -s "$EXCHANGE_OUTPUT" && ! -L "$EXCHANGE_OUTPUT" ]] || blocked operator_authority_envelope_missing
[[ "$(stat -c '%a' "$EXCHANGE_OUTPUT" 2>/dev/null || true)" == 600 ]] \
  || blocked operator_authority_envelope_permissions_invalid
[[ "$(stat -c '%u' "$EXCHANGE_OUTPUT" 2>/dev/null || true)" == "$(id -u)" ]] \
  || blocked operator_authority_envelope_owner_invalid

validation="$(python3 - "$EXCHANGE_OUTPUT" "$issuer" "$audience" "$MIN_TTL" <<'PY'
import base64, json, pathlib, re, sys, time
path, issuer, audience, minimum = sys.argv[1:]
minimum = int(minimum)
doc = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
if doc.get("authority_source") != "oidc-federated":
    raise SystemExit("oidc_federation_required")
if doc.get("signature_verified") is not True:
    raise SystemExit("authority_signature_unverified")
token = doc.get("token")
if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~-]+", token):
    raise SystemExit("token_missing")
claims = doc.get("claims") if isinstance(doc.get("claims"), dict) else {}
if token.count(".") == 2:
    try:
        part = token.split(".")[1]
        decoded = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        if isinstance(decoded, dict):
            claims = {**claims, **decoded}
    except Exception:
        raise SystemExit("jwt_payload_invalid")
if claims.get("iss") != issuer:
    raise SystemExit("issuer_mismatch")
aud = claims.get("aud")
if not (aud == audience or (isinstance(aud, list) and audience in aud)):
    raise SystemExit("audience_mismatch")
scope = claims.get("scope")
if isinstance(scope, dict):
    scope = scope.get("kind")
if scope != "system":
    raise SystemExit("system_scope_required")
roles = claims.get("roles", claims.get("role", claims.get("capabilities", [])))
if isinstance(roles, str):
    roles = roles.split()
if not isinstance(roles, list) or "operator" not in roles:
    raise SystemExit("operator_role_required")
try:
    exp = int(claims["exp"])
except Exception:
    raise SystemExit("expiry_missing")
remaining = exp - int(time.time())
if remaining < minimum:
    raise SystemExit("insufficient_token_ttl")
print(remaining)
PY
)" || blocked "$validation"

python3 - "$EXCHANGE_OUTPUT" "$TOKEN_FILE" <<'PY'
import json, os, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
token = doc["token"].encode("utf-8")
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, token + b"\n")
finally:
    os.close(fd)
PY
printf 'o3k-p15-7-operator-token-v1\nrun=%s\n' "$RUN_ID" >"$TOKEN_MARKER"
chmod 0600 -- "$TOKEN_MARKER"
rm -f -- "$EXCHANGE_OUTPUT"

write_artifact passed preflight passed sufficient passed
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'P15_7_PROTECTED_PREFLIGHT=PASS\n'
    printf 'SYSTEM_OPERATOR_AUTHORITY=PASS\n'
    printf 'TOKEN_TTL=SUFFICIENT\n'
    printf 'MULTI_VM_CAPACITY=PASS\n'
    printf 'O3K_P15_7_OPERATOR_TOKEN_FILE=%s\n' "$TOKEN_FILE"
  } >>"$GITHUB_OUTPUT"
fi
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'O3K_P15_7_OPERATOR_TOKEN_FILE=%s\n' "$TOKEN_FILE" >>"$GITHUB_ENV"
fi
PREFLIGHT_SUCCESS=true
echo "P15_7_PROTECTED_PREFLIGHT: PASS"
echo "SYSTEM_OPERATOR_AUTHORITY: PASS"
echo "TOKEN_TTL: SUFFICIENT"
echo "MULTI_VM_CAPACITY: PASS"
