#!/usr/bin/env bash
set -Eeuo pipefail

binary="${1:?usage: check-a10-publisher-disabled.sh RELEASE_O3K_BINARY [OTHER_EXECUTABLE_ARTIFACT ...]}"
shift
[[ -f "$binary" && -x "$binary" ]] || {
  echo "release o3k binary is missing or not executable: $binary" >&2
  exit 2
}

output="$(mktemp)"
trap 'rm -f -- "$output"' EXIT
if "$binary" recovery-migrate-v2 --help >"$output" 2>&1; then
  echo "release o3k unexpectedly dispatched the A10.1 migration publisher" >&2
  exit 1
fi
if grep -Fq 'Usage: o3k recovery-migrate-v2' "$output" \
  || ! grep -Fq 'unrecognized subcommand' "$output"; then
  echo "release o3k did not reject the migration command as absent" >&2
  cat "$output" >&2
  exit 1
fi

artifacts=("$binary" "$@")
for artifact in "${artifacts[@]}"; do
  [[ -f "$artifact" && -x "$artifact" ]] || {
    echo "release executable artifact is missing or not executable: $artifact" >&2
    exit 2
  }
  if command -v nm >/dev/null 2>&1; then
    if nm -C --defined-only "$artifact" 2>/dev/null | grep -Fq 'recovery_migration_publisher'; then
      echo "release executable contains linked A10.1 publisher symbols: $artifact" >&2
      exit 1
    fi
  fi

  if command -v strings >/dev/null 2>&1; then
    for marker in O3K_A10_MIGRATION_CRASH_AT O3K_A10_MIGRATION_PAUSE_AT; do
      if strings "$artifact" | grep -Fq "$marker"; then
        echo "release executable contains A10 test fault-injection marker $marker: $artifact" >&2
        exit 1
      fi
    done
    fixture_key="$(awk 'NF && $0 !~ /^-----BEGIN / && $0 !~ /^-----END / { print; exit }' \
      "$(dirname "$0")/../bins/o3k/tests/fixtures/a10-release-verify.pub")"
    if [[ -n "$fixture_key" ]] && strings "$artifact" | grep -Fq -- "$fixture_key"; then
      echo "release executable contains the A10 fixture verification key: $artifact" >&2
      exit 1
    fi
  fi
done

echo "A10.1 migration publisher is absent from release binary: $binary"
