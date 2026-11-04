#!/usr/bin/env bash
set -Eeuo pipefail

# Canonical public test-key marker from bins/o3k/tests/fixtures/a10-release-verify.pub.
# Keep synchronized by tests/a10-publisher-key-drift.sh. It is public test data,
# not signing material; production artifacts must never embed it.
TEST_VERIFICATION_KEY_MARKER='MCowBQYDK2VwAyEArPErSswcZgqDJq7TQDnvtyil5JZIgkD1CpMqt6ulF1E='

binary="${1:?usage: check-a10-publisher-disabled.sh RELEASE_O3K_BINARY [OTHER_EXECUTABLE_ARTIFACT ...]}"
shift
[[ -f "$binary" && -x "$binary" ]] || {
  echo "release o3k binary is missing or not executable: $binary" >&2
  exit 2
}

inspection_dir="$(mktemp -d)"
trap 'rm -rf -- "$inspection_dir"' EXIT
output="$inspection_dir/dispatch-output"
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
for tool in nm strings; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "$tool (binutils) is required to inspect release executables" >&2
    exit 2
  }
done

reject_if_present() {
  local marker="$1" description="$2" artifact="$3" inspected_file="$4" status=0
  grep -Fq -- "$marker" "$inspected_file" || status=$?
  case "$status" in
    0)
      echo "$description: $artifact" >&2
      exit 1
      ;;
    1) ;;
    *)
      echo "could not search inspected release executable output: $artifact" >&2
      exit 2
      ;;
  esac
}

for artifact in "${artifacts[@]}"; do
  [[ -f "$artifact" && -x "$artifact" ]] || {
    echo "release executable artifact is missing or not executable: $artifact" >&2
    exit 2
  }
  if ! nm -C --defined-only "$artifact" >"$inspection_dir/symbols"; then
    echo "could not inspect release executable symbols: $artifact" >&2
    exit 2
  fi
  reject_if_present 'recovery_migration_publisher' \
    'release executable contains linked A10.1 publisher symbols' "$artifact" "$inspection_dir/symbols"

  if ! strings "$artifact" >"$inspection_dir/strings"; then
    echo "could not inspect release executable strings: $artifact" >&2
    exit 2
  fi
  for marker in O3K_A10_MIGRATION_CRASH_AT O3K_A10_MIGRATION_PAUSE_AT; do
    reject_if_present "$marker" \
      "release executable contains A10 test fault-injection marker $marker" "$artifact" "$inspection_dir/strings"
  done
  reject_if_present "$TEST_VERIFICATION_KEY_MARKER" \
    'release executable contains the A10 fixture verification key' "$artifact" "$inspection_dir/strings"
done

echo "A10.1 migration publisher is absent from release binary: $binary"
