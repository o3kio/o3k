#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_ARCHIVE="${1:?usage: release-extracted-bundle.sh RELEASE_ARCHIVE.tar.gz}"
[[ -f "$SOURCE_ARCHIVE" ]] || { echo "release archive not found: $SOURCE_ARCHIVE" >&2; exit 2; }
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-extracted-release-gate.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT

ARCHIVE_ENTRIES="$WORK_DIR/archive-entries.txt"
tar -tzf "$SOURCE_ARCHIVE" >"$ARCHIVE_ENTRIES"
[[ -s "$ARCHIVE_ENTRIES" ]] || { echo "release archive is empty" >&2; exit 1; }
first_entry="$(head -n 1 "$ARCHIVE_ENTRIES")"
[[ "$first_entry" == ./* ]] || { echo "release archive path is not rooted at ./: $first_entry" >&2; exit 1; }
archive_root="${first_entry#./}"
archive_root="${archive_root%%/*}"
[[ -n "$archive_root" && "$archive_root" != *..* ]] || {
  echo "release archive has an invalid root directory: $archive_root" >&2
  exit 1
}
while IFS= read -r entry; do
  [[ "$entry" == "./$archive_root" || "$entry" == "./$archive_root/"* ]] || {
    echo "release archive contains an entry outside ./$archive_root: $entry" >&2
    exit 1
  }
  case "$entry" in
    *'/../'*|*'/..'|'..') echo "release archive contains a parent path: $entry" >&2; exit 1 ;;
  esac
done <"$ARCHIVE_ENTRIES"
EXTRACTED_ROOT="$WORK_DIR/extracted"
mkdir -p "$EXTRACTED_ROOT"
tar -xzf "$SOURCE_ARCHIVE" -C "$EXTRACTED_ROOT" --no-same-owner --no-same-permissions
SOURCE_BUNDLE="$EXTRACTED_ROOT/$archive_root"
[[ -d "$SOURCE_BUNDLE" && ! -L "$SOURCE_BUNDLE" ]] || {
  echo "release archive did not extract its bundle root: $SOURCE_BUNDLE" >&2
  exit 1
}

case_number=0
record() {
  case_number=$((case_number + 1))
  printf 'CASE %02d %s: %s\n' "$case_number" "$1" "$2"
}
clone_bundle() {
  local destination="$1"
  mkdir -p "$destination"
  cp -a "$SOURCE_BUNDLE/." "$destination/"
}
rehash() {
  local bundle="$1"
  (cd "$bundle" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
    | xargs -0 sha256sum >"$WORK_DIR/SHA256SUMS.generated")
  mv "$WORK_DIR/SHA256SUMS.generated" "$bundle/SHA256SUMS"
}
expect_pass() {
  local label="$1" bundle="$2" log="$3" status
  # Only the extracted archive is available as the verifier's working tree.
  # env -i removes checkout-related environment and the packaged verifier
  # resolves dependencies relative to its extracted packaging directory.
  if env -i HOME="$WORK_DIR/home" PATH="$PATH" /bin/bash \
    "$bundle/packaging/verify-release-bundle.sh" "$bundle" >"$log" 2>&1; then
    status=0
  else
    status=$?
  fi
  [[ "$status" -eq 0 ]] || { cat "$log" >&2; echo "$label failed with exit $status" >&2; exit 1; }
  record "$label" "PASS (exit $status)"
}
expect_fail() {
  local label="$1" bundle="$2" log="$3" expected="$4" status
  if env -i HOME="$WORK_DIR/home" PATH="$PATH" /bin/bash \
    "$bundle/packaging/verify-release-bundle.sh" "$bundle" >"$log" 2>&1; then
    status=0
  else
    status=$?
  fi
  [[ "$status" -ne 0 ]] || { cat "$log" >&2; echo "$label unexpectedly passed" >&2; exit 1; }
  if [[ -n "$expected" ]] && ! grep -Fq -- "$expected" "$log"; then
    cat "$log" >&2
    echo "$label failed for the wrong reason (expected diagnostic: $expected)" >&2
    exit 1
  fi
  record "$label" "FAIL as expected (exit $status; $expected)"
}

bash "$ROOT_DIR/tests/a10-publisher-key-drift.sh"
BASE="$WORK_DIR/base"
clone_bundle "$BASE"
[[ ! -e "$BASE/bins/o3k/tests/fixtures" ]] || {
  echo "release bundle unexpectedly contains source test fixtures" >&2
  exit 1
}
expect_pass "optimized extracted bundle; source fixture directory absent" "$BASE" "$WORK_DIR/positive.log"

# Validate a stripped copy of the actual optimized release binary through the
# exact packaged A10 checker. Keep the original bundle artifact untouched.
STRIPPED="$WORK_DIR/stripped"
clone_bundle "$STRIPPED"
strip --strip-unneeded "$STRIPPED/bin/o3k"
rehash "$STRIPPED"
expect_pass "optimized stripped release binary" "$STRIPPED" "$WORK_DIR/stripped.log"

MALFORMED="$WORK_DIR/malformed-sums"
clone_bundle "$MALFORMED"
printf 'not a sha256 manifest\n' >"$MALFORMED/SHA256SUMS"
expect_fail "malformed SHA256SUMS" "$MALFORMED" "$WORK_DIR/malformed.log" "malformed"

CHANGED="$WORK_DIR/changed-content"
clone_bundle "$CHANGED"
printf '\nchanged without digest update\n' >>"$CHANGED/docs/compatibility.md"
expect_fail "changed bundle file without matching digest" "$CHANGED" "$WORK_DIR/changed.log" "FAILED"

DEBUG="$WORK_DIR/debug-marker"
clone_bundle "$DEBUG"
printf '\nO3K_A10_MIGRATION_CRASH_AT\n' >>"$DEBUG/bin/o3kd"
rehash "$DEBUG"
expect_fail "rehashed A10 fault-injection marker" "$DEBUG" "$WORK_DIR/debug.log" "fault-injection marker"

KEY="$WORK_DIR/test-key"
clone_bundle "$KEY"
awk 'NF && $0 !~ /^-----/ { print; exit }' "$ROOT_DIR/bins/o3k/tests/fixtures/a10-release-verify.pub" \
  >>"$KEY/bin/o3kd"
rehash "$KEY"
expect_fail "rehashed embedded public test verification key" "$KEY" "$WORK_DIR/key.log" "fixture verification key"

LINKED="$WORK_DIR/linked-publisher"
clone_bundle "$LINKED"
FAKE_NM="$WORK_DIR/fake-nm"
mkdir -p "$FAKE_NM"
cat >"$FAKE_NM/nm" <<'EOF'
#!/usr/bin/env bash
printf '0000000000000000 T recovery_migration_publisher::publish\n'
EOF
chmod 0755 "$FAKE_NM/nm"
(cd "$LINKED" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
  | xargs -0 sha256sum >"$WORK_DIR/SHA256SUMS.generated")
mv "$WORK_DIR/SHA256SUMS.generated" "$LINKED/SHA256SUMS"
if env -i HOME="$WORK_DIR/home" PATH="$FAKE_NM:$PATH" /bin/bash \
  "$LINKED/packaging/verify-release-bundle.sh" "$LINKED" >"$WORK_DIR/linked.log" 2>&1; then
  status=0
else
  status=$?
fi
if [[ "$status" -eq 0 ]] || ! grep -Fq 'linked A10.1 publisher symbols' "$WORK_DIR/linked.log"; then
  cat "$WORK_DIR/linked.log" >&2
  echo "detectable linked publisher symbol was not rejected (exit $status)" >&2
  exit 1
fi
record "detectable linked publisher symbol" "FAIL as expected (exit $status)"

# Keep all ordinary verifier tools available, but deliberately omit nm. The
# packaged checker must fail closed before accepting any release executable.
NO_NM="$WORK_DIR/path-without-nm"
mkdir -p "$NO_NM"
for tool in bash python3 sha256sum find sort xargs grep mktemp rm strings dirname; do
  target="$(command -v "$tool")"
  ln -s "$target" "$NO_NM/$tool"
done
NO_TOOL="$WORK_DIR/no-inspector"
clone_bundle "$NO_TOOL"
if env -i HOME="$WORK_DIR/home" PATH="$NO_NM" /bin/bash \
  "$NO_TOOL/packaging/verify-release-bundle.sh" "$NO_TOOL" >"$WORK_DIR/no-nm.log" 2>&1; then
  status=0
else
  status=$?
fi
if [[ "$status" -eq 0 ]] || ! grep -Fq 'nm (binutils) is required' "$WORK_DIR/no-nm.log"; then
  cat "$WORK_DIR/no-nm.log" >&2
  echo "missing nm was not rejected by the packaged checker (exit $status)" >&2
  exit 1
fi
record "missing symbol inspection tool" "FAIL as expected (exit $status; nm required)"

BAD_STRINGS="$WORK_DIR/bad-strings"
clone_bundle "$BAD_STRINGS"
BAD_STRINGS_PATH="$WORK_DIR/path-with-bad-strings"
mkdir -p "$BAD_STRINGS_PATH"
cat >"$BAD_STRINGS_PATH/strings" <<'EOF'
#!/usr/bin/env bash
exit 43
EOF
chmod 0755 "$BAD_STRINGS_PATH/strings"
if env -i HOME="$WORK_DIR/home" PATH="$BAD_STRINGS_PATH:$PATH" /bin/bash \
  "$BAD_STRINGS/packaging/verify-release-bundle.sh" "$BAD_STRINGS" >"$WORK_DIR/bad-strings.log" 2>&1; then
  status=0
else
  status=$?
fi
if [[ "$status" -ne 2 ]] || ! grep -Fq 'could not inspect release executable strings' "$WORK_DIR/bad-strings.log"; then
  cat "$WORK_DIR/bad-strings.log" >&2
  echo "nonfunctional strings tool was not rejected explicitly (exit $status)" >&2
  exit 1
fi
record "nonfunctional string inspection tool" "FAIL as expected (exit $status; explicit inspection error)"

if "$BASE/bin/o3k" recovery-migrate-v2 --help >"$WORK_DIR/command.log" 2>&1; then
  echo "production o3k exposed recovery-migrate-v2" >&2
  exit 1
fi
grep -Fq 'unrecognized subcommand' "$WORK_DIR/command.log" || {
  cat "$WORK_DIR/command.log" >&2
  echo "production o3k rejected the migration command unexpectedly" >&2
  exit 1
}
record "production recovery-migrate-v2 command unavailable" "PASS (nonzero dispatch; unrecognized subcommand)"
