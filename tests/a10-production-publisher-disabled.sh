#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-a10-release-guard.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --release -p o3k --bin o3k
RELEASE_BIN="$ROOT_DIR/target/release/o3k"
bash "$ROOT_DIR/packaging/check-a10-publisher-disabled.sh" "$RELEASE_BIN"

for debug_assertions in false true; do
  if CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS="$debug_assertions" \
    cargo check --manifest-path "$ROOT_DIR/Cargo.toml" --release -p o3k \
      --features a10-process-test-hooks >"$WORK_DIR/feature-build-$debug_assertions.log" 2>&1; then
    echo "optimized o3k unexpectedly accepted a10-process-test-hooks (debug assertions=$debug_assertions)" >&2
    exit 1
  fi
  if ! grep -Fq 'a10-process-test-hooks is a debug-only qualification feature' \
    "$WORK_DIR/feature-build-$debug_assertions.log"; then
    echo "optimized feature rejection did not come from the build-time guard (debug assertions=$debug_assertions)" >&2
    tail -80 "$WORK_DIR/feature-build-$debug_assertions.log" >&2
    exit 1
  fi
done

PACKAGE="$WORK_DIR/package"
mkdir -p "$PACKAGE/bin"
cat >"$PACKAGE/bin/o3k" <<EOF
#!/bin/sh
exec "$RELEASE_BIN" "\$@"
EOF
chmod 0755 "$PACKAGE/bin/o3k"
printf 'placeholder\n' >"$PACKAGE/bin/o3kd"
(cd "$PACKAGE" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS)
bash "$ROOT_DIR/packaging/verify-release-bundle.sh" "$PACKAGE"

# A debug qualification executable must not sneak into an otherwise valid
# release bundle under a second installed name. The bundle verifier scans all
# executable artifacts, not only the normal `o3k` path.
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p o3k --bin o3k \
  --features a10-process-test-hooks
mkdir -p "$PACKAGE/bin"
cp "$ROOT_DIR/target/debug/o3k" "$PACKAGE/bin/o3k-migration-qualification"
chmod 0755 "$PACKAGE/bin/o3k-migration-qualification"
(cd "$PACKAGE" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS)
if bash "$ROOT_DIR/packaging/verify-release-bundle.sh" "$PACKAGE" \
  >"$WORK_DIR/debug-artifact-rejected.log" 2>&1; then
  echo "release bundle verifier accepted an A10 qualification executable" >&2
  exit 1
fi
if ! grep -Fq 'A10' "$WORK_DIR/debug-artifact-rejected.log"; then
  echo "qualification executable rejection did not come from the A10 artifact guard" >&2
  cat "$WORK_DIR/debug-artifact-rejected.log" >&2
  exit 1
fi

echo "A10.1 release compile-time and bundle guards passed"
