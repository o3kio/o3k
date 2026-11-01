#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="${1:?usage: verify-release-bundle.sh BUNDLE_DIR}"
[[ -d "$BUNDLE_DIR" ]] || { echo "release bundle is not a directory: $BUNDLE_DIR" >&2; exit 2; }

python3 - "$BUNDLE_DIR" <<'PY'
import pathlib
import stat
import subprocess
import sys

bundle = pathlib.Path(sys.argv[1]).resolve()
checksums = bundle / "SHA256SUMS"
if not checksums.is_file() or checksums.is_symlink():
    raise SystemExit("release bundle must contain a regular SHA256SUMS file")

files = set()
for path in bundle.rglob("*"):
    relative = path.relative_to(bundle)
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        raise SystemExit(f"release bundle must not contain symlinks: {relative}")
    if not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
        raise SystemExit(f"release bundle must not contain special files: {relative}")
    if stat.S_ISREG(mode) and path != checksums:
        files.add(f"./{relative.as_posix()}")

entries = {}
for line_number, line in enumerate(checksums.read_text(encoding="utf-8").splitlines(), start=1):
    if not line or "  " not in line:
        raise SystemExit(f"SHA256SUMS line {line_number} is malformed")
    digest, name = line.split("  ", 1)
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise SystemExit(f"SHA256SUMS line {line_number} has an invalid digest")
    if not name.startswith("./") or name in entries:
        raise SystemExit(f"SHA256SUMS line {line_number} has an invalid or duplicate path")
    candidate = pathlib.PurePosixPath(name)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise SystemExit(f"SHA256SUMS line {line_number} escapes the bundle")
    entries[name] = digest

if set(entries) != files:
    missing = sorted(files - set(entries))
    extra = sorted(set(entries) - files)
    raise SystemExit(
        "SHA256SUMS must cover exactly the regular bundle files "
        f"(missing={missing}, extra={extra})"
    )

result = subprocess.run(
    ["sha256sum", "--check", "--strict", "SHA256SUMS"],
    cwd=bundle,
    check=False,
    text=True,
)
if result.returncode:
    raise SystemExit(result.returncode)
PY

# Release binaries must execute on every advertised target. Debian 12
# (bookworm) ships glibc 2.36, so a binary requiring newer glibc symbols
# (e.g. GLIBC_2.38/2.39 from an Ubuntu 24.04 host build) fails at exec on the
# clean-Debian target; the release bundle must be built on the Debian 12
# baseline instead (scripts/build-release-binaries-debian12.sh). The baseline
# check skips non-ELF files, so scripts and documentation in the bundle are
# unaffected.
if [[ -d "$BUNDLE_DIR/bin" ]]; then
  if [[ -f "$BUNDLE_DIR/bin/o3k" ]]; then
    release_binaries=()
    while IFS= read -r -d '' binary; do
      release_binaries+=("$binary")
    done < <(find "$BUNDLE_DIR/bin" -maxdepth 1 -type f -perm /111 -print0 | sort -z)
    bash "$SCRIPT_DIR/check-a10-publisher-disabled.sh" "$BUNDLE_DIR/bin/o3k" "${release_binaries[@]}"
  fi
  BINARIES=()
  while IFS= read -r -d '' binary; do
    BINARIES+=("$binary")
  done < <(find "$BUNDLE_DIR/bin" -maxdepth 1 -type f -print0)
  if (( ${#BINARIES[@]} > 0 )); then
    bash "$SCRIPT_DIR/check-glibc-baseline.sh" "${BINARIES[@]}"
  fi
fi

echo "verified release bundle integrity: $BUNDLE_DIR"
