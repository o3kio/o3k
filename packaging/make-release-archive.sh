#!/usr/bin/env bash
set -Eeuo pipefail

# make-release-archive.sh — produce the downloadable release assets from an
# existing verified bundle directory (dist/o3k-<version>/, created by
# packaging/make-release.sh). Issue #613 one-line installer.
#
# Usage: packaging/make-release-archive.sh VERSION [BUNDLE_DIR]
#
# Release asset contract for the GitHub Release (produced together with
# packaging/make-release.sh):
#   dist/install.sh                            one-line installer (0755),
#                                              byte-identical export of
#                                              packaging/get-o3k.sh —
#                                              re-verified here before
#                                              archiving (drift gate);
#   dist/o3k-<version>-linux-x86_64.tar.gz     this script's outputs
#   dist/o3k-<version>-linux-x86_64.tar.gz.sha256
#   plus o3kd, o3k-compute, SHA256SUMS, sbom.spdx.json, and manifest.json
#   from the bundle directory (the manifest records install.sh's SHA-256).
#
# Outputs (the assets that packaging/get-o3k.sh downloads):
#
#   dist/o3k-<version>-linux-x86_64.tar.gz
#   dist/o3k-<version>-linux-x86_64.tar.gz.sha256
#
# ASSET NAMING CONTRACT (consumed by packaging/get-o3k.sh; do not change
# without updating the wrapper):
#   - tarball name:    o3k-<version>-linux-x86_64.tar.gz   (<version> has no "v")
#   - published hash:  o3k-<version>-linux-x86_64.tar.gz.sha256
#     with coreutils two-space format "<hex64>  o3k-<version>-linux-x86_64.tar.gz"
#     so `sha256sum -c` works out of the box
#   - served at:       <release-base>/v<version>/... (GitHub Release tag v<version>)
#   - tarball entries: every entry starts with "./" and contains no ".." path
#     component; verified again here and re-verified by the wrapper before
#     extraction
#
# Signing: this script delegates to packaging/make-provenance.sh, which binds
# every published asset to the exact source commit and signs that binding
# with the O3K release ed25519 key (release-digests.txt/.sig, provenance.json,
# release-verify.pub). The .sha256 file remains an integrity checksum, not an
# authenticity signature (see docs/RELEASE.md for the signing position).
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:?usage: make-release-archive.sh VERSION [BUNDLE_DIR]}"
VERSION_RE='^[0-9]+(\.[0-9]+){1,2}(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$'
if [[ ! "$VERSION" =~ $VERSION_RE ]]; then
  echo "version must be a numeric release version with an optional prerelease suffix" >&2
  exit 2
fi
BUNDLE_DIR="${2:-$ROOT_DIR/dist/o3k-$VERSION}"
[[ -d "$BUNDLE_DIR" && ! -L "$BUNDLE_DIR" ]] || { echo "release bundle is not a directory: $BUNDLE_DIR" >&2; exit 2; }
BUNDLE_DIR="$(cd "$BUNDLE_DIR" && pwd)"
BUNDLE_NAME="$(basename "$BUNDLE_DIR")"
[[ "$BUNDLE_NAME" == "o3k-$VERSION" ]] || {
  echo "release bundle directory must be named o3k-$VERSION: $BUNDLE_DIR" >&2
  exit 2
}

# Archive only an integrity-verified bundle (SHA256SUMS covers exactly the
# regular files, no symlinks, glibc floor holds for the binaries).
bash "$ROOT_DIR/packaging/verify-release-bundle.sh" "$BUNDLE_DIR"

DIST_DIR="$ROOT_DIR/dist"
mkdir -p -- "$DIST_DIR"
TARBALL="$DIST_DIR/o3k-$VERSION-linux-x86_64.tar.gz"
SHA_FILE="$TARBALL.sha256"

# install.sh drift gate at release time: the published installer must be the
# byte-identical export of packaging/get-o3k.sh created by make-release.sh.
# The archive is never produced from a drifted installer source.
INSTALL_SH="$DIST_DIR/install.sh"
[[ -f "$INSTALL_SH" && ! -L "$INSTALL_SH" ]] || {
  echo "install.sh release asset is missing: $INSTALL_SH (run packaging/make-release.sh first)" >&2
  exit 1
}
cmp -s -- "$ROOT_DIR/packaging/get-o3k.sh" "$INSTALL_SH" || {
  echo "install.sh release asset drifted from packaging/get-o3k.sh — refusing to archive" >&2
  exit 1
}
INSTALL_SH_SHA256="$(sha256sum "$INSTALL_SH" | awk '{print $1}')"

tar -C "$(dirname "$BUNDLE_DIR")" -czf "$TARBALL" "./$BUNDLE_NAME"

# Verify the archive shape before publishing anything: every entry must start
# with "./" and must not contain a ".." path component.
ENTRY_COUNT=0
while IFS= read -r entry; do
  [[ -n "$entry" ]] || { echo "release archive contains an empty entry" >&2; exit 1; }
  [[ "$entry" == ./* ]] || { echo "release archive entry does not start with ./: $entry" >&2; exit 1; }
  case "$entry" in
    *'/../'*|*'/..'|'..')
      echo "release archive entry contains a .. component: $entry" >&2
      exit 1
      ;;
  esac
  ENTRY_COUNT=$((ENTRY_COUNT + 1))
done < <(tar -tzf "$TARBALL")
(( ENTRY_COUNT > 0 )) || { echo "release archive is empty" >&2; exit 1; }

DIGEST="$(sha256sum "$TARBALL" | awk '{print $1}')"
printf '%s  %s\n' "$DIGEST" "o3k-$VERSION-linux-x86_64.tar.gz" >"$SHA_FILE"
# Prove the published file round-trips with the exact tool the wrapper uses.
(cd "$DIST_DIR" && sha256sum -c --strict -- "o3k-$VERSION-linux-x86_64.tar.gz.sha256" >/dev/null) \
  || { echo "published SHA-256 file does not verify" >&2; exit 1; }

# Provenance/signature material (contracts/release-bundle-v1.yaml): binds
# every published asset to the exact source commit and signs the binding with
# the O3K release ed25519 key. Fail closed when the signing key is absent —
# an unsigned release archive must not be produced silently.
bash "$ROOT_DIR/packaging/make-provenance.sh" "v$VERSION" "$DIST_DIR"

echo "release archive: $TARBALL ($ENTRY_COUNT entries, all ./ prefixed)"
echo "published SHA-256: $SHA_FILE"
echo "install.sh release asset: $INSTALL_SH (sha256 $INSTALL_SH_SHA256)"
