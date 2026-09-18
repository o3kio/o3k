#!/usr/bin/env bash
# make-provenance.sh — release-level provenance and signature material (PP.1).
#
# The bundle-level SHA256SUMS (integrity) covers files INSIDE the release
# bundle. This script binds the PUBLISHED release assets to one exact source
# commit and signs that binding with the O3K release ed25519 key:
#
#   release-digests.txt   sha256 of every published asset (bundle manifest,
#                         bundle SHA256SUMS, SBOM, install.sh, tarball, .sha256)
#   release-digests.sig   detached ed25519 signature over release-digests.txt
#   provenance.json       machine-readable binding (release, source commit,
#                         asset digests, signature description)
#   release-verify.pub    copy of the committed release public key
#                         (packaging/release-verify.pub) for offline verification
#
# Integrity (SHA-256) is not authenticity: verify with
#   openssl pkeyutl -verify -pubin -inkey release-verify.pub -rawin \
#     -in release-digests.txt -sigfile release-digests.sig
#
# Usage: make-provenance.sh VERSION DIST_ROOT
# Requires: O3K_RELEASE_SIGNING_KEY (path to the ed25519 private key PEM;
#           NEVER committed; held by the release operator) and a dist root
#           produced by make-release.sh + make-release-archive.sh.
set -euo pipefail

VERSION="${1:-}"
DIST_ROOT="${2:-}"
if [[ -z "$VERSION" || -z "$DIST_ROOT" ]]; then
  echo "usage: make-provenance.sh VERSION DIST_ROOT" >&2
  exit 2
fi
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_NO_V="${VERSION#v}"
BUNDLE_DIR="$DIST_ROOT/o3k-$VERSION_NO_V"
KEY="${O3K_RELEASE_SIGNING_KEY:-}"

[[ -d "$BUNDLE_DIR" ]] || { echo "release bundle directory is missing: $BUNDLE_DIR" >&2; exit 2; }
[[ -n "$KEY" ]] || { echo "O3K_RELEASE_SIGNING_KEY is not set (ed25519 private key PEM, never committed)" >&2; exit 2; }
[[ -f "$KEY" && ! -L "$KEY" ]] || { echo "release signing key is missing or unsafe: $KEY" >&2; exit 2; }
grep -q 'PRIVATE KEY' "$KEY" || { echo "release signing key is not a private key PEM: $KEY" >&2; exit 2; }
[[ -f "$DIST_ROOT/install.sh" ]] || { echo "install.sh release asset is missing: $DIST_ROOT/install.sh" >&2; exit 2; }
[[ -f "$DIST_ROOT/o3k-$VERSION_NO_V-linux-x86_64.tar.gz" ]] \
  || { echo "release tarball is missing for o3k-$VERSION_NO_V" >&2; exit 2; }
[[ -f "$DIST_ROOT/o3k-$VERSION_NO_V-linux-x86_64.tar.gz.sha256" ]] \
  || { echo "release tarball checksum is missing for o3k-$VERSION_NO_V" >&2; exit 2; }
for required in manifest.json SHA256SUMS sbom.spdx.json; do
  [[ -f "$BUNDLE_DIR/$required" ]] || { echo "bundle file is missing: $BUNDLE_DIR/$required" >&2; exit 2; }
done
cmp -s "$ROOT_DIR/packaging/get-o3k.sh" "$DIST_ROOT/install.sh" \
  || { echo "install.sh release asset drifted from packaging/get-o3k.sh" >&2; exit 1; }
PUBLIC_KEY="$ROOT_DIR/packaging/release-verify.pub"
[[ -f "$PUBLIC_KEY" ]] || { echo "release verification public key is missing: $PUBLIC_KEY" >&2; exit 2; }

COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"
WORKFLOW="${GITHUB_WORKFLOW:-local}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT_DIR" show -s --format=%ct HEAD)}"
SIGNED_AT="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"

cd "$DIST_ROOT"
DIGESTS="release-digests.txt"
: >"$DIGESTS"
for asset in \
  "install.sh" \
  "o3k-$VERSION_NO_V-linux-x86_64.tar.gz" \
  "o3k-$VERSION_NO_V-linux-x86_64.tar.gz.sha256" \
  "o3k-$VERSION_NO_V/manifest.json" \
  "o3k-$VERSION_NO_V/SHA256SUMS" \
  "o3k-$VERSION_NO_V/sbom.spdx.json"; do
  [[ -f "$asset" ]] || { echo "cannot digest missing asset: $asset" >&2; exit 2; }
  sha256sum "$asset" >>"$DIGESTS"
done

openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$DIGESTS" -out release-digests.sig \
  || { echo "release signing failed" >&2; exit 1; }
openssl pkeyutl -verify -pubin -inkey "$PUBLIC_KEY" -rawin \
  -in "$DIGESTS" -sigfile release-digests.sig \
  || { echo "release signature self-verification failed" >&2; exit 1; }
cp "$PUBLIC_KEY" release-verify.pub

python3 - "$VERSION" "$COMMIT" "$WORKFLOW" "$SIGNED_AT" <<'PY'
import hashlib
import json
import pathlib
import sys

version, commit, workflow, signed_at = sys.argv[1:5]
digests = {}
for line in pathlib.Path("release-digests.txt").read_text(encoding="utf-8").splitlines():
    digest, name = line.split(None, 1)
    digests[name.strip()] = digest
doc = {
    "schema_version": 1,
    "artifact_type": "o3k-release-provenance",
    "release": version,
    "source_commit": commit,
    "builder": workflow,
    "signed_at": signed_at,
    "signature_algorithm": "ed25519",
    "public_key_asset": "release-verify.pub",
    "digests_asset": "release-digests.txt",
    "signature_asset": "release-digests.sig",
    "assets": [
        {"name": name, "sha256": digest}
        for name, digest in sorted(digests.items())
    ],
}
pathlib.Path("provenance.json").write_text(
    json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

# Never leak the private key into the published release assets (the release
# binaries legitimately embed PEM marker strings for TLS handling, so scope
# the sweep to the assets this script produces).
if grep -Eql 'BEGIN (OPENSSH|RSA|EC|DSA|PGP|ENCRYPTED)? ?PRIVATE KEY-----' \
    "$DIGESTS" release-digests.sig provenance.json release-verify.pub 2>/dev/null; then
  echo "refusing to publish private key material in the provenance assets" >&2
  exit 1
fi

echo "provenance material written to $DIST_ROOT:"
echo "  release-digests.txt  release-digests.sig  provenance.json  release-verify.pub"
