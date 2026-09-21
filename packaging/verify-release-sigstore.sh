#!/usr/bin/env bash
# Verify a v2 release using the exact O3K GitHub workflow identity.
set -Eeuo pipefail
VERSION="${1:-}"
DIST_ROOT="${2:-}"
if [[ -z "$VERSION" || -z "$DIST_ROOT" ]]; then
  echo "usage: verify-release-sigstore.sh VERSION DIST_ROOT" >&2
  exit 2
fi
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_NO_V="${VERSION#v}"
TAG="v$VERSION_NO_V"
for asset in release-digests.txt release-digests.sigstore.json provenance.json; do
  [[ -f "$DIST_ROOT/$asset" ]] || { echo "missing Sigstore release asset: $asset" >&2; exit 2; }
done
COMMIT="${RELEASE_SOURCE_COMMIT:-}"
if [[ -z "$COMMIT" && -f "$DIST_ROOT/source-commit.txt" ]]; then
  COMMIT="$(sed -n '1p' "$DIST_ROOT/source-commit.txt")"
fi
if [[ -n "$COMMIT" ]]; then
  python3 "$ROOT_DIR/packaging/verify-sigstore-bundle.py" "$VERSION" "$DIST_ROOT" "$COMMIT"
else
  python3 "$ROOT_DIR/packaging/verify-sigstore-bundle.py" "$VERSION" "$DIST_ROOT"
fi
COMMIT="$(python3 - "$DIST_ROOT/provenance.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["source_commit"])
PY
)"
python3 "$ROOT_DIR/packaging/validate-sigstore-provenance.py" \
  "$DIST_ROOT/provenance.json" "$ROOT_DIR/packaging/trust-policy.yaml" "$VERSION" "$COMMIT"
COSIGN="${COSIGN:-cosign}"
command -v "$COSIGN" >/dev/null 2>&1 || { echo "cosign is required for Sigstore verification" >&2; exit 2; }
IDENTITY="https://github.com/o3kio/o3k/.github/workflows/release.yml@refs/tags/$TAG"
"$COSIGN" verify-blob \
  --bundle "$DIST_ROOT/release-digests.sigstore.json" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$DIST_ROOT/release-digests.txt"
echo "verified keyless O3K release: $TAG ($IDENTITY)"
