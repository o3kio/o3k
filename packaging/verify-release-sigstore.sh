#!/usr/bin/env bash
# Verify a v2 release using the exact O3K GitHub workflow identity.
set -Eeuo pipefail
VERSION="${1:-}"
DIST_ROOT="${2:-}"
REPORT_FILE="${3:-}"
if [[ -z "$VERSION" || -z "$DIST_ROOT" || $# -gt 3 ]]; then
  echo "usage: verify-release-sigstore.sh VERSION DIST_ROOT [REPORT_JSON]" >&2
  exit 2
fi
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_NO_V="${VERSION#v}"
TAG="v$VERSION_NO_V"
for asset in release-digests.txt release-digests.sigstore.json provenance.json; do
  [[ -f "$DIST_ROOT/$asset" ]] || { echo "missing Sigstore release asset: $asset" >&2; exit 2; }
done
COMMIT="${RELEASE_SOURCE_COMMIT:-}"
TREE="${RELEASE_SOURCE_TREE:-}"
if [[ ! "$COMMIT" =~ ^[0-9a-fA-F]{40}$ || ! "$TREE" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "independent expected source commit and tree are required" >&2
  exit 2
fi

# When the tag exists locally, bind both expected values to Git rather than
# allowing the provenance document to authorize its own source identity.
TAG_REPO="${O3K_RELEASE_TAG_REPO:-$ROOT_DIR}"
if git -C "$TAG_REPO" rev-parse "refs/tags/$TAG^{commit}" >/dev/null 2>&1; then
  TAG_COMMIT="$(git -C "$TAG_REPO" rev-parse "refs/tags/$TAG^{commit}")"
  TAG_TREE="$(git -C "$TAG_REPO" rev-parse "refs/tags/$TAG^{tree}")"
  [[ "$TAG_COMMIT" == "$COMMIT" ]] || { echo "release tag commit differs from expected source" >&2; exit 1; }
  [[ "$TAG_TREE" == "$TREE" ]] || { echo "release tag tree differs from expected source" >&2; exit 1; }
fi

python3 "$ROOT_DIR/packaging/verify-sigstore-bundle.py" "$VERSION" "$DIST_ROOT" "$COMMIT"
python3 - "$DIST_ROOT/provenance.json" "$COMMIT" "$TREE" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    provenance = json.load(stream)
if provenance.get("source_commit") != sys.argv[2]:
    raise SystemExit("provenance source commit does not match the independent expected identity")
if provenance.get("source_tree") != sys.argv[3]:
    raise SystemExit("provenance source tree does not match the independent expected identity")
PY
python3 "$ROOT_DIR/packaging/validate-sigstore-provenance.py" \
  "$DIST_ROOT/provenance.json" "$ROOT_DIR/packaging/trust-policy.yaml" "$VERSION" "$COMMIT" "$TREE"
COSIGN="${COSIGN:-cosign}"
command -v "$COSIGN" >/dev/null 2>&1 || { echo "cosign is required for Sigstore verification" >&2; exit 2; }
IDENTITY="https://github.com/o3kio/o3k/.github/workflows/release.yml@refs/tags/$TAG"
"$COSIGN" verify-blob \
  --bundle "$DIST_ROOT/release-digests.sigstore.json" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$DIST_ROOT/release-digests.txt"
echo "verified keyless O3K release: $TAG ($IDENTITY)"

if [[ -n "$REPORT_FILE" ]]; then
  python3 "$ROOT_DIR/packaging/write_release_verification_report.py" \
    "$REPORT_FILE" "$VERSION_NO_V" "$TAG" "$COMMIT" "$TREE"
fi
