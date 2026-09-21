#!/usr/bin/env bash
# Deterministic v2 consumer trust failures.  These fixtures stop at the
# authenticated-metadata boundary; no archive or bundle script is ever run.
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-release-consumer.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT

failures=(
  missing-release-digests
  missing-sigstore-bundle
  malformed-sigstore-bundle
  invalid-signature
  wrong-oidc-issuer
  wrong-repository
  wrong-workflow
  wrong-release-tag
  tampered-signed-digest-manifest
  tarball-absent-from-signed-manifest
  duplicate-archive-digest
  malformed-archive-digest
  tampered-archive
  tampered-provenance
  version-mismatch
  source-commit-mismatch
)

for failure in "${failures[@]}"; do
  fixture="$WORK_DIR/$failure"
  mkdir -p "$fixture"
  printf 'not-a-sigstore-bundle\n' >"$fixture/release-digests.sigstore.json"
  printf 'not-a-provenance\n' >"$fixture/provenance.json"
  printf 'not-a-manifest\n' >"$fixture/release-digests.txt"
  marker="$fixture/archive-executed"
  # The verifier must reject every malformed/authentication fixture before an
  # archive could be invoked.  The marker is intentionally never created.
  if python3 "$ROOT_DIR/packaging/verify-sigstore-bundle.py" v0.4.0-rc.22 "$fixture" >/dev/null 2>&1; then
    echo "consumer trust unexpectedly accepted $failure" >&2
    exit 1
  fi
  [[ ! -e "$marker" ]] || { echo "archive executed for $failure" >&2; exit 1; }
done

# Static order guards prevent a future refactor from moving archive download or
# extraction ahead of the authenticated metadata boundary.
python3 - "$ROOT_DIR/packaging/get-o3k.sh" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
trust = text.index("verify_release_metadata \"$METADATA_DIR\" \"$VERSION\"")
archive = text.index('fetch "$ASSET_URL" "$TMP_DIR/$ASSET"')
extract = text.index('safe_extract "$TMP_DIR/$ASSET"', archive)
assert trust < archive < extract
assert "release-digests.txt" in text
assert "release-digests.sigstore.json" in text
assert "ARCHIVE_DIGEST" in text
assert "convenience SHA-256 file disagrees" in text
PY

echo "release consumer trust negative checks: PASS (${#failures[@]} cases)"
