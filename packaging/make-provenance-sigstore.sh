#!/usr/bin/env bash
# Generate v2 release digests and provenance. Cosign signs the digest manifest
# in the protected GitHub release workflow; this script never needs a key.
set -Eeuo pipefail

VERSION="${1:-}"
DIST_ROOT="${2:-}"
if [[ -z "$VERSION" || -z "$DIST_ROOT" ]]; then
  echo "usage: make-provenance-sigstore.sh VERSION DIST_ROOT" >&2
  exit 2
fi
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_NO_V="${VERSION#v}"
BUNDLE_DIR="$DIST_ROOT/o3k-$VERSION_NO_V"
[[ -d "$BUNDLE_DIR" ]] || { echo "release bundle directory is missing: $BUNDLE_DIR" >&2; exit 2; }
[[ -f "$DIST_ROOT/install.sh" && -f "$DIST_ROOT/o3k-$VERSION_NO_V-linux-x86_64.tar.gz" ]] \
  || { echo "release payload assets are incomplete" >&2; exit 2; }
[[ -f "$DIST_ROOT/o3k-$VERSION_NO_V-linux-x86_64.tar.gz.sha256" ]] \
  || { echo "tarball checksum is missing" >&2; exit 2; }
for required in manifest.json SHA256SUMS sbom.spdx.json; do
  [[ -f "$BUNDLE_DIR/$required" ]] || { echo "bundle file is missing: $required" >&2; exit 2; }
done
cmp -s "$ROOT_DIR/packaging/get-o3k.sh" "$DIST_ROOT/install.sh" \
  || { echo "install.sh drifted from packaging/get-o3k.sh" >&2; exit 1; }

COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"
MANIFEST_COMMIT="$(python3 - "$BUNDLE_DIR/manifest.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream).get("source_commit")
if not isinstance(value, str) or len(value) != 40:
    raise SystemExit("manifest source_commit is missing")
print(value)
PY
)"
[[ "$COMMIT" == "$MANIFEST_COMMIT" ]] || {
  echo "provenance source drift: HEAD is $COMMIT but manifest records $MANIFEST_COMMIT" >&2
  exit 1
}

cd "$DIST_ROOT"
DIGESTS=release-digests.txt
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT_DIR" show -s --format=%ct HEAD)}"
SIGNED_AT="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
WORKFLOW="${GITHUB_WORKFLOW:-O3K protected release workflow}"
# Provenance is deliberately written before the digest manifest.  The
# manifest then includes provenance.json, avoiding the circular "provenance
# lists the digest of the manifest that lists provenance" dependency.  The
# signed digest manifest is the byte-level binding for provenance itself.
python3 - "$VERSION" "$COMMIT" "$WORKFLOW" "$SIGNED_AT" <<'PY'
import hashlib, json, pathlib, sys
version, commit, workflow, signed_at = sys.argv[1:5]
assets = [
    "install.sh",
    f"o3k-{version.removeprefix('v')}-linux-x86_64.tar.gz",
    f"o3k-{version.removeprefix('v')}-linux-x86_64.tar.gz.sha256",
    f"o3k-{version.removeprefix('v')}/manifest.json",
    f"o3k-{version.removeprefix('v')}/SHA256SUMS",
    f"o3k-{version.removeprefix('v')}/sbom.spdx.json",
]
for asset in assets:
    if not pathlib.Path(asset).is_file():
        raise SystemExit(f"cannot digest missing asset: {asset}")
doc = {
    "schema_version": 2,
    "artifact_type": "o3k-release-provenance",
    "release": version,
    "source_commit": commit,
    "signature_scheme": "sigstore-keyless",
    "oidc_issuer": "https://token.actions.githubusercontent.com",
    "repository": "o3kio/o3k",
    "workflow": ".github/workflows/release.yml",
    "builder": workflow,
    "signed_at": signed_at,
    "digest_manifest": "release-digests.txt",
    "signature_bundle": "release-digests.sigstore.json",
    "assets": [{"name": name, "sha256": hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()} for name in sorted(assets)],
    "self_digest_binding": "release-digests.txt",
}
pathlib.Path("provenance.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

: >"$DIGESTS"
for asset in \
  install.sh \
  "o3k-$VERSION_NO_V-linux-x86_64.tar.gz" \
  "o3k-$VERSION_NO_V-linux-x86_64.tar.gz.sha256" \
  provenance.json \
  "o3k-$VERSION_NO_V/manifest.json" \
  "o3k-$VERSION_NO_V/SHA256SUMS" \
  "o3k-$VERSION_NO_V/sbom.spdx.json"; do
  [[ -f "$asset" ]] || { echo "cannot digest missing asset: $asset" >&2; exit 2; }
  sha256sum "$asset" >>"$DIGESTS"
done

python3 "$ROOT_DIR/packaging/validate-sigstore-provenance.py" \
  provenance.json "$ROOT_DIR/packaging/trust-policy.yaml" "$VERSION" "$COMMIT"
echo "sigstore provenance material written to $DIST_ROOT (Cosign signing is required next)"
