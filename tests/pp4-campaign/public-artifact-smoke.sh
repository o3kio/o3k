#!/usr/bin/env bash
# Short public-artifact smoke: download only the published O3K assets, verify
# the public archive before extraction, verify the release bundle, and then
# exercise the exact Araf image-load boundary. This is intentionally not the
# full browser/host campaign.
set -Eeuo pipefail
VERSION="${1:?usage: public-artifact-smoke.sh v0.4.0-rc.N}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE="https://github.com/o3kio/o3k/releases/download/${VERSION}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/o3k-public-smoke.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

asset="o3k-${VERSION#v}-linux-x86_64.tar.gz"
curl -fsSL --retry 3 -o "$WORK/install.sh" "$BASE/install.sh"
curl -fsSL --retry 3 -o "$WORK/$asset" "$BASE/$asset"
curl -fsSL --retry 3 -o "$WORK/$asset.sha256" "$BASE/$asset.sha256"
(cd "$WORK" && sha256sum -c --strict "$asset.sha256")
grep -Fq "O3K_INSTALLER_VERSION=\"$VERSION\"" "$WORK/install.sh"
tar -tzf "$WORK/$asset" | grep -Fxq "./o3k-${VERSION#v}/packaging/o3k-araf-demo.sh"
tar -xzf "$WORK/$asset" -C "$WORK"
BUNDLE="$WORK/o3k-${VERSION#v}"
bash "$BUNDLE/packaging/verify-release-bundle.sh" "$BUNDLE"
grep -Fq "O3K_TUPLE_VERSION=\"$VERSION\"" "$BUNDLE/packaging/o3k-araf-demo.sh"
"$ROOT_DIR/tests/pp4-campaign/oci-identity-smoke.sh"
echo "public artifact smoke: PASS ($VERSION)"
