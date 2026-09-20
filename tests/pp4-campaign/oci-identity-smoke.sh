#!/usr/bin/env bash
# Focused PP.4 Araf OCI identity gate.  This deliberately exercises the
# published rc.15 archives through the host Docker engine, including engines
# that rematerialize OCI configs and therefore expose a different local image
# ID after `docker load`.
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="v1.0.0-rc.15"
SOURCE_SHA="f0c2a04a671d5edf7711cab63c4f83c49a9170d2"
BASE="https://github.com/o3kio/araf/releases/download/${VERSION}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/o3k-araf-oci.XXXXXX")"
LOADED_IDS=()
cleanup() {
  local image
  for image in "${LOADED_IDS[@]}"; do
    docker image rm "${image}" >/dev/null 2>&1 || true
  done
  rm -rf -- "$WORK"
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }

printf 'engine=%s\n' "$(docker version --format '{{.Server.Version}}')"
printf 'os=%s\n' "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")"

declare -A TAR_SHA=(
  [bff]=e4a682a836c60859c3d0330d082ab4b84d4ef112c8912f3f5d66849017b67459
  [tenant-console]=68847dbd75635ad705ca3575e056a0191ba8d2816239ffb3707ca2cd8352d0e8
  [operator-console]=8504d57ce10096cbd743e5260ecde5d51c900117c1614d500f5e09e9b75a7139
)
declare -A CONFIG_SHA=(
  [bff]=f0aba789573c0bf250f99e0dab4096ec1f707a93392afb5fad04ff26179c515f
  [tenant-console]=3f6028fc9d6eac2bc5d0b93fa7ea1605e4be6c263d9b6b3f973ef49300eda527
  [operator-console]=81d10a46b7a99f5a66003c3a9e7bf85843586010c4ccc1e147725657361b6715
)

for component in bff tenant-console operator-console; do
  archive="$WORK/araf-${component}-${VERSION}.oci.tar"
  curl -fsSL --retry 3 -o "$archive" "$BASE/araf-${component}-${VERSION}.oci.tar"
  printf '%s  %s\n' "${TAR_SHA[$component]}" "$archive" | sha256sum -c - >/dev/null
  python3 - "$archive" "${CONFIG_SHA[$component]}" "$SOURCE_SHA" <<'PY'
import hashlib
import json
import sys
import tarfile

archive, expected, source = sys.argv[1:]
with tarfile.open(archive, "r") as tar:
    manifest = json.load(tar.extractfile("manifest.json"))[0]
    config_path = manifest["Config"]
    config_blob = tar.extractfile(config_path).read()
    actual = hashlib.sha256(config_blob).hexdigest()
    assert actual == expected, (actual, expected)
    config = json.loads(config_blob)
    assert config["config"]["Labels"]["org.opencontainers.image.revision"] == source
PY
  loaded="$(docker load -i "$archive" 2>&1 | sed -n 's/^Loaded image\( ID\)\?: //p' | head -1)"
  [ -n "$loaded" ] || { echo "$component: docker load did not return an image ID" >&2; exit 1; }
  LOADED_IDS+=("$loaded")
  revision="$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$loaded")"
  [ "$revision" = "$SOURCE_SHA" ] || { echo "$component: revision mismatch: $revision" >&2; exit 1; }
  printf '%s: archive-config=%s docker-id=%s revision=%s\n' \
    "$component" "${CONFIG_SHA[$component]}" "$loaded" "$revision"
done
echo 'OCI identity smoke: PASS'
