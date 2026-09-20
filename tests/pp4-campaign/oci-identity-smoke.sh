#!/usr/bin/env bash
# Focused PP.4 Araf OCI identity gate.  This deliberately exercises the
# published rc.16 archives through the host Docker engine, including engines
# that rematerialize OCI configs and therefore expose a different local image
# ID after `docker load`.
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="v1.0.0-rc.16"
SOURCE_SHA="98ea45245c0be8d4ad1e340f1e6cbc5a8d949293"
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
  [bff]=85afa9361225c40281c0371e1aad9f361aa8c988f4efc50d31669a43ca877c9c
  [tenant-console]=39f4392c97deec8db246f1383425896d3743872fc3a0c465b8ff5ac72341a0e0
  [operator-console]=4ebad231d0a7a189c8f5f1299654db295256821461a24cbbbdef08703ae29956
)
declare -A CONFIG_SHA=(
  [bff]=c54b961b26d4c22b9bc1dec31dd33fd365047d6970e42a5cbcbe36610aa1afbe
  [tenant-console]=2117dd6b268e2feb0a50835beff2a805c925dbeead87a3466cf5156434a4501a
  [operator-console]=2ea47baa764eac8b493447c904d2237d1250b815fee588e4d866fee51b6c92ab
)
declare -A INDEX_DIGEST=(
  [bff]=sha256:d136814198eaa4df2f1028c35b421c6b5cfcdc3d6450584ad9b6e8d7e7b83f29
  [tenant-console]=sha256:3fd0a3c93a0bdcbd733227fd063e232851cf605038077f1fddfbf1a4762309f1
  [operator-console]=sha256:1abd14091eaf20ba1c2f3032743fd2804f7d1ebb182722bca989c56a21169a4e
)
declare -A PLATFORM_DIGEST=(
  [bff]=sha256:95eae6e725aff5c11cf9a0fca7e6ad12e5644016e3e524a3c98cd1289b0804c9
  [tenant-console]=sha256:5544725ee8e3d1f0667d0b781356a2d400a0428b915b05b1eba185d78e4a793d
  [operator-console]=sha256:3043604f8a7c66cc1723a519777d7f98ce1160e7d5921b909260e1ca2b3c866b
)
declare -A IMAGE=(
  [bff]=ghcr.io/o3kio/araf-bff
  [tenant-console]=ghcr.io/o3kio/araf-tenant-console
  [operator-console]=ghcr.io/o3kio/araf-operator-console
)

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }

for component in bff tenant-console operator-console; do
  ref="${IMAGE[$component]}:${VERSION}"
  docker pull --platform linux/amd64 "$ref" >/dev/null
  actual_index="$(docker image inspect -f '{{index .RepoDigests 0}}' "$ref")"
  expected_ref="${IMAGE[$component]}@${INDEX_DIGEST[$component]}"
  [ "$actual_index" = "$expected_ref" ] || {
    echo "$component: index digest mismatch: $actual_index (expected $expected_ref)" >&2
    exit 1
  }
  actual_platform="$(docker manifest inspect --verbose "$ref" | python3 -c '
import json
import sys

document = json.load(sys.stdin)
if isinstance(document, list):
    document = document[0]
print(document["Descriptor"]["digest"])
')"
  [ "$actual_platform" = "${PLATFORM_DIGEST[$component]}" ] || {
    echo "$component: platform digest mismatch: $actual_platform (expected ${PLATFORM_DIGEST[$component]})" >&2
    exit 1
  }
  docker image rm "$ref" >/dev/null 2>&1 || true
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
  printf '%s: index=%s platform=%s config=%s docker-id=%s revision=%s\n' \
    "$component" "${INDEX_DIGEST[$component]}" "${PLATFORM_DIGEST[$component]}" \
    "${CONFIG_SHA[$component]}" "$loaded" "$revision"
done
echo 'OCI identity smoke: PASS'
