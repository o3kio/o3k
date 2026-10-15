#!/usr/bin/env bash
set -Eeuo pipefail

# Verify and extract one exact release for protected PP.5 runners.  The
# caller supplies the expected source SHA and archive digest; neither is
# inferred from the archive name or the checkout.
VERSION="${1:?usage: pp5-verify-release-artifact.sh VERSION SOURCE_SHA SOURCE_TREE ARCHIVE_SHA256 DIST_ROOT OUTPUT_ROOT}"
SOURCE_SHA="${2:?usage: pp5-verify-release-artifact.sh VERSION SOURCE_SHA SOURCE_TREE ARCHIVE_SHA256 DIST_ROOT OUTPUT_ROOT}"
SOURCE_TREE="${3:?usage: pp5-verify-release-artifact.sh VERSION SOURCE_SHA SOURCE_TREE ARCHIVE_SHA256 DIST_ROOT OUTPUT_ROOT}"
ARCHIVE_SHA256="${4:?usage: pp5-verify-release-artifact.sh VERSION SOURCE_SHA SOURCE_TREE ARCHIVE_SHA256 DIST_ROOT OUTPUT_ROOT}"
DIST_ROOT="${5:?usage: pp5-verify-release-artifact.sh VERSION SOURCE_SHA SOURCE_TREE ARCHIVE_SHA256 DIST_ROOT OUTPUT_ROOT}"
OUTPUT_ROOT="${6:?usage: pp5-verify-release-artifact.sh VERSION SOURCE_SHA SOURCE_TREE ARCHIVE_SHA256 DIST_ROOT OUTPUT_ROOT}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ "$VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "invalid release version" >&2; exit 2; }
[[ "$SOURCE_SHA" =~ ^[0-9a-fA-F]{40}$ ]] || { echo "invalid release source SHA" >&2; exit 2; }
[[ "$SOURCE_TREE" =~ ^[0-9a-fA-F]{40}$ ]] || { echo "invalid release source tree" >&2; exit 2; }
[[ "$ARCHIVE_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "invalid release archive digest" >&2; exit 2; }
[[ -d "$DIST_ROOT" && ! -L "$DIST_ROOT" ]] || { echo "release asset directory is unsafe" >&2; exit 2; }
[[ "$OUTPUT_ROOT" == /* && "$OUTPUT_ROOT" != *..* && ! -e "$OUTPUT_ROOT" && ! -L "$OUTPUT_ROOT" ]] || { echo "release output directory is unsafe" >&2; exit 2; }

VERSION_NO_V="${VERSION#v}"
TAG="v$VERSION_NO_V"
TAG_REPO="${O3K_RELEASE_TAG_REPO:-$ROOT_DIR}"
[[ -d "$TAG_REPO/.git" || -f "$TAG_REPO/.git" ]] || { echo "release tag repository is unavailable" >&2; exit 2; }
TAG_OBJECT="$(git -C "$TAG_REPO" rev-parse "refs/tags/$TAG" 2>/dev/null)" || { echo "release tag is not fetched: $TAG" >&2; exit 2; }
PEELED_COMMIT="$(git -C "$TAG_REPO" rev-parse "refs/tags/$TAG^{commit}" 2>/dev/null)" || { echo "release tag does not peel to a commit" >&2; exit 1; }
PEELED_TREE="$(git -C "$TAG_REPO" rev-parse "refs/tags/$TAG^{tree}" 2>/dev/null)" || { echo "release tag tree is unavailable" >&2; exit 1; }
[[ "$PEELED_COMMIT" == "$SOURCE_SHA" ]] || { echo "release tag commit does not match candidate" >&2; exit 1; }
[[ "$PEELED_TREE" == "$SOURCE_TREE" ]] || { echo "release tag tree does not match candidate" >&2; exit 1; }
ARCHIVE="$DIST_ROOT/o3k-${VERSION_NO_V}-linux-x86_64.tar.gz"
[[ -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] || { echo "release archive is missing" >&2; exit 2; }
actual_archive="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
[[ "$actual_archive" == "${ARCHIVE_SHA256,,}" ]] || { echo "release archive digest mismatch" >&2; exit 1; }

# This invokes the repository's existing OIDC/Sigstore and provenance checks.
VERIFIER_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-pp5-release-verify.XXXXXX")"
VERIFIER_LOG="$VERIFIER_DIR/verifier.log"
VERIFIER_REPORT="$VERIFIER_DIR/verifier-report.json"
trap 'rm -rf -- "$VERIFIER_DIR"' EXIT
if ! RELEASE_SOURCE_COMMIT="$SOURCE_SHA" RELEASE_SOURCE_TREE="$SOURCE_TREE" \
    O3K_RELEASE_TAG_REPO="$TAG_REPO" \
    bash "$ROOT_DIR/packaging/verify-release-sigstore.sh" "$VERSION" "$DIST_ROOT" \
      "$VERIFIER_REPORT" >"$VERIFIER_LOG" 2>&1; then
  cat "$VERIFIER_LOG" >&2
  exit 1
fi
EXPECTED_IDENTITY="https://github.com/o3kio/o3k/.github/workflows/release.yml@refs/tags/$TAG"
VERIFIED_IDENTITY="$(python3 - "$VERIFIER_REPORT" "$VERSION_NO_V" "$TAG" "$SOURCE_SHA" "$SOURCE_TREE" "$EXPECTED_IDENTITY" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
try:
    report = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit("Sigstore verifier structured report is missing or malformed") from error
expected = {
    "schema": "o3k.release-verification.v1",
    "status": "passed",
    "version": sys.argv[2],
    "tag": sys.argv[3],
    "source_commit": sys.argv[4],
    "source_tree": sys.argv[5],
    "workflow_identity": sys.argv[6],
    "checks": {
        "provenance": "passed",
        "signature": "passed",
        "source_identity": "passed",
        "transparency": "passed",
    },
}
if report != expected:
    raise SystemExit("Sigstore verifier structured report does not match the requested release identity")
print(report["workflow_identity"])
PY
)"
[[ "$VERIFIED_IDENTITY" == "$EXPECTED_IDENTITY" ]] || { echo "release verifier identity mismatch" >&2; exit 1; }
VERIFIER_REPORT_SHA256="$(sha256sum "$VERIFIER_REPORT" | awk '{print $1}')"

python3 "$ROOT_DIR/scripts/pp5_release_archive.py" "$ARCHIVE" "$OUTPUT_ROOT" "$VERSION_NO_V"
python3 "$ROOT_DIR/scripts/validate_pp5_release_manifest.py" \
  "$OUTPUT_ROOT/o3k-${VERSION_NO_V}/manifest.json" "$SOURCE_SHA" "$SOURCE_TREE" "$VERSION_NO_V"
python3 - "$OUTPUT_ROOT/o3k-${VERSION_NO_V}" <<'PY'
import pathlib, sys

release = pathlib.Path(sys.argv[1])
for binary in ("o3kd", "o3k", "o3k-compute"):
    path = release / "bin" / binary
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"release binary is missing or unsafe: {binary}")
PY

bash "$ROOT_DIR/packaging/verify-release-bundle.sh" "$OUTPUT_ROOT/o3k-${VERSION_NO_V}"
python3 - "$DIST_ROOT" "$OUTPUT_ROOT/o3k-${VERSION_NO_V}" "$OUTPUT_ROOT" "$VERSION_NO_V" "$ARCHIVE_SHA256" "$TAG_OBJECT" "$PEELED_COMMIT" "$PEELED_TREE" "$SOURCE_SHA" "$SOURCE_TREE" "$VERIFIED_IDENTITY" "$VERIFIER_REPORT" "$VERIFIER_REPORT_SHA256" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

dist, bundle, output, version, archive_sha, tag_object, commit, tree, source, source_tree, verified_identity, verifier_report_path, verifier_report_sha = sys.argv[1:]
dist_path, bundle_path, output_path = map(pathlib.Path, (dist, bundle, output))
archive_name = f"o3k-{version}-linux-x86_64.tar.gz"
required_assets = ["install.sh", archive_name, archive_name + ".sha256",
                   "release-digests.txt", "release-digests.sigstore.json", "provenance.json"]

def regular_file(root: pathlib.Path, name: str) -> pathlib.Path:
    relative = pathlib.PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise SystemExit(f"unsafe release asset path: {name}")
    path = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise SystemExit(f"release asset path traverses a symlink: {name}")
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"release asset is missing or unsafe: {name}")
    return path

for name in required_assets:
    regular_file(dist_path, name)

digest_lines: dict[str, str] = {}
for line in regular_file(dist_path, "release-digests.txt").read_text(encoding="utf-8").splitlines():
    fields = line.split()
    if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]):
        raise SystemExit("signed release digest list is malformed")
    name = fields[1]
    if name.startswith("./"):
        name = name[2:]
    relative = pathlib.PurePosixPath(name)
    if name in digest_lines or relative.is_absolute() or ".." in relative.parts:
        raise SystemExit("signed release digest list has a duplicate or unsafe path")
    digest_lines[name] = fields[0]

def verify_digest(root: pathlib.Path, digest_name: str, file_name: str | None = None) -> pathlib.Path:
    file_name = file_name or digest_name
    path = regular_file(root, file_name)
    expected = digest_lines.get(digest_name.removeprefix("./"))
    if expected is None or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit(f"signed release digest does not bind {digest_name}")
    return path

archive = verify_digest(dist_path, archive_name)
installer = verify_digest(dist_path, "install.sh")
verify_digest(dist_path, archive_name + ".sha256")
provenance_path = verify_digest(dist_path, "provenance.json")
manifest_path = verify_digest(bundle_path, f"o3k-{version}/manifest.json", "manifest.json")
checksums_path = verify_digest(bundle_path, f"o3k-{version}/SHA256SUMS", "SHA256SUMS")
sbom_path = verify_digest(bundle_path, f"o3k-{version}/sbom.spdx.json", "sbom.spdx.json")
if regular_file(dist_path, archive_name + ".sha256").read_text(encoding="utf-8").split()[0].lower() != archive_sha.lower():
    raise SystemExit("published archive checksum does not match requested digest")

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
if (manifest.get("source_commit") != source or manifest.get("source_tree") != source_tree
        or provenance.get("source_commit") != source or provenance.get("source_tree") != source_tree):
    raise SystemExit("release manifest/provenance source commit differs from the requested candidate")
if manifest.get("version") not in (version, f"v{version}") or provenance.get("release") not in (version, f"v{version}"):
    raise SystemExit("release manifest/provenance version differs from the requested release")
if commit != source or tree != source_tree:
    raise SystemExit("verified tag identity differs from the requested source identity")
expected_identity = f"https://github.com/o3kio/o3k/.github/workflows/release.yml@refs/tags/v{version}"
if verified_identity != expected_identity:
    raise SystemExit("Sigstore verifier identity differs from the requested release tag")
verifier_report_bytes = pathlib.Path(verifier_report_path).read_bytes()
if hashlib.sha256(verifier_report_bytes).hexdigest() != verifier_report_sha:
    raise SystemExit("release verifier structured report digest changed")
verifier_report = json.loads(verifier_report_bytes)
if verifier_report.get("schema") != "o3k.release-verification.v1" or verifier_report.get("status") != "passed":
    raise SystemExit("release verifier structured report is not a passing report")
if (verifier_report.get("version") != version or verifier_report.get("tag") != f"v{version}"
        or verifier_report.get("source_commit") != source or verifier_report.get("source_tree") != source_tree
        or verifier_report.get("workflow_identity") != verified_identity
        or verifier_report.get("checks") != {
            "provenance": "passed", "signature": "passed",
            "source_identity": "passed", "transparency": "passed"}):
    raise SystemExit("release verifier structured report differs from the requested release")

provenance_assets = provenance.get("assets")
if not isinstance(provenance_assets, list):
    raise SystemExit("release provenance assets are missing")
provenance_map = {}
for item in provenance_assets:
    if not isinstance(item, dict) or not isinstance(item.get("name"), str):
        raise SystemExit("release provenance asset entry is malformed")
    name = item["name"][2:] if item["name"].startswith("./") else item["name"]
    if name in provenance_map:
        raise SystemExit(f"release provenance contains duplicate asset: {name}")
    provenance_map[name] = item.get("sha256")
for name in ("install.sh", archive_name, archive_name + ".sha256",
             f"o3k-{version}/manifest.json", f"o3k-{version}/SHA256SUMS",
             f"o3k-{version}/sbom.spdx.json"):
    if provenance_map.get(name) != digest_lines.get(name):
        raise SystemExit(f"provenance does not bind the signed digest for {name}")

report = {
    "schema": "o3k.release-verification-report.v1",
    "status": "passed",
    "version": version,
    "tag": f"v{version}",
    "tag_object": tag_object,
    "source_sha": source,
    "source_tree": source_tree,
    "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    "install_sha256": hashlib.sha256(installer.read_bytes()).hexdigest(),
    "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    "sbom_sha256": hashlib.sha256(sbom_path.read_bytes()).hexdigest(),
    "provenance_sha256": hashlib.sha256(provenance_path.read_bytes()).hexdigest(),
    "signature_bundle_sha256": hashlib.sha256(regular_file(dist_path, "release-digests.sigstore.json").read_bytes()).hexdigest(),
    "sigstore_verification_report_sha256": verifier_report_sha,
    "checks": {
        "archive_round_trip": "passed",
        "signature": "passed",
        "provenance": "passed",
        "workflow_identity": "passed",
        "transparency": "passed",
    },
    "verifier": {
        "name": "O3K packaging release verifier",
        "version": "repository-pinned",
        "workflow_identity": verified_identity,
    },
}
(output_path / "pp5-release-verification.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
printf '%s\n' "$OUTPUT_ROOT/o3k-${VERSION_NO_V}"
