#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="${ROOT_DIR}/scripts/pp5-verify-release-artifact.sh"
ARCHIVE_HELPER="${ROOT_DIR}/scripts/pp5_release_archive.py"
MANIFEST_TESTS="${ROOT_DIR}/scripts/test_validate_pp5_release_manifest.py"
python3 - "${HELPER}" <<'PY'
import pathlib, sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
required = (
    "SOURCE_TREE", "PEELED_TREE", "bundle_path",
    'name.startswith("./")', 'digest_name.removeprefix("./")',
    'manifest.json")', 'SHA256SUMS")', 'sbom.spdx.json")',
    'o3k.release-verification-report.v1', 'status": "passed"',
    'source_sha', 'source_tree',
    'release provenance contains duplicate asset', 'signature_bundle_sha256',
    'pp5_release_archive.py', 'validate_pp5_release_manifest.py',
)
for needle in required:
    assert needle in text, f"release verifier lost required binding: {needle}"
assert 'path = root.joinpath(*relative.parts)' in text
manifest_validator = pathlib.Path(sys.argv[1]).parent / "validate_pp5_release_manifest.py"
manifest_text = manifest_validator.read_text(encoding="utf-8")
assert 'release manifest source_tree does not match candidate' in manifest_text
PY

python3 - "${ARCHIVE_HELPER}" <<'PY'
import pathlib, sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert 'parts == (release_root,)' in text, "archive root directory must be accepted"
assert 'O_EXCL' in text and 'O_NOFOLLOW' in text, "archive files must be created safely"
assert 'bundle.extractall' not in text, "generic tar extraction must not be used"
PY

python3 "${MANIFEST_TESTS}"
python3 "${ROOT_DIR}/scripts/test_pp5_release_archive.py"

echo "PP.5 release artifact guards: PASS"
