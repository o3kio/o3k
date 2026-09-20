#!/usr/bin/env bash
# Contract and negative tests for the v1 -> v2 release trust transition.
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT_DIR" <<'PY'
import pathlib
import subprocess
import tempfile
import yaml

root = pathlib.Path(__import__("sys").argv[1])
policy = yaml.safe_load((root / "packaging/trust-policy.yaml").read_text())
assert policy["legacy"]["scheme"] == "ed25519"
assert policy["legacy"]["public_key_fingerprint_sha256"] == (
    "0b75fba397c47600bfb7244a9bac2720ebecc5c4057b758ae9a4ce5ead23cef7"
)
assert policy["current"] == {
    "scheme": "sigstore-keyless",
    "first_release": "v0.4.0-rc.9",
    "oidc_issuer": "https://token.actions.githubusercontent.com",
    "repository": "o3kio/o3k",
    "workflow": ".github/workflows/release.yml",
    "environment": "release",
    "certificate_identity_template": "https://github.com/o3kio/o3k/.github/workflows/release.yml@refs/tags/{tag}",
    "transparency_log_required": True,
}
assert (root / "packaging/trust/o3k-release-ed25519-legacy.pub").read_bytes() == (
    root / "packaging/release-verify.pub"
).read_bytes()

workflow = (root / ".github/workflows/release.yml").read_text()
assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
assert "sigstore/cosign-installer@828df1e55de306ba29db814d6057ddae71883cda" in workflow
assert "cosign-release: v3.1.3" in workflow
assert "environment: release" in workflow
assert "id-token: write" in workflow
assert "O3K_RELEASE_SIGNING_KEY" not in workflow
assert "pull_request" not in workflow
assert "workflow_call" not in workflow

contract = yaml.safe_load((root / "contracts/release-bundle-v2.yaml").read_text())
assert contract["schema_version"] == 2
assert contract["authentication"]["scheme"] == "sigstore-keyless"
assert contract["authentication"]["workflow"] == ".github/workflows/release.yml"
assert contract["authentication"]["private_signing_key_required"] is False

with tempfile.TemporaryDirectory() as tmp:
    tmp_path = pathlib.Path(tmp)
    valid = {
        "schema_version": 2,
        "signature_scheme": "sigstore-keyless",
        "release": "v0.4.0-rc.9",
        "source_commit": "a" * 40,
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "repository": "o3kio/o3k",
        "workflow": ".github/workflows/release.yml",
        "digest_manifest": "release-digests.txt",
        "assets": [{"name": "install.sh", "sha256": "b" * 64}],
    }
    path = tmp_path / "provenance.json"
    path.write_text(__import__("json").dumps(valid))
    checker = root / "packaging/validate-sigstore-provenance.py"
    subprocess.run([checker, path, root / "packaging/trust-policy.yaml", "v0.4.0-rc.9", "a" * 40], check=True)
    for field, bad in (("oidc_issuer", "https://example.invalid"),
                       ("repository", "o3kio/other"),
                       ("workflow", ".github/workflows/other.yml"),
                       ("source_commit", "c" * 40)):
        changed = dict(valid)
        changed[field] = bad
        path.write_text(__import__("json").dumps(changed))
        assert subprocess.run([checker, path, root / "packaging/trust-policy.yaml", "v0.4.0-rc.9", "a" * 40]).returncode != 0

print("release signing migration checks: PASS")
PY

bash -n "$ROOT_DIR/packaging/make-provenance-sigstore.sh"
bash -n "$ROOT_DIR/packaging/verify-release-sigstore.sh"
