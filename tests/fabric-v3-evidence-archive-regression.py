#!/usr/bin/env python3
"""Prove sensitive campaign artifacts and credential fixtures stay out of archives."""
from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "fabric_v3_evidence_archive", ROOT / "fabric-v3-evidence-archive.py"
)
assert SPEC and SPEC.loader
archive_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive_module)


class EvidenceArchiveRegression(unittest.TestCase):
    def test_archive_excludes_credentials_private_keys_and_private_runtime_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            evidence = root / "campaign-run"
            archive = root / "campaign-run.tar.gz"
            files = {
                "api/auth.headers.raw": "X-Subject-Token: SECRET_BEARER_SENTINEL\n",
                "api/auth.headers": "X-Subject-Token: [REDACTED]\n",
                "api/auth.body": '{"token":"response-shape-only"}\n',
                "management/campaign_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\n",
                "management/probe_ed25519": "PRIVATE_KEY_SENTINEL\n",
                "management/tls/certs/controller-key.pem": "TLS_PRIVATE_KEY_SENTINEL\n",
                "environment/stage/credential.txt": "PASSWORD_SENTINEL\n",
                "environment/product-source/secret.txt": "PRODUCT_SOURCE_SENTINEL\n",
                "controller-data/o3k.sqlite": "DATABASE_SENTINEL\n",
                "result.json": '{"result":"FAIL"}\n',
            }
            for relative, contents in files.items():
                path = evidence / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)

            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "fabric-v3-evidence-archive.py"),
                    "--evidence-dir",
                    str(evidence),
                    "--archive",
                    str(archive),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            with tarfile.open(archive, "r:gz") as bundle:
                names = bundle.getnames()
                members = [
                    bundle.extractfile(member).read()
                    for member in bundle.getmembers()
                    if member.isfile()
                ]
            combined = b"\n".join(members)
            self.assertIn("campaign-run/result.json", names)
            self.assertIn("[REDACTED]", combined.decode())
            for excluded in archive_module.EXCLUDED_PATHS:
                self.assertFalse(
                    any(name == f"campaign-run/{excluded}" or name.startswith(f"campaign-run/{excluded}/") for name in names),
                    excluded,
                )
            for sentinel in (
                b"SECRET_BEARER_SENTINEL",
                b"OPENSSH PRIVATE KEY",
                b"PRIVATE_KEY_SENTINEL",
                b"TLS_PRIVATE_KEY_SENTINEL",
                b"PASSWORD_SENTINEL",
                b"PRODUCT_SOURCE_SENTINEL",
                b"DATABASE_SENTINEL",
            ):
                self.assertNotIn(sentinel, combined)


if __name__ == "__main__":
    unittest.main()
