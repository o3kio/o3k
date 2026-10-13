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
                "api/auth.headers": "X-Subject-Token: AUTH_HEADER_SENTINEL\n",
                "api/auth.body": '{"token":"AUTH_BODY_SENTINEL"}\n',
                "management/campaign_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\n",
                "management/probe_ed25519": "PRIVATE_KEY_SENTINEL\n",
                "management/tls/certs/controller-key.pem": "TLS_PRIVATE_KEY_SENTINEL\n",
                "management/o3kd.log": "ingress_owner_token=LOG_TOKEN_SENTINEL\n",
                "management/known_hosts": "KNOWN_HOST_SENTINEL\n",
                "management/guest-a-fabric-control.pcap": b"PCAP_SENTINEL\x00\x01".decode("latin1"),
                "attachments/dhcp-dora.pcap": "DHCP_PCAP_SENTINEL",
                "environment/stage/credential.txt": "PASSWORD_SENTINEL\n",
                "environment/product-source/secret.txt": "PRODUCT_SOURCE_SENTINEL\n",
                "controller-data/o3k.sqlite": "DATABASE_SENTINEL\n",
                "before-departure/plans/host-a-fabric-plan.json":
                    '{"ingress_owner_token":"JSON_TOKEN_SENTINEL","accessToken":"CAMEL_ACCESS_TOKEN_SENTINEL",'
                    '"refreshToken":"CAMEL_REFRESH_TOKEN_SENTINEL","clientSecret":"CAMEL_SECRET_SENTINEL",'
                    '"privateKey":"CAMEL_PRIVATE_KEY_SENTINEL","note":"Bearer JSON_BEARER_SENTINEL","generation":3}\n',
                "diagnostics/accidental-token.txt": "token=TEXT_TOKEN_SENTINEL\n",
                "diagnostics/malformed.json": '{"token":"MALFORMED_JSON_SENTINEL"\n',
                "result.json": '{"result":"FAIL"}\n',
            }
            for relative, contents in files.items():
                path = evidence / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            outside_secret = root / "outside-secret.txt"
            outside_secret.write_text("SYMLINK_SECRET_SENTINEL\n")
            (evidence / "diagnostics/external-secret.txt").symlink_to(outside_secret)

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
                member_contents = {
                    member.name: bundle.extractfile(member).read()
                    for member in bundle.getmembers()
                    if member.isfile()
                }
            members = list(member_contents.values())
            combined = b"\n".join(members)
            self.assertIn("campaign-run/result.json", names)
            self.assertIn(
                b'"ingress_owner_token": "[REDACTED]"',
                member_contents["campaign-run/before-departure/plans/host-a-fabric-plan.json"],
            )
            self.assertIn(
                b'"note": "[REDACTED]"',
                member_contents["campaign-run/before-departure/plans/host-a-fabric-plan.json"],
            )
            redacted_plan = member_contents["campaign-run/before-departure/plans/host-a-fabric-plan.json"]
            for key in (b"accessToken", b"refreshToken", b"clientSecret", b"privateKey"):
                self.assertIn(key + b'": "[REDACTED]"', redacted_plan)
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
                b"AUTH_HEADER_SENTINEL",
                b"AUTH_BODY_SENTINEL",
                b"LOG_TOKEN_SENTINEL",
                b"KNOWN_HOST_SENTINEL",
                b"PCAP_SENTINEL",
                b"DHCP_PCAP_SENTINEL",
                b"JSON_TOKEN_SENTINEL",
                b"CAMEL_ACCESS_TOKEN_SENTINEL",
                b"CAMEL_REFRESH_TOKEN_SENTINEL",
                b"CAMEL_SECRET_SENTINEL",
                b"CAMEL_PRIVATE_KEY_SENTINEL",
                b"JSON_BEARER_SENTINEL",
                b"TEXT_TOKEN_SENTINEL",
                b"MALFORMED_JSON_SENTINEL",
                b"SYMLINK_SECRET_SENTINEL",
            ):
                self.assertNotIn(sentinel, combined)
            self.assertNotIn("campaign-run/diagnostics/malformed.json", names)
            self.assertNotIn("campaign-run/diagnostics/external-secret.txt", names)
            for excluded in (
                "campaign-run/management/guest-a-fabric-control.pcap",
                "campaign-run/attachments/dhcp-dora.pcap",
                "campaign-run/management/known_hosts",
            ):
                self.assertNotIn(excluded, names)


if __name__ == "__main__":
    unittest.main()
