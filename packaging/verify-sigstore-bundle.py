#!/usr/bin/env python3
"""Verify an O3K v2 digest manifest without trusting the release archive.

This verifier intentionally uses only Python's standard library and the
OpenSSL executable supplied by the supported operating systems.  It is kept
outside the release archive so the installer can authenticate the archive
before extraction.  Cosign remains the authoritative implementation in the
publisher workflow; this is the small public-consumer bootstrap verifier.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"sigstore verification failed: {message}")


def b64(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        fail(f"{field} is missing")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        fail(f"{field} is not base64: {error}")


def run(*args: str) -> str:
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT, text=True)
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "output", "")
        fail(f"{' '.join(args)}: {detail.strip() or error}")


def run_bytes(*args: str) -> bytes:
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT)
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "output", b"")
        fail(f"{' '.join(args)}: {detail.decode(errors='replace').strip() or error}")


def one_digest_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        fail(f"cannot read digest manifest: {error}")
    if not lines:
        fail("digest manifest is empty")
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]):
            fail("digest manifest contains a malformed entry")
        name = fields[1]
        if name in entries:
            fail(f"digest manifest contains duplicate entry: {name}")
        if name.startswith("/") or ".." in Path(name).parts:
            fail(f"digest manifest contains an unsafe path: {name}")
        entries[name] = fields[0]
    return entries


def verify_transparency(tlog: dict, manifest: Path) -> None:
    proof = tlog.get("inclusionProof")
    if not isinstance(proof, dict):
        fail("transparency inclusion proof is missing")
    checkpoint = proof.get("checkpoint")
    if not isinstance(checkpoint, dict) or not isinstance(checkpoint.get("envelope"), str):
        fail("transparency checkpoint is missing")
    envelope = checkpoint["envelope"]
    if "rekor.sigstore.dev" not in envelope:
        fail("transparency checkpoint is not from the governed Rekor log")
    try:
        note, signature_line = envelope.rsplit("\n\n", 1)
        signature_line = signature_line.strip()
        _, signer, encoded = signature_line.split(" ", 2)
        signature = b64(encoded, "checkpoint signature")
        if len(signature) <= 4:
            fail("checkpoint signature is truncated")
        origin, size_text, root_text = note.splitlines()[:3]
        tree_size = int(size_text)
        root_hash = base64.b64decode(root_text, validate=True)
    except (ValueError, TypeError) as error:
        fail(f"malformed transparency checkpoint: {error}")
    if signer != "rekor.sigstore.dev" or not origin.startswith("rekor.sigstore.dev - "):
        fail("checkpoint signer/origin is wrong")
    proof_root = b64(proof.get("rootHash"), "inclusionProof.rootHash")
    if tree_size != int(proof.get("treeSize", -1)) or root_hash != proof_root:
        fail("checkpoint does not bind the inclusion proof root")
    key = Path(__file__).with_name("trust") / "rekor.pub"
    if not key.is_file():
        fail("pinned Rekor public key is missing")
    key_der = run_bytes("openssl", "pkey", "-pubin", "-in", str(key), "-outform", "DER")
    if signature[:4] != hashlib.sha256(key_der).digest()[:4]:
        fail("checkpoint key hint does not match the pinned Rekor key")
    with tempfile.TemporaryDirectory(prefix="o3k-rekor-verify-") as temp:
        work = Path(temp)
        (work / "checkpoint").write_bytes((note + "\n").encode())
        (work / "signature").write_bytes(signature[4:])
        run("openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(work / "signature"), str(work / "checkpoint"))
    hashes = proof.get("hashes")
    if not isinstance(hashes, list):
        fail("inclusion proof hashes are missing")
    index = int(proof.get("logIndex", -1))
    if index < 0 or index >= tree_size:
        fail("inclusion proof index is outside the checkpoint tree")
    body = b64(tlog.get("canonicalizedBody"), "tlog canonicalizedBody")
    node = hashlib.sha256(b"\0" + body).digest()
    inner = (index ^ (tree_size - 1)).bit_length()
    border = (index >> inner).bit_count()
    if len(hashes) != inner + border:
        fail("inclusion proof has the wrong number of hashes")
    for level, encoded_hash in enumerate(hashes[:inner]):
        sibling = b64(encoded_hash, "inclusion proof hash")
        children = (node + sibling) if ((index >> level) & 1) == 0 else (sibling + node)
        node = hashlib.sha256(b"\1" + children).digest()
    for encoded_hash in hashes[inner:]:
        node = hashlib.sha256(b"\1" + b64(encoded_hash, "inclusion proof hash") + node).digest()
    if node != proof_root:
        fail("inclusion proof does not reach the signed checkpoint root")
    try:
        body_json = json.loads(body)
        logged_digest = body_json["spec"]["data"]["hash"]["value"]
    except (ValueError, KeyError, TypeError) as error:
        fail(f"malformed transparency body: {error}")
    if logged_digest != hashlib.sha256(manifest.read_bytes()).hexdigest():
        fail("transparency entry is not for release-digests.txt")


def verify(version: str, root: Path, expected_commit: str | None = None) -> None:
    manifest = root / "release-digests.txt"
    bundle = root / "release-digests.sigstore.json"
    if not manifest.is_file() or not bundle.is_file():
        fail("release-digests.txt and release-digests.sigstore.json are required")
    try:
        document = json.loads(bundle.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"malformed Sigstore bundle: {error}")
    if document.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        fail("unsupported Sigstore bundle media type")
    material = document.get("verificationMaterial")
    signature = document.get("messageSignature")
    if not isinstance(material, dict) or not isinstance(signature, dict):
        fail("bundle is missing verification material or message signature")
    digest = hashlib.sha256(manifest.read_bytes()).digest()
    message_digest = signature.get("messageDigest")
    if not isinstance(message_digest, dict) or message_digest.get("algorithm") != "SHA2_256":
        fail("bundle does not use SHA-256 for the signed manifest")
    if b64(message_digest.get("digest"), "messageDigest.digest") != digest:
        fail("signed message digest does not match release-digests.txt")
    signature_bytes = b64(signature.get("signature"), "messageSignature.signature")
    certificate = material.get("certificate")
    if not isinstance(certificate, dict):
        fail("bundle has no signing certificate")
    leaf = b64(certificate.get("rawBytes"), "certificate.rawBytes")
    tlogs = material.get("tlogEntries")
    if not isinstance(tlogs, list) or not tlogs or not isinstance(tlogs[0], dict):
        fail("Sigstore bundle has no transparency-log entry")
    try:
        integrated_time = str(int(tlogs[0]["integratedTime"]))
    except (KeyError, TypeError, ValueError):
        fail("transparency entry has no valid integrated time")
    tag = "v" + version.removeprefix("v")
    identity = f"https://github.com/o3kio/o3k/.github/workflows/release.yml@refs/tags/{tag}"
    with tempfile.TemporaryDirectory(prefix="o3k-sigstore-") as tmp:
        work = Path(tmp)
        leaf_path = work / "leaf.der"
        leaf_path.write_bytes(leaf)
        root_cert = Path(__file__).with_name("trust") / "fulcio_v1.crt.pem"
        intermediate_cert = Path(__file__).with_name("trust") / "fulcio_intermediate_v1.crt.pem"
        if not root_cert.is_file():
            fail("pinned Fulcio root is missing")
        if not intermediate_cert.is_file():
            fail("pinned Fulcio intermediate is missing")
        run("openssl", "verify", "-attime", integrated_time, "-CAfile", str(root_cert), "-untrusted", str(intermediate_cert), str(leaf_path))
        pub = run("openssl", "x509", "-inform", "DER", "-in", str(leaf_path), "-pubkey", "-noout")
        san = run("openssl", "x509", "-inform", "DER", "-in", str(leaf_path), "-noout", "-ext", "subjectAltName")
        if f"URI:{identity}" not in san:
            fail("certificate identity is not the exact protected release tag")
        if "https://token.actions.githubusercontent.com" not in run(
            "openssl", "x509", "-inform", "DER", "-in", str(leaf_path), "-text", "-noout"
        ):
            fail("certificate does not name the GitHub Actions OIDC issuer")
        pub_path = work / "pub.pem"
        pub_path.write_text(pub, encoding="ascii")
        sig_path = work / "signature.der"
        sig_path.write_bytes(signature_bytes)
        run("openssl", "dgst", "-sha256", "-verify", str(pub_path), "-signature", str(sig_path), str(manifest))

    entries = one_digest_manifest(manifest)
    expected_archive = f"o3k-{version.removeprefix('v')}-linux-x86_64.tar.gz"
    if expected_archive not in entries:
        fail("release archive is absent from the authenticated digest manifest")
    for required in ("install.sh", expected_archive, "provenance.json"):
        if required not in entries:
            fail(f"authenticated digest manifest omits {required}")

    provenance_path = root / "provenance.json"
    if not provenance_path.is_file():
        fail("provenance.json is required")
    if entries["provenance.json"] != hashlib.sha256(provenance_path.read_bytes()).hexdigest():
        fail("provenance.json does not match the authenticated digest manifest")
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"malformed provenance.json: {error}")
    if provenance.get("release") != tag or provenance.get("repository") != "o3kio/o3k":
        fail("provenance release or repository binding is wrong")
    if provenance.get("workflow") != ".github/workflows/release.yml":
        fail("provenance workflow binding is wrong")
    if provenance.get("oidc_issuer") != "https://token.actions.githubusercontent.com":
        fail("provenance OIDC issuer binding is wrong")
    if expected_commit is not None and provenance.get("source_commit") != expected_commit:
        fail("provenance source commit does not match the expected tag identity")

    verify_transparency(tlogs[0], manifest)
    print(f"verified keyless O3K release: {tag} ({identity})")


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        raise SystemExit("usage: verify-sigstore-bundle.py VERSION DIST_ROOT [SOURCE_COMMIT]")
    verify(sys.argv[1], Path(sys.argv[2]), sys.argv[3] if len(sys.argv) == 4 else None)
