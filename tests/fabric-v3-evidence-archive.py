#!/usr/bin/env python3
"""Create a bounded, secret-aware archive of Fabric campaign evidence."""
from __future__ import annotations

import argparse
import io
import json
import pathlib
import re
import tarfile


EXCLUDED_PATHS = {
    "management/campaign_ed25519",
    "management/probe_ed25519",
    "management/tls/certs",
    "environment/stage",
    "environment/product-source",
    "controller-data",
    "api/auth.body",
    "api/auth.headers",
    "api/auth.headers.raw",
    "management/o3kd.log",
    "management/known_hosts",
}

SENSITIVE_FIELD = re.compile(
    r"(?:^|_)(?:token|secret|password|passwd|credential|credentials|private_key|authorization|api_key)(?:$|_)",
    re.IGNORECASE,
)
EXCLUDED_SUFFIXES = (".pcap", ".pcapng", ".pem", ".key", ".log")
EXCLUDED_NAME_PARTS = ("keyscan",)
SENSITIVE_TEXT = re.compile(
    rb"(?im)^\s*(?:authorization|proxy-authorization|x-auth-token|x-subject-token)\s*:"
    rb"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    rb"|\b(?:access|auth|bearer|client|ingress_owner|refresh|service)?_?"
    rb"(?:token|secret|password|passwd|credential)\b\s*[:= ]\s*[^\s\"']{4,}"
    rb"|\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"
    rb"|https?://[^/\s:@]+:[^@\s/]+@"
)


def _excluded(relative: pathlib.PurePosixPath) -> bool:
    name = relative.as_posix()
    lowered = relative.name.lower()
    return (
        any(name == entry or name.startswith(entry + "/") for entry in EXCLUDED_PATHS)
        or name.startswith("api/auth.")
        or lowered.endswith(EXCLUDED_SUFFIXES)
        or any(part in lowered for part in EXCLUDED_NAME_PARTS)
    )


def _redact_json(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if SENSITIVE_FIELD.search(str(key)) else _redact_json(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if isinstance(value, str) and SENSITIVE_TEXT.search(value.encode()):
        return "[REDACTED]"
    return value


def _safe_contents(path: pathlib.Path, relative: pathlib.PurePosixPath) -> bytes | None:
    contents = path.read_bytes()
    if relative.suffix.lower() == ".json":
        try:
            value = json.loads(contents)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        contents = (json.dumps(_redact_json(value), sort_keys=True, indent=2) + "\n").encode()
    elif SENSITIVE_TEXT.search(contents):
        return None
    return contents


def create_archive(evidence_dir: pathlib.Path, archive_path: pathlib.Path) -> None:
    root = evidence_dir.resolve(strict=True)
    archive = archive_path.resolve()
    if not root.is_dir() or root == archive or root in archive.parents:
        raise ValueError("archive must be a file outside the evidence directory")
    archive.parent.mkdir(parents=True, exist_ok=True)
    root_name = root.name
    with tarfile.open(archive, "w:gz") as output:
        output.add(root, arcname=root_name, recursive=False)
        for path in sorted(root.rglob("*")):
            relative = pathlib.PurePosixPath(path.relative_to(root).as_posix())
            if path.is_symlink() or _excluded(relative):
                continue
            if any(_excluded(parent) for parent in relative.parents if parent != pathlib.PurePosixPath(".")):
                continue
            if path.is_dir():
                output.add(path, arcname=f"{root_name}/{relative.as_posix()}", recursive=False)
                continue
            if not path.is_file():
                continue
            contents = _safe_contents(path, relative)
            if contents is None:
                continue
            info = output.gettarinfo(str(path), arcname=f"{root_name}/{relative.as_posix()}")
            info.size = len(contents)
            output.addfile(info, io.BytesIO(contents))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True, type=pathlib.Path)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    args = parser.parse_args()
    create_archive(args.evidence_dir, args.archive)


if __name__ == "__main__":
    main()
