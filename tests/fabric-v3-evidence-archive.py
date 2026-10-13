#!/usr/bin/env python3
"""Create a bounded, secret-aware archive of Fabric campaign evidence."""
from __future__ import annotations

import argparse
import pathlib
import tarfile


EXCLUDED_PATHS = {
    "management/campaign_ed25519",
    "management/probe_ed25519",
    "management/tls/certs",
    "environment/stage",
    "environment/product-source",
    "controller-data",
    "api/auth.headers.raw",
}


def _excluded(relative: pathlib.PurePosixPath) -> bool:
    name = relative.as_posix()
    return any(name == entry or name.startswith(entry + "/") for entry in EXCLUDED_PATHS)


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
            if _excluded(relative):
                continue
            if any(_excluded(parent) for parent in relative.parents if parent != pathlib.PurePosixPath(".")):
                continue
            output.add(path, arcname=f"{root_name}/{relative.as_posix()}", recursive=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True, type=pathlib.Path)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    args = parser.parse_args()
    create_archive(args.evidence_dir, args.archive)


if __name__ == "__main__":
    main()
