#!/usr/bin/env python3
"""Atomically write the release verifier's machine-readable success record."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import secrets


def open_real_directory(path: pathlib.Path) -> int:
    """Open every parent component without following symlinks."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("verification report parent must be a normalized absolute path")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def write_report(path: pathlib.Path, version: str, tag: str, commit: str, tree: str) -> None:
    expected_tag = f"v{version}"
    expected_identity = (
        f"https://github.com/o3kio/o3k/.github/workflows/release.yml@refs/tags/{expected_tag}"
    )
    if tag != expected_tag:
        raise ValueError("verified release tag does not match version")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("verified release version is malformed")
    for value in (commit, tree):
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError("verified source identity is malformed")
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ValueError("verification report path must be an unused absolute path")
    try:
        resolved_parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise ValueError("verification report parent must be an existing directory") from error
    if resolved_parent != path.parent or not resolved_parent.is_dir():
        raise ValueError("verification report parent must not contain symlinks")

    report = {
        "schema": "o3k.release-verification.v1",
        "status": "passed",
        "version": version,
        "tag": tag,
        "source_commit": commit,
        "source_tree": tree,
        "workflow_identity": expected_identity,
        "checks": {
            "provenance": "passed",
            "signature": "passed",
            "source_identity": "passed",
            "transparency": "passed",
        },
    }
    if not path.name or path.name in {".", ".."} or "/" in path.name:
        raise ValueError("verification report filename is invalid")
    directory_fd = open_real_directory(path.parent)
    temporary_name = f".{path.name}.{secrets.token_hex(12)}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            json.dump(report, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # linkat publishes only if the destination name is absent and stays
        # within the already-opened real parent directory.
        os.link(temporary_name, path.name, src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd, follow_symlinks=False)
        os.unlink(temporary_name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(directory_fd)



def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=pathlib.Path)
    parser.add_argument("version")
    parser.add_argument("tag")
    parser.add_argument("commit")
    parser.add_argument("tree")
    args = parser.parse_args()
    try:
        write_report(args.path, args.version, args.tag, args.commit, args.tree)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
