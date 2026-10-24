"""Safely unpack one verified PP.5 release archive.

The caller verifies the archive digest and release signature before invoking
this module. This module still treats the archive as untrusted input and only
extracts regular files and directories below the expected release root.
"""

from __future__ import annotations

import os
import pathlib
import stat
import sys
import tarfile


class ArchiveError(ValueError):
    pass


def normalized_member_path(name: str, release_root: str) -> tuple[str, ...]:
    path = pathlib.PurePosixPath(name)
    if name.startswith("/") or path.is_absolute() or ".." in path.parts:
        raise ArchiveError(f"unsafe release archive path: {name}")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if not parts:
        raise ArchiveError(f"empty release archive path: {name}")
    if parts[0] != release_root:
        raise ArchiveError(f"unexpected release archive root: {name}")
    return parts


def safe_extract(archive: pathlib.Path, output: pathlib.Path, version: str) -> pathlib.Path:
    release_root = f"o3k-{version}"
    entries: dict[tuple[str, ...], bool] = {}
    if archive.is_symlink() or not archive.is_file():
        raise ArchiveError("release archive must be an existing regular file, not a symlink")
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ArchiveError("release output path must be absolute and new")
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ArchiveError("release output parent must be an existing regular directory")
    output_parent = output.parent.resolve(strict=True)
    if output_parent != output.parent:
        raise ArchiveError("release output parent must not contain symlinks")

    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            raise ArchiveError("release archive is empty")

        for member in members:
            parts = normalized_member_path(member.name, release_root)
            is_directory = member.isdir()
            if parts == (release_root,) and not is_directory:
                raise ArchiveError("release archive root entry must be a directory")
            if not (member.isfile() or is_directory):
                raise ArchiveError(f"release archive contains non-regular entry: {member.name}")
            if member.mode & (stat.S_ISUID | stat.S_ISGID):
                raise ArchiveError(f"release archive contains a privileged mode: {member.name}")
            if parts in entries:
                raise ArchiveError(f"release archive contains a duplicate path: {member.name}")

            for index in range(1, len(parts)):
                parent = parts[:index]
                if entries.get(parent) is False:
                    raise ArchiveError(f"release archive path traverses a regular file: {member.name}")
            if not is_directory and any(existing[: len(parts)] == parts for existing in entries):
                raise ArchiveError(f"release archive file conflicts with a child path: {member.name}")
            entries[parts] = is_directory

        if not any(parts[0] == release_root and len(parts) > 1 for parts in entries):
            raise ArchiveError("release archive contains no files below the release root")

        # Extraction is deliberately implemented here instead of using
        # extractall: every destination is derived from validated POSIX path
        # components, files are created with O_EXCL, and archive links/special
        # entries are rejected before any filesystem mutation.
        old_umask = os.umask(0o077)
        try:
            output.mkdir(mode=0o700, exist_ok=False)
        finally:
            os.umask(old_umask)
        if stat.S_IMODE(output.stat().st_mode) != 0o700:
            raise ArchiveError("release output directory does not have mode 0700")

        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle.getmembers():
                parts = normalized_member_path(member.name, release_root)
                destination = output.joinpath(*parts)
                if member.isdir():
                    destination.mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise ArchiveError(f"release archive file cannot be read: {member.name}")
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    member.mode & 0o777,
                )
                try:
                    with os.fdopen(descriptor, "wb", closefd=False) as target:
                        while chunk := source.read(1024 * 1024):
                            target.write(chunk)
                    os.fchmod(descriptor, member.mode & 0o777)
                finally:
                    os.close(descriptor)
                    source.close()

    return output / release_root


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: pp5_release_archive.py ARCHIVE OUTPUT_ROOT VERSION", file=sys.stderr)
        return 2
    archive, output, version = sys.argv[1:]
    if not version or "/" in version or version in (".", ".."):
        print("invalid release version", file=sys.stderr)
        return 2
    try:
        safe_extract(pathlib.Path(archive), pathlib.Path(output), version)
    except (ArchiveError, OSError, tarfile.TarError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
