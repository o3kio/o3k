from __future__ import annotations

import io
import pathlib
import stat
import tarfile
import tempfile
import unittest

from pp5_release_archive import ArchiveError, safe_extract


VERSION = "0.4.0-rc.25"
ROOT = f"o3k-{VERSION}"


def add_file(bundle: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mode = mode
    bundle.addfile(member, io.BytesIO(data))


def make_archive(path: pathlib.Path, entries: list[tuple[str, str, object]]) -> None:
    with tarfile.open(path, "w:gz") as bundle:
        for name, kind, value in entries:
            if kind == "directory":
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE
                member.mode = int(value)
                bundle.addfile(member)
            elif kind == "file":
                data, mode = value if isinstance(value, tuple) else (value, 0o644)
                add_file(bundle, name, bytes(data), int(mode))
            elif kind == "symlink":
                member = tarfile.TarInfo(name)
                member.type = tarfile.SYMTYPE
                member.linkname = str(value)
                bundle.addfile(member)
            else:
                raise AssertionError(kind)


class ReleaseArchiveTests(unittest.TestCase):
    def test_accepts_packager_root_and_preserves_binary_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "release.tar.gz"
            output = root / "out"
            make_archive(archive, [
                (f"./{ROOT}/", "directory", 0o755),
                (f"./{ROOT}/bin/", "directory", 0o755),
                (f"./{ROOT}/bin/o3kd", "file", (b"binary", 0o755)),
                (f"./{ROOT}/manifest.json", "file", b"{}"),
            ])
            release = safe_extract(archive, output, VERSION)
            self.assertEqual((release / "manifest.json").read_bytes(), b"{}")
            self.assertEqual(stat.S_IMODE((release / "bin/o3kd").stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)

    def test_rejects_traversal_wrong_root_duplicate_and_links_before_output(self) -> None:
        malformed = (
            [(f"./{ROOT}/", "directory", 0o755), (f"./{ROOT}/../escape", "file", b"x")],
            [("./other/manifest.json", "file", b"{}")],
            [(f"./{ROOT}/manifest.json", "file", b"{}"), (f"./{ROOT}/manifest.json", "file", b"{}")],
            [(f"./{ROOT}/link", "symlink", "manifest.json")],
            [(f"./{ROOT}/manifest.json", "file", (b"{}", 0o4644))],
        )
        for entries in malformed:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                archive = root / "bad.tar.gz"
                output = root / "out"
                make_archive(archive, entries)
                with self.assertRaises(ArchiveError):
                    safe_extract(archive, output, VERSION)
                self.assertFalse(output.exists())

    def test_rejects_existing_output_and_symlinked_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "release.tar.gz"
            make_archive(archive, [(f"./{ROOT}/manifest.json", "file", b"{}")])
            output = root / "existing"
            output.mkdir()
            with self.assertRaises(ArchiveError):
                safe_extract(archive, output, VERSION)

            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ArchiveError):
                safe_extract(archive, alias / "out", VERSION)

    def test_rejects_symlinked_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "release.tar.gz"
            make_archive(archive, [(f"./{ROOT}/manifest.json", "file", b"{}")])
            alias = root / "archive-link.tar.gz"
            alias.symlink_to(archive)
            output = root / "out"

            with self.assertRaises(ArchiveError):
                safe_extract(alias, output, VERSION)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
