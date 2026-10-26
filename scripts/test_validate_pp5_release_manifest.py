#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from validate_pp5_release_manifest import validate


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / "manifest.json"
        self.document = {
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "version": "0.4.0-rc.25",
        }
        self.write()

    def write(self, document: dict | None = None) -> None:
        self.manifest.write_text(json.dumps(document or self.document), encoding="utf-8")

    def test_exact_identity_passes(self) -> None:
        validate(self.manifest, "a" * 40, "b" * 40, "0.4.0-rc.25")

    def test_wrong_source_sha_fails(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_commit"):
            validate(self.manifest, "c" * 40, "b" * 40, "0.4.0-rc.25")

    def test_wrong_source_tree_fails(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_tree"):
            validate(self.manifest, "a" * 40, "c" * 40, "0.4.0-rc.25")

    def test_missing_source_tree_fails(self) -> None:
        document = dict(self.document)
        del document["source_tree"]
        self.write(document)
        with self.assertRaisesRegex(ValueError, "source_tree"):
            validate(self.manifest, "a" * 40, "b" * 40, "0.4.0-rc.25")

    def test_wrong_version_fails(self) -> None:
        with self.assertRaisesRegex(ValueError, "version"):
            validate(self.manifest, "a" * 40, "b" * 40, "0.4.0-rc.26")

    def test_symlink_manifest_fails(self) -> None:
        target = self.root / "actual.json"
        target.write_text(json.dumps(self.document), encoding="utf-8")
        self.manifest.unlink()
        self.manifest.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            validate(self.manifest, "a" * 40, "b" * 40, "0.4.0-rc.25")


if __name__ == "__main__":
    unittest.main()
