#!/usr/bin/env python3
"""Regression tests for the release verifier's structured success report."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile

from write_release_verification_report import write_report


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        report = root / "result.json"
        write_report(report, "0.4.0-rc.25", "v0.4.0-rc.25", "a" * 40, "b" * 40)
        document = json.loads(report.read_text(encoding="utf-8"))
        assert document == {
            "schema": "o3k.release-verification.v1",
            "status": "passed",
            "version": "0.4.0-rc.25",
            "tag": "v0.4.0-rc.25",
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "workflow_identity": "https://github.com/o3kio/o3k/.github/workflows/release.yml@refs/tags/v0.4.0-rc.25",
            "checks": {
                "provenance": "passed", "signature": "passed",
                "source_identity": "passed", "transparency": "passed",
            },
        }
        assert os.stat(report).st_mode & 0o777 == 0o600

        try:
            write_report(report, "0.4.0-rc.25", "v0.4.0-rc.25", "a" * 40, "b" * 40)
        except ValueError as error:
            assert "unused absolute path" in str(error)
        else:
            raise AssertionError("existing verification report was overwritten")

        symlink = root / "symlink.json"
        symlink.symlink_to(report)
        try:
            write_report(symlink, "0.4.0-rc.25", "v0.4.0-rc.25", "a" * 40, "b" * 40)
        except ValueError as error:
            assert "unused absolute path" in str(error)
        else:
            raise AssertionError("symlinked report path was accepted")

        missing_parent_report = root / "missing" / "result.json"
        try:
            write_report(missing_parent_report, "0.4.0-rc.25", "v0.4.0-rc.25", "a" * 40, "b" * 40)
        except ValueError as error:
            assert "existing directory" in str(error)
        else:
            raise AssertionError("missing report parent was created implicitly")
        assert not missing_parent_report.parent.exists()

        real_parent = root / "real-parent"
        real_parent.mkdir()
        parent_symlink = root / "linked-parent"
        parent_symlink.symlink_to(real_parent, target_is_directory=True)
        linked_report = parent_symlink / "result.json"
        try:
            write_report(linked_report, "0.4.0-rc.25", "v0.4.0-rc.25", "a" * 40, "b" * 40)
        except ValueError as error:
            assert "must not contain symlinks" in str(error)
        else:
            raise AssertionError("report path through a symlinked parent was accepted")
        assert not (real_parent / "result.json").exists()

        for bad in (
            ("0.4.0-rc.25", "v0.4.0-rc.24", "a" * 40, "b" * 40),
            ("0.4.0-rc.25", "v0.4.0-rc.25", "A" * 40, "b" * 40),
            ("0.4.0-rc.25", "v0.4.0-rc.25", "a" * 40, "z" * 40),
        ):
            try:
                write_report(root / f"bad-{len(list(root.iterdir()))}.json", *bad)
            except ValueError:
                pass
            else:
                raise AssertionError("malformed verifier identity was accepted")


if __name__ == "__main__":
    main()
    print("release verification report tests passed")
