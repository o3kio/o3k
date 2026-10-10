#!/usr/bin/env python3
"""Regression tests for exact, ownership-safe nested-domain cleanup."""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("fabric-v3-owned-domain-storage.py")
SPEC = importlib.util.spec_from_file_location("owned_domain_storage", MODULE_PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class OwnedDomainStorageTest(unittest.TestCase):
    def xml(self, extra: str = "") -> str:
        return f"""<domain><name>run-compute-a</name><uuid>owned-uuid</uuid><devices>
          <disk type="file" device="disk"><source file="/images/run-compute-a.qcow2"/></disk>
          <disk type="file" device="cdrom"><source file="/images/run-compute-a-seed.iso"/></disk>
          {extra}
        </devices></domain>"""

    def matches(self, xml: str) -> bool:
        return module.matches_owned_domain(
            xml,
            "run-compute-a",
            "owned-uuid",
            "/images/run-compute-a.qcow2",
            "/images/run-compute-a-seed.iso",
        )

    def test_exact_run_owned_disk_and_seed_are_accepted(self):
        self.assertTrue(self.matches(self.xml()))

    def test_additional_disk_is_rejected(self):
        self.assertFalse(
            self.matches(
                self.xml(
                    '<disk type="file" device="disk"><source file="/foreign/data.qcow2"/></disk>'
                )
            )
        )

    def test_changed_disk_seed_name_or_uuid_is_rejected(self):
        self.assertFalse(self.matches(self.xml().replace("run-compute-a.qcow2", "foreign.qcow2")))
        self.assertFalse(self.matches(self.xml().replace("owned-uuid", "foreign-uuid")))
        self.assertFalse(self.matches(self.xml().replace("run-compute-a</name>", "other</name>")))

    def test_non_file_or_unexpected_storage_source_is_rejected(self):
        self.assertFalse(self.matches(self.xml().replace('source file="/images/run-compute-a.qcow2"', 'source dev="/dev/sda"')))
        self.assertFalse(self.matches("not xml"))


if __name__ == "__main__":
    unittest.main()
