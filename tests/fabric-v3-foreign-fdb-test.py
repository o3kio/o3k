#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("foreign_fdb", Path(__file__).with_name("fabric-v3-foreign-fdb.py"))
assert SPEC and SPEC.loader
foreign_fdb = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(foreign_fdb)


class ForeignFdbTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, content):
        path = self.root / name
        path.write_text(content)
        return path

    def test_ordering_is_ignored(self):
        before = self.write("before", "aa dev eth0 master br0\nbb dev eth1 master br1\n")
        after = self.write("after", "bb dev eth1 master br1\naa dev eth0 master br0\n")
        foreign_fdb.compare(before, after, set())

    def test_foreign_change_fails(self):
        before = self.write("before", "aa dev eth0 master br0\n")
        after = self.write("after", "cc dev eth0 master br0\n")
        with self.assertRaises(AssertionError):
            foreign_fdb.compare(before, after, set())

    def test_run_owned_device_is_excluded(self):
        before = self.write("before", "aa dev vxlan0 master br0\n")
        after = self.write("after", "bb dev vxlan0 master br0\n")
        foreign_fdb.compare(before, after, {"vxlan0"})

    def test_missing_scope_fails(self):
        with self.assertRaises(FileNotFoundError):
            foreign_fdb.compare(self.root / "missing", self.root / "after", set())


if __name__ == "__main__":
    unittest.main()
