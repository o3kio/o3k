#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile
import unittest
import json
import subprocess

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

    def test_bridge_json_ordering_and_device_exclusion_are_semantic(self):
        before = self.write("json-before", json.dumps([{"mac": "aa", "ifname": "eth0"}, {"mac": "old", "ifname": "vxlan0"}]))
        after = self.write("json-after", json.dumps([{"ifname": "vxlan0", "mac": "new"}, {"ifname": "eth0", "mac": "aa"}]))
        foreign_fdb.compare(before, after, {"vxlan0"})

    def test_missing_scope_fails(self):
        with self.assertRaises(FileNotFoundError):
            foreign_fdb.compare(self.root / "missing", self.root / "after", set())

    def test_namespace_ordering_and_run_scope_are_normalized(self):
        before = self.write("ns-before", "foreign-a\nrun-fabric\n")
        after = self.write("ns-after", "run-fabric\nforeign-a\n")
        foreign_fdb.compare_namespaces(before, after, {"run-fabric"})

    def test_foreign_namespace_change_fails(self):
        before = self.write("ns-before", "foreign-a\n")
        after = self.write("ns-after", "foreign-b\n")
        with self.assertRaises(AssertionError):
            foreign_fdb.compare_namespaces(before, after, set())

    def test_malformed_json_and_non_object_rows_fail_closed(self):
        malformed = self.write("bad.json", "not-json")
        valid = self.write("valid.json", "[]")
        with self.assertRaises(ValueError):
            foreign_fdb.compare(malformed, valid, set())
        non_object = self.write("rows.json", json.dumps(["bad"]))
        with self.assertRaises(ValueError):
            foreign_fdb.compare(non_object, valid, set())

    def test_namespace_only_cli_invocation_succeeds(self):
        before = self.write("cli-before", "foreign\nrun\n")
        after = self.write("cli-after", "run\nforeign\n")
        result = subprocess.run(
            ["python3", str(Path(__file__).with_name("fabric-v3-foreign-fdb.py")),
             "--before-namespaces", str(before), "--after-namespaces", str(after),
             "--owned-namespace", "run"], check=False,
        )
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
