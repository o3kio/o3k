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
        before = self.write("ns-before", "foreign-a (id: 4026532000)\nrun-fabric (id: 4026532001)\n")
        after = self.write("ns-after", "run-fabric (id: 4026532001)\nforeign-a (id: 4026532000)\n")
        foreign_fdb.compare_namespaces(before, after, {"run-fabric"})

        wrong = self.write("ns-wrong", "foreign-a (id: 4026532000)\nother (id: 4026532001)\n")
        with self.assertRaises(AssertionError):
            foreign_fdb.compare_namespaces(before, wrong, {"run-fabric"})

    def test_shell_first_field_accepts_annotated_namespace(self):
        command = "awk -v expected=foreign-a '$1 == expected { found=1 } END { exit found ? 0 : 1 }'"
        result = subprocess.run(["bash", "-c", command], input="foreign-a (id: 4026532000)\n", text=True, check=False)
        self.assertEqual(result.returncode, 0)
        result = subprocess.run(["bash", "-c", command], input="other (id: 4026532000)\n", text=True, check=False)
        self.assertNotEqual(result.returncode, 0)

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
        for content in ("null", "{}"):
            non_list = self.write("non-list.json", content)
            with self.assertRaises(ValueError):
                foreign_fdb.compare(non_list, valid, set())

    def test_json_set_like_fields_are_order_insensitive(self):
        before = self.write("flags-before.json", json.dumps([{"dev": "eth0", "flags": ["self", "permanent"]}]))
        after = self.write("flags-after.json", json.dumps([{"flags": ["permanent", "self"], "dev": "eth0"}]))
        foreign_fdb.compare(before, after, set())

    def test_namespace_only_cli_invocation_succeeds(self):
        before = self.write("cli-before", "foreign\nrun\n")
        after = self.write("cli-after", "run\nforeign\n")
        result = subprocess.run(
            ["python3", str(Path(__file__).with_name("fabric-v3-foreign-fdb.py")),
             "--before-namespaces", str(before), "--after-namespaces", str(after),
             "--owned-namespace", "run"], check=False,
        )
        self.assertEqual(result.returncode, 0)

    def test_cli_without_comparison_fails_closed(self):
        result = subprocess.run(["python3", str(Path(__file__).with_name("fabric-v3-foreign-fdb.py"))], check=False)
        self.assertEqual(result.returncode, 2)

    def test_non_utf8_observation_is_harness_error(self):
        before = self.root / "undecodable.json"
        before.write_bytes(b"\xff")
        after = self.write("empty.json", "[]")
        result = subprocess.run(
            ["python3", str(Path(__file__).with_name("fabric-v3-foreign-fdb.py")),
             "--before", str(before), "--after", str(after)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_distinguishes_observation_error_from_mutation(self):
        script = str(Path(__file__).with_name("fabric-v3-foreign-fdb.py"))
        missing = subprocess.run(["python3", script, "--before", str(self.root / "missing"), "--after", str(self.root / "after")], check=False)
        self.assertEqual(missing.returncode, 2)
        before = self.write("changed-before", "aa dev eth0 master br0\n")
        after = self.write("changed-after", "bb dev eth0 master br0\n")
        changed = subprocess.run(["python3", script, "--before", str(before), "--after", str(after)], check=False)
        self.assertEqual(changed.returncode, 1)


if __name__ == "__main__":
    unittest.main()
