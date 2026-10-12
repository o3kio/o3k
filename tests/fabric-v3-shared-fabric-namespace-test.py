#!/usr/bin/env python3
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).with_name("fabric-v3-shared-fabric-namespace.py")


class SharedFabricNamespaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ownership = self.root / "ownership.json"
        self.post_ownership = self.root / "post-ownership.json"
        self.namespaces = self.root / "namespaces.txt"
        self.output = self.root / "namespace-state.json"
        self.ownership.write_text(json.dumps({"fabric": {"namespace": "o3k-fabric"}}))
        self.post_ownership.write_text(json.dumps({"fabric": None, "realms": {}}))

    def tearDown(self):
        self.temp.cleanup()

    def _run(self):
        return subprocess.run(
            [
                sys.executable,
                str(HELPER),
                str(self.ownership),
                str(self.post_ownership),
                str(self.namespaces),
                str(self.output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_present_namespace_is_observed_using_pre_delete_identity(self):
        self.namespaces.write_text("o3k-fabric (id: 4026533001)\n")

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["namespace"], "o3k-fabric")
        self.assertEqual(evidence["state"], "present")
        self.assertEqual(evidence["post_ownership_namespace"], None)
        self.assertFalse(evidence["post_ownership_claims_namespace"])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_absent_namespace_is_a_valid_post_remove_observation(self):
        self.namespaces.write_text("")

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["state"], "absent")
        self.assertEqual(evidence["observer"], "ip-netns-list")
        self.assertEqual(evidence["post_ownership_namespace"], None)
        self.assertFalse(evidence["post_ownership_claims_namespace"])

    def test_missing_pre_delete_fabric_identity_fails_closed(self):
        self.ownership.write_text(json.dumps({"fabric": None, "realms": {}}))
        self.post_ownership.write_text(json.dumps({"fabric": None, "realms": {}}))
        self.namespaces.write_text("")

        result = self._run()

        self.assertEqual(result.returncode, 2)
        self.assertIn("HARNESS_GAP", result.stderr)
        self.assertFalse(self.output.exists())

    def test_post_remove_ownership_claim_is_recorded_for_gate_rejection(self):
        self.post_ownership.write_text(json.dumps({"fabric": {"namespace": "o3k-fabric"}}))
        self.namespaces.write_text("")

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["state"], "absent")
        self.assertTrue(evidence["post_ownership_claims_namespace"])
        self.assertEqual(evidence["post_ownership_namespace"], "o3k-fabric")

    def test_changed_post_namespace_identity_is_recorded_for_gate_rejection(self):
        self.post_ownership.write_text(json.dumps({"fabric": {"namespace": "o3k-fabric-2"}}))
        self.namespaces.write_text("o3k-fabric\n")

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["namespace"], "o3k-fabric")
        self.assertEqual(evidence["post_ownership_namespace"], "o3k-fabric-2")

    def test_invalid_namespace_name_fails_closed(self):
        self.ownership.write_text(json.dumps({"fabric": {"namespace": "bad/name"}}))
        self.namespaces.write_text("")

        result = self._run()

        self.assertEqual(result.returncode, 2)
        self.assertIn("HARNESS_GAP", result.stderr)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
