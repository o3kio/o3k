import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fabric_v3_acceptance_status", ROOT / "scripts/fabric_v3_acceptance_status.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class AcceptanceStatusTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(
            (ROOT / "docs/evidence/fabric-v3-validation-status.json").read_text()
        )

    def test_authorized_deferral_is_nonblocking_but_not_a_pass(self):
        result = MODULE.evaluate(self.record)
        self.assertEqual(result["automated_product_validation"], "PASS")
        self.assertEqual(result["real_host_nested_microgate"], "DEFERRED_BY_POLICY")
        self.assertEqual(result["physical_three_host_gate_b"], "DEFERRED_BY_POLICY")
        self.assertFalse(result["merge_blocked_by_physical_validation"])
        self.assertFalse(result["final_physical_certification_claimed"])

    def test_unauthorized_deferral_is_rejected(self):
        self.record["authorized_deferrals"].pop("physical_three_host_gate_b")
        with self.assertRaisesRegex(ValueError, "lacks explicit authorization"):
            MODULE.evaluate(self.record)

    def test_failure_is_not_reclassified_as_deferral(self):
        self.record["evidence"]["physical_three_host_gate_b"] = "FAIL"
        result = MODULE.evaluate(self.record)
        self.assertEqual(result["physical_three_host_gate_b"], "FAIL")
        self.assertTrue(result["merge_blocked_by_physical_validation"])

    def test_not_run_remains_not_run_and_blocks_when_not_authorized(self):
        self.record["evidence"]["physical_three_host_gate_b"] = "NOT_RUN"
        result = MODULE.evaluate(self.record)
        self.assertEqual(result["physical_three_host_gate_b"], "NOT_RUN")
        self.assertTrue(result["merge_blocked_by_physical_validation"])

    def test_nonpassing_automated_validation_stays_nonpassing(self):
        self.record["evidence"]["sqlite_lifecycle"] = "NOT_RUN"
        result = MODULE.evaluate(self.record)
        self.assertEqual(result["automated_product_validation"], "FAIL")
        self.assertEqual(result["missing_automated_passes"], ["sqlite_lifecycle"])

    def test_unknown_state_is_rejected(self):
        self.record["evidence"]["physical_three_host_gate_b"] = "SKIPPED"
        with self.assertRaisesRegex(ValueError, "unsupported state"):
            MODULE.evaluate(self.record)


if __name__ == "__main__":
    unittest.main()
