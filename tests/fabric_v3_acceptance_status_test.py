import contextlib
import io
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch


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

    def test_nested_failure_blocks_review(self):
        self.record["evidence"]["real_host_nested_microgate"] = "FAIL"
        result = MODULE.evaluate(self.record)
        self.assertEqual(result["real_host_nested_microgate"], "FAIL")
        self.assertTrue(result["merge_blocked_by_physical_validation"])

    def test_nested_not_run_blocks_review(self):
        self.record["evidence"]["real_host_nested_microgate"] = "NOT_RUN"
        result = MODULE.evaluate(self.record)
        self.assertEqual(result["real_host_nested_microgate"], "NOT_RUN")
        self.assertTrue(result["merge_blocked_by_physical_validation"])

    def test_authorized_nested_deferral_does_not_claim_a_pass(self):
        result = MODULE.evaluate(self.record)
        self.assertEqual(result["real_host_nested_microgate"], "DEFERRED_BY_POLICY")
        self.assertFalse(result["merge_blocked_by_physical_validation"])
        self.assertFalse(result["final_physical_certification_claimed"])

    def test_nonpassing_automated_validation_stays_nonpassing(self):
        self.record["evidence"]["sqlite_lifecycle"] = "NOT_RUN"
        result = MODULE.evaluate(self.record)
        self.assertEqual(result["automated_product_validation"], "FAIL")
        self.assertEqual(result["missing_automated_passes"], ["sqlite_lifecycle"])

    def test_unknown_state_is_rejected(self):
        self.record["evidence"]["physical_three_host_gate_b"] = "SKIPPED"
        with self.assertRaisesRegex(ValueError, "unsupported state"):
            MODULE.evaluate(self.record)

    def test_non_string_state_is_rejected(self):
        self.record["evidence"]["physical_three_host_gate_b"] = ["PASS"]
        with self.assertRaisesRegex(ValueError, "unsupported state"):
            MODULE.evaluate(self.record)

    def test_non_string_authorization_is_rejected(self):
        self.record["authorized_deferrals"]["physical_three_host_gate_b"] = ["approved"]
        with self.assertRaisesRegex(ValueError, "lacks explicit authorization"):
            MODULE.evaluate(self.record)

    def test_non_object_record_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "status record must be an object"):
            MODULE.evaluate([])

    def test_cli_returns_failure_when_nested_gate_is_not_run(self):
        self.record["evidence"]["real_host_nested_microgate"] = "NOT_RUN"
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as status_file:
            json.dump(self.record, status_file)
            status_file.flush()
            with patch.object(
                sys, "argv", ["fabric_v3_acceptance_status.py", status_file.name]
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(MODULE.main(), 1)

    def test_cli_accepts_authorized_deferral_without_certification(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as status_file:
            json.dump(self.record, status_file)
            status_file.flush()
            with patch.object(
                sys, "argv", ["fabric_v3_acceptance_status.py", status_file.name]
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(MODULE.main(), 0)


if __name__ == "__main__":
    unittest.main()
