#!/usr/bin/env python3
"""Regression coverage for Fabric campaign cleanup result aggregation."""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
DRIVER = (ROOT / "fabric-v3-o3k-three-host-campaign.sh").read_text()
HELPER_PATH = ROOT / "fabric_v3_campaign_result.py"
SPEC = importlib.util.spec_from_file_location("fabric_v3_campaign_result", HELPER_PATH)
helper = None
if SPEC and SPEC.loader:
    helper = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(helper)


class CampaignResultRegression(unittest.TestCase):
    def test_metadata_is_not_interpreted_as_a_cleanup_predicate(self):
        self.assertIsNotNone(helper, "cleanup result predicate helper is required")
        cleanup = {
            "acceptance_gate": "FABRIC V3 DURABLE HOST RETIREMENT MICROGATE",
            "api_resources": "PASS",
            "owned_guests_and_storage": "PASS",
            "controller_process": "PASS",
            "post_cleanup_host_inventory": "PASS",
            "foreign_state_unchanged": "PASS",
            "run_owned_dhcp_capture": "PASS",
            "image_store_pool_refresh": "PASS",
        }
        self.assertTrue(helper.cleanup_predicates_pass(cleanup))

    def test_failed_or_missing_cleanup_predicate_fails_closed(self):
        self.assertIsNotNone(helper, "cleanup result predicate helper is required")
        complete = {
            key: "PASS" for key in helper.CLEANUP_PREDICATE_KEYS
        }
        for key in helper.CLEANUP_PREDICATE_KEYS:
            with self.subTest(key=key):
                failed = dict(complete, **{key: "FAIL"})
                self.assertFalse(helper.cleanup_predicates_pass(failed))
                missing = dict(complete)
                del missing[key]
                self.assertFalse(helper.cleanup_predicates_pass(missing))

    def test_not_applicable_is_allowed_for_optional_cleanup_predicates(self):
        self.assertIsNotNone(helper, "cleanup result predicate helper is required")
        cleanup = {key: "PASS" for key in helper.CLEANUP_PREDICATE_KEYS}
        cleanup["run_owned_dhcp_capture"] = "NOT_APPLICABLE"
        self.assertTrue(helper.cleanup_predicates_pass(cleanup))

    def test_campaign_finalizer_uses_the_explicit_predicate_helper(self):
        self.assertIn("cleanup_predicates_pass(cleanup)", DRIVER)
        self.assertNotIn("cleanup.values()", DRIVER)
        self.assertIn("fabric-v3-campaign-result-test.py", DRIVER)


if __name__ == "__main__":
    unittest.main()
