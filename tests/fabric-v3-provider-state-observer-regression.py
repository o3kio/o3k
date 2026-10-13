#!/usr/bin/env python3
"""Regression tests for fail-closed guest provider-state observations."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "fabric_v3_provider_state_observer", ROOT / "fabric-v3-provider-state-observer.py"
)
assert SPEC and SPEC.loader
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


class ProviderStateObserverRegression(unittest.TestCase):
    def test_exact_ip_missing_device_error_is_absent(self) -> None:
        result = observer.parse_link_result("o3k-tap-test", 1, "", 'Device "o3k-tap-test" does not exist.')
        self.assertEqual(result["status"], "absent")
        self.assertEqual(result["reason"], "link_absent")

    def test_unrelated_ip_failure_is_error_not_absence(self) -> None:
        with self.assertRaises(observer.ObservationError) as raised:
            observer.parse_link_result("o3k-tap-test", 255, "", "sudo: a password is required")
        self.assertEqual(raised.exception.command_class, "ip_link_observation")
        self.assertEqual(raised.exception.exit_code, 255)

    def test_malformed_successful_link_inventory_is_error(self) -> None:
        with self.assertRaisesRegex(observer.ObservationError, "malformed JSON"):
            observer.parse_link_result("o3k-tap-test", 0, "not json", "")

    def test_link_present_is_typed_and_limited_to_nonsecret_identity(self) -> None:
        link = {"ifname": "o3k-tap-test", "address": "52:54:00:00:00:01", "link_type": "ether", "linkinfo": {"info_kind": "veth"}, "master": "bridge"}
        result = observer.parse_link_result("o3k-tap-test", 0, json.dumps([link]), "")
        self.assertEqual(result["status"], "present")
        self.assertEqual(result["link"]["ifname"], "o3k-tap-test")
        self.assertNotIn("master", result["link"])

    def test_missing_namespace_is_absent_only_on_exact_kernel_diagnostic(self) -> None:
        result = observer.parse_link_result(
            "vxlan0", 1, "", 'Cannot open network namespace "o3k-fabric": No such file or directory', "o3k-fabric"
        )
        self.assertEqual(result["status"], "absent")
        with self.assertRaises(observer.ObservationError):
            observer.parse_link_result("vxlan0", 1, "", "ssh: connection refused", "o3k-fabric")

    def test_namespace_command_failure_is_not_an_empty_inventory(self) -> None:
        with self.assertRaises(observer.ObservationError):
            observer.parse_namespace_list(255, "", "sudo failed", "o3k-fabric")
        absent = observer.parse_namespace_list(0, "default\n", "", "o3k-fabric")
        self.assertEqual(absent["status"], "absent")

    def test_exact_missing_path_is_absent_but_other_lstat_errors_fail(self) -> None:
        missing = observer.observe_path(pathlib.Path("/path/missing"), lstat=mock.Mock(side_effect=FileNotFoundError()))
        self.assertEqual(missing["status"], "absent")
        with self.assertRaises(observer.ObservationError):
            observer.observe_path(pathlib.Path("/path/denied"), lstat=mock.Mock(side_effect=PermissionError()))

    def test_owned_tree_root_that_is_not_a_directory_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "state"
            path.write_text("present")
            with self.assertRaisesRegex(observer.ObservationError, "not a directory"):
                observer.observe_tree(path)

    def test_process_observer_matches_absolute_dnsmasq_executable_and_run_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc = pathlib.Path(directory)
            process = proc / "123"
            process.mkdir()
            (process / "exe").symlink_to("/usr/sbin/dnsmasq")
            (process / "cmdline").write_bytes(
                b"/usr/sbin/dnsmasq\0--conf-file=/var/lib/o3k/run/network/dhcp/dnsmasq.conf\0"
            )
            result = observer.observe_process(
                "dnsmasq", "/var/lib/o3k/run/network/dhcp", proc
            )
            self.assertEqual(result["status"], "present")
            self.assertEqual(result["owned_pids"], [123])

    def test_foreign_dnsmasq_process_is_not_misclassified_as_run_owned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc = pathlib.Path(directory)
            process = proc / "456"
            process.mkdir()
            (process / "exe").symlink_to("/usr/sbin/dnsmasq")
            (process / "cmdline").write_bytes(
                b"/usr/sbin/dnsmasq\0--conf-file=/etc/dnsmasq.conf\0"
            )
            result = observer.observe_process(
                "dnsmasq", "/var/lib/o3k/run/network/dhcp", proc
            )
            self.assertEqual(result["status"], "absent")
            self.assertEqual(result["matching_process_count"], 1)
            self.assertEqual(result["owned_process_count"], 0)

    def test_matching_process_with_unreadable_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc = pathlib.Path(directory)
            process = proc / "789"
            process.mkdir()
            (process / "exe").symlink_to("/usr/sbin/dnsmasq")
            (process / "cmdline").write_bytes(b"")
            with self.assertRaisesRegex(observer.ObservationError, "empty command line"):
                observer.observe_process("dnsmasq", "/var/lib/o3k/run/network/dhcp", proc)


if __name__ == "__main__":
    unittest.main()
